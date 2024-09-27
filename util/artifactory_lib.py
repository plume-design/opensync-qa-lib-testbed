#!/usr/bin/env python3

import sys
import requests
import re
import urllib.request
import urllib.error
import urllib.parse
import json
import traceback

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.object_resolver import ObjectResolver


def get_map(model, map_type="build_map.json"):
    try:
        bm_file = ObjectResolver.resolve_model_path_file(file_name=map_type, model=model)
    except Exception as err:
        log.error(err)
        return {}
    with open(bm_file) as bm:
        return json.load(bm)


def add_model(cfg, matrix, cmodel, module=None, https=True, **kwargs):
    # expected cmodel format: [model, fw_version, residentialGateway, [prerequisiteVersions: (list)]]
    def get_fw_info(cmodel):
        m_model = cmodel[0].strip()
        m_fw_version = cmodel[1].strip()
        m_resident_gw = cmodel[2]
        m_prerequisite_versions = []
        if len(cmodel) > 3:
            m_prerequisite_versions = cmodel[3]
        regex = r"((?P<prefix>[a-zA-Z-]*))?(?P<branch>\d.\d.\d)-(?P<build>\d*)-(?P<sha>\w+)-(?P<profile>.*)"
        fw_match = re.match(regex, m_fw_version)
        if not fw_match:
            log.error("Cannot parse %s" % m_fw_version)
            prefix = "native-" if "native" in m_fw_version else ""
            m_fw_version = m_fw_version.replace("native-", "")
            version = m_fw_version.split("-")[0]
            img_profile = "-".join(m_fw_version.split("-")[3:])
        else:
            fw_parts = fw_match.groupdict()
            version = fw_parts["branch"]
            prefix = fw_parts["prefix"].lower()
            m_fw_version = f"{fw_parts['branch']}-{fw_parts['build']}-{fw_parts['sha']}-{fw_parts['profile']}"
            img_profile = fw_parts["profile"]

        model_map = get_map(m_model)
        if not model_map:
            log.error(f"!! Model {m_model} not supported.")
            sys.exit(23)

        if prefix + version not in model_map:
            log.warning(f"Cannot find proper branch for {version} for {m_model}. Trying master branch")
            version = "master"

        build_data = model_map[prefix + version]
        bucket = build_data["s3-bucket"] if "s3-bucket" in build_data else model_map["s3-bucket"]
        base_name = f"{build_data['fn-prefix']}-{m_fw_version}"

        # for downloadUrl add the first fw version that supports encrypted upgrade
        if "firstEncryptedBuild" in build_data and build_data["encryption"]:
            first_raw_version = build_data["firstEncryptedBuild"]
            first_version = first_raw_version.split("-")[0]
            if first_version not in model_map:
                log.error(f"!! Version {first_version} not supported for model {m_model}.")
                sys.exit(23)
            first_build_data = model_map[first_version]
            first_fn_prefix = first_build_data["fn-prefix"]
            # Get image profile of the desired VM  prod/dev-debug..
            first_m_fw_version = f"{first_raw_version}-{img_profile}"
            first_base_name = f"{first_fn_prefix}-{first_m_fw_version}"
            img_name = first_base_name + ".img"
        else:
            if "img-suffix" in build_data:
                img_name = f'{base_name}.{build_data["img-suffix"]}'
            elif "enc-suffix" in build_data:
                img_name = f'{base_name}.{build_data["enc-suffix"]}'
            else:
                raise Exception("Inappropriate configuration. Set either img-suffix or enc-suffix")

        s3_url = cfg["artifactory"]["s3_url"]
        if not https:
            s3_url = s3_url.replace("https://", "http://")
        img_url = f"{s3_url}/{bucket}/{img_name}"

        if build_data["encryption"]:
            enc_name = f'{base_name}.{build_data["enc-suffix"]}'
            key_name = f'{enc_name}.{build_data["key-suffix"]}'
            enc_url = f"{s3_url}/{bucket}/{enc_name}"
            key_url = f'{cfg["artifactory"]["url"]}/{build_data["proj-name"]}/{key_name}'

        model = dict()
        model["firmwareVersion"] = m_fw_version
        model["model"] = m_model

        if "img-hash" in build_data:
            hall_fw_version = model["firmwareVersion"].split("-")
            hall_fw_version[2] = build_data["img-hash"]
            model["firmwareVersion"] = "-".join(hall_fw_version)

        if isinstance(m_resident_gw, str):
            if m_resident_gw.strip().lower() in ["true", "yes", "ok", "correct", "y", "t"]:
                model["residentialGateway"] = True
            else:
                model["residentialGateway"] = False
        else:
            model["residentialGateway"] = m_resident_gw

        if test_url(img_url, **kwargs):
            model["downloadUrl"] = img_url

        if build_data["encryption"] and test_url(enc_url, **kwargs):
            key = get_enc_key(key_url)
            model["encryptedDownloadUrl"] = enc_url
            model["firmwareEncryptionKey"] = key

        if module:
            model["modules"] = [
                {"filename": f"app_signatures-{module}.tar.gz", "name": "app_signatures", "version": module}
            ]
        if m_prerequisite_versions:
            model["prerequisiteVersions"] = []
            for version in m_prerequisite_versions:
                prerequisite_version = get_fw_info([cmodel[0], version, False, []])
                model["prerequisiteVersions"].append(prerequisite_version)

        return model

    model_info = get_fw_info(cmodel)
    matrix["models"].append(model_info)


def get_enc_key(url):
    log.info(f"Attempting to read encryption key from {url}")
    resp = urllib.request.urlopen(url)
    code = resp.getcode()
    if code == 200:
        return resp.read().decode().strip("").strip("\n").strip(" ")
    raise Exception(f"Failed to download key from {url}: HTTP code: {code}")


def test_url(url, **kwargs):
    if kwargs.get("skip_url_test"):
        return True
    log.info(f">> Testing availability of URL {url}")
    try:
        urllib.request.urlopen(url)
        return True
    except urllib.error.HTTPError as err:
        if err.code == 403:
            raise ValueError(f"File not found: {err}")
        else:
            raise Exception(f"URL test failed: {err}")


def query_artifactory_for_artifact_list(cfg, build_name, build_number):
    """Query artifactory API for a list of all artifacts."""
    artif_url = cfg["artifactory"]["url"] + "/api/search/buildArtifacts"
    headers = {
        "Content-Type": "application/json",
    }

    data = '{ "buildName":"' + build_name + '", "buildNumber":"' + build_number + '" }'
    log.debug(data)
    fwjson = {}
    try:
        fwresp = requests.post(artif_url, headers=headers, data=data)
        fwjson = fwresp.json()
    except Exception as e:
        traceback.print_exc()
        log.error(str(e))
    if fwjson.get("errors"):
        errors = fwjson.get("errors")[0]
        log.error(f'Status={errors.get("status")}: {errors.get("message")}')
        return []
    else:
        log.debug(fwjson)
        return fwjson


def get_artifactory_fw_url(cfg, fw_ver, model, map_type="build_map.json", use_build_map_suffix=False):
    fw_ver = fw_ver.split("-")
    legacy = ""
    if "legacy" in fw_ver:
        legacy = "legacy-"
        fw_ver.remove("legacy")
    native = ""
    if "native" in fw_ver:
        native = "native-"
        fw_ver.remove("native")
    fw_map_full = get_map(model, map_type)
    fw_map = fw_map_full[legacy + native + fw_ver[0]]
    fw_regex = fw_map.get("fn-regex", fw_map_full.get("fn-regex"))
    # TODO please suggest an alternative to get tar.bz2 from img-suffix in here for "pod gw upgrade" command -
    #  why not simply use img-suffix, enc-suffix when they're provided?
    use_build_map_suffix = fw_map.get("use-build-map-suffix", use_build_map_suffix)

    # TODO how to override this for some res GW which is not using this - overriding this at deployment file level
    #  seems wrong
    build_profile = fw_map.get("use-build-map-build-profile", cfg.get("build_profile", "dev-debug"))
    build_name = fw_map["proj-name"].split("/")[0]
    build_number = fw_ver[1]
    if use_build_map_suffix:
        if fw_map["encryption"]:
            suffix = fw_map["enc-suffix"]
        else:
            suffix = fw_map["img-suffix"]
    else:
        suffix = "img"
    # Get raw data from artifactory
    fwjson = query_artifactory_for_artifact_list(cfg, build_name, build_number)
    # If the query result is empty, return None
    if not fwjson:
        return None
    all_urls = [url["downloadUri"] for url in fwjson["results"]]
    filter_urls = []
    fw_artifacts = []

    # Filter out only the correct build_profile and suffix
    for url in all_urls:
        if build_profile in url and url.endswith(suffix):
            filter_urls.append(url)
    # Use fn-regex to match filenames if available
    if fw_regex:
        fw_artifacts = [url for url in filter_urls if re.findall(fw_regex, url)]
        if len(fw_artifacts) == 1:
            return fw_artifacts[0]

    # Alternatively use fn-prefix
    tmp_urls = filter_urls if len(fw_artifacts) == 0 else fw_artifacts
    urls = []
    for url in tmp_urls:
        if fw_map["fn-prefix"] in url:
            urls.append(url)
    if len(urls) != 1:
        log.error(all_urls)
        raise Exception(f"Could not get exactly one FW URL for build {build_name} number {build_number}: {urls}")
    else:
        fw_artifacts = urls
    return fw_artifacts[0]


def generate_artifactory_fw_url(cfg, fw_ver, model, map_type="build_map.json", use_build_map_suffix=False):
    fw_map = get_map(model, map_type)[fw_ver.split("-")[0]]
    if use_build_map_suffix:
        if fw_map["encryption"]:
            suffix = fw_map["enc-suffix"]
        else:
            suffix = fw_map["img-suffix"]
    else:
        suffix = "img"
    return f'{cfg["artifactory"]["url"]}/{fw_map["proj-name"]}/{fw_map["fn-prefix"]}-{fw_ver}.{suffix}'


def search_artifact_by_name(cfg, regex):
    regex = requests.utils.quote(regex)
    artifactory_https = cfg["artifactory"]["url"]
    headers = cfg["artifactory"]["headers"]
    artif_url = f"{artifactory_https}/api/search/artifact?name={regex}"
    artif_key = "results"
    item_key = "uri"

    try:
        rest_response = requests.get(artif_url, headers=headers)
    except Exception as exception:
        traceback.print_exc()
        raise exception

    resp_json = rest_response.json()
    results = [item[item_key].lstrip("/") for item in resp_json[artif_key] if item_key in item.keys()]
    url_list = []

    for result in results:
        url = result.replace("api/storage/", "")
        url_list.append(url)

    return url_list
