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


def get_map(model, map_type='build_map.json'):
    try:
        bm_file = ObjectResolver.resolve_model_path_file(file_name=map_type, model=model)
    except Exception as err:
        log.error(err)
        return {}
    with open(bm_file) as bm:
        return json.load(bm)


def add_model(cfg, matrix, cmodel, module=None, https=True, **kwargs):
    m_model = cmodel[0].strip()
    m_fw_version = cmodel[1].strip()
    m_resident_gw = cmodel[2].strip()

    version = m_fw_version.split('-')[0]
    model_map = get_map(m_model)
    if not model_map:
        log.error(f'!! Model {m_model} not supported.')
        sys.exit(23)

    if version not in model_map:
        log.warning(f'Cannot find proper branch for {version} for {m_model}. Trying master branch')
        version = 'master'

    build_data = model_map[version]
    bucket = build_data['s3-bucket'] if 's3-bucket' in build_data else model_map['s3-bucket']
    base_name = f"{build_data['fn-prefix']}-{m_fw_version}"

    # for downloadUrl add the first fw version that supports encrypted upgrade
    if 'firstEncryptedBuild' in build_data and build_data['encryption']:
        first_raw_version = build_data['firstEncryptedBuild']
        first_version = first_raw_version.split('-')[0]
        if first_version not in model_map:
            log.error(f'!! Version {first_version} not supported for model {m_model}.')
            sys.exit(23)
        first_build_data = model_map[first_version]
        first_fn_prefix = first_build_data['fn-prefix']
        # Get image profile of the desired VM  prod/dev-debug..
        img_profile = "-".join(m_fw_version.split("-")[3:])
        first_m_fw_version = f'{first_raw_version}-{img_profile}'
        first_base_name = f'{first_fn_prefix}-{first_m_fw_version}'
        img_name = first_base_name + '.img'
    else:
        if 'img-suffix' in build_data:
            img_name = f'{base_name}.{build_data["img-suffix"]}'
        elif 'enc-suffix' in build_data:
            img_name = f'{base_name}.{build_data["enc-suffix"]}'
        else:
            raise Exception('Inappropriate configuration. Set either img-suffix or enc-suffix')

    s3_url = cfg["artifactory"]["s3_url"]
    if not https:
        s3_url = s3_url.replace('https://', 'http://')
    img_url = f'{s3_url}/{bucket}/{img_name}'

    if build_data['encryption']:
        enc_name = f'{base_name}.{build_data["enc-suffix"]}'
        key_name = f'{enc_name}.{build_data["key-suffix"]}'
        enc_url = f'{s3_url}/{bucket}/{enc_name}'
        key_url = f'{cfg["artifactory"]["url"]}/{build_data["proj-name"]}/{key_name}'

    model = dict()
    model['firmwareVersion'] = m_fw_version
    model['model'] = m_model

    if 'img-hash' in build_data:
        hall_fw_version = model['firmwareVersion'].split('-')
        hall_fw_version[2] = build_data['img-hash']
        model['firmwareVersion'] = '-'.join(hall_fw_version)

    if m_resident_gw.lower() in ['true', 'yes', 'ok', 'correct', 'y', 't']:
        model['residentialGateway'] = True
    else:
        model['residentialGateway'] = False

    if test_url(img_url, **kwargs):
        model['downloadUrl'] = img_url

    if build_data['encryption'] and test_url(enc_url, **kwargs):
        key = get_enc_key(key_url)
        model['encryptedDownloadUrl'] = enc_url
        model['firmwareEncryptionKey'] = key

    if module:
        model['modules'] = [{'filename': f"app_signatures-{module}.tar.gz",
                             'name': "app_signatures",
                             'version': module}]

    matrix['models'].append(model)


def get_enc_key(url):
    log.info(f"Attempting to read encryption key from {url}")
    resp = urllib.request.urlopen(url)
    code = resp.getcode()
    if code == 200:
        return resp.read().decode().strip('').strip('\n').strip(' ')
    raise Exception(f'Failed to download key from {url}: HTTP code: {code}')


def test_url(url, **kwargs):
    if kwargs.get('skip_url_test'):
        return True
    log.info(f">> Testing availability of URL {url}")
    try:
        urllib.request.urlopen(url)
        return True
    except urllib.error.HTTPError as err:
        if err.code == 403:
            raise Exception(f'File not found; HTTP error: {err}')
        else:
            raise Exception(f'URL test failed; HTTP error: {err}')


def query_artifactory_for_artifact_list(cfg, build_name, build_number):
    """Query artifactory API for a list of all artifacts."""
    artif_url = cfg["artifactory"]["url"] + '/api/search/buildArtifacts'
    headers = {
        'Content-Type': 'application/json',
    }

    data = '{ "buildName":"' + build_name + '", "buildNumber":"' + build_number + '" }'
    log.debug(data)
    fwjson = []
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


def get_artifactory_fw_url(cfg, fw_ver, model, map_type='build_map.json', use_build_map_suffix=False):
    fw_ver = fw_ver.split('-')
    fw_map_full = get_map(model, map_type)
    fw_map = fw_map_full[fw_ver[0]]
    fw_regex = fw_map.get('fn-regex', fw_map_full.get('fn-regex'))
    build_profile = cfg.get('build_profile', 'dev-debug')
    build_name = fw_map['proj-name'].split('/')[0]
    build_number = fw_ver[1]
    if use_build_map_suffix:
        if fw_map['encryption']:
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
    all_urls = [url['downloadUri'] for url in fwjson["results"]]
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
        if fw_map['fn-prefix'] in url:
            urls.append(url)
    if len(urls) != 1:
        log.error(all_urls)
        raise Exception(f'Could not get exactly one FW URL for build {build_name} number {build_number}: {urls}')
    else:
        fw_artifacts = urls
    return fw_artifacts[0]


def generate_artifactory_fw_url(cfg, fw_ver, model, map_type='build_map.json', use_build_map_suffix=False):
    fw_map = get_map(model, map_type)[fw_ver.split('-')[0]]
    if use_build_map_suffix:
        if fw_map['encryption']:
            suffix = fw_map["enc-suffix"]
        else:
            suffix = fw_map["img-suffix"]
    else:
        suffix = "img"
    return f'{cfg["artifactory"]["url"]}/{fw_map["proj-name"]}/{fw_map["fn-prefix"]}-{fw_ver}.{suffix}'
