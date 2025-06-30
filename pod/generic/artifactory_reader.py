import re
import os
import tempfile
import requests
import functools
from pathlib import Path


from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.common import wait_for, get_md5sum
from lib_testbed.generic.util.artifactory_lib import get_artifactory_fw_url, get_map


DEFAULT_BUILD_MAP = "build_map.json"


class ArtifactoryReader:
    downloading = False

    def __init__(self, lib, model=None, artifactory_cfg=None, map_type: str = DEFAULT_BUILD_MAP):
        self.lib = lib
        self.initialized = False
        self.model = model
        self.map_type = map_type
        self.artifactory = artifactory_cfg if artifactory_cfg else self.lib.config.get("artifactory")
        self.version_map = {"version": "", "build_num": "", "native": "", "legacy": ""}
        self.header = {"Content-Type": "application/json"}
        self.tmp_dir = f"{tempfile.gettempdir()}/plume/fw"

    def initialize(self):
        if self.initialized:
            return
        if self.artifactory is None:
            raise Exception("Missing artifactory section in config, cannot move forward")
        if self.model is None:
            self.model = self.lib.device.config["model_org"]
        Path(self.tmp_dir).mkdir(exist_ok=True, parents=True)
        self.initialized = True

    def update_version_map(self, requested_version: str) -> None:
        self.initialize()
        parsed_data = {}
        parsed_data["version"], parsed_data["build_num"] = self.parse_requested_build(requested_version)
        self.version_map.update(parsed_data)

    def get_list_of_files(self, version: dict, final_version: str = None) -> tuple:
        def build_sort_func(build_name):
            build_name_separated = build_name.split("-")
            version_from_regex = re.search(r"\d+\.\d+\.\d+(\.\d+)?", build_name).group(0)
            version_index = build_name_separated.index(version_from_regex)

            return int(build_name_separated[version_index + 1])

        self.initialize()
        fw_list = []
        if not final_version:
            final_version = version["version"]
        storage_url = self.artifactory["url"] + f'/api/storage/{self.build_map[final_version]["proj-name"]}?list&deep=1'

        if self.artifactory.get("user") and self.artifactory.get("password"):
            auth = (self.artifactory.get("user"), self.artifactory["password"])
        else:
            auth = None

        get_response = requests.get(storage_url, headers=self.header, auth=auth, timeout=60)
        get_response.raise_for_status()
        fwjson = get_response.json()["files"]
        img_suffix = (
            self.build_map[final_version]["enc-suffix"]
            if self.build_map[final_version]["encryption"]
            else self.build_map[final_version]["img-suffix"]
        )
        fw_suffix = "%s.%s" % (
            self.lib.config.get("build_profile", self.build_map.get("build-profile", "")),
            img_suffix,
        )
        for element in fwjson:
            uri = element["uri"]
            if self.is_image_prefix_correct(uri, final_version) and self.is_image_got_correct_suffix(uri, fw_suffix):
                fw_list.append(uri)
        fw_list.sort(key=build_sort_func)

        status = 0 if get_response.status_code == requests.codes.ok else 1

        return status, fw_list

    @staticmethod
    def is_image_got_correct_suffix(image_name: str, img_suffix: str) -> bool:
        return image_name.endswith(img_suffix)

    def is_image_prefix_correct(self, image_name: str, version: str) -> bool:
        self.initialize()
        if self.build_map[version].get("fn-prefix"):
            return self.build_map[version]["fn-prefix"] in image_name
        else:
            return re.search(self.build_map[version]["fn-regex"], image_name) is not None

    def build_list(self, requested_version: str) -> list:
        self.initialize()
        self.update_version_map(requested_version)
        status, fw_list = self.get_list_of_files(self.version_map)

        return [status, "\n".join(fw_list), ""]

    def get_newest_build(self) -> str:
        self.initialize()
        status, fw_list = self.get_list_of_files(self.version_map)
        return fw_list[-1]

    @classmethod
    def is_downloading(cls):
        return cls.downloading

    @classmethod
    def is_not_downloading(cls):
        return not cls.is_downloading()

    @classmethod
    def start_downloading_flag(cls):
        cls.downloading = True

    @classmethod
    def stop_downloading_flag(cls):
        cls.downloading = False

    def _download_proper_version(self, version: str, **kwargs) -> (str | None, str | None, str | None):
        destination_dir = kwargs.pop("destination", self.tmp_dir)
        self.initialize()
        url = self.get_url_for_fw(version, **kwargs)
        try:
            filename = self.get_filename_from_url(url)
        except (AttributeError, IndexError):
            log.error("Cannot extract filename from %s", url)
            return None, None, None
        #  The conditions below must work with the following use cases:
        #  1. Doing a regular pod upgrade, download one firmware for all 3 pods.
        #  2. Doing a pod upgrade-multi, download one firmware per version specified by the user.
        #  3. This method is invoked at roughly the same time, i.e. all downloads must start before at least one
        #     of them is finished - otherwise this logic might not work as expected. It's because the very first
        #     finished download sets cls.downloading to False [the very first thread that is done]. This might be the
        #     case when downloading multiple firmware versions in parallel.
        if (
            Path(destination_dir).joinpath(filename).is_file()
            and self.is_not_downloading()
            and self.build_map[self.version_map["version"]]["encryption"]
        ):
            if self.build_map[self.version_map["version"]]["encryption"]:
                fw_key = self.get_fw_key_from_artifactory(
                    url, self.build_map[self.version_map["version"]]["key-suffix"]
                )
            else:
                fw_key = ""
            return filename, "", fw_key
        if not (os.path.exists(f"{destination_dir}/{filename}") and self.is_downloading()):
            self.start_downloading_flag()
            with open(f"{destination_dir}/{filename}", "wb") as file:
                file.write(b"")  # make sure that empty file exists
            log.info(f"Downloading {url} to {self.tmp_dir} directory")
            downloaded_image = requests.get(url)
            with open(f"{destination_dir}/{filename}", "wb") as file:
                file.write(downloaded_image.content)
            self.stop_downloading_flag()
        else:
            wait_for(self.is_not_downloading, 1200, 5.0)
        check_sum = self.get_md5_sum_from_artifactory(url)
        if self.build_map[self.version_map["version"]]["encryption"]:
            fw_key = self.get_fw_key_from_artifactory(url, self.build_map[self.version_map["version"]]["key-suffix"])
        else:
            fw_key = ""
        return filename, check_sum, fw_key

    def download_proper_version(self, version: str, **kwargs) -> (str | None, str | None):
        filename, check_sum, fw_key = self._download_proper_version(version, **kwargs)
        if filename and not self.validate_check_sum(check_sum, filename):
            log.error("Trying to download firmware image one more time...")
            Path(os.path.join(self.tmp_dir, filename)).unlink(missing_ok=True)
            filename, check_sum, fw_key = self._download_proper_version(version, **kwargs)
            if not self.validate_check_sum(check_sum, filename):
                raise Exception("MD5 check sum failed for downloaded image file.")
        return filename, fw_key

    def validate_check_sum(self, art_check_sum: str, file_name: str) -> bool:
        if not art_check_sum:
            # Probably the check sum file is not generated for this particular image.
            log.warning("Skip validating check sum...")
            return True
        local_path_file = os.path.join(self.tmp_dir, file_name)
        local_md5_sum = get_md5sum(local_path_file)
        status = True
        if local_md5_sum != art_check_sum:
            log.error(
                f"Mismatch between downloaded image MD5sum: {local_md5_sum} "
                f"and the MD5sum from the artifactory: {art_check_sum}"
            )
            status = False
        return status

    def _get_url_body(self, url):
        try:
            _request = requests.get(url)
            response = _request.text
        except requests.HTTPError:
            return ""
        if not _request.ok:
            log.warning(f"Can not get: {url}")
            return ""
        return response.split()[0]

    def get_md5_sum_from_artifactory(self, fw_url: str, suffix: str = "md5.save") -> str:
        md5_sum_url = "%s.%s" % (fw_url, suffix)
        return self._get_url_body(md5_sum_url)

    def get_fw_key_from_artifactory(self, fw_url: str, suffix: str) -> str:
        fw_key_url = "%s.%s" % (fw_url, suffix)
        return self._get_url_body(fw_key_url)

    def get_url_for_fw(self, version: str, **kwargs) -> str:
        self.initialize()
        self.update_version_map(version)
        version = f"{self.version_map['version']}-{self.version_map['build_num']}"
        model = kwargs.pop("model", self.model)
        map_type = kwargs.pop("map_type", self.map_type)

        if self.version_map["build_num"] == "LATEST":
            url = (
                f'{self.artifactory["url"]}/'
                f'{self.build_map[self.version_map["version"]]["proj-name"]}'
                f"{self.get_newest_build()}"
            )
        else:
            if DEFAULT_BUILD_MAP != map_type:
                url = get_artifactory_fw_url(self.lib.config, version, model, map_type)
            else:  # Don't load build-map twice
                url = get_artifactory_fw_url(self.lib.config, version, model, map_type, build_map=self.build_map)
        return url

    @staticmethod
    def get_filename_from_url(url: str) -> str:
        return url.split("/")[-1]

    @staticmethod
    def parse_requested_build(requested_version: str) -> [str, str]:
        """Parse requested fw build to extract build name and build number from requested version."""
        # Possible options:
        # master
        # legacy_native_master
        # legacy_native_master-123
        # 6.4.0
        # 6.4.0-123
        # native_5.8.0-80-g93c317-dev-debug
        splitted_version_to_build = requested_version.split("-")
        build_name = splitted_version_to_build[0]
        build_num = splitted_version_to_build[1] if len(splitted_version_to_build) >= 2 else "LATEST"
        return build_name, build_num

    @functools.cached_property
    def build_map(self) -> dict:
        if self.model is None:
            self.model = self.lib.device.config["model_org"]
        return get_map(self.model, map_type=self.map_type)
