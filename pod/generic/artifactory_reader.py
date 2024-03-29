import re
import requests
from pathlib import Path

from lib_testbed.generic.util.common import wait_for
from lib_testbed.generic.util.artifactory_lib import get_artifactory_fw_url, get_map, get_enc_key


class ArtifactoryReader:
    downloading = False

    def __init__(self, lib, model=None, artifactory_cfg=None):
        self.lib = lib
        self.initialized = False
        self.model = model
        self.build_map = None
        self.artifactory = artifactory_cfg if artifactory_cfg else self.lib.config.get("artifactory")
        self.version_map = {"version": "", "build_num": "", "native": "", "legacy": ""}
        self.header = {"Content-Type": "application/json"}
        self.tmp_dir = "/tmp/plume/fw"

    def initialize(self):
        if self.initialized:
            return
        if self.artifactory is None:
            raise Exception("Missing artifactory section in config, cannot move forward")
        if self.model is None:
            self.model = self.lib.device.config['model_org']
        self.build_map = get_map(self.model)
        Path(self.tmp_dir).mkdir(exist_ok=True, parents=True)
        self.initialized = True

    def update_version_map(self, requested_version: str) -> None:
        self.initialize()
        parsed_data = {}
        if (
                "master" in requested_version
                or "fbb" in requested_version
                or "native" in requested_version
                or "legacy" in requested_version
        ):
            splitted_version_to_build = requested_version.split("-")
        else:
            version_and_build_num = re.search(r"\d+.\d+(.\d+)?(.\d+)?(-\d+)?", requested_version).group(0)
            if "-LATEST" in requested_version and "-LATEST" not in version_and_build_num:
                version_and_build_num += "-LATEST"
            splitted_version_to_build = version_and_build_num.split("-")

        if "native" in requested_version:
            parsed_data["native"] = "native"
            splitted_version_to_build.remove("native")

        if "legacy" in requested_version:
            parsed_data["legacy"] = "legacy"
            splitted_version_to_build.remove("legacy")

        if len(splitted_version_to_build) == 2:
            parsed_data.update({"version": splitted_version_to_build[0], "build_num": splitted_version_to_build[1]})
        else:
            parsed_data["version"] = splitted_version_to_build[0]

        self.version_map.update(parsed_data)

    def get_list_of_files(self, version: dict) -> tuple:
        def build_sort_func(build_name):
            build_name_separated = build_name.split("-")
            version_from_regex = re.search(r"\d+.\d+.\d+", build_name).group(0)
            version_index = build_name_separated.index(version_from_regex)

            return int(build_name_separated[version_index + 1])

        self.initialize()
        fw_list = []
        final_version = version["native"] + "-" + version["version"] if version["native"] else version["version"]
        final_version = version["legacy"] + "-" + final_version if version["legacy"] else final_version
        storage_url = self.artifactory["url"] + f'/api/storage/{self.build_map[final_version]["proj-name"]}'

        if self.artifactory.get("user") and self.artifactory.get("password"):
            auth = (self.artifactory.get("user"), self.artifactory["password"])
        else:
            auth = None

        get_response = requests.get(storage_url, headers=self.header, auth=auth)

        fwjson = get_response.json()["children"]

        for element in fwjson:
            uri = element["uri"]
            if self.is_image_a_dev_debug(uri) and self.is_image_got_correct_prefix(uri, final_version):
                fw_list.append(uri)
        fw_list.sort(key=build_sort_func)

        status = 0 if get_response.status_code == requests.codes.ok else 1

        return status, fw_list

    @staticmethod
    def is_image_a_dev_debug(image_name: str) -> bool:
        return image_name[-13:] == "dev-debug.img"

    def is_image_got_correct_prefix(self, image_name: str, version: str) -> bool:
        self.initialize()
        return self.build_map[version]["fn-prefix"] in image_name

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

    def download_proper_version(self, version: str, **kwargs) -> str:
        destination_dir = kwargs.pop("destination", self.tmp_dir)
        self.initialize()
        url = self.get_url_for_fw(version, **kwargs)
        filename = self.get_filename_from_url(url)
        if Path(destination_dir).joinpath(filename).is_file():
            return filename
        if not self.is_downloading():
            self.start_downloading_flag()
            downloaded_image = requests.get(url)
            with open(f"{destination_dir}/{filename}", "wb") as file:
                file.write(downloaded_image.content)
            self.stop_downloading_flag()
        else:
            wait_for(self.is_not_downloading, 1200, 5.0)
        return filename

    def get_url_for_fw(self, version: str, **kwargs) -> str:
        self.initialize()
        self.update_version_map(version)
        native = "native-" if self.version_map["native"] else ""
        legacy = "legacy-" if self.version_map["legacy"] else ""
        if self.version_map["version"] == "fbb":
            self.version_map["version"] = "build_device_featurebranch"
            version = f"{legacy}{native}{self.version_map['version']}-{self.version_map['build_num']}"
        if self.version_map["version"] and self.version_map["build_num"]:
            url = get_artifactory_fw_url(self.lib.config, version, self.model, **kwargs)
        else:
            url = (
                f'{self.artifactory["url"]}/'
                f'{self.build_map[legacy + native + self.version_map["version"]]["proj-name"]}'
                f"{self.get_newest_build()}"
            )

        return url

    @staticmethod
    def get_filename_from_url(url: str) -> str:
        return url.split("/")[-1]

    def get_enc_key(self, version: str, **kwargs) -> str:
        url = self.get_url_for_fw(version, use_build_map_suffix=True, **kwargs)
        return get_enc_key(f"{url}.key")
