import os
import re
import requests

from lib_testbed.generic.util.common import wait_for
from lib_testbed.generic.util.artifactory_lib import get_artifactory_fw_url, get_map


class ArtifactoryReader:

    downloading = False

    def __init__(self, lib):
        self.lib = lib
        self.initialized = False
        self.model = None
        self.build_map = None
        self.artifactory = self.lib.config.get('artifactory')
        self.version_map = {
            'version': '',
            'build_num': ''
        }
        self.header = {'Content-Type': 'application/json'}
        self.tmp_dir = '/tmp/plume/fw'

    def initialize(self):
        if self.initialized:
            return
        if self.artifactory is None:
            raise Exception("Missing artifactory section in config, cannot move forward")
        self.model = self.lib.get_model()[1]
        self.build_map = get_map(self.model)
        os.makedirs(self.tmp_dir, exist_ok=True)
        self.initialized = True

    def update_version_map(self, requested_version: str) -> None:
        self.initialize()
        if 'master' in requested_version or 'fbb' in requested_version:
            splitted_version_to_build = requested_version.split('-')
        else:

            version_and_build_num = re.search(r'\d+.\d+.\d+(-\d+)?', requested_version).group(0)

            splitted_version_to_build = version_and_build_num.split('-')

        if len(splitted_version_to_build) == 2:
            parsed_data = {
                'version': splitted_version_to_build[0],
                'build_num': splitted_version_to_build[1]
            }

        else:
            parsed_data = {'version': splitted_version_to_build[0]}

        self.version_map.update(parsed_data)

    def get_list_of_files(self, version: str) -> tuple:
        def build_sort_func(build_name):
            build_name_separated = build_name.split('-')
            version_from_regex = re.search(r'\d+.\d+.\d+', build_name).group(0)
            version_index = build_name_separated.index(version_from_regex)

            return int(build_name_separated[version_index + 1])

        self.initialize()
        fw_list = []
        storage_url = self.artifactory["url"] + f'/api/storage/{self.build_map[version]["proj-name"]}'

        get_response = requests.get(storage_url, headers=self.header,
                                    auth=(self.artifactory["user"], self.artifactory["password"]))

        fwjson = get_response.json()['children']

        for element in fwjson:
            uri = element['uri']
            if self.is_image_a_dev_debug(uri) and self.is_image_got_correct_prefix(uri, version):
                fw_list.append(uri)
        fw_list.sort(key=build_sort_func)

        status = 0 if get_response.status_code == requests.codes.ok else 1

        return status, fw_list

    @staticmethod
    def is_image_a_dev_debug(image_name: str) -> bool:
        return image_name[-13:] == 'dev-debug.img'

    def is_image_got_correct_prefix(self, image_name: str, version: str) -> bool:
        self.initialize()
        return self.build_map[version]['fn-prefix'] in image_name

    def build_list(self, requested_version: str) -> list:
        self.initialize()
        self.update_version_map(requested_version)
        status, fw_list = self.get_list_of_files(self.version_map['version'])

        return [status, '\n'.join(fw_list), '']

    def get_newest_build(self, requested_version: str) -> str:
        self.initialize()
        self.update_version_map(requested_version)
        status, fw_list = self.get_list_of_files(self.version_map['version'])

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

    def download_proper_version(self, version: str) -> str:
        self.initialize()
        url = self.get_url_for_fw(version)
        filename = self.get_filename_from_url(url)

        if not self.is_downloading():

            self.start_downloading_flag()

            downloaded_image = requests.get(url)

            with open(f'{self.tmp_dir}/{filename}', 'wb') as file:
                file.write(downloaded_image.content)

            self.stop_downloading_flag()

        else:
            wait_for(self.is_not_downloading, 1200, 5.)

        return filename

    def get_url_for_fw(self, version: str) -> str:
        self.initialize()
        self.update_version_map(version)
        if self.version_map['version'] == 'fbb':
            self.version_map['version'] = 'build_device_featurebranch'
            version = f"{self.version_map['version']}-{self.version_map['build_num']}"
        if self.version_map['version'] and self.version_map['build_num']:
            url = get_artifactory_fw_url(self.lib.config, version, self.model)
        else:
            url = f'{self.artifactory["url"]}/' \
                  f'{self.build_map[self.version_map["version"]]["proj-name"]}' \
                  f'{self.get_newest_build(self.version_map["version"])}'

        return url

    @staticmethod
    def get_filename_from_url(url: str) -> str:
        return url.split('/')[-1]
