"""Firmware Manager for getting fixed firmwares from "test_fw_version.json"."""
import os
import re
import json
from pathlib import Path
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.object_resolver import ObjectResolver
from lib_testbed.generic.util.common import DeviceCommon


FW_VERSION_LIST = "test_fw_version.json"
NEW_SDK_FW_VERSION_LIST = "test_fw_version_new_sdk.json"


class FwManager:
    def __init__(self, tb_cfg: dict):
        self.tb_cfg = tb_cfg
        self.fw_map = self.load_fw_map()

    def is_new_sdk(self) -> bool:
        return bool(
            re.search("new sdk", self.tb_cfg.get("purpose", ""), re.IGNORECASE)
        ) or "NEW_SDK" in self.tb_cfg.get("capabilities", [])

    def load_fw_map(self) -> dict:
        fw_map = dict()
        new_sdk = self.is_new_sdk()
        device_models = list(
            set([pod_cfg["model_org"] for pod_cfg in self.tb_cfg["Nodes"]])
        )
        for device_model in device_models:
            fw_file = self.get_file_to_load(device_model=DeviceCommon.convert_model_name(device_model), new_sdk=new_sdk)
            if not fw_file:
                continue
            with open(fw_file) as fw:
                fw_dict = json.load(fw)
            fw_map[device_model] = fw_dict
        return fw_map

    @staticmethod
    def get_file_to_load(device_model: str, new_sdk: bool) -> str:
        fw_file = ""
        try:
            fw_file = ObjectResolver.resolve_model_path_file(file_name=FW_VERSION_LIST, model=device_model)
            if new_sdk:
                model_dir = Path(fw_file).absolute().parents[0].as_posix()
                if NEW_SDK_FW_VERSION_LIST in os.listdir(model_dir):
                    fw_file = ObjectResolver.resolve_model_path_file(
                        file_name=NEW_SDK_FW_VERSION_LIST, model=device_model
                    )
        except Exception as err:
            log.error(err)
            log.info(f"Upgrading {device_model} is not supported")
        return fw_file

    def get_fw_with_rounds(self, models: list, version: str = "latest_released_fw") -> tuple[dict, int]:
        """
        Args:
            models: (list) models to check
            version: (str) fw type from test_fw_version.json file

        Returns: (tuple) {model: fw}, int() rounds
        """
        latest_fw = {}
        rounds = []
        for model in models:
            fw_dict = self.fw_map.get(model)
            if not fw_dict:
                continue
            latest_fw[model] = fw_dict.get(version)
            rounds.append(fw_dict["rounds"])
            # in case model does not specify its version cancel whole upgrade
            if latest_fw[model] is None:
                log.warning(f"Cannot get {version}_released_fw for {model}. Skipping it")
                return {}, 0
        assert latest_fw, f"Not found any FW for fw type: {version} and models: {models}"
        return latest_fw, max(rounds)

    def get_fw_model_map(self, models: list, fw_type: str) -> dict:
        """
        Get firmware model map
        Args:
            models: (list) List of models
            fw_type: (str) FW type specified in test_fw_version.json file

        Returns: (dict) {model: fw_type}

        """
        fw_model_map = dict()
        for model in models:
            fw_dict = self.fw_map.get(model)
            if not fw_dict:
                continue
            expected_fw = fw_dict.get(fw_type)
            if not expected_fw:
                log.warning(f"Cannot get {fw_type} firmware for {model}. Skipping it")
                continue
            fw_model_map[model] = expected_fw
        assert fw_model_map, f"Not found any FW for fw type: {fw_type} and models: {models}"
        return fw_model_map

    def get_upgradeable_models(self) -> list:
        """Get upgradeable models from the tb-config"""
        upgradeable_models = list(self.fw_map.keys())
        log.info(f"Upgradeable models: {upgradeable_models}")
        return upgradeable_models

    def get_latest_released_fw(self, models: list) -> tuple[dict, int]:
        return self.get_fw_with_rounds(models, "latest_released_fw")

    def get_first_released_fw(self, models: list) -> tuple[dict, int]:
        return self.get_fw_with_rounds(models, "first_released_fw")

    def get_monitoring_fw(self, models: list) -> tuple[dict, int]:
        return self.get_fw_with_rounds(models, "monitoring_released_fw")

    def get_ga_fw(self, models: list) -> tuple[dict, int]:
        return self.get_fw_with_rounds(models, "ga_released_fw")

    def get_capabilities_fw(self, models: list) -> tuple[dict, int]:
        return self.get_fw_with_rounds(models, "capabilities_released_fw")

    def get_ipv6_capable_and_downloadable_fw(self, models: list) -> tuple[dict, int]:
        """Returns ipv6 capable firmware. In case none is available, falls back
        to "first" firmware."""
        test_fw = self.get_fw_with_rounds(models, "ipv6_released_fw")
        if test_fw[0]:
            return test_fw
        return self.get_fw_with_rounds(models, "first_released_fw")
