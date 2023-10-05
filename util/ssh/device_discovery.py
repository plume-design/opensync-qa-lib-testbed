import re
import json
import sys
import os
import copy
import traceback

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.util.common import DeviceCommon
from lib_testbed.generic.util.config import LOCAL_HOST_CLIENT_NAME, REMOTE_HOST_CLIENT_NAME, IPERF_CLIENT_TYPE

SSH_GATEWAY = "ssh_gateway"


class DeviceDiscovery:
    def __init__(self, device_type, multi_devices, config, **kwargs):
        self.config = config
        self.device_type = device_type
        self.multi_devices = multi_devices
        self.role_prefix = kwargs.pop("role_prefix", "")
        self.name = ""
        self.device = None
        self.main_object = False
        self.skip_logging = kwargs.pop("skip_logging", False)
        self.skip_init = kwargs.pop("skip_init", False)

        # check no_ssh option
        session_config = kwargs.get("session_config")
        if session_config:
            del kwargs["session_config"]
        if device_type == "Nodes" and session_config and session_config.option.no_ssh:
            self.set_no_mgmt_access()
            return
        device_config = self.get_available_device(kwargs)
        if not device_config:
            return
        self.name = device_config["name"]
        role = f"{self.role_prefix}_" if self.role_prefix else ""
        name_prefix = f"multi_{role}" if self.multi_devices else ""
        serial = f'[{device_config["id"]}]' if device_config.get("id") else ""
        if not self.skip_logging:
            log.info(f"Assign {self.device_type[:-1].lower()} name: {name_prefix}{self.name} {serial}")

        # Update ssh gateway with default value if not provided in Nodes
        if SSH_GATEWAY not in device_config:
            ssh_gateway = config.get(SSH_GATEWAY)
            if ssh_gateway:
                device_config[SSH_GATEWAY] = ssh_gateway
        from lib_testbed.generic.util.ssh.device_ssh import DeviceSsh  # TODO: remove

        if "hostname" in device_config or "host" in device_config or "screen" in device_config:
            # TODO: split DeviceSsh between DeviceExpect and DeviceScreen
            self.device = DeviceSsh(self.device_type, self.name, device_config)

        # Update device state with busy flag (skip testbed server as its object used for multiple purposes)
        if device_config.get("capabilities", {}).get("device_type", "") != "host":
            self.set_device_busy(device_config)
        # Mark main object to skip doing recovery, collecting logs etc. twice for the same device
        self.set_main_object(device_config)

    def validate_device(self, filter_dict, device):
        key, value = list(filter_dict.items())[0]
        # first remove already busy devices and devices without mgmt access
        if self.is_device_busy(device):
            if key == "name" and device["name"] == value:
                log.warning(f"{'[Devices]' if self.multi_devices else '[Device]'} Skip busy {device['name']}")
            return False
        if key == "capab":
            return self.has_device_capabilities(value, device)

        if value is None:
            return True if key not in device else False

        if key not in device:
            return False

        if isinstance(device[key], str):
            config_value = device[key]
            matched = re.compile(value).match(config_value)
        elif isinstance(device[key], bool):
            config_value = device[key]
            matched = value == config_value
        elif isinstance(device[key], dict) and isinstance(value, dict):
            config_value = device[key]
            matched = value.items() <= config_value.items()
        else:
            config_value = json.dumps(device[key])
            matched = value == config_value
            if not matched:
                matched = re.compile(value).match(config_value)
        return matched

    def get_available_device(self, kwargs):  # noqa: C901
        devices = self.config[self.device_type].copy() if self.device_type in self.config else []
        name = kwargs.pop("nickname", "")
        use_host = False
        if (name and "host" in name) or kwargs.get(IPERF_CLIENT_TYPE):
            use_host = True

        possible_no_mgmt = False
        if "mgmt" in kwargs and kwargs["mgmt"] == "optional":
            kwargs.pop("mgmt")
            possible_no_mgmt = True
        device_kwargs = kwargs

        if name:
            all_names = [device["name"] for device in devices]
            if name not in all_names:
                raise Exception(f"name: {name} not found in config[{self.device_type}]. Available names: {all_names}")
            device_kwargs["name"] = name

        for device in devices:
            model = device.get("model")
            if model:
                device["model"] = DeviceCommon.convert_model_name(model)

        # at least check mgm access
        if not device_kwargs:
            device_kwargs["name"] = ".*"

        model = device_kwargs.get("model")
        if model:
            device_kwargs["model"] = DeviceCommon.convert_model_name(model)

        filtered_devices = devices.copy()  # Devices considered to be checked
        if (idx := device_kwargs.get("index", None)) is not None:
            filtered_devices = [devices[idx]]
            devices = []  # set to empty list to skip the next for loop
        for key, value in device_kwargs.items():
            if key in ["config", "dev"]:
                continue
            for device in devices:
                if device not in filtered_devices:
                    continue
                if name and name != device["name"]:
                    filtered_devices.remove(device)
                    continue
                if device.get("name", "") in [LOCAL_HOST_CLIENT_NAME, REMOTE_HOST_CLIENT_NAME] and not use_host:
                    filtered_devices.remove(device)
                    continue
                if not self.validate_device({key: value}, device):
                    filtered_devices.remove(device)
                    continue
        if possible_no_mgmt and not devices and not filtered_devices:
            # Create dummy filtered device in case the client list in testbed config is empty
            filtered_devices = [{"name": "unknown"}]
        if not filtered_devices:
            raise KeyError(f"No device found matching criteria: {device_kwargs}")
        if (
            filtered_devices
            and "hostname" not in filtered_devices[0]
            and "host" not in filtered_devices[0]
            and "screen" not in filtered_devices[0]
        ):
            if not possible_no_mgmt:
                raise Exception(
                    f"Can not initiate pod lib without management access for pods:" f' {filtered_devices[0]["name"]}'
                )
            self.set_no_mgmt_access()
            return None
        return filtered_devices[0]

    def set_no_mgmt_access(self):
        log.info("Mgmt access with device not required")
        if self.device_type == "Nodes":
            os.environ["PODS_NO_MGMT"] = "true"
        elif self.device_type == "Clients":
            os.environ["CLIENTS_NO_MGMT"] = "true"

    def is_device_busy(self, device):
        return True if not self.multi_devices and device.get("busy") else False

    def set_device_busy(self, device, state=True):
        if not self.multi_devices:
            device["busy"] = state

    def set_main_object(self, device):
        self.main_object = True if not device.get("main_object") else False
        if not device.get("main_object"):
            device["main_object"] = True

    def get_device_capabilities(self, device):
        if self.device_type != "Clients":
            raise OpenSyncException(
                f"Getting capabilities for {self.device_type} is not supported",
                'Implement "device_discovery.get_device_capabilities()"',
            )
        from lib_testbed.generic.client.client import Client

        kwargs = {"config": copy.deepcopy(self.config), "nickname": device["name"], "multi_obj": False}
        try:
            client_obj = Client(**kwargs)
            client_lib = client_obj.resolve_obj(**kwargs).lib
        except Exception as e:
            traceback.print_exc(limit=2, file=sys.stdout)
            if re.compile(r"name: .* not found in config").match(str(e)):
                log.error(
                    f"Unexpected client name: '{kwargs['nickname']}'\n"
                    "First parameter should be client name specifier"
                )
            raise
        info_response = client_lib.info()
        if not info_response[1]:
            return None
        info = info_response[1]
        info["name"] = device["name"]
        return info

    def has_device_capabilities(self, capabs, device):
        # skipping eth client from config since restarting dhclient consumes 5 sec!
        if device.get("eth") == "true":
            return False
        dev_capab = self.get_device_capabilities(device)
        if not dev_capab:
            return False
        caps_supported = True
        for capab, capab_value in capabs.items():
            caps_supported &= self.has_device_capability(capab, capab_value, dev_capab)
        return caps_supported

    def has_device_capability(self, cap, cap_value, dev_capabs):
        if cap in dev_capabs and dev_capabs[cap] == cap_value:
            return True

        # special case for bt, wlan end eth capability
        for iface in ["bt", "wlan", "eth"]:
            if not dev_capabs[iface]:
                continue
            for dev_iface, dev_iface_capab in dev_capabs[iface].items():
                if cap not in dev_iface_capab:
                    continue
                if cap_value == "*" or dev_iface_capab[cap] == cap_value:
                    return True
        return False
