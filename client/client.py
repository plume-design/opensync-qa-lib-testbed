from lib_testbed.generic.util.object_factory import ObjectFactory
from lib_testbed.generic.client.models.generic.client_api import ClientApi as LinuxClientApi
from lib_testbed.generic.util.ssh.device_api import DevicesApi
from lib_testbed.generic.util.ssh.device_discovery import DeviceDiscovery
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.object_resolver import ObjectResolver
from lib_testbed.generic.util.config import FIXED_HOST_CLIENTS


DIRECTORY_TYPE = "generic"


class Client(ObjectFactory):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.linux: LinuxClientApi()
        self.debian: LinuxClientApi()
        self.mac: LinuxClientApi()
        self.rpi: LinuxClientApi()
        self.all: LinuxClientApi()
        self.wifi: LinuxClientApi()
        self.w1: LinuxClientApi()
        self.w2: LinuxClientApi()
        self.w3: LinuxClientApi()
        self.eth: LinuxClientApi()
        self.e1: LinuxClientApi()
        self.e2: LinuxClientApi()
        self.e3: LinuxClientApi()

    def resolve_obj(self, **kwargs) -> LinuxClientApi:
        kwargs["device_type"] = "Clients"
        dev_discovered = ClientResolver().get_device(**kwargs)
        api_class = ClientResolver().resolve_client_api_class(dev_discovered)
        kwargs["dev"] = dev_discovered
        return api_class(**kwargs)


class Clients(ObjectFactory):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.linux: LinuxClientApi()
        self.debian: LinuxClientApi()
        self.mac: LinuxClientApi()
        self.rpi: LinuxClientApi()
        self.all: LinuxClientApi()
        self.w1: LinuxClientApi()
        self.w2: LinuxClientApi()
        self.w3: LinuxClientApi()
        self.e1: LinuxClientApi()
        self.e2: LinuxClientApi()
        self.e3: LinuxClientApi()

    def resolve_obj(self, **kwargs) -> LinuxClientApi:
        obj_list = []
        device_type = "Clients"
        names = kwargs.get("nicknames", [])
        if names:
            del kwargs["nicknames"]
        if not kwargs["config"].get(device_type) and "host" not in names:
            raise Exception(f"Missing '{device_type}' config for {kwargs['config'].get('user_name', 'unknown')}")
        kwargs["device_type"] = device_type
        use_host = False
        if "host" in names:
            use_host = True
        devices = kwargs["config"][device_type]
        for device in devices:
            name = device["name"]
            if names and name not in names:
                continue
            if name in FIXED_HOST_CLIENTS and not use_host:
                continue

            kwargs["nickname"] = device["name"]
            try:
                dev_discovered = ClientResolver().get_device(**kwargs)
            except KeyError as e:
                if "No device found matching criteria" not in str(e):
                    raise
                continue
            api_class = ClientResolver().resolve_client_api_class(dev_discovered)
            dev_discovered.directory_type = DIRECTORY_TYPE
            kwargs["dev"] = dev_discovered
            try:
                class_obj = api_class(**kwargs)
            except Exception as e:
                log.warning(repr(e))
                continue
            obj_list.append(class_obj)
        if not obj_list:
            raise Exception(f"No client available for: {kwargs}")
        return DevicesApi(obj_list, **kwargs)


class ClientResolver:
    @staticmethod
    def get_device(**kwargs):
        multi_devices = kwargs.get("multi_obj")
        if multi_devices is not None:
            del kwargs["multi_obj"]
        return DeviceDiscovery(multi_devices=multi_devices, **kwargs)

    @staticmethod
    def resolve_client_api_class(dev_discovered):
        file_name = "client_api.py"
        model = "no_mgmt_access"
        if dev_discovered.device:
            model = dev_discovered.device.config["type"]
        return ObjectResolver.resolve_client_class(file_name=file_name, model=model)
