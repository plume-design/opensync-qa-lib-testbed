import pytest
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

    def resolve_obj(self, request=None, **kwargs) -> LinuxClientApi:
        kwargs["device_type"] = "Clients"
        dev_discovered = ClientResolver().get_device(request=request, **kwargs)
        api_class = ClientResolver().resolve_client_api_class(dev_discovered)
        kwargs["dev"] = dev_discovered
        return api_class(**kwargs)

    @staticmethod
    def resolve_obj_by_fixture(request, **kwargs) -> LinuxClientApi:
        """Resolve client object by fixture to have one reference of object per pytest session."""
        multi_devices = kwargs.pop("multi_obj", False)
        dev_discovery = DeviceDiscovery(device_type="Clients", multi_devices=multi_devices, request=request, **kwargs)
        filtered_device = dev_discovery.filter_device()

        # mgmt optional access
        if not filtered_device:
            return request.getfixturevalue("_dummy_client_object")

        try:
            return request.getfixturevalue(f"_{filtered_device['name']}_object")
        except pytest.FixtureLookupError:
            log.info("Requested fixture not found, create a new client obj for {}".format(filtered_device["name"]))
            dev_discovery.assign_device(filtered_device)
            api_class = ClientResolver().resolve_client_api_class(dev_discovery)
            kwargs["dev"] = dev_discovery
            return api_class(device_type="Clients", **kwargs)
        except Exception as err:
            raise err

    @staticmethod
    def create_dummy_client_obj(config) -> LinuxClientApi:
        """Create dummy client object without filtering a device for clients with optional mgmt access"""
        dev_discovered = DeviceDiscovery(device_type="Clients", config=config, multi_devices=False)
        api_class = ClientResolver().resolve_client_api_class(dev_discovered)
        return api_class(config=config, dev=dev_discovered, device_type="Clients")


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

    def resolve_obj(self, request=None, **kwargs) -> DevicesApi:
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
                dev_discovered = ClientResolver().get_device(request=request, **kwargs)
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

    @staticmethod
    def resolve_obj_by_fixture(request, **kwargs) -> DevicesApi:
        """Resolve client object by fixture to have one reference of object per pytest session."""
        obj_list = []
        device_type = "Clients"
        devices = kwargs["config"][device_type]
        names = kwargs.pop("nicknames", [])
        exception = None
        use_host = False
        if "host" in names:
            use_host = True

        for device in devices:
            name = device["name"]
            if names and name not in names:
                continue
            if name in FIXED_HOST_CLIENTS and not use_host:
                continue
            kwargs["nickname"] = device["name"]
            try:
                class_obj = Client().resolve_obj_by_fixture(request, **kwargs)
            except KeyError as e:
                if "No device found matching criteria" not in str(e):
                    raise
                exception = e
                continue
            obj_list.append(class_obj)
        if not obj_list:
            if exception:
                raise exception
            else:
                raise Exception(f"No device found matching requested criteria: {kwargs}")
        return DevicesApi(obj_list, **kwargs)


class ClientResolver:
    @staticmethod
    def get_device(request=None, **kwargs):
        multi_devices = kwargs.pop("multi_obj", False)
        with DeviceDiscovery(multi_devices=multi_devices, request=request, **kwargs) as dev_discovery:
            return dev_discovery

    @staticmethod
    def resolve_client_api_class(dev_discovered):
        file_name = "client_api.py"
        model = "no_mgmt_access"
        if dev_discovered.device:
            model = dev_discovered.device.config["type"]
        return ObjectResolver.resolve_client_class(file_name=file_name, model=model)
