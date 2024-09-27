import pytest
from lib_testbed.generic.util.object_factory import ObjectFactory
from lib_testbed.generic.pod.generic.pod_api import PodApi
from lib_testbed.generic.util.ssh.device_api import DevicesApi
from lib_testbed.generic.util.ssh.device_discovery import DeviceDiscovery
from lib_testbed.generic.util.object_resolver import ObjectResolver
from lib_testbed.generic.util.logger import log


class Pod(ObjectFactory):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.gw: PodApi
        self.leaf: PodApi
        self.leafs: PodApi
        self.all: PodApi
        self.l1: PodApi
        self.l2: PodApi

    def resolve_obj(self, request=None, **kwargs) -> PodApi:
        kwargs["device_type"] = "Nodes"
        dev_discovered = PodResolver().get_device(request=request, **kwargs)
        api_class = PodResolver().resolve_pod_api_class(dev_discovered)
        kwargs["dev"] = dev_discovered
        return api_class(**kwargs)

    @staticmethod
    def resolve_obj_by_fixture(request, **kwargs) -> PodApi:
        """Resolve pod object by fixture to have one reference of object per pytest session."""
        set_device_role(kwargs["config"])
        multi_devices = kwargs.pop("multi_obj", False)
        dev_discovery = DeviceDiscovery(device_type="Nodes", multi_devices=multi_devices, request=request, **kwargs)
        filtered_device = dev_discovery.filter_device()

        # mgmt optional access
        if not filtered_device:
            return request.getfixturevalue("_dummy_pod_object")

        try:
            return request.getfixturevalue(f"_{filtered_device['name']}_object")
        except pytest.FixtureLookupError:
            log.info("Requested fixture not found, create a new pod obj for {}".format(filtered_device["name"]))
            dev_discovery.assign_device(filtered_device)
            api_class = PodResolver().resolve_pod_api_class(dev_discovery)
            kwargs["dev"] = dev_discovery
            return api_class(device_type="Nodes", **kwargs)
        except Exception as err:
            raise err

    @staticmethod
    def create_dummy_pod_obj(config) -> PodApi:
        """Create dummy pod object without filtering a device for nodes with optional mgmt access"""
        dev_discovered = DeviceDiscovery(device_type="Nodes", config=config, multi_devices=False)
        api_class = PodResolver().resolve_pod_api_class(dev_discovered)
        return api_class(config=config, dev=dev_discovered, device_type="Nodes")


class Pods(ObjectFactory):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.gw: PodApi
        self.leaf: PodApi
        self.leafs: PodApi
        self.all: PodApi
        self.l1: PodApi
        self.l2: PodApi

    def resolve_obj(self, request=None, **kwargs) -> DevicesApi:
        obj_list = []
        device_type = "Nodes"
        devices = kwargs["config"][device_type]
        kwargs["device_type"] = device_type

        names = kwargs.get("nicknames")
        if names:
            del kwargs["nicknames"]

        exception = None
        for device in devices:
            if names and device["name"] not in names:
                continue
            kwargs["nickname"] = device["name"]

            try:
                dev_discovered = PodResolver().get_device(request, **kwargs)
            except KeyError as e:
                if "No device found matching criteria" not in str(e):
                    raise
                exception = e
                continue
            api_class = PodResolver().resolve_pod_api_class(dev_discovered)
            kwargs["dev"] = dev_discovered
            try:
                class_obj = api_class(**kwargs)
            except Exception as e:
                log.warning(e)
                continue
            obj_list.append(class_obj)
        if not obj_list:
            if exception:
                raise exception
            else:
                raise Exception(f"No device found matching requested criteria: {kwargs}")
        return DevicesApi(obj_list, **kwargs)

    @staticmethod
    def resolve_obj_by_fixture(request, **kwargs) -> DevicesApi:
        """Resolve pod object by fixture to have one reference of object per pytest session."""
        obj_list = []
        device_type = "Nodes"
        devices = kwargs["config"][device_type]
        names = kwargs.pop("nicknames", [])
        exception = None
        for device in devices:
            if names and device["name"] not in names:
                continue
            kwargs["nickname"] = device["name"]
            try:
                class_obj = Pod().resolve_obj_by_fixture(request, **kwargs)
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


class PodResolver:

    def get_device(self, request=None, **kwargs):
        set_device_role(kwargs["config"])
        multi_devices = kwargs.pop("multi_obj", False)
        with DeviceDiscovery(multi_devices=multi_devices, request=request, **kwargs) as dev_discovery:
            return dev_discovery

    @staticmethod
    def resolve_pod_api_class(dev_discovered):
        file_name = "pod_api.py"
        model = "no_mgmt_access"
        wifi_vendor = "no_mgmt_access"
        if dev_discovered.device:
            model = dev_discovered.device.config["model"]
            wifi_vendor = dev_discovered.device.config["capabilities"].get("wifi_vendor")
            assert wifi_vendor, "Can not get wifi vendor from the capabilities device config"
        return ObjectResolver.resolve_pod_class(file_name=file_name, model=model, wifi_vendor=wifi_vendor)


def set_device_role(config):
    pods = config.get("Nodes")
    assert pods, f'Nodes section is missing in config. Config location file: {config.get("location_file")}'
    # Extend config with roles: gw or leaf
    # Assume that the first Node configured in Nodes list is a gateway and the rest are leafs
    for i, pod in enumerate(pods):
        if pod.get("role"):
            continue
        if i == 0:
            role = "gw"
        else:
            role = "leaf"
        pod["role"] = role
