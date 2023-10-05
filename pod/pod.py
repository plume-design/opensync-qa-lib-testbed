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

    def resolve_obj(self, **kwargs) -> PodApi:
        kwargs["device_type"] = "Nodes"
        dev_discovered = PodResolver().get_device(**kwargs)
        api_class = PodResolver().resolve_pod_api_class(dev_discovered)
        kwargs["dev"] = dev_discovered
        return api_class(**kwargs)


class Pods(ObjectFactory):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.gw: PodApi
        self.leaf: PodApi
        self.leafs: PodApi
        self.all: PodApi
        self.l1: PodApi
        self.l2: PodApi

    def resolve_obj(self, **kwargs) -> PodApi:
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
                dev_discovered = PodResolver().get_device(**kwargs)
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


class PodResolver:
    @staticmethod
    def get_device(**kwargs):
        config = kwargs["config"]
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
        multi_devices = kwargs.get("multi_obj")
        if multi_devices is not None:
            del kwargs["multi_obj"]
        return DeviceDiscovery(multi_devices=multi_devices, **kwargs)

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
