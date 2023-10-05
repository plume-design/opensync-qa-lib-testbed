from packaging import version

from lib_testbed.generic.pod.generic.pod_api import PodApi as PodApiGeneric
from lib_testbed.generic.util.request_handler import parse_request


class PodApi(PodApiGeneric):
    @parse_request
    def setup_class_handler_main_object(self, request):
        super().setup_class_handler_main_object(request)
        none_ver = self.version()
        if version.parse(".".join(none_ver.replace("-", ".").split(".")[:4])) > version.parse("5.8.0.0"):
            self.lib.capabilities.device_capabilities["interfaces"]["backhaul_ap"] = {
                "24g": "b-ap-24",
                "5g": None,
                "5gl": "b-ap-l50",
                "5gu": "b-ap-u50",
                "6g": None,
            }
