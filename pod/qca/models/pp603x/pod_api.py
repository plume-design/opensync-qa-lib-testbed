from lib_testbed.generic.util.common import compare_fw_versions
from lib_testbed.generic.pod.generic.pod_api import PodApi as PodApiGeneric
from lib_testbed.generic.util.request_handler import parse_request


class PodApi(PodApiGeneric):
    @parse_request
    def setup_class_handler_main_object(self, request):
        super().setup_class_handler_main_object(request)
        self.override_version_specific_ifnames()

    def override_version_specific_ifnames(self) -> None:
        none_ver = self.version()
        if compare_fw_versions(none_ver, "6.0.0.0", ">"):
            self.lib.capabilities.device_capabilities["interfaces"]["backhaul_ap"] = {
                "24g": "b-24",
                "5g": "b-50",
                "5gl": None,
                "5gu": None,
                "6g": "b-60",
            }
            self.lib.capabilities.device_capabilities["interfaces"]["home_ap"] = {
                "24g": "h-24",
                "5g": "h-50",
                "5gl": None,
                "5gu": None,
                "6g": "h-60",
            }
