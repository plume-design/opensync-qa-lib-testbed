from lib_testbed.generic.util.common import compare_fw_versions
from lib_testbed.generic.pod.generic.pod_api import PodApi as PodApiGeneric
from lib_testbed.generic.util.request_handler import parse_request


class PodApi(PodApiGeneric):
    @parse_request
    def setup_class_handler_main_object(self, request):
        super().setup_class_handler_main_object(request)
        self.override_version_specific_ifnames()

    def override_version_specific_ifnames(self) -> None:
        try:
            none_ver = self.version()
        except Exception:
            none_ver = "100.0.0.0"
        if compare_fw_versions(none_ver, "6.0.0.0", ">"):
            self.lib.capabilities.device_capabilities["interfaces"]["backhaul_ap"] = {
                "24g": "b-24",
                "5g": None,
                "5gl": "b-l5",
                "5gu": "b-u5",
                "6g": None,
            }
            self.lib.capabilities.device_capabilities["interfaces"]["home_ap"] = {
                "24g": "h-24",
                "5g": None,
                "5gl": "h-l5",
                "5gu": "h-u5",
                "6g": None,
            }
        elif compare_fw_versions(none_ver, "5.8.0.0", ">"):
            self.lib.capabilities.device_capabilities["interfaces"]["backhaul_ap"] = {
                "24g": "b-ap-24",
                "5g": None,
                "5gl": "b-ap-l50",
                "5gu": "b-ap-u50",
                "6g": None,
            }
