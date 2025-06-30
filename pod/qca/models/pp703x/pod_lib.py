import re
import time
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.common import wait_for
from lib_testbed.generic.pod.qca.pod_lib import PodLib as PodLibGeneric

QSDK_12_VER = "QSDK12"
QSDK_13_VER = "QSDK13"
FULL_FIT_BUILD_MAP_PREFIX = "full_fit_"
FULL_FIT_FN_PREFIX = "full-fit"
FIT_FN_IMAGE_PREFIX = "fit"


class PodLib(PodLibGeneric):
    SUPPORTED_REGULATORY_DOMAINS = {
        "EU",
        "JP",
        "US",
    }

    def upgrade_from_artifactory(self, image: str, *args, **kwargs):
        """Overwrite this method to apply full-fit image in case when SDK version from requested image
        is different from current SDK version."""
        current_sdk_ver = self.get_used_sdk_version()
        build_name, build_num = self.artifactory.parse_requested_build(image)
        build_details = self.artifactory.build_map.get(build_name).copy()
        if not build_details:
            raise Exception(
                "Build details are not specified in %s build_map.json file for requested image: %s."
                % (self.device.config["model_org"], image)
            )
        image_prefix = build_details["fn-prefix"]
        if current_sdk_ver in image_prefix:
            return super().upgrade_from_artifactory(image, *args, **kwargs)
        # Different SDK detected - use full-fit image to update uboot
        log.info(
            "Detected difference between current used SDK version and SDK version from requested image."
            " Updating %s device with use full-fit image.",
            self.get_nickname(),
        )
        build_name = f"{FULL_FIT_BUILD_MAP_PREFIX}{build_name}"
        if not self.artifactory.build_map.get(build_name):
            build_details["fn-prefix"] = build_details["fn-prefix"].replace(FIT_FN_IMAGE_PREFIX, FULL_FIT_FN_PREFIX)
            self.artifactory.build_map[build_name] = build_details
        image = f"{FULL_FIT_BUILD_MAP_PREFIX}{image}"
        return super().upgrade_from_artifactory(image, *args, **kwargs)

    def get_region(self, **kwargs):
        # FW above 5.4.X has region entry in Wifi_Radio_State table, so start from there
        table_check = super().get_region(override_region=True, **kwargs)
        if table_check[0] == 0:
            return table_check
        response = self.run_command(
            "cfg80211tool wifi0 getCountry; cfg80211tool wifi1 getCountry; cfg80211tool wifi2 getCountry", **kwargs
        )
        cc_codes = re.findall(r"(?<=getCountry:).*", response[1])
        if not cc_codes:
            return [1, "", "Cannot get region"]
        if len(set(cc_codes)) > 1:
            return [2, "", f"Different regions for different radios: {cc_codes}"]
        return [0, cc_codes[0], ""]

    def set_region_three_radios_model(self, region, **kwargs):
        if region not in self.SUPPORTED_REGULATORY_DOMAINS:
            # Return error message in both stdout and stderr, dfs tests expect it to be in stdout
            return [1, f"Region {region} is not supported", f"Region {region} is not supported"]
        log.info(f"Set {region} region for node {self.get_nickname()}")
        if region == "EU":
            region = "CH"
        # it takes time
        res = self.run_command(
            f"pmf -fw {region} -ccode0; pmf -fw {region} -ccode1; pmf -fw {region} -ccode2", timeout=90
        )
        log.info("Rebooting pod")
        self.reboot()
        time.sleep(10)
        self.wait_available(timeout=2 * 60)
        wait_for(lambda: self.get_stdout(self.get_region(), skip_exception=True), timeout=120, tick=2)
        return res

    def set_eth_link_speed(self, iface: str, speed: int, duplex: str, **kwargs):
        """
        Set speed on the port
        """
        log.info(
            "Setting link status on interface %s speed %d duplex %s",
            iface,
            speed,
            duplex,
        )
        # ETHTOOL_LINK_MODE_10baseT_Half_BIT = 0,
        # ETHTOOL_LINK_MODE_10baseT_Full_BIT = 1,
        # ETHTOOL_LINK_MODE_100baseT_Half_BIT = 2,
        # ETHTOOL_LINK_MODE_100baseT_Full_BIT = 3,
        # ETHTOOL_LINK_MODE_1000baseT_Half_BIT = 4,
        # ETHTOOL_LINK_MODE_1000baseT_Full_BIT = 5,
        # ETHTOOL_LINK_MODE_2500baseT_Full_BIT = 47,
        match (speed, duplex):
            case 10, "half":
                advertise_code = hex(1 << 0)
            case 10, "full":
                advertise_code = hex(1 << 1)
            case 100, "half":
                advertise_code = hex(1 << 2)
            case 100, "full":
                advertise_code = hex(1 << 3)
            case 1000, "half":
                advertise_code = hex(1 << 4)
            case 1000, "full":
                advertise_code = hex(1 << 5)
            case 2500, "full":
                advertise_code = hex(1 << 47)
            case _:
                raise KeyError("Incorrect configuration")

        return self.run_command(f"ethtool -s {iface} advertise {advertise_code}", **kwargs)

    def get_boot_partition(self, **kwargs):
        """
        Get boot partition name
        Args:
            **kwargs:

        Returns: list(retval, stdout, stderr)
        """
        self.run_command("bootconfig -r", **kwargs)
        boot_partition_logs = self.run_command("logread -p BOOTCFG | grep 'current boot image' -i")
        boot_partition = re.search("boot image:.*", boot_partition_logs[1], re.IGNORECASE)
        if not boot_partition:
            return [1, "", "Can't get current boot partition with use 'bootconfig -r' command"]
        boot_partition = boot_partition.group()
        return [0, boot_partition, ""]

    def get_used_sdk_version(self) -> str:
        """Get current SDK version used by device."""
        kernel_version = self.get_stdout(self.get_kernel_release())
        if kernel_version >= "6.6.47":
            return QSDK_13_VER
        else:
            return QSDK_12_VER
