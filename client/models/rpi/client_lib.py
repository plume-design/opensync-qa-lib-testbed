import os
import time
import random

from lib_testbed.generic.client.models.debian.client_lib import DebianClientUpgrade
from lib_testbed.generic.client.models.debian.client_lib import ClientLib as DebianClientLib


class ClientLib(DebianClientLib):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def client_to_pod(self, **kwargs):
        return ["1", "", "Rpi client is not a pod"]

    def pod_to_client(self, **kwargs):
        return ["1", "", "Rpi client is not a pod"]

    def upgrade(
        self,
        fw_path=None,
        restore_cfg=True,
        force=False,
        http_address="",
        download_locally=True,
        version=None,
        restore_files=None,
        **kwargs,
    ):
        """
        Upgrade raspberry clients to target firmware if fw_path=None download latest build version from artifactory
        Args:
            fw_path: (str) Path to image
            force: (bool) Flash image even though the same firmware is already on the device
            restore_cfg: (bool) Restore a client configuration (hostname, dhcpd.conf)
            http_address: (str) Start download image directly from provided HTTP server address
            download_locally: (bool) If True download upgrade files to local machine
            version: (str) version to download from the artifactory (or get latest or stable version)
            restore_files: (str): Paths of files to restore. eg. restore_files=/home/plume/file1,/etc/file2
            **kwargs:

        Returns: (ret_val, std_out, str_err)

        """
        self.run_command("rm -R /tmp/automation/")
        # short sleep to spread threads in time
        time.sleep(random.randint(1, 10) / 10)
        rpi_upgrade = RpiClientUpgrade(
            lib=self, restore_cfg=restore_cfg, download_locally=download_locally, restore_files=restore_files
        )
        if http_address:
            if rpi_upgrade.device_type not in http_address:
                return [20, "", f"Provided RPI image is not intended for {rpi_upgrade.device_type}"]
            fw_path = rpi_upgrade.download_image_from_url(http_address)
        if fw_path and not os.path.isabs(fw_path):
            fw_path = os.path.abspath(fw_path)
        return rpi_upgrade.start_upgrade(fw_path, force, version, **kwargs)

    def limit_tx_power(self, state=True, **kwargs):
        """
        Limit WiFi Tx power on the devices in the testbed
        state: (bool) Enable/disable Tx power modification
        """
        if state:
            out = self.run_command("sudo touch /.tx_power_enable.flag", **kwargs)
            if out[0]:
                return out
            out[1] = "Please reboot your pods to make it happen"
        else:
            out = self.run_command("sudo rm /.tx_power_enable.flag", **kwargs)
            if "No such file or directory" in out[2]:
                return [0, "Limiting Tx power was not enabled", ""]
        return out

    def set_tx_power(self, tx_power, ifname="", **kwargs):
        """
        Set client Tx power for iface

        Args:
            tx_power: (int) Tx power value to set (dBm)
            ifname: (str) client interface name

        Returns:

        """
        return [1, "", "RPi does not support changing Tx power"]

    def get_tx_power(self, ifname="", **kwargs):
        """
        Get client Tx power for iface

        Args:
            ifname: (str) client interface name

        Returns:

        """
        return [1, "", "RPi does not support changing Tx power"]

    def get_max_tx_power(self, ifname="", **kwargs):
        """
        Get max Tx power value from iw
        Args:
            ifname: (str) name of wifi interface
            **kwargs:

        Returns:
        """
        return [1, "", "RPi does not support changing Tx power"]

    def get_min_tx_power(self, ifname="", **kwargs):
        """
        Get max Tx power value from iw
        Args:
            ifname: (str) name of wifi interface
            **kwargs:

        Returns:
        """
        return [1, "", "RPi does not support changing Tx power"]

    def check_hackrf_status(self, **kwargs):
        return [1, "", "RPi does not support HackRF"]

    def hackrf_generate_radar_pulse(self, channel, region="us", vector=0, **kwargs):
        return [1, "", "RPi does not support HackRF"]


class RpiClientUpgrade(DebianClientUpgrade):
    upgrade_script = "upgrade-rpi"
    compression_type = "tar.gz"
    checksum_type = "md5"
    build_name = "build_rpi_c_plume"
    build_separator = r"\.|-"
    type_version_separator = "__"
    version_pattern = r"(\d+\.\d+\-\d+)"
