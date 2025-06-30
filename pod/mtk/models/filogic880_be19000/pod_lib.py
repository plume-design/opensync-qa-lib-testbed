from lib_testbed.generic.pod.mtk.pod_lib import PodLib as PodLibGeneric
from lib_testbed.generic.util.logger import log


UPGRADE_SUCCESS_MESSAGE = "Commencing upgrade. Closing all shell sessions."


class PodLib(PodLibGeneric):
    def get_region(self, **kwargs):
        return [0, "US", ""]

    def get_boot_partition(self, **kwargs):
        """
        Get boot partition name
        Args:
            **kwargs:

        Returns: list(retval, stdout, stderr)
        """
        # MTK Wi-Fi 7 refboard only has one partition
        return self.run_command('echo "single-partition device"')

    def trigger_single_radar_detected_event(
        self, phy_radio_name, segment_id: int = None, chirp: int = None, freq_offest: int = None, **kwargs
    ):
        """
        Trigger radar detected event
        Args:
            phy_radio_name: (str): Phy radio name
            segment_id: (int): Segment ID - optional
            chirp: (int) Chirp information - optional
            freq_offest: (int) Frequency offset - optional
            **kwargs:

        Returns: list(retval, stdout, stderr)

        """
        if segment_id or chirp or freq_offest:
            raise NotImplementedError

        ret = self.run_command("mwctl rai0 set rddreport=1", **kwargs)
        return [0, ret[1], ret[2]]

    # Override the default upgrade method because this model does not finish the upgrade gracefully,
    # and we can't get the upgrade status code. This method should remain the same as the parent one
    # with the difference that we override the final status code when standard output indicates success.
    def trigger_upgrade(self, image_path: str, dec_passwd: str, **kwargs) -> [int, str, str]:
        """
        Trigger upgrade on the device.
        Args:
            image_path: (str) Path to the image for upgrade trigger
            dec_passwd: (str) Decrypted password for encrypted images
            **kwargs:

        Returns: [int, str, str]

        """
        result = super().trigger_upgrade(image_path, dec_passwd, **kwargs)
        # Since successful upgrade returns 255 we determine if the upgrade was successful by parsing the output message
        if UPGRADE_SUCCESS_MESSAGE in result[2]:
            log.info("Changing upgrade result status code because success message was found")
            result[0] = 0
        return result

    def run_traffic_acceleration_monitor(self, samples: int = 5, interval: int = 5, delay: int = 20, **kwargs) -> dict:
        """
        Start making traffic acceleration statistics dumps on the pod in the background
        Args:
            samples: (int) number of statistic dumps
            interval: (int) seconds apart
            delay: (int) seconds after the method is called.
            **kwargs:

        Returns: Return (dict) dict(sfe_dump=dict(dump_file="", pid="")) Acceleration statistics dumps details.

        """
        return self._run_traffic_acceleration_monitor(
            acc_name="hnat",
            acc_tool="cat /sys/kernel/debug/hnat/all_entry | grep state=BIND",
            samples=samples,
            interval=interval,
            delay=delay,
        )

    # Proprietary MTK driver doesn't allow setting txpower via cfg80211 / iw tool:
    #
    #   root@opensync:~# iw ra0 info | grep txpower
    #   txpower 12.00 dBm
    #   root@opensync:~# iw ra0 set txpower fixed 1000
    #   command failed: Not supported (-95)
    #
    # There is a startup script always limiting txpower on these boards anyway.
    # optional
    def decrease_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Decrease value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns:

        """
        self.last_cmd["command"] = "unknown"
        self.last_cmd["name"] = "unknown"
        return [0, "", ""]

    # optional
    def increase_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Increase value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns:

        """
        self.last_cmd["command"] = "unknown"
        self.last_cmd["name"] = "unknown"
        return [0, "", ""]

    # optional
    def set_tx_power(self, tx_power, interfaces=None, **kwargs):
        """
        Set current Tx power in dBm
        Args:
            interfaces: (str) or (list) Name of wireless interfaces
            tx_power: (int) Tx power in dBm.

        Returns:

        """
        self.last_cmd["command"] = "unknown"
        self.last_cmd["name"] = "unknown"
        return [0, "", ""]
