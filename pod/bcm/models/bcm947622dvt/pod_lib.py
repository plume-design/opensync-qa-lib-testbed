from lib_testbed.generic.util.logger import log
from lib_testbed.generic.pod.bcm.pod_lib import PodLib as PodLibGeneric


class PodLib(PodLibGeneric):

    def trigger_upgrade(self, image_path: str, dec_passwd: str, **kwargs) -> [int, str, str]:
        """
        Trigger upgrade on the device.
        Args:
            image_path: (str) Path to the image for upgrade trigger
            dec_passwd: (str) Decrypted password for encrypted images
            **kwargs:

        Returns: [int, str, str]

        """
        # Check if safeupdate tool is available
        check_result = self.run_command("safeupdate")
        if not check_result[0] or "usage" in check_result[2].lower():
            return super().trigger_upgrade(image_path, dec_passwd, **kwargs)

        result = self.check_upgrade_image_sdk(image_path)
        if result[0]:
            return result

        self.run_command("rmmod wl || true", **kwargs)
        self.run_command("rmmod dhd || true", **kwargs)
        self.run_command("killall wlmngr2 smbd radvd nas eapd vis-dcon vis-datacollector wlevt2 || true", **kwargs)

        upg_comm = f"bcm_flasher {image_path}"
        log.debug("Upgrade command: %s", upg_comm)
        result = self.run_command(upg_comm, timeout=10 * 60, **kwargs)

        # Initiate reboot
        self.run_command("bcm_bootstate 1", **kwargs)
        self.run_command("reboot -f", **kwargs)
        return result

    def check_upgrade_image_sdk(self, image: str, **kwargs) -> [int, str, str]:
        """Check if image is compatible with sdk version
        5.02.* builds will end in .w while for 5.04.* will end in .pkgtb"""
        get_version_result = self.run_command("grep -m1 \"version: '\" /etc/patch.version | awk '{print $2}'", **kwargs)
        get_release_result = self.run_command("grep -m3 \"release: '\" /etc/patch.version | awk '{print $2}'", **kwargs)
        if "5" not in get_version_result[1]:
            return [1, "", f"Only upgrade for version 5 is implemented. Version on device {get_version_result[1]}"]
        else:
            if "02" in get_release_result[1] and image[-1:] != "w":
                return [1, "", f"FW image should end with .w for release 02. Release on device {get_release_result[1]}"]
            elif "04" in get_release_result[1] and image[-5:] != "pkgtb":
                return [
                    1,
                    "",
                    f"FW image should end with .pkgtb for release 04. " f"Release on device {get_release_result[1]}",
                ]
        return [0, "", ""]
