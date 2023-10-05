import os
import time
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.pod.cfg80211.pod_lib import PodLib as PodLibGeneric


class PodLib(PodLibGeneric):
    def get_boot_partition(self, **kwargs):
        """
        Get boot partition name
        Args:
            **kwargs:

        Returns: list(retval, stdout, stderr)
        """
        response = self.run_command('cat /proc/cmdline | sed -r "s/ubi.mtd=([a-zA-Z0-9]+).*/\\1/g"', **kwargs)
        return response

    def trigger_single_radar_detected_event(self, phy_radio_name, **kwargs):
        """
        Trigger radar detected event
        Args:
            phy_radio_name: (str): Phy radio name
            **kwargs:

        Returns: list(retval, stdout, stderr)

        """
        response = self.run_command(
            f"echo 1 > /sys/kernel/debug/ieee80211/{phy_radio_name}/ath10k/dfs_simulate_radar", **kwargs
        )
        return response

    def upgrade(self, image, *args, **kwargs):
        """Upgrade node firmware, Optional: -p=<encyp_key>, -n->skip version check"""
        if kwargs.get("skip_if_the_same"):
            cur_ver = self.version()[1]
            if cur_ver in image:
                return [0, cur_ver, ""]
        kwargs.pop("skip_if_the_same", "")

        skip_version_check = False
        image_file = os.path.basename(image)
        target_file_name = f"/tmp/pfirmware/{image_file}"
        dec_passwd = None
        for arg in args:
            if arg == "-n" or arg == "skip_version_check":
                skip_version_check = True
            if "-p=" in arg:
                dec_passwd = arg[3:]

        if dec_passwd and image[-3:] == "eim":
            raise Exception("Encrypted images are not supported.")

        self.run_command("mkdir -p /tmp/pfirmware", **kwargs)
        self.put_file(image, "/tmp/pfirmware")
        remote_md5sum = self.run_command(f'md5sum /tmp/pfirmware/{image_file} | cut -d" " -f1', **kwargs)
        remote_md5sum = self.get_stdout(remote_md5sum)
        local_md5sum = os.popen(f'md5sum {image} | cut -d" " -f1').read().strip()

        md5sum = remote_md5sum.strip()
        if md5sum != local_md5sum:
            return [1, "", f"Failed MD5sum image: {local_md5sum} node: {md5sum} "]

        upg_comm = f"sysupgrade -n {target_file_name}"

        result = self.run_command(upg_comm, timeout=5 * 60, **kwargs)

        # wait for nodes to start rebooting
        time.sleep(10)
        self.wait_available(timeout=180)

        # don't rely on update return value
        result = self.merge_result(result, self.wait_available(60, **kwargs))

        if skip_version_check:
            return result

        log.info("Checking version")
        check_version = self.version(**kwargs)
        return self.merge_result([result[0], "", result[2]], check_version)
