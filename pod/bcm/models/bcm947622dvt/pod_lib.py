import os
import time
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.pod.bcm.pod_lib import PodLib as PodLibGeneric


class PodLib(PodLibGeneric):

    def upgrade(self, image, *args, **kwargs):
        # Check if safeupdate tool is available
        check_result = self.run_command('safeupdate')
        if not check_result[0] or 'usage' in check_result[2].lower():
            log.info("safeupdate tool is available on device. Using it instead!")
            return PodLibGeneric.upgrade(image, *args, **kwargs)

        """Upgrade node firmware, Optional: -p=<encyp_key>, -e-> erase certificates, -n->skip version check"""
        if kwargs.get('skip_if_the_same'):
            cur_ver = self.version()[1]
            if cur_ver in image:
                return [0, cur_ver, '']
        kwargs.pop('skip_if_the_same', '')
        skip_version_check = None
        image_file = os.path.basename(image)
        target_file_name = f"/tmp/img/{image_file}"
        for arg in args:
            if arg == '-n' or arg == 'skip_version_check':
                skip_version_check = True

        # Check if image is compatible with sdk version
        # 5.02.* builds will end in .w while for 5.04.* will end in .pkgtb
        get_version_result = self.run_command("grep -m1 \"version: '\" /etc/patch.version | awk '{print $2}'", **kwargs)
        get_release_result = self.run_command("grep -m3 \"release: '\" /etc/patch.version | awk '{print $2}'", **kwargs)
        if '5' not in get_version_result[1]:
            return [1, "", f"Only upgrade for version 5 is implemented. Version on device {get_version_result[1]}"]
        else:
            if '02' in get_release_result[1] and image[-1:] != 'w':
                return [1, "", f"FW image should end with .w for release 02. Release on device {get_release_result[1]}"]
            elif '04' in get_release_result[1] and image[-5:] != 'pkgtb':
                return [1, "", f"FW image should end with .pkgtb for release 04. "
                               f"Release on device {get_release_result[1]}"]

        # Prepare device before image upgrade
        self.run_command("rm -rf /tmp/img || true", **kwargs)
        self.run_command("mkdir -p /tmp/img", **kwargs)
        self.run_command("rmmod wl || true", **kwargs)
        self.run_command("rmmod dhd || true", **kwargs)
        self.run_command("killall wlmngr2 smbd radvd nas eapd vis-dcon vis-datacollector wlevt2 || true", **kwargs)

        # Transfer image
        self.put_file(image, "/tmp/img")

        # Validate md5sum
        remote_md5sum = self.run_command(f'md5sum /tmp/img/{image_file} | cut -d" " -f1', **kwargs)
        remote_md5sum = self.get_stdout(remote_md5sum)
        local_md5sum = os.popen(f'md5sum {image} | cut -d" " -f1').read().strip()
        md5sum = remote_md5sum.strip()
        if md5sum != local_md5sum:
            return [1, "", f"Failed MD5sum image: {local_md5sum} node: {md5sum} "]

        upg_comm = f"bcm_flasher {target_file_name}"
        result = self.run_command(upg_comm, timeout=10 * 60, **kwargs)

        # Initiate reboot
        self.run_command("bcm_bootstate 1", **kwargs)
        self.run_command("reboot -f", **kwargs)

        # wait for nodes to start rebooting
        time.sleep(10)
        self.wait_available(timeout=180)

        # don't rely on update return value
        result = self.merge_result(result, self.wait_available(60, **kwargs))

        if skip_version_check:
            return result

        log.info("Checking version")
        check_version = self.version(**kwargs)
        return self.merge_result([result[0], '', result[2]], check_version)
