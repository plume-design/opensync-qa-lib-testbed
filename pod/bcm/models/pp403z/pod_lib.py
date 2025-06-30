import os

from lib_testbed.generic.pod.bcm.pod_lib import PodLib as PodLibGeneric
from lib_testbed.generic.pod.generic.artifactory_reader import ArtifactoryReader

NEW_SDK_VER = "5.8.0"
NEW_SDK_KERNEL_VER = "4.19.183"
BUILD_MAP_SDK_TRANSITION = "build_map_sdk_transition.json"


class PodLib(PodLibGeneric):
    def upgrade_from_artifactory(self, image: str, *args, **kwargs):
        # Upgrade to the new SDK requires additional steps
        if image >= NEW_SDK_VER:
            if NEW_SDK_KERNEL_VER > self.get_stdout(self.get_kernel_release()):
                return self.upgrade_to_new_sdk(image, **kwargs)
        return super().upgrade_from_artifactory(image, *args, **kwargs)

    def upgrade_to_new_sdk(self, image: str, **kwargs):
        # From SDK 5.02 → SDK 5.04
        artifactory_transition = ArtifactoryReader(lib=self, map_type=BUILD_MAP_SDK_TRANSITION)
        filename, fw_key = artifactory_transition.download_proper_version(image)
        if not filename:
            return [5, "", "Cannot upgrade as filename is unknown"]
        filepath = os.path.join(artifactory_transition.tmp_dir, filename)
        # This prevents on some older pods to lose SSH access after first upgrade
        self.run_command("pmf -d -w 0; pmf -d -w 1")
        args = ("-p=%s" % fw_key if fw_key else None,)
        status = self.upgrade_from_local_file(filepath, *args, **kwargs)
        if status[0]:
            raise Exception(f"Upgrade to the new SDK failed: {status}")
        self.wait_available(timeout=180)
        # This prevents on some older pods to lose SSH access after first upgrade
        self.run_command("pmf -d -w 0; pmf -d -w 1")
        # Already on SDK 5.04
        return super().upgrade_from_artifactory(image, **kwargs)
