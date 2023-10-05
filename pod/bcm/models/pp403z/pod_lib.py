import os
from lib_testbed.generic.pod.bcm.pod_lib import PodLib as PodLibGeneric

NEW_SDK_VER = "5.8.0"
NEW_SDK_KERNEL_VER = "4.19.183"
BUILD_MAP_SDK_TRANSITION = "build_map_sdk_transition.json"


class PodLib(PodLibGeneric):
    def upgrade_from_artifactory(self, image: str, *args, **kwargs):
        # Upgrade to the new SDK requires additional steps
        if image > NEW_SDK_VER:
            if NEW_SDK_KERNEL_VER > self.get_stdout(self.get_kernel_release()):
                return self.upgrade_to_new_sdk(image, **kwargs)
            enc_key = self.artifactory.get_enc_key(version=image)
            return super().upgrade_from_artifactory(image, True, f"-p={enc_key}", **kwargs)
        return super().upgrade_from_artifactory(image, *args, **kwargs)

    def upgrade_to_new_sdk(self, image: str, **kwargs):
        # From SDK 5.02 → SDK 5.04
        filename = self.artifactory.download_proper_version(
            image, map_type=BUILD_MAP_SDK_TRANSITION, use_build_map_suffix=True
        )
        filepath = os.path.join(self.artifactory.tmp_dir, filename)
        enc_key = self.artifactory.get_enc_key(version=image, map_type=BUILD_MAP_SDK_TRANSITION)
        # This prevents on some older pods to lose SSH access after first upgrade
        self.run_command("pmf -d -w 0; pmf -d -w 1")
        status = self.upgrade_from_local_file(filepath, f"-p={enc_key}", **kwargs)
        if status[0]:
            raise Exception(f"Upgrade to the new SDK failed: {status}")
        self.wait_available(timeout=180)
        # This prevents on some older pods to lose SSH access after first upgrade
        self.run_command("pmf -d -w 0; pmf -d -w 1")
        # Already on SDK 5.04
        enc_key = self.artifactory.get_enc_key(version=image)
        return super().upgrade_from_artifactory(image, True, f"-p={enc_key}", **kwargs)
