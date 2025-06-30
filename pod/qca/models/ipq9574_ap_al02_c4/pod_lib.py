from lib_testbed.generic.pod.mtk.pod_lib import PodLib as PodLibGeneric
from lib_testbed.generic.util.logger import log


UPGRADE_SUCCESS_MESSAGE = "Commencing upgrade. Closing all shell sessions."
RESULT_STD_OUT = 1


class PodLib(PodLibGeneric):
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
        if UPGRADE_SUCCESS_MESSAGE in result[RESULT_STD_OUT]:
            log.info("Changing upgrade result status code because success message was found")
            result[0] = 0
        return result
