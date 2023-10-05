from lib_testbed.generic.util.base_lib import BaseLib
from lib_testbed.generic.pod.pod_config import TBCFG_NODE_DEPLOY
from lib_testbed.generic.util.logger import log


class PodBase(BaseLib):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def get_node_deploy_path(self):
        device_deploy_path = self.device.config.get(TBCFG_NODE_DEPLOY)
        if device_deploy_path:
            return device_deploy_path
        generic_deploy_path = self.config.get(TBCFG_NODE_DEPLOY)
        if not generic_deploy_path:
            log.error("Define node_deploy_to in locations config file")
            return "/opt/tb"
        return generic_deploy_path
