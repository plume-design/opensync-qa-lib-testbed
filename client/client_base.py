from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.util.base_lib import BaseLib
from lib_testbed.generic.client.client_config import TBCFG_CLIENT_DEPLOY, TBCFG_NETWORKS, TBCFG_NETWORKS_SSID,\
    TBCFG_NETWORKS_ALIAS, TBCFG_NETWORKS_KEY


class ClientBase(BaseLib):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def get_network_name(self):
        networks = self.config.get(TBCFG_NETWORKS)
        if not networks:
            return None
        return networks[0][TBCFG_NETWORKS_SSID]

    def get_network(self, name):
        if TBCFG_NETWORKS in self.config:
            for network in self.config[TBCFG_NETWORKS]:
                ssid = network[TBCFG_NETWORKS_SSID]
                alias = network.get(TBCFG_NETWORKS_ALIAS, "")
                try:
                    if name == ssid or name == alias:
                        return (network[TBCFG_NETWORKS_SSID],
                                network[TBCFG_NETWORKS_KEY])
                except Exception:
                    raise OpenSyncException("Network not properly defined in config",
                                            f"Network should have {TBCFG_NETWORKS_SSID}, {TBCFG_NETWORKS_KEY} and"
                                            f" optionally {TBCFG_NETWORKS_ALIAS} defined")
        return None, None

    def get_tool_path(self):
        if TBCFG_CLIENT_DEPLOY not in self.config:
            raise OpenSyncException("client_deploy_to: configuration not set",
                                    "Define client_deploy_to in locations config file")
        return self.config[TBCFG_CLIENT_DEPLOY]

    @property
    def type(self):
        return self.device.config.get('type', '')
