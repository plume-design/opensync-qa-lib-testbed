from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.util.base_lib import BaseLib
from lib_testbed.generic.util.config import get_mdu_loc_cfg
from lib_testbed.generic.client.client_config import (
    TBCFG_CLIENT_DEPLOY,
    TBCFG_NETWORKS,
    TBCFG_NETWORKS_SSID,
    TBCFG_NETWORKS_ALIAS,
    TBCFG_NETWORKS_KEY,
)


class ClientBase(BaseLib):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def get_tb_networks(self) -> list:
        if not self.is_mdu_location():
            networks = self.config.get(TBCFG_NETWORKS, [])
        else:
            networks = self.get_mdu_unit_networks()
        return networks

    def get_network_name(self) -> str | None:
        networks = self.get_tb_networks()
        if not networks:
            return None
        return networks[0][TBCFG_NETWORKS_SSID]

    def get_mdu_unit_networks(self) -> list:
        default_loc = self.device.config["default_location"]
        location_cfg = get_mdu_loc_cfg(self.config, location_name=default_loc)
        return location_cfg.get(TBCFG_NETWORKS, [])

    def get_network(self, name: str) -> tuple[str, str] | tuple[None, None]:
        tb_networks = self.get_tb_networks()
        for network in tb_networks:
            ssid = network[TBCFG_NETWORKS_SSID]
            alias = network.get(TBCFG_NETWORKS_ALIAS, "")
            try:
                if name == ssid or name == alias:
                    return (network[TBCFG_NETWORKS_SSID], network[TBCFG_NETWORKS_KEY])
            except Exception:
                raise OpenSyncException(
                    "Network not properly defined in config",
                    f"Network should have {TBCFG_NETWORKS_SSID}, {TBCFG_NETWORKS_KEY} and"
                    f" optionally {TBCFG_NETWORKS_ALIAS} defined",
                )
        return None, None

    def get_tool_path(self):
        if TBCFG_CLIENT_DEPLOY not in self.config:
            raise OpenSyncException(
                "client_deploy_to: configuration not set", "Define client_deploy_to in locations config file"
            )
        return self.config[TBCFG_CLIENT_DEPLOY]

    @property
    def type(self):
        return self.device.config.get("type", "")
