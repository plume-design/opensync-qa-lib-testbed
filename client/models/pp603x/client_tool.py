from lib_testbed.generic.client.models.pod.client_tool import ClientTool as ClientToolGeneric


class ClientTool(ClientToolGeneric):
    def connect(
        self, ssid="", psk="", band="6G", htmode="", hwmode="", bssid="", key_mgmt="sae", timeout=60, **kwargs
    ):
        """Connect [pod] client(s) to the network"""
        return self.lib.connect_uci(ssid, psk, band, htmode, hwmode, bssid, key_mgmt, timeout, **kwargs)
