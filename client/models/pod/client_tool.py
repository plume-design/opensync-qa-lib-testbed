from lib_testbed.generic.client.models.generic.client_tool import ClientTool as ClientToolGeneric


class ClientTool(ClientToolGeneric):
    def connect(
        self, ssid="", psk="", band="5G", htmode="", hwmode="", bssid="", key_mgmt="psk2", timeout=60, **kwargs
    ):
        """Connect [pod] client(s) to the network"""
        return self.lib.connect_uci(ssid, psk, band, htmode, hwmode, bssid, key_mgmt, timeout, **kwargs)

    def disconnect(self, **kwargs):
        """Disconnect [pod] client(s) to the network"""
        return self.lib.disconnect(**kwargs)
