from lib_testbed.generic.client.models.generic.client_tool import ClientTool as ClientToolGeneric


class ClientTool(ClientToolGeneric):
    def get_hostname(self, **kwargs):
        return self.lib.get_hostname(**kwargs)

    def wifi_connection_info(self, **kwargs):
        return self.lib.wifi_connection_info(**kwargs)

    def get_iface_info(self, **kwargs):
        return self.lib.get_iface_info(**kwargs)

    def get_client_info(self, **kwargs):
        return self.lib.get_client_info(**kwargs)

    def turn_on_wifi(self, ifname="", **kwargs):
        return self.lib.turn_on_wifi(ifname, **kwargs)

    def turn_off_wifi(self, ifname="", **kwargs):
        return self.lib.turn_off_wifi(ifname, **kwargs)

    def wifi_scan(self, ifname="", **kwargs):
        return self.lib.wifi_scan(ifname, **kwargs)

    def wifi_disconnect(self, ifname="", **kwargs):
        return self.lib.wifi_disconnect(ifname, **kwargs)

    def connect_to_network(self, ssid, psk, ifname="", ping_ip=None, skip_exception=False, retry=5, **kwargs):
        return self.lib.connect_to_network(ssid, psk, ifname, ping_ip, skip_exception, retry, **kwargs)

    def put_dir(self, directory, location, **kwargs):
        """Copy dir into client(s)"""
        return self.lib.put_dir(directory, location, **kwargs)

    def wifi_monitor(self, channel, ifname="", **kwargs):
        """Set interface into monitor mode"""
        return self.lib.wifi_monitor(channel, ifname, **kwargs)

    def wifi_station(self, ifname="", **kwargs):
        """Set interface into station mode"""
        return self.lib.wifi_station(ifname, **kwargs)
