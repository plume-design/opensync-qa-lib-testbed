from lib_testbed.generic.client.models.generic.client_api import ClientApi as ClientApiGeneric


class ClientApi(ClientApiGeneric):

    def version(self, **kwargs):
        result = self.lib.version(**kwargs)
        ver = self.get_stdout(result, skip_exception=True)
        return ver if ver else '100.0.0 [UNKNOWN]'

    def wifi_connection_info(self, **kwargs):
        results = self.lib.wifi_connection_info(**kwargs)
        return self.get_stdout(results)

    def get_iface_info(self, **kwargs):
        results = self.lib.get_iface_info(**kwargs)
        return self.get_stdout(results)

    def get_client_info(self, **kwargs):
        results = self.lib.get_client_info(**kwargs)
        return self.get_stdout(results)

    def ping(self, host='', **kwargs):
        results = self.lib.ping(host, **kwargs)
        return self.get_stdout(results)

    def wifi_scan(self, ifname='', **kwargs):
        results = self.lib.wifi_scan(ifname, **kwargs)
        return self.get_stdout(results)

    def wifi_disconnect(self, ifname='', **kwargs):
        results = self.lib.wifi_disconnect(ifname, **kwargs)
        return self.get_stdout(results, skip_exception=True)

    def connect_to_network(self, ssid, psk, ifname='',
                           ping_ip=None, skip_exception=False, retry=5, **kwargs):
        results = self.lib.connect_to_network(ssid, psk, ifname, ping_ip, skip_exception, retry, **kwargs)
        return self.get_stdout(results, skip_exception=True)

    def get_file(self, remote_file, location, **kwargs):
        """Copy a file from client(s)"""
        results = self.lib.get_file(remote_file, location, **kwargs)
        return self.get_stdout(results)

    def put_dir(self, directory, location, **kwargs):
        """Copy dir into client(s)"""
        results = self.lib.put_dir(directory, location, **kwargs)
        return self.get_stdout(results)

    def put_file(self, file_name, location, **kwargs):
        results = self.lib.put_file(file_name, location, **kwargs)
        return self.get_stdout(results)

    def reboot(self, **kwargs):
        """Reboot client(s)"""
        resposne = self.lib.reboot(**kwargs)
        return self.get_stdout(resposne)

    def wifi_monitor(self, channel, ifname='', **kwargs):
        results = self.lib.wifi_monitor(channel, ifname, **kwargs)
        return self.get_stdout(results)

    def wifi_station(self, ifname="", **kwargs):
        results = self.lib.wifi_station(ifname, **kwargs)
        return self.get_stdout(results)

    def get_wlan_iface(self, **kwargs):
        return self.lib.get_wlan_iface(**kwargs)

    def get_eth_iface(self, **kwargs):
        return self.lib.get_iface("Ethernet", **kwargs)

    def get_network_service_by_ip(self, ip):
        return self.lib.get_network_service_by_ip(ip)
