from lib_testbed.generic.client.models.generic.client_tool import ClientTool as ClientToolGeneric


class ClientTool(ClientToolGeneric):

    def connect(self, ssid=None, psk=None, bssid=None, band=None, key_mgmt='WPA-PSK', timeout=60,
                dhclient=True, e_gl_param='', e_net_param='', country='US', proto='RSN', pmf_mode='enabled', **kwargs):
        """Connect [pod] client(s) to the network"""
        result = [1, '', 'Not started']
        bands = [band] if band else ['24g', '5gl', '5gu']
        for band in bands:
            result = self.lib.connect(ssid=ssid, psk=psk, bssid=bssid, band=band, key_mgmt=key_mgmt, timeout=timeout,
                                      dhclient=dhclient, e_gl_param=e_gl_param, e_net_param=e_net_param,
                                      country=country, proto=proto, pmf_mode=pmf_mode, **kwargs)
            if result[0] == 0:
                break
        return result

    def refresh_ip_address(self, ifname, timeout=20, **kwargs):
        """Starts dhcp client on wifi iface"""
        return self.lib.start_dhcp_client(ifname=ifname, timeout=timeout, **kwargs)

    def get_temperature(self, **kwargs):
        """Get radio temperatures from device"""
        radio_idxs = self.lib.iface.radio_index_map()
        radio_temps = []
        for radio_band, radio_idx in radio_idxs.items():
            radio_temp = self.lib.get_stdout(self.lib.strip_stdout_result(
                (self.lib.get_radio_temperature(radio_idx, **kwargs))))
            radio_temps.append(f'{radio_band}: {radio_temp}°C')
        temp_to_print = '\n'.join(radio_temps)
        return [0, temp_to_print, '']

    def set_region(self, region, **kwargs):
        """Set regional domain (EU, US, UK, CA, JP)"""
        return self.lib.set_region_three_radios_model(region=region, **kwargs)
