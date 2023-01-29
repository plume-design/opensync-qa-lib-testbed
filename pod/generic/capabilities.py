import re


class Capabilities:
    def __init__(self, lib):
        # TODO: Make the capabilities config accessible in case no mgmt access
        #  - In case no mgmt dev_discovered.device doesn't exist
        # Handle no mgmt case
        self.device_capabilities = dict()
        if lib.device:
            self.device_capabilities = lib.device.config['capabilities']

    @staticmethod
    def parse_results(default_results, return_type, freq_band=''):
        # Always skip None values
        if return_type is dict:
            results = dict()
            for key, value in default_results.items():
                if not value or freq_band and freq_band not in key:
                    continue
                results[key] = value
        elif return_type is list:
            results = list()
            for key, value in default_results.items():
                if not value or freq_band and freq_band not in key:
                    continue
                results.append(value)
        else:
            assert False, f'Not supported type: {return_type}'
        return results

    @staticmethod
    def parse_freq_band(freq_band):
        # Fix mismatch between naming 2G band in the capabilities cfg 2.4G != 24g
        freq_band = freq_band.lower()
        if freq_band in ['2.4g', '2g']:
            freq_band = '24g'
        return freq_band

    # BASE SECTION

    def get_wifi_vendor(self):
        return self.device_capabilities['wifi_vendor']

    def get_opensync_rootdir(self):
        return self.device_capabilities.get('opensync_rootdir', '')

    def get_shell_path(self):
        return self.device_capabilities.get('shell_path', '')

    def get_logread_command(self):
        return self.device_capabilities['logread']

    def get_logread_method(self):
        return self.device_capabilities['frv_logread']

    def is_fan(self):
        return self.device_capabilities['active_cooling']

    def is_dfs(self):
        return self.device_capabilities['dfs']

    def is_regulatory_domain_managed(self):
        return self.device_capabilities.get('regulatory_domain_managed', False)

    def get_device_type(self):
        return self.device_capabilities['device_type']

    def get_supported_security_modes(self):
        return self.device_capabilities['security']

    # INTERFACE SECTION
    def get_radio_hw_mode(self, freq_band):
        freq_band = self.parse_freq_band(freq_band)
        return self.device_capabilities['interfaces']['radio_hw_mode'].get(freq_band)

    def get_radio_hw_modes(self, return_type=dict):
        return self.parse_results(self.device_capabilities['interfaces']['radio_hw_mode'], return_type)

    def get_max_channel_width(self, freq_band):
        freq_band = self.parse_freq_band(freq_band)
        return self.device_capabilities['interfaces']['max_channel_width'].get(freq_band)

    def get_max_channel_widths(self, return_type=dict):
        return self.parse_results(self.device_capabilities['interfaces']['max_channel_width'], return_type)

    def get_bhaul_sta_ifname(self, freq_band):
        freq_band = self.parse_freq_band(freq_band)
        return self.device_capabilities['interfaces']['backhaul_sta'].get(freq_band)

    def get_bhaul_sta_ifnames(self, return_type=dict, freq_band=''):
        freq_band = self.parse_freq_band(freq_band)
        return self.parse_results(self.device_capabilities['interfaces']['backhaul_sta'], return_type,
                                  freq_band=freq_band)

    def get_bhaul_ap_ifname(self, freq_band):
        freq_band = self.parse_freq_band(freq_band)
        return self.device_capabilities['interfaces']['backhaul_ap'].get(freq_band)

    def get_bhaul_ap_ifnames(self, return_type=dict, freq_band=''):
        freq_band = self.parse_freq_band(freq_band)
        return self.parse_results(self.device_capabilities['interfaces']['backhaul_ap'], return_type,
                                  freq_band=freq_band)

    def get_home_ap_ifname(self, freq_band):
        freq_band = self.parse_freq_band(freq_band)
        return self.device_capabilities['interfaces']['home_ap'].get(freq_band)

    def get_home_ap_ifnames(self, return_type=dict, freq_band=''):
        freq_band = self.parse_freq_band(freq_band)
        return self.parse_results(self.device_capabilities['interfaces']['home_ap'], return_type, freq_band=freq_band)

    def get_onboard_ap_ifname(self, freq_band):
        freq_band = self.parse_freq_band(freq_band)
        return self.device_capabilities['interfaces']['onboard_ap'].get(freq_band)

    def get_onboard_ap_ifnames(self, return_type=dict, freq_band=''):
        freq_band = self.parse_freq_band(freq_band)
        return self.parse_results(self.device_capabilities['interfaces']['onboard_ap'], return_type,
                                  freq_band=freq_band)

    def get_uplink_gre_ifname(self, freq_band):
        freq_band = self.parse_freq_band(freq_band)
        return self.device_capabilities['interfaces']['uplink_gre'].get(freq_band)

    def get_uplink_gre_ifnames(self, return_type=dict, freq_band=''):
        freq_band = self.parse_freq_band(freq_band)
        return self.parse_results(self.device_capabilities['interfaces']['uplink_gre'], return_type,
                                  freq_band=freq_band)

    def get_phy_radio_ifname(self, freq_band):
        freq_band = self.parse_freq_band(freq_band)
        return self.device_capabilities['interfaces']['phy_radio_name'].get(freq_band)

    def get_phy_radio_ifnames(self, return_type=dict, freq_band=''):
        freq_band = self.parse_freq_band(freq_band)
        return self.parse_results(self.device_capabilities['interfaces']['phy_radio_name'], return_type,
                                  freq_band=freq_band)

    def get_radio_antenna(self, freq_band):
        freq_band = self.parse_freq_band(freq_band)
        return self.device_capabilities['interfaces']['radio_antennas'].get(freq_band)

    def get_radio_antennas(self, return_type=dict):
        return self.parse_results(self.device_capabilities['interfaces']['radio_antennas'], return_type)

    def get_vif_radio_idx(self):
        return self.device_capabilities['interfaces']['vif_radio_idx']

    def get_supported_radio_channels(self, freq_band):
        freq_band = self.parse_freq_band(freq_band)
        return self.device_capabilities['interfaces']['radio_channels'].get(freq_band)

    def get_all_supported_channels(self, channel_type=int):
        radio_channels = self.device_capabilities['interfaces']['radio_channels']
        all_supported_channels = list()
        for channel_set in radio_channels.values():
            if not channel_set:
                continue
            all_supported_channels.extend(channel_set)
        # set expected channel var type
        all_supported_channels = [channel_type(channel) for channel in all_supported_channels]
        return all_supported_channels

    def get_lan_bridge_ifname(self):
        return self.device_capabilities['interfaces']['lan_bridge']

    def get_wan_bridge_ifname(self):
        return self.device_capabilities['interfaces']['wan_bridge']

    def get_primary_wan_iface(self):
        return self.device_capabilities['interfaces']['primary_wan_interface']

    def get_primary_lan_iface(self):
        return self.device_capabilities['interfaces']['primary_lan_interface']

    def get_lan_ifaces(self):
        return self.device_capabilities['interfaces']['lan_interfaces']

    def get_wan_ifaces(self):
        return self.device_capabilities['interfaces']['wan_interfaces']

    def get_patch_port_lan_to_wan_iface(self):
        return self.device_capabilities['interfaces']['patch_port_lan_to_wan']

    def get_patch_port_wan_to_lan_iface(self):
        return self.device_capabilities['interfaces']['patch_port_wan_to_lan']

    def get_wifi_index(self, freq_band):
        freq_band = self.parse_freq_band(freq_band)
        ifname = self.get_phy_radio_ifname(freq_band)
        assert ifname, f'can not describe wifi index for: {freq_band} band'
        return int(re.search(r'\d+', ifname).group())

    def get_wifi_indexes(self):
        ifnames = self.get_phy_radio_ifnames()
        wifi_indexes = dict()
        for freq_band, ifname in ifnames.items():
            wifi_indexes[freq_band] = int(re.search(r'\d+', ifname).group())
        return wifi_indexes

    def get_supported_bands(self):
        return self.device_capabilities['supported_bands']

    # MTU SECTION

    def get_bhaul_mtu(self):
        return self.device_capabilities['mtu']['backhaul']

    def get_uplink_gre_mtu(self):
        return self.device_capabilities['mtu']['uplink_gre']

    def get_wan_mtu(self):
        return self.device_capabilities['mtu']['wan']

    # KPI SECTION

    def get_boot_time_kpi(self):
        return self.device_capabilities['kpi']['boot_time']

    def get_bt_on_time_kpi(self):
        return self.device_capabilities['kpi']['bt_on_time']

    def get_cloud_gw_onboard_time_kpi(self):
        return self.device_capabilities['kpi']['cloud_gw_onboard_time']

    def get_cloud_leaf_onboard_time_kpi(self):
        return self.device_capabilities['kpi']['cloud_leaf_onboard_time']

    def get_cloud_location_onboard_time_kpi(self):
        return self.device_capabilities['kpi']['cloud_location_onboard_time']

    def get_network_cred_update_time_kpi(self):
        return self.device_capabilities['kpi']['network_credential_update']

    def get_sm_restart_time_kpi(self):
        return self.device_capabilities['kpi']['sm_restart']
