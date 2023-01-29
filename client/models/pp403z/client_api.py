from lib_testbed.generic.util.logger import log
from lib_testbed.generic.client.models.generic.client_api import ClientApi as ClientApiGeneric


class ClientApi(ClientApiGeneric):

    def connect(self, ssid=None, psk=None, bssid=None, band='24g', key_mgmt='WPA-PSK', timeout=60,
                dhclient=True, e_gl_param='', e_net_param='', country=None, proto='RSN', pmf_mode='enabled', **kwargs):
        """Connect [pod] client(s) to the network"""
        if country is None:
            if self.lib.config.get('loc_region'):
                country = self.lib.config.get('loc_region')
            else:
                log.warn("Country code not provided, using US")
                country = 'US'

        # there is no country code like EU, so we need to switch do DE
        country = 'DE' if country == 'EU' else country
        result = self.lib.connect(ssid=ssid, psk=psk, bssid=bssid, band=band, key_mgmt=key_mgmt, timeout=timeout,
                                  dhclient=dhclient, e_gl_param=e_gl_param, e_net_param=e_net_param, country=country,
                                  proto=proto, pmf_mode=pmf_mode, **kwargs)
        return self.get_stdout(result, **kwargs)

    def get_bit_rate(self, ifname, **kwargs):
        """
        Get bit rate
        Args:
            ifname:
            **kwargs:

        Returns:

        """
        result = self.lib.get_bit_rate(ifname=ifname, **kwargs)
        return int(float(self.get_stdout(result, **kwargs)))

    def set_legacy_data_rate(self, ifname, rate, **kwargs):
        """
        Set legacy data rate
        Args:
            ifname: (str) name of interface
            rate: (int) rate in bytes

        Returns: stdout from run commands

        """
        result = self.lib.set_legacy_data_rate(ifname, rate, **kwargs)
        return self.get_stdout(result, **kwargs)

    def set_ht_data_rate(self, ifname, bandwidth, mcs, **kwargs):
        """
        Set ht data rate
        Args:
            ifname: (str) name of interface
            bandwidth: (int) bandwidth Mhz
            mcs: (int) number of mcs

        Returns: stdout from run commands

        """
        result = self.lib.set_ht_data_rate(ifname, bandwidth, mcs, **kwargs)
        return self.get_stdout(result, **kwargs)

    def set_vht_data_rate(self, ifname, bandwidth, nss, mcs, **kwargs):
        """
        Set vht data rate
        Args:
            ifname: (str) name of interface
            bandwidth: (int) bandwidth Mhz
            nss: (int) number of nss
            mcs: (int) number of mcs

        Returns: stdout from run commands

        """
        result = self.lib.set_vht_data_rate(ifname, bandwidth, nss, mcs, **kwargs)
        return self.get_stdout(result, **kwargs)

    def get_tx_power(self, ifname, **kwargs):
        """
        Get current Tx power in dBm
        Args:
            ifname: (str) Wireless interface

        Returns: (str) Tx power [dBm]

        """
        result = self.lib.get_tx_power(ifname, **kwargs)
        std_out = self.get_stdout(result, **kwargs)
        return int(float(std_out))

    def get_max_tx_power(self, ifname='', **kwargs):
        """
        Get max Tx power value
        Args:
            **kwargs:

        Returns: (str) max Tx power [dBm]
        """
        result = self.lib.get_max_tx_power()
        return self.get_stdout(result, **kwargs)

    def get_min_tx_power(self, ifname='', **kwargs):
        """
        Get min Tx power value
        Args:
            **kwargs:

        Returns: (str) min Tx power [dBm]
        """
        result = self.lib.get_min_tx_power()
        return self.get_stdout(result, **kwargs)

    def set_default_tx_power(self, ifname, **kwargs):
        """
        Set Tx power to default value
        Args:
            ifname: (str) Name of wireless interfaces
            **kwargs:

        Returns:

        """
        result = self.lib.set_default_tx_power(ifname=ifname, **kwargs)
        return self.get_stdout(result, **kwargs)

    def restore_data_rates(self, **kwargs):
        """
        Restore data rates to default values
        Args:
            **kwargs:

        Returns:

        """
        result = self.lib.restore_data_rates(**kwargs)
        return self.get_stdout(result, **kwargs)
