import re
from lib_testbed.generic.client.models.generic.client_api import ClientApi as ClientApiGeneric


class ClientApi(ClientApiGeneric):
    def get_bit_rate(self, ifname, **kwargs):
        """
        Get bit rate
        Args:
            ifname:
            **kwargs:

        Returns:

        """
        result = self.lib.get_bit_rate(ifname=ifname, **kwargs)
        result = self.get_stdout(result, **kwargs)
        # get only digits
        bit_rate = re.search(r"\d+", result)
        return int(float(bit_rate.group())) if bit_rate else result

    def connect_uci(self, ssid, psk, band, htmode="", hwmode="", bssid="", key_mgmt="psk2", timeout=60, **kwargs):
        """
        Connect client to network by the uci configuration
        Args:
            ssid: (str) ssid
            psk: (str) psk
            band: (str) type of band
            htmode: (str) ht mode
            hwmode: (str) hw mode
            bssid: (str) bssid of target device
            key_mgmt: (str) key mgmt
            timeout: (int) timeout for connect client to network
            **kwargs:

        Returns: stdout from run commands

        """
        result = self.lib.connect_uci(ssid, psk, band, htmode, hwmode, bssid, key_mgmt, timeout, **kwargs)
        return self.get_stdout(result, **kwargs)

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

    def set_ht_data_rate(self, ifname, bw_index, mcs, **kwargs):
        """
        Set ht data rate
        Args:
            ifname: (str) name of interface
            bw_index: (int) bandwidth index
            mcs: (int) number of mcs

        Returns: stdout from run commands

        """
        result = self.lib.set_ht_data_rate(ifname, bw_index, mcs, **kwargs)
        return self.get_stdout(result, **kwargs)

    def set_vht_data_rate(self, ifname, bw_index, nss, mcs, **kwargs):
        """
        Set vht data rate
        Args:
            ifname: (str) name of interface
            bw_index: (int) bandwidth index
            nss: (int) number of nss
            mcs: (int) number of mcs

        Returns: stdout from run commands

        """
        result = self.lib.set_vht_data_rate(ifname, bw_index, nss, mcs, **kwargs)
        return self.get_stdout(result, **kwargs)

    def get_frequency(self, ifname="", **kwargs):
        """
        Provide operating frequency for client iface when connected to AP
        Args:
            ifname: (str) name of wlan interface

        Returns: (int) frequency in MHz

        """
        result = self.lib.get_frequency(ifname, **kwargs)
        return self.get_stdout(result, **kwargs)

    def set_tx_power(self, tx_power, ifname, **kwargs):
        """
        Set current Tx power in dBm
        Args:
            ifname: (str) Name of wireless interfaces
            tx_power: (int) Tx power in dBm.

        Returns:

        """
        result = self.lib.set_tx_power(tx_power, ifname, **kwargs)
        return self.get_stdout(result, **kwargs)

    def get_tx_power(self, ifname, **kwargs):
        """
        Get current Tx power in dBm
        Args:
            ifname: (str) Wireless interface

        Returns: (str) Tx power [dBm]

        """
        result = self.lib.get_tx_power(ifname, **kwargs)
        return self.get_stdout(result, **kwargs)

    def get_max_tx_power(self, ifname, **kwargs):
        """
        Get max Tx power value from iwlist
        Args:
            ifname: (str) name of wifi interface
            **kwargs:

        Returns: (str) max Tx power [dBm]
        """
        result = self.lib.get_max_tx_power(ifname, **kwargs)
        return self.get_stdout(result, **kwargs)

    def get_min_tx_power(self, ifname, **kwargs):
        """
        Get min Tx power value from iwlist
        Args:
            ifname: (str) name of wifi interface
            **kwargs:

        Returns: (str) min Tx power [dBm]
        """
        result = self.lib.get_min_tx_power(ifname, **kwargs)
        return self.get_stdout(result, **kwargs)

    def get_wifi_power_management(self, **kwargs):
        """Get wifi client power save state"""
        mode = None
        ifname = self.get_wlan_iface(**kwargs)
        if not ifname:
            return [1, mode, "No wlan interface"]
        result = self.run_command(f'iwconfig {ifname} | grep "Power Management"')
        if self.lib.result_ok(result):
            mode = self.lib.strip_stdout_result(result)[1].replace("Power Management:", "")
        return [0, mode, ""]

    def disconnect(self, **kwargs):
        """Connect client(s) to network with wpa_supplicant"""
        result = self.lib.disconnect(**kwargs)
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
