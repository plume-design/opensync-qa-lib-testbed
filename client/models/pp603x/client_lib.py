import time
from lib_testbed.generic.util.base_lib import Iface
from lib_testbed.generic.client.models.pp603x.client_tool import ClientTool
from lib_testbed.generic.client.models.pod.client_lib import ClientLib as ClientLibGeneric


class ClientLib(ClientLibGeneric):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.iface = ClientIface(lib=self)
        self.tool = ClientTool(lib=self)

    # TODO: Implement regular connect from generic library
    def connect_uci(self, ssid, psk, band, htmode="", hwmode="", bssid="", key_mgmt="sae", timeout=60, **kwargs):
        """
        Connect client to network by the uci configuration
        Args:
            ssid: (str) ssid
            psk: (str) psk
            band: (str) type of band: 2.4G, 5G, 6G
            htmode: (str) ht mode: 11A 11NA_HT20 11NA_HT40PLUS 11NA_HT40MINUS 11NA_HT40 11AC_VHT20 11AC_VHT40PLUS
                                   11AC_VHT40MINUS 11AC_VHT40 11AC_VHT80 11AC_VHT160 11AC_VHT80_80 11AXA_HE20
                                   11AXA_HE40PLUS 11AXA_HE40MINUS 11AXA_HE40 11AXA_HE80 11AXA_HE160 11AXA_HE80_80
            hwmode: (str) hw mode: 11g, 11a, 11ac, 11axg, 11axa,
            bssid: (str) bssid of target device
            key_mgmt: (str) key mgmt
            timeout: (int) timeout for connect client to network
            **kwargs:

        Returns: raw output from run commands

        """
        name = self.get_network_name()
        default_ssid, default_password = self.get_network(name)
        ssid = ssid if ssid else default_ssid
        psk = psk if psk else default_password

        if_name = self.iface.get_interface_from_band(band)
        match band:
            case "2.4G":
                interface_index = 1
            case "5G":
                interface_index = 0
            case "6G":
                interface_index = 2

        # TODO: 6G connection does not work
        connect_settings = (
            f"/etc/init.d/qca-wpa-supplicant boot; wifi unload; "
            f"wifi detect > /etc/config/wireless; "
            f"uci set wireless.@wifi-iface[{interface_index}].mode=sta; "
            f"uci set wireless.@wifi-iface[{interface_index}].ssid={ssid}; "
            f"uci set wireless.@wifi-iface[{interface_index}].key={psk}; "
            f"uci set wireless.@wifi-iface[{interface_index}].encryption={key_mgmt}; "
            f"uci set wireless.wifi{interface_index}.disabled=0; "
        )
        if bssid:
            connect_settings += f"uci set wireless.@wifi-iface[{interface_index}].bssid={bssid}; "
        if key_mgmt == "sae":
            connect_settings += (f"uci set wireless.@wifi-iface[{interface_index}].sae=1; "
                                 f"uci set wireless.@wifi-iface[{interface_index}].ieee80211w=2; ")
        if htmode:
            connect_settings += f"uci set wireless.wifi{interface_index}.htmode={htmode}; "
        if hwmode:
            connect_settings += f"uci set wireless.wifi{interface_index}.hwmode={hwmode}; "

        connect_settings += (
            f"uci commit wireless; "
            f"uci set network.lan=interface; "
            f"uci set network.lan.ifname={if_name}; "
            f"uci set network.lan.proto=dhcp; "
            f"uci commit network; "
            f"sleep 1; "
            f"/etc/init.d/network reload; "
        )

        wifi_down = self.run_command("wifi down", **kwargs)
        self.run_command("killall wpa_supplicant", skip_exception=True)
        connect = self.run_command(connect_settings, timeout=60)
        results = self.merge_result(wifi_down, connect)

        if not results[0]:
            # wait a few minutes for connect client to network
            time_to_wait = time.time() + timeout
            connection_status = None
            while time_to_wait > time.time():
                connection_status = self.ping_check(ipaddr="", count=3, fqdn_check=False, v6=False)
                if not connection_status[0]:
                    break
                time.sleep(5)
            return [0, "Client connected successfully", ""] if not connection_status[0] else connection_status
        return results

    def set_legacy_data_rate(self, ifname, rate, **kwargs):
        """
        Set legacy data rate
        Args:
            ifname: (str) name of interface
            rate: (int) rate in bytes

        Returns: raw output [ret, stdout, stderr] from run command

        """
        result = self.run_command(f"iwconfig {ifname} rate {rate}", **kwargs)
        return result

    def set_ht_data_rate(self, ifname, bw_index, mcs, **kwargs):
        """
        Set ht data rate
        Args:
            ifname: (str) name of interface
            bw_index: (int) bandwidth index
            mcs: (int) number of mcs

        Returns: raw output [ret, stdout, stderr] from run commands

        """
        ht_mcs = hex(128 + mcs)
        result = self.run_command(
            f"iwpriv {ifname} chwidth {bw_index}; " f"iwpriv {ifname} shortgi 0; " f"iwconfig {ifname} rate {ht_mcs}",
            **kwargs,
        )
        return result

    def set_vht_data_rate(self, ifname, bw_index, nss, mcs, **kwargs):
        """
        Set vht data rate
        Args:
            ifname: (str) name of interface
            bw_index: (int) bandwidth index
            nss: (int) number of nss
            mcs: (int) number of mcs

        Returns: raw output [ret, stdout, stderr] from run commands

        """
        result = self.run_command(
            f"iwpriv {ifname} nss {nss}; " f"iwpriv {ifname} chwidth {bw_index}; " f"iwpriv {ifname} vhtmcs {mcs}",
            **kwargs,
        )
        return result

    def get_frequency(self, ifname, **kwargs):
        """
        Provide operating frequency for client iface when connected to AP
        Args:
            ifname: (str) name of wlan interface

        Returns: (str) frequency in MHz

        """
        freq = None
        wifi_info = self.get_stdout(self.run_command(f"iwconfig {ifname}", **kwargs)).splitlines()
        for line in wifi_info:
            if "frequency:" in line.lower():
                freq = line.split(":")[1].strip()
                break

        return [0, freq, ""] if freq else [1, "", f"Frequency on {ifname} not found"]

    def set_tx_power(self, tx_power, ifname, **kwargs):
        """
        Set current Tx power in dBm
        Args:
            ifname: (str) Name of wireless interfaces
            tx_power: (int) Tx power in dBm.

        Returns:

        """
        response = self.run_command(f"iwconfig {ifname} txpower {tx_power}dbm", **kwargs)
        return response

    def get_tx_power(self, ifname, **kwargs):
        """
        Get current Tx power in dBm
        Args:
            ifname: (str) Wireless interface

        Returns: raw output [(int) ret, (std) std_out, (str) str_err]

        """
        cmd = "iwconfig %s | grep Tx-Power | awk '{print $4}'" % ifname
        response = self.strip_stdout_result(self.run_command(cmd, **kwargs))
        if not response[0]:
            response[1] = response[1].split(":")[-1] if ":" in response[1] else response[1].split("=")[-1]
        return response

    def get_max_tx_power(self, ifname, **kwargs):
        """
        Get max Tx power value from iwlist
        Args:
            ifname: (str) name of wifi interface
            **kwargs:

        Returns: (str) max Tx power [dBm]
        """
        # make sure that Tx power on client has a default value
        self.set_tx_power(0, ifname)
        time.sleep(5)
        response = self.strip_stdout_result(self.run_command(f"iwlist {ifname} txpower", **kwargs))
        if not response[0]:
            max_tx_power = response[1].split("\n")[-2]
            max_tx_power = max_tx_power.split()[0]
            response[1] = max_tx_power
        return response

    def get_min_tx_power(self, ifname, **kwargs):
        """
        Get max Tx power value from iwlist
        Args:
            ifname: (str) name of wifi interface
            **kwargs:

        Returns: (str) max Tx power [dBm]
        """
        self.set_tx_power(1, ifname)
        time.sleep(5)
        response = self.strip_stdout_result(self.run_command(f"iwlist {ifname} txpower", **kwargs))
        if not response[0]:
            # get second element of list because first element is a 0 dBm which restoring Tx power to default value
            max_tx_power = response[1].split("\n")[2]
            max_tx_power = max_tx_power.split()[0]
            response[1] = max_tx_power
        self.set_tx_power(0, ifname)
        return response

    def set_default_tx_power(self, ifname, **kwargs):
        """
        Set Tx power to default value
        Args:
            ifname: (str) Name of wireless interfaces
            **kwargs:

        Returns:

        """
        return self.set_tx_power(tx_power=0, ifname=ifname, **kwargs)

    # Specific fqdn_check implementation to avoid checking dig since the dig packet does not exist on pod devices
    def fqdn_check(self, count=1, v6=False, dns_address="www.google.com", **kwargs):
        dns_address = (
            self.config["wifi_check"]["dns_check"]
            if self.config.get("wifi_check", {}).get("dns_check")
            else dns_address
        )
        ping_ver = "ping6" if v6 else "ping"
        result = self.run_command(f"{ping_ver} -c {count} -t 200 -W 5 {dns_address}", **kwargs)
        # Clear stdout in case of error so that it doesn't get confused for success
        if result[0]:
            result[1] = ""
        return result

    # Skip this check since pod-client does not have namespace
    def check_wireless_client(self):
        return True

    def get_bit_rate(self, ifname, **kwargs):
        response = self.run_command(f"iwconfig {ifname} | grep 'Bit Rate' | awk '{{print $2}}'", **kwargs)
        return self.strip_stdout_result(response)


class ClientIface(Iface):
    ALLOWED_BANDS = ["2.4G", "5G", "6G"]

    @staticmethod
    def define_band_by_channel(channel, dut_band):
        if "2" in dut_band and channel in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]:
            return "2.4G"
        elif "5" in dut_band and channel in [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
                                             132, 136, 140, 144, 149, 153, 157, 161, 165]:
            return "5G"
        elif "6" in dut_band and channel in [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73,
                                             77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 129, 133, 137,
                                             141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189, 193, 197,
                                             201, 205, 209, 213, 217, 221, 225, 229, 233]:
            return "6G"
        assert False, f"Can not define band name for {channel} channel"

    @staticmethod
    def get_interface_from_band(band):
        """
        Get client interface name
        Args:
            band: (str) band name 2.4G, 5G or 6G

        Returns: (str) name of wireless interface

        """
        match band:
            case "2.4G":
                return "ath1"
            case "5G":
                return "ath0"
            case "6G":
                return "ath2"
            case "_":
                raise Exception("Incorrect band '%s' for PP603X device" % band)

    @staticmethod
    def get_wireless_ifaces():
        return ["ath1", "ath0", "ath2"]

