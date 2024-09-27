import os
import time
from datetime import datetime
from pathlib import Path
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.base_lib import Iface
from lib_testbed.generic.client.models.pod.client_tool import ClientTool
from lib_testbed.generic.client.models.generic.client_lib import ClientLib as ClientLibGeneric


class ClientLib(ClientLibGeneric):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.iface = ClientIface(lib=self)
        self.tool = ClientTool(lib=self)

    # TODO: Implement regular connect from generic library
    def connect_uci(self, ssid, psk, node_band, htmode="", hwmode="", bssid="", key_mgmt="psk2", timeout=60, **kwargs):
        """
        Connect client to network by the uci configuration
        Args:
            ssid: (str) ssid
            psk: (str) psk
            node_band: (str) type of band
            htmode: (str) ht mode
            hwmode: (str) hw mode
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

        if_name = self.iface.get_interface_from_band(node_band)
        interface_index = 0 if "2.4G" in node_band else 1
        connect_settings = (
            f"/etc/init.d/qca-wpa-supplicant boot; wifi unload; "
            f"wifi detect > /etc/config/wireless; "
            f"uci set wireless.@wifi-iface[{interface_index}].mode=sta; "
            f"uci set wireless.@wifi-iface[{interface_index}].ssid={ssid}; "
            f"uci set wireless.@wifi-iface[{interface_index}].key={psk}; "
            f"uci set wireless.@wifi-iface[{interface_index}].encryption={key_mgmt}; "
            f"uci set wireless.@wifi-iface[{interface_index}].bssid={bssid}; "
            f"uci set wireless.@wifi-iface[{interface_index}].cwmenable=0; "
            f"uci set wireless.@wifi-iface[{interface_index}].disablecoext=1; "
            f"uci set wireless.@wifi-iface[{interface_index}].short_preamble=1; "
            f"uci set wireless.wifi{interface_index}.disabled=0; "
            f"uci set wireless.wifi{interface_index}.htmode={htmode}; "
            f"uci set wireless.wifi{interface_index}.hwmode={hwmode}; "
            f"uci set wireless.wifi{interface_index}.ht_coex=1; "
            f"uci commit wireless; "
            f"uci set network.lan=interface; "
            f"uci set network.lan.ifname={if_name}; "
            f"uci set network.lan.proto=dhcp; "
            f"uci commit network; "
            f"sleep 1; "
            f"/etc/init.d/network reload; "
        )

        stats_cmd = (
            f"cfg80211tool wifi{interface_index} disablestats 0; "
            if interface_index == 0
            else f"cfg80211tool wifi{interface_index} enable_ol_stats 1"
        )
        connect_settings += stats_cmd

        wifi_down = self.run_command("wifi down", **kwargs)
        self.run_command("killall wpa_supplicant", skip_exception=True)
        connect = self.run_command(connect_settings, timeout=60)
        cfg80211tool_settings = self.run_command(
            f"cfg80211tool {if_name} cwmenable 0; cfg80211tool {if_name} powersave 0; "
            f"cfg80211tool {if_name} disablecoext 1"
        )
        results = self.merge_result(wifi_down, connect)
        results = self.merge_result(results, cfg80211tool_settings)

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

    def disconnect(self, **kwargs):
        """
        Push down wifi interfaces and reload config
        Returns: (list) raw output from command

        """
        results = self.run_command(
            "wifi down; rm -f /etc/config/wireless; wifi detect > /etc/config/wireless; /etc/init.d/network reload",
            **kwargs,
        )
        results[2] = "" if not results[0] else results[2]
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
            f"cfg80211tool {ifname} chwidth {bw_index}; "
            f"cfg80211tool {ifname} shortgi 0; "
            f"iwconfig {ifname} rate {ht_mcs}",
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
            f"cfg80211tool {ifname} nss {nss}; "
            f"cfg80211tool {ifname} chwidth {bw_index}; "
            f"cfg80211tool {ifname} vhtmcs {mcs}",
            **kwargs,
        )
        return result

    def restore_data_rates(self, **kwargs):
        results = [0, '', '']
        for iface in self.iface.get_wireless_ifaces():
            results = self.merge_result(results, self.run_command("iwconfig %s rate auto" % iface, **kwargs))
        return results

    def pod_to_client(self, **kwargs):
        """
        Change pod to client
        Returns:

        """
        # /etc/init.d/client script can break the BCM devices.
        # It's prevention of it, when client type is wrong filled
        bcm_platform = self.run_command("which wl", skip_exception=True)
        if not bcm_platform[0]:
            return [5, "", "Detected BCM driver. Update config with correct type of client"]
        check_script = self.run_command("ls /etc/init.d/ | grep client")
        if check_script[0]:
            log.info('Deploying "client" script to /etc/init.d/ directory')
            main_directory = Path(__file__).absolute().parents[0].as_posix()
            script_path = os.path.join(main_directory, "deploy", "client")
            self.put_file(script_path, "/etc/init.d/")
            self.run_command("chmod 755 /etc/init.d/client")
        self.run_command("/etc/init.d/client enable", **kwargs)
        self.run_command('echo "100.1.1 [$(cat /.version)]" > /.version')
        start_script = self.run_command("/etc/init.d/client start", **kwargs)
        # After run script wait until the device back
        timeout = time.time() + 180
        while timeout > time.time():
            # Set current date
            current_date = str(datetime.timestamp(datetime.now())).split(".")[0]
            response = self.run_command(f"date +%s -s @{current_date}")
            if not response[0]:
                break
            time.sleep(10)
        return start_script

    def client_to_pod(self, **kwargs):
        """
        Change client to pod
        Returns:

        """
        # /etc/init.d/client script can break the BCM devices.
        # It's prevention of it, when client type is wrong filled
        bcm_platform = self.run_command("which wl", skip_exception=True)
        if not bcm_platform[0]:
            return [5, "", "Detected BCM driver. Update config with correct type of client"]
        check_script = self.run_command("ls /etc/init.d/ | grep client")
        if check_script[0]:
            log.info('Deploying "client" script to /etc/init.d/ directory')
            main_directory = Path(__file__).absolute().parents[0].as_posix()
            script_path = os.path.join(main_directory, "deploy", "client")
            self.put_file(script_path, "/etc/init.d/")
            self.run_command("chmod 755 /etc/init.d/client")
        disable_script = self.run_command("/etc/init.d/client disable", **kwargs)
        stop_script = self.run_command("/etc/init.d/client stop", **kwargs)
        result = self.merge_result(disable_script, stop_script)
        # After stop script wait until the device back
        timeout = time.time() + 180
        while timeout > time.time():
            # Set current date
            current_date = str(datetime.timestamp(datetime.now())).split(".")[0]
            response = self.run_command(f"date +%s -s @{current_date}")
            if not response[0]:
                break
            time.sleep(10)
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
    ALLOWED_BANDS = ["2.4G", "5G"]

    @staticmethod
    def define_band_by_channel(channel, dut_band):
        if channel in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]:
            dut_band += ""
            return "2.4G"
        else:
            return "5G"

    @staticmethod
    def get_interface_from_band(band) -> str:
        """
        Get client interface name
        Args:
            band: (str) band name 2.4G or 5G

        Returns: (str) name of wireless interface

        """
        assert band in ClientIface.ALLOWED_BANDS, (
            f"Provided not supported band: {band}. " f"Allowed bands: {ClientIface.ALLOWED_BANDS}"
        )
        match band:
            case "2.4G":
                return "ath0"
            case "5G":
                return "ath1"

    @staticmethod
    def get_wireless_ifaces():
        return ["ath0", "ath1"]
