import re
import time
from collections import ChainMap
from functools import partial
from typing import List
from time import sleep
from ipaddress import IPv4Network

from lib_testbed.generic.util.common import wait_for
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.client.models.generic.client_lib import ClientLib as ClientLibGeneric
from lib_testbed.generic.client.models.windows.client_tool import ClientTool
from lib_testbed.generic.util.base_lib import Iface


class ClientLib(ClientLibGeneric):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.tool = ClientTool(lib=self)
        self.iface = ClientIface(lib=self)

    def ping(self, host=None, v6=False, **kwargs):
        ip_ver = "-6" if v6 else "-4"
        if not host:
            host = self.device.get_ip()
        cmd = f"ping {ip_ver} -n 1 -w 1000 {host}"
        result = self.strip_stdout_result(self.run_command(cmd, **kwargs))
        return result

    def uptime(self, out_format="user", **kwargs):
        if out_format == "user":
            cmd = "(get-date) - (gcim Win32_OperatingSystem).LastBootUpTime"
        elif out_format == "timestamp":
            cmd = "[DateTimeOffset]::Now.ToUnixTimeSeconds()"

        result = self.run_command(cmd, **kwargs)
        return self.strip_stdout_result(result)

    def version(self, short=False, **kwargs):
        """Get Windows version"""
        if short:
            cmd = 'systeminfo /fo csv | ConvertFrom-Csv | select "OS Version" | Format-List'
        else:
            cmd = "systeminfo /fo csv | ConvertFrom-Csv | select OS*, System*, Hotfix* | Format-List"
        result = self.run_command(cmd, **kwargs)

        return self.strip_stdout_result(result)

    def deploy(self, **kwargs):
        # Not needed?
        return [1, "", "Not implemented on Windows"]

    def hw_info(self, **kwargs):
        """Get client hardware info"""
        cmd = "(Get-ComputerInfo)"
        model_name = f"{cmd}.CsProcessors.Name"
        model = f"{cmd}.CsModel"
        machine = f"{cmd}.CsSystemSKUNumber"

        result = (
            f"model_name: {self.run_command(model_name, **kwargs)[1]}; "
            f"Model: {self.run_command(model, **kwargs)[1]}; "
            f"machine: {self.run_command(machine, **kwargs)[1]}"
        )
        return [0, result, ""]

    def get_wifi_power_management(self, **kwargs):
        # TODO: Find a way to detect this parameter using PowerShell CMD
        # Get-NetAdapterPowerManagement -Name "Wi-Fi" does not prints parametes related to wifi power management
        return [0, "off", ""]

    def set_wifi_power_management(self, state, **kwargs):
        # TODO: get_wifi_power_management
        return [0, "ok", ""]

    def reboot(self, **kwargs):
        cmd = "Restart-Computer -Force"
        result = self.run_command(cmd, **kwargs)
        return result

    def info(self, **kwargs):
        """
        Display all client(s) information

        Returns: (list) [[(int) ret, (dict) stdout, (str) stderr]]

        """
        arch_info = self.get_stdout(self.get_architecture(**kwargs))
        eth_info = self.get_stdout(self.get_eth_info(**kwargs), skip_exception=True)
        wlan_info = self.get_stdout(self.get_wlan_information(**kwargs), skip_exception=True)
        bt_info = self.get_stdout(self.get_bt_info(**kwargs), skip_exception=True)
        name = self.get_stdout(self.strip_stdout_result(self.run_command("hostname")), skip_exception=True)
        os_info = {"os": "Windows"}
        hostname = {"hostname": name}
        all_info = dict(ChainMap(arch_info, eth_info, wlan_info, bt_info, os_info, hostname.copy()))
        return [0, all_info.copy(), ""]

    def get_architecture(self, **kwargs):
        """
        ARM CPUs are not supported on Windows
        """
        return [0, {"arch": "x86"}, ""]

    def check_chariot(self, **kwargs):
        """
        Chariot is not supported for Windows

        """

        return [1, "", "Chariot is not supported for Windows"]

    def get_eth_info(self, timeout=5, **kwargs):
        """
        Get information from eth interface
        Args:
            timeout: (int) timeout to wait for an dhcp
            **kwargs:

        Returns: (list) [[(int) ret, (dict) stdout, (str) stderr]]
        (dict) stdout: {'eth': {'eth_iface': {'mac': (str) mac_address, 'ip': (str) ip_address}}}

        """

        eth_info = {"eth": {}}
        for iface_alias in self.get_eth_iface(force=True):
            get_ip_cmd = f'(Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "{iface_alias}").IPAddress'
            eth_info["eth"][iface_alias] = {"eth": "true"}
            eth_info["eth"][iface_alias]["mac"] = self.get_mac(iface_alias)[1]
            interface_status = self.get_stdout(
                self.strip_stdout_result(self.run_command(f'"(Get-NetAdapter -Name "{iface_alias}").Status"', **kwargs))
            )
            if "Up" in interface_status:
                self.refresh_ip_address(iface=iface_alias, timeout=timeout, **kwargs)
            eth_info["eth"][iface_alias]["ip"] = self.get_stdout(
                self.strip_stdout_result(self.run_command(get_ip_cmd, **kwargs))
            )

            return [0, eth_info, ""]

    @staticmethod
    def get_iw_supported_commands(iw_info):
        # get supported commands:
        return [1, "", "iw is not supported on Windows"]

    @staticmethod
    def get_iw_supported_modes(iw_info):
        return [1, "", "iw is not supported on Windows"]

    @staticmethod
    def get_iw_supported_ciphers(iw_info):
        return [1, "", "iw is not supported on Windows"]

    def get_wlan_information(self, **kwargs):
        """
        Get information from wlan interface
        Args:
            **kwargs:

        Returns: (list) [[(int) ret, (dict) stdout, (str) stderr]]
        (dict) stdout {'wlan': {'ifname': {'driver': (str) driver_name, 'mac': (str) (mac_addr), 'phy': (str) phy
        , 'FT': (bool) state, 'channels': (list)(int),'ip': (str) ip_address}}}
        """

        iface_alias = self.get_wlan_iface()

        get_wlan_driver_info_cmd = (
            f'Get-NetAdapter -Name "{iface_alias}" | '
            f"Select Name, DriverDescription, DriverVersion, DriverDate, DriverProvider"
        )
        get_ip_cmd = f'(Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "{iface_alias}").IPAddress'
        get_802_11ac_support_cmd = (
            f'(Get-NetAdapterAdvancedProperty -Name "{iface_alias}" ' f"-RegistryKeyword IEEE11nMode).RegistryValue"
        )

        is_802_11ac_supported = (
            self.get_stdout(self.strip_stdout_result(self.run_command(get_802_11ac_support_cmd, **kwargs))) == "2"
        )

        wlan_info = {
            "wlan": {
                iface_alias: {
                    "driver": self.get_stdout(self.strip_stdout_result(self.run_command(get_wlan_driver_info_cmd))),
                    "mac": self.get_mac(iface_alias)[1],
                    "phy": "phy object is not available on Windows OS",
                    "FT": "iw is not available on Windows OS",
                    "channels": ["Getting supported WiFi channels is not available on Windows OS"],
                    "ip": self.get_stdout(self.strip_stdout_result(self.run_command(get_ip_cmd))),
                    "wifi": True,
                    "monitor": bool,  # Cannot get info from Windows CLI
                    "wpa3": bool,  # Cannot get infro from Windows CLI
                    "802.11ac": is_802_11ac_supported,
                }
            }
        }

        return [0, wlan_info.copy(), ""]

    def get_bt_info(self, **kwargs):
        """
        Get bluetooth information
        Args:
            **kwargs:

        Returns:

        """
        get_bt_if_name_cmd = '(Get-NetAdapter).Name | Select-String -Pattern "Blue"'
        bt_alias = self.get_stdout(
            self.strip_stdout_result(self.run_command(get_bt_if_name_cmd, **kwargs)), skip_exception=True
        )

        get_bt_if_addr_cmd = f'(Get-NetAdapter -Name "{bt_alias}").MacAddress'

        bt_addr = self.get_stdout(
            self.strip_stdout_result(self.run_command(get_bt_if_addr_cmd, **kwargs)), skip_exception=True
        )

        bt_info = {"bt": {bt_alias: {"name": bt_alias, "bt": any(bt_addr), "addr": bt_addr}}}

        return [0, bt_info.copy(), ""]

    def prepare_bt(self, iface=None, **kwargs):
        raise NotImplementedError

    def get_wlan_iface(self, **kwargs) -> str:
        """
        Get all WLAN interfaces, if force=True get interface name directly from device
        Returns: (list) interfaces

        """
        force = kwargs.pop("force", False)

        if hasattr(self, "wlan_iface") and not force:
            iface = self.wlan_iface
        else:
            primary_wifi_iface_details = self.iface.get_primary_wifi_iface_details()
            self.wlan_iface = iface = primary_wifi_iface_details["name"]

        return iface

    def get_eth_iface(self, **kwargs) -> List[str]:
        """
        Get all eth interfaces if force=True get interface name directly from device
        Returns: (list) interfaces

        """
        force = kwargs.pop("force", False)
        cmd_get_eth_interfaces = '(Get-NetAdapter).Name | Select-String -Pattern "Eth"'

        if hasattr(self, "eth_iface") and not force:
            iface = self.eth_iface
        else:
            iface = self.get_stdout(self.strip_stdout_result(self.run_command(cmd_get_eth_interfaces, **kwargs)))
            self.eth_iface = iface

        return iface

    def join_ifaces(self, **kwargs):
        wlan_interface = self.get_wlan_iface(**kwargs)
        eth_interface = self.get_eth_iface(**kwargs)

        interface = wlan_interface + eth_interface

        return interface

    def eth_connect(
        self, pod, port_alias=None, ifname=None, dhclient=True, ipv4=True, ipv6=False, ipv6_stateless=False, **kwargs
    ):
        """
        Connect Ethernet client to specified pod and optional switch port_alias.

        Args:
            pod: (pod_api) pod object to connect to
            port_alias: (str) name of pod port to connect to
            ifname: (str) interface name
            dhclient: (bool) if True, start dhcp client after establishing connection
            ipv4 (bool) get IPv4 address
            ipv6 (bool) get IPv6 address
            ipv6_stateless (bool) IPv6 stateless mode

        Returns: (list) Merged sub-command results triple
        """
        result = self._check_eth_connect_parameters(ifname)
        if len(result) == 3:
            return result
        ifname, _ = result
        pod_name = pod.get_nickname()
        unused_ports = self.switch.get_unused_pod_ports(pod_name)
        if not unused_ports:
            return [4, "", f"pod '{pod_name}' has no free ports left"]
        if port_alias is None:
            port_alias = unused_ports[0]
        if port_alias not in unused_ports:
            return [5, "", f"'{port_alias}' port alias doesn't exist or is already in use"]
        result = self.eth_disconnect(ifname, keep_down=True, **kwargs)
        if result[0]:
            return result
        pod.wait_eth_connection_ready()
        port = self.switch.connect_eth_client(pod_name, self.get_nickname(), port_alias)
        result = self.run_command(f'Enable-NetAdapter -Name "{ifname}"', **kwargs)
        if result[0]:
            return result
        result = [0, f"connected to '{port}'", ""]
        if dhclient:
            dhcp_result = self.start_dhcp_client(ifname, ipv4=ipv4, ipv6=ipv6, ipv6_stateless=ipv6_stateless, **kwargs)
            result = self.merge_result(result, dhcp_result)
        return result

    def eth_disconnect(self, ifname=None, keep_down=False, **kwargs):
        """
        Disconnect client from all pod Ethernet ports.

        Args:
            ifname: (str) interface name
            keep_down: (bool) (internal) keep interface down after disconnecting

        Returns: (list) Merged sub-command results triple
        """
        result = self._check_eth_connect_parameters(ifname)
        if len(result) == 3:
            return result
        ifname, my_blackhole_vlan = result
        res1 = self.stop_dhcp_client(ifname, clear_cache=True, **kwargs)
        res2 = self.run_command(f'Disable-NetAdapter -Name "{ifname}"', **kwargs)
        self.switch.disconnect_all_pods_from_client_vlan(my_blackhole_vlan)
        result = self.merge_result(res1, res2)
        # Testebed ethernet clients are expected to have their interface up and IPv4 dhclient running.
        if not keep_down:
            self.run_command(f"sudo ip link set {ifname} up", skip_exception=True)
            self.start_dhcp_client(ifname, clear_dhcp=False, skip_exception=True)
        return result

    def refresh_ip_address(
        self,
        iface=None,
        ipv4=True,
        ipv6=False,
        ipv6_stateless=False,
        timeout=20,
        reuse=False,
        static_ip=None,
        clear_dhcp=True,
        reuse_only=False,
        **kwargs,
    ):
        """
        Refresh ip_address.
        Args:
            iface: (str) name of interface
            ipv4 (bool) get IPv4 address
            ipv6 (bool) get IPv6 address
            ipv6_stateless (bool) IPv6 stateful/stateless mode
            timeout (int) how long to wait for dhclient to start (in seconds)
            reuse (bool) If true, restarts dhclient with existing dhclient arguments
            reuse_only (bool) If true, aborts in case dhclient is not already running
            static_ip (str) If specified, use this static IP address instead of starting dhclient
            clear_dhcp (bool) If true stop dhcp client before refresh IP address
            **kwargs:

        Returns: (ret_val, std_out, str_err)

        """
        result = self._check_dhclient_parameters(iface, ipv4, ipv6, ipv6_stateless)
        if len(result) == 3:
            return result
        iface, ipv4, ipv6, ipv6_stateless = result

        if static_ip:
            return self.set_ip_address(static_ip, iface=iface)
        else:
            return self.dhcp_renew(iface)

    def start_dhcp_client(
        self, ifname, cf=None, ipv4=True, ipv6=False, ipv6_stateless=False, timeout=20, clear_dhcp=True, **kwargs
    ):
        """
        Start dhcp client on network interface
        Args:
            ifname: (str) network interface name
            cf: (str) contents of custom config file for dhclient
            ipv4 (bool) get IPv4 address
            ipv6 (bool) get IPv6 address
            ipv6_stateless (bool) IPv6 stateful/stateless mode
            timeout (int) how long to wait for dhclient to start (in seconds)
            clear_dhcp (bool) If true, stop dhcp client before starting it

        Returns: (list) clients response
        """
        result = self._check_dhclient_parameters(ifname, ipv4, ipv6, ipv6_stateless)
        if len(result) == 3:
            return result
        ifname, ipv4, ipv6, ipv6_stateless = result

        if clear_dhcp:
            self.stop_dhcp_client(ifname, clear_cache=True)

        out = [0, "", ""]

        cmd = f"Set-NetIPInterface -InterfaceAlias {ifname} -AddressFamily"

        if ipv4:
            cmd += " IPv4"
        if ipv6:
            cmd += " IPv6"

        ret = self.run_command(cmd, **kwargs)

        if ipv4:
            ipv4_granted = wait_for(partial(self.get_ip_address, ifname, "IPv4"), timeout=timeout + 20, tick=1.0)[0]
            if not ipv4_granted:
                ret[2] = "Unable to get IPv4"
            else:
                log.info("IPv4 received from DHCP server")

            out = self.merge_result(out, ret)

        if ipv6:
            ipv6_granted = wait_for(partial(self.get_ip_address, ifname, "IPv6"), timeout=timeout + 20, tick=1.0)[0]
            if not ipv6_granted:
                ret[2] = "Unable to get IPv6"
            else:
                log.info("IPv6 reveived from DHCP server")

            out = self.merge_result(out, ret)

        return out

    def stop_dhcp_client(self, ifname, clear_cache=False, **kwargs):
        log.info("Stopping old dhclient instances")
        self.run_command(f"sudo dhclient -4 -r {ifname}", **kwargs)
        self.run_command(f"sudo dhclient -6 -r {ifname}", **kwargs)
        self.run_command(f"sudo ip addr flush {ifname} scope global", **kwargs)
        command = (
            f"sudo ps aux | grep /var/run/dhclient.{ifname}.pid | grep -v grep | awk '{{print $2}}' | "
            f"xargs sudo kill"
        )
        self.run_command(command, **kwargs)
        command = (
            f"sudo ps aux | grep /var/run/dhclient6.{ifname}.pid | grep -v grep | awk '{{print $2}}' | "
            f"xargs sudo kill"
        )
        self.run_command(command, **kwargs)
        if clear_cache:
            # clear cached DHCP leases
            self.run_command(f"""sudo rm -f /var/lib/dhcp/dhclient*.{ifname}.leases""", **kwargs)
            # and "cached" DNS nameservers
            self.run_command('''sudo sh -c "echo '' > /etc/resolv.conf"''', **kwargs)
        sleep(1.2)

        # since we kill all types, we could have false negative responses, so returning 0
        return [0, "", ""]

    def set_ip_address(self, ip, netmask="255.255.255.0", iface=None, **kwargs):
        prefix_len = IPv4Network(f"{ip}/{netmask}").prefixlen
        cmd = f"Set-NetIPAddress -InterfaceName {iface} -IPAddress {ip} -PrefixLength {prefix_len}"
        return self.run_command(cmd, **kwargs)

    def dhcp_renew(self, iface):
        dhcp_renew_cmd = f"ipconfig /renew '{iface}'"
        return self.run_command(dhcp_renew_cmd)

    def get_mac(self, ifname="", **kwargs):
        get_mac_cmd = f'(Get-NetAdapter -Name "{ifname}").MacAddress'
        result = self.strip_stdout_result(self.run_command(get_mac_cmd, **kwargs))
        result[1] = result[1].replace("-", ":")

        if not result[0] and not getattr(self, f"{ifname}_mac", False):
            setattr(self, f"{ifname}_mac", result[1])

        return result

    def set_mac(self, interface, new_mac, **kwargs):
        cmd = f"Set-NetAdapter -Name {interface} -MacAddress {new_mac}"
        return self.strip_stdout_result(self.run_command(cmd, **kwargs))

    def get_region(self, **kwargs):
        return [1, "", "Getting WiFi region is on possible on Windows OS"]

    def upgrade(self, fw_path=None, restore_cfg=True, force=False, http_address="", **kwargs):
        return [1, "", "Cannot upgrade machine with Windows OS"]

    def change_driver_settings(self, ifname, settings, **kwargs):
        return [1, "", "Cannot change driver settings on Windows OS"]

    def get_ip_address(self, iface_alias: str, ip_version: str):
        """
        Args:
            iface_alias: (str) name of network interface
            ip_version: (str) IPv4 or IPv6
        """
        cmd = f'(Get-NetIPAddress -AddressFamily {ip_version} -InterfaceAlias "{iface_alias}").IPAddress'
        output = self.get_stdout(self.strip_stdout_result(self.run_command(cmd)))
        return output

    def connect(
        self,
        ssid=None,
        psk=None,
        ifname=None,
        bssid=None,
        key_mgmt=None,
        timeout=60,
        dhclient=True,
        e_gl_param="",
        e_net_param="",
        country="US",
        ipv4=True,
        ipv6=False,
        ipv6_stateless=False,
        wps=False,
        proto="RSN",
        pmf_mode="enabled",
        retry=3,
        **kwargs,
    ):
        """
        Connect client(s) to network starting own wpa_supplicant
        Args:
            ssid: ssid
            psk: password
            ifname: interface name
            bssid: bssid if needed
            key_mgmt: WPA-PSK, FT-PSK or NONE for open network
            timeout: timeout for connecting to network
            dhclient: start dhcp client after association
            e_gl_param: extra wpa_supplicant global parameters separated with ','
            e_net_param: extra wpa_supplicant network parameters separated with ','
            country: force regulatory domain for desired country; default country is US
            ipv4 (bool) get IPv4 address
            ipv6 (bool) get IPv6 address
            ipv6_stateless (bool) IPv6 stateless mode
            wps (bool) connect using WPS-PBC
            proto (str)
            pmf_mode (str): Used only in case connection with SAE, WPA-PSK-SHA256
            retry (int) number of connect retries in case of wifi driver crash on the client
            **kwargs:

        Returns: (list) merged clients response

        """
        if ssid is None:
            name = self.get_network_name()
            ssid, _ = self.get_network(name)

        if psk is None:
            name = self.get_network_name()
            _, psk = self.get_network(name)

        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)
        if not ifname:
            return [1, "", "Missing wlan interface"]

        self.run_command(f'Enable-NetAdapter -Name "{ifname}"')
        key_mgmt = self._define_wifi_key_mgmt(key_mgmt=key_mgmt, ssid=ssid)
        log.info(
            f"Connect clients {self.device.name} iface: {ifname} to ssid: {ssid}, bssid: {bssid}, "
            f"key mgmt: {key_mgmt}"
        )

        self._create_windows_wifi_profile(ssid, psk, key_mgmt)

        output = self._connect_to_wlan(ssid)
        log.info("Waiting for connection established")
        if not wait_for(partial(self._is_wifi_connected), 60, 5.0)[0]:
            return [1, "", "Client is not connected to WiFi"]

        if bssid:
            output = self.connect_client_to_expected_bssid(ssid=ssid, bssid=bssid)

        if not wait_for(partial(self._is_gateway_reachable, ifname), 60, 5.0)[0]:
            return [1, "", "Default gateway is not reachable"]

        return output

    def connect_client_to_expected_bssid(self, ssid: str, bssid: str):
        self.run_command(f'WifiInfoView.exe /ConnectAP "{ssid}" "{bssid}"; sleep 15', timeout=60)
        current_bssid = self.get_client_bssid()
        if current_bssid == bssid:
            return [0, f"Client has been connected to expected bssid: {bssid}", ""]
        return [1, "", f"Client was not connected to expected bssid: {bssid}. Current assoc bssid: {current_bssid}"]

    def _is_gateway_reachable(self, ifname):
        gateway_ip = self._get_ipv4_gateway(ifname)
        cmd = f"(Get-NetNeighbor -IPAddress {gateway_ip}).State"
        stdout = self.strip_stdout_result(self.run_command(cmd))[1]

        if stdout == "Reachable":
            return True
        else:
            return False

    def _get_ipv4_gateway(self, ifname):
        cmd = (
            f'Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ifAlias "{ifname}" | '
            f'Select-Object -ExpandProperty "NextHop"'
        )
        return self.strip_stdout_result(self.run_command(cmd))[1]

    def _create_windows_wifi_profile(self, ssid, psk, key_mgmt: str = None):
        # Remove all existed windows network profiles to be sure the client won't be associated to wrong network.
        self.run_command("netsh wlan delete profile name=* i=*")
        cmd = (
            f'$PW = ConvertTo-SecureString "{psk}" -AsPlainText -Force; '
            f"Set-WiFiProfile -ProfileName {ssid} -ConnectionMode auto "
            f"-Password $PW -Encryption AES"
        )
        if key_mgmt:
            cmd += f" -Authentication {key_mgmt} "
        self.run_command(cmd)

    def _define_wifi_key_mgmt(self, key_mgmt: str, ssid: str) -> str:
        if not key_mgmt:
            key_mgmt = self._get_used_wpa_mode(ssid=ssid)
            assert key_mgmt, f"Can not define WPA-MODE for provided network: {ssid}"
        key_mgmt = self._parse_key_mgmt_to_proper_authentication(key_mgmt)
        return key_mgmt

    def _get_used_wpa_mode(self, ssid: str, timeout: int = 60) -> str | None:
        wpa_mode = None
        encoding_fix = False
        time_to_wait = timeout + time.time()
        while time_to_wait > time.time():
            self.run_command("Search-WiFiNetwork")
            scan_result = self.run_command(
                "Get-WiFiAvailableNetwork | Format-Table -AutoSize | Out-String -Width 10000"
            )
            if isinstance(scan_result[1], bytes) and not encoding_fix:
                log.warning("Powershell encoding issue detected. Forcing encoding to UTF-8...")
                self._change_powershell_encoding()
                encoding_fix = True
                time_to_wait = timeout + time.time()
                continue
            scan_result = self.strip_stdout_result(scan_result)
            for line in scan_result[1].splitlines():
                if ssid not in line:
                    continue
                if wpa_mode := re.search(r"AUTH_.([^\s]+)", line):
                    wpa_mode = wpa_mode.group()
                    break
            if wpa_mode:
                break
        return wpa_mode

    def disconnect(self, ifname=None, **kwargs):
        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)
        if not ifname:
            return [1, "", "Missing wlan interface"]

        self.run_command("netsh wlan delete profile name=* i=*")
        cmd = f'netsh wlan disconnect interface="{ifname}"'

        return self.strip_stdout_result(self.run_command(cmd))

    def _connect_to_wlan(self, ssid):
        cmd = f"Connect-WiFiProfile -ProfileName {ssid}"
        output = self.strip_stdout_result(self.run_command(cmd))
        return output

    @staticmethod
    def _parse_key_mgmt_to_proper_authentication(key_mgmt):
        if "SAE" in key_mgmt:
            parameter = "WPA3SAE"
        elif "WPA-PSK" in key_mgmt or "RSNA_PSK" in key_mgmt:
            parameter = "WPA2PSK"
        elif "FT-PSK" in key_mgmt:
            parameter = "WPA2"  # Not sure about this
        else:
            parameter = "open"
        return parameter

    def _is_wifi_connected(self) -> bool:
        wifi_iface_details = self.iface.get_primary_wifi_iface_details()
        return wifi_iface_details["state"] == "connected"

    def make_dir(self, path, **kwargs):
        path = path.replace("/", "\\")
        response = self.run_command(f'mkdir "{path}"')
        return response

    def remove_dir(self, path, **kwargs):
        path = path.replace("/", "\\")
        response = self.run_command(f'if exist "{path}" rmdir "{path}" /q /s')
        return response

    def remove_file(self, path, **kwargs):
        path = path.replace("/", "\\")
        response = self.run_command(f'if exist "{path}" del "{path}" /q /s')
        return response

    def list_files(self, path, **kwargs):
        path = path.replace("/", "\\")
        response = self.run_command(f'dir /b /s "{path}"', **kwargs)
        if response[0]:
            response[2] = f"{response[1]}\n{response[2]}"
            response[1] == ""
        response[1].replace("\r\n", "\n")
        return response

    @property
    def current_time(self):
        cmd = 'Get-Date -Format "HH:mm"'
        output = self.run_command(cmd)
        return self.strip_stdout_result(output)[1]

    def wifi_winfo(self, ifname, **kwargs):
        ifname = ifname if ifname else self.get_wlan_iface()
        if not ifname:
            return [1, "", "Missing wlan interface"]
        return self.run_command(f"netsh wlan show interfaces {ifname}", **kwargs)

    def strip_stdout_result(self, result):
        stdout = result[1]
        if stdout:
            stdout = stdout.strip("\r\n").strip()
            result[1] = stdout
        return result

    def get_client_bssid(self) -> str:
        wifi_info = self.wifi_winfo(self.get_wlan_iface())[1]
        if client_bssid := re.search(r"(?<=BSSID ).+", wifi_info):
            client_bssid = re.search("(?<=: ).+(?=\r)", client_bssid.group())
        if not client_bssid:
            return "unknown"
        return client_bssid.group()

    def _change_powershell_encoding(self):
        """Force change powershell encoding to be able to use unicodes."""
        # Set UTF-8 for powershell profile
        self.run_command(
            "'$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = "
            "New-Object System.Text.UTF8Encoding' + [Environment]::Newline + "
            "(Get-Content -Raw $PROFILE -ErrorAction SilentlyContinue) | Set-Content -Encoding utf8 $PROFILE"
        )
        # Set UTF-8 encoding in registry
        self.run_command("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage /t REG_SZ /v ACP /d 65001 /f")
        self.run_command(
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage /t REG_SZ /v OEMCP /d 65001 /f"
        )
        self.run_command(
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage /t REG_SZ /v MACCP /d 65001 /f"
        )
        self.run_command("shutdown /r")
        # Wait for reboot
        wait_for(lambda: self.uptime(retry=False, skip_logging=True)[0], timeout=120, tick=10)
        self.wait_available(timeout=120)


class ClientIface(Iface):
    def get_wifi_interfaces(self) -> list:
        all_wifi_interfaces = self.lib.get_stdout(
            self.lib.strip_stdout_result(self.lib.run_command("netsh wlan show interfaces"))
        ).split("\r\n\r\n")
        parsed_wifi_interfaces = list()
        keys_to_parse = ["name", "type", "state"]
        for interface_details in all_wifi_interfaces:
            if "Name" not in interface_details:
                continue
            parsed_interface_details = dict()
            for key_to_parse in keys_to_parse:
                for interface_entry in interface_details.splitlines():
                    if key_to_parse in interface_entry.lower():
                        if parsed_value := re.search(r"(?<=: ).*", interface_entry):
                            parsed_interface_details[key_to_parse] = parsed_value.group()
                        break
            parsed_wifi_interfaces.append(parsed_interface_details)

        return parsed_wifi_interfaces

    def get_primary_wifi_iface_details(self) -> dict:
        all_wifi_interfaces = self.get_wifi_interfaces()
        primary_wifi_iface = next(
            filter(lambda wifi_iface: (wifi_iface["type"] == "Primary"), all_wifi_interfaces), None
        )
        if not primary_wifi_iface:
            raise Exception(f"Not found any primary Wi-F interface. All Wi-Fi interfaces:\n{all_wifi_interfaces}")
        return primary_wifi_iface
