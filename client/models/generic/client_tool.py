from typing import TYPE_CHECKING, Literal

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.pod.pod import Pod
from lib_testbed.generic.util import config


class ClientTool:
    def __init__(self, lib):
        self.lib = lib
        if TYPE_CHECKING:
            from lib_testbed.generic.client.models.generic.client_lib import ClientLib

            self.lib = ClientLib()

    def get_name(self):
        return self.lib.get_name()

    def list(self, **kwargs):
        """List all configured clients"""
        return self.lib.shell_list(**kwargs)

    def run(self, command, *args, **kwargs):
        """Run a command

        :return: list of stdout"""
        result = self.lib.run_command(command, *args, retry=False, **kwargs)
        return self.lib.strip_stdout_result(result)

    def ssh(self, params="", **kwargs):
        """Start interactive ssh session"""
        return self.lib.ssh(params, retry=False, **kwargs)

    def info(self):
        """Pretty client(s) information string

        Prints out information about configured clients, their architecture
        wlan capabilities, macs bluetooth capabilities, driver information"""
        response = self.lib.info(retry=False)
        info = response[1]
        if not info:
            return [response[0], "", "No output from tb script"]

        info_txt = f'architecture: {info["arch"]}\n'
        info_txt += f'client model: {info["client_model"]}\n'
        info_txt += f'os: {info["os"]}\n'
        info_txt += f'version: {info["version"]}\n'
        if "chariot" in info:
            info_txt += f'chariot: {info["chariot"]}\n'
        if "eth" in info:
            for eth, einfo in info["eth"].items():
                info_txt += f"eth: {eth}\n"
                if "ip" in einfo:
                    info_txt += f' {eth} ip: {einfo["ip"]}\n'
                info_txt += f' {eth} mac: {einfo["mac"]}\n'
        if "wlan" in info:
            for wlan, winfo in info["wlan"].items():
                info_txt += f"wifi: {wlan}\n"
                info_txt += f" model: {self.lib.get_wlan_model(retry=False)}\n"
                if "driver" in winfo:
                    info_txt += f' {wlan} driver: {winfo["driver"]}\n'
                info_txt += f' {wlan} mac: {winfo["mac"]}\n'
                info_txt += " support:\n"
                info_txt += f'  802.11ac = {winfo["802.11ac"]}\n'
                info_txt += f'  802.11ax = {winfo["802.11ax"]}\n'
                info_txt += f'  802.11ax (6E) = {winfo["6e"]}\n'
        if "bt" in info:
            for bt, info in info["bt"].items():
                info_txt += f"bt: {bt}\n"
                if "name" in info:
                    info_txt += f' {bt} name: {info["name"]}\n'
                info_txt += f' {bt} addr: {info["addr"]}\n'
        return [response[0], info_txt, response[2]]

    def reboot(self, **kwargs):
        """Reboot"""
        return self.lib.reboot(retry=False, **kwargs)

    def ping(self, host=None, **kwargs):
        """Single ping

        Prints out the result"""
        return self.lib.ping(host, retry=False, **kwargs)

    def uptime(self, **kwargs):
        """Uptime"""
        return self.lib.uptime(out_format="user", retry=False, **kwargs)

    def version(self, short=False, **kwargs):
        """Display FW ver on the device"""
        return self.lib.version(short, retry=False, **kwargs)

    def deploy(self, **kwargs):
        """Deploy files to client(s)

        Files from lib_testbed/generic/client/models/generic/deploy are to
        be deployed to client.
        """
        return self.lib.deploy(**kwargs)

    def ep(self, command, **kwargs):
        """<stop|start|restart> Control IxChariot endpoint on client(s)"""
        if command not in ("stop", "start", "restart"):
            raise ValueError("Wrong parameter value")
        return self.lib.run_command(f"{self.lib.get_tool_path()}/wifi endpoint {command}", retry=False, **kwargs)

    def wifi_winfo(self, ifname="", **kwargs):
        """Display client(s) wireless information

        The information includes connected status, rates, signal strength, etc."""
        return self.lib.wifi_winfo(ifname, retry=False, **kwargs)

    def ping_check(self, ipaddr="", count=1, fqdn_check=False, v6=False, **kwargs):
        """Check client(s) wireless connectivity (ICMP).

        Returns the information if ping command finished successfully
        (exit code 0)"""
        return self.lib.ping_check(count=count, fqdn_check=fqdn_check, v6=v6, ipaddr=ipaddr, retry=False, **kwargs)

    def wifi_monitor(self, channel, ht="HT20", ifname="", band="5G", **kwargs):
        """Set interface into monitor mode"""
        return self.lib.wifi_monitor(channel, ht, ifname, band, **kwargs)

    def wifi_station(self, ifname="", **kwargs):
        """Set interface into station mode"""
        return self.lib.wifi_station(ifname, **kwargs)

    def get_ifaces(self, **kwargs):
        """List all client interfaces"""
        interface = self.lib.join_ifaces(retry=False, **kwargs).split(",")[0]
        if not interface:
            response = [1, "", "No interface found"]
        else:
            response = [0, interface, ""]
        return response

    def put_file(self, file_name, location, **kwargs):
        """Copy a file/directory to device

        Uses scp to copy files"""
        return self.lib.put_file(file_name, location, **kwargs)

    def get_file(self, remote_file, location, **kwargs):
        """Copy a file/directory from device

        Uses scp to copy files
        """
        return self.lib.get_file(remote_file, location, **kwargs)

    def eth_connect(
        self, pod_or_port, ifname=None, dhclient=True, ipv4=True, ipv6=False, ipv6_stateless=False, timeout=20, **kwargs
    ):
        """Connect Ethernet client to specified pod or switch port alias."""
        if "_" in pod_or_port:
            pod_name = pod_or_port.split("_")[0]
            port_alias = pod_or_port
        else:
            pod_name = pod_or_port
            port_alias = None
        kwargs = {"config": self.lib.config, "multi_obj": False, "nickname": pod_name}
        pod_obj = Pod(**kwargs)
        pod = pod_obj.resolve_obj(**kwargs)
        return self.lib.eth_connect(
            pod,
            port_alias=port_alias,
            ifname=ifname,
            dhclient=dhclient,
            ipv4=ipv4,
            ipv6=ipv6,
            ipv6_stateless=ipv6_stateless,
            timeout=timeout,
            **kwargs,
        )

    def eth_disconnect(self, ifname=None, disable_unused_ports=True, **kwargs):
        """Disconnect client from all Ethernet pod ports."""
        return self.lib.eth_disconnect(ifname, disable_unused_ports=disable_unused_ports, **kwargs)

    def connect(
        self,
        ssid=None,
        psk=None,
        ifname=None,
        bssid=None,
        key_mgmt=None,
        timeout=30,
        dhclient=True,
        country="US",
        ipv4=True,
        ipv6=False,
        ipv6_stateless=False,
        wps=False,
        eap=None,
        identity=None,
        password=None,
        global_params=None,
        net_params=None,
        node_name=None,
        node_band=None,
        **kwargs,
    ):
        """Connect Wi-Fi client(s) to the network

        Available optional arguments:
        ssid: network SSID, if not specified used from tesbed config
        psk: network password, if not specified used from testbed config
        ifname: client Wi-Fi interface name, if not specified used the first interface founded in the system
        bssid: specific BSSID, where you want to associate
        key_mgmt: wpa_supplicant key management: WPA-PSK, WPA-EAP, FT-PSK, FT-EAP, SAE, ... or NONE for open network
        timeout: association timeout
        dhclient: (True/False) start dhclient after successful association
        country: client country code
        ipv4 (bool) get IPv4 address
        ipv6 (bool) get IPv6 address
        ipv6_stateless (bool) IPv6 stateless mode
        wps (bool) connect using WPS-PBC
        eap (str): which enterprise authentication method to use (e.g. PEAP, TTLS, PWD, ...).
        identity (str): user name or id used for EAP authentication.
        password (str): password used for EAP authentication.
        global_params: extra wpa_supplicant config global parameters
        net_params: extra wpa_supplicant config network parameters
        node_name: testbed node name to associate with (requires cloud access)
        node_band: testbed node band to associate with (requires cloud access, e.g.: 2.4G, 5G, 5GL, 5GU, 6G)
        """

        def _get_bssid_from_node_name():
            if bssid:
                log.warning("BSSID already specified, ignoring node name argument")
                return bssid

            node_id = None
            for node in self.lib.config.get("Nodes"):
                if node["name"] != node_name:
                    continue
                node_id = node["id"]
                break
            if not node_id:
                log.warning(
                    f"Requested node name {node_name} not found in the testbed config," f" ignoring node name argument"
                )
                return

            # as HW related tools loads only location config, we need to load deployment
            loc_deployment = config.get_deployment(self.lib.config)
            deployment_cfg = config.load_file(config.find_deployment_file(loc_deployment))
            self.lib.config.update(deployment_cfg)

            try:
                from lib.cloud.custbase import CustBase

                custbase = CustBase(self.lib.config)
            except ModuleNotFoundError:
                log.warning("Custbase module not found, ignoring node_name argument")
                return
            custbase.initialize()
            node_bssids = custbase.get_node_home_ap_bssids(node_id=node_id, group_into=dict)
            if node_band and node_band in node_bssids:
                return node_bssids[node_band]
            # get the fastest band or the closest one to requested (5G -> 5GL/5GU)
            _node_band = node_band[0] if node_band else node_band
            for band_name in ["6G", "5GU", "5GL", "5G", "2.4G"]:
                if not _node_band and band_name in node_bssids:
                    return node_bssids[band_name]
                if _node_band and _node_band in band_name and band_name in node_bssids:
                    return node_bssids[band_name]
            log.warning(f"No BSSID found for requested {band_name}")

        key_mgmt = [m.strip() for m in key_mgmt.split(",")] if key_mgmt else None
        e_gl_param = global_params.replace(":", "=") if global_params else ""
        e_net_param = net_params.replace(":", "=") if net_params else ""

        if node_band and not node_name:
            return [71, "", f"Node name not specified, while node band is set to {node_band}"]

        # get node bssid from the cloud
        if node_name:
            bssid = _get_bssid_from_node_name()

        return self.lib.connect(
            ssid,
            psk,
            ifname=ifname,
            bssid=bssid,
            key_mgmt=key_mgmt,
            timeout=timeout,
            dhclient=dhclient,
            country=country,
            ipv4=ipv4,
            ipv6=ipv6,
            ipv6_stateless=ipv6_stateless,
            wps=wps,
            eap=eap,
            identity=identity,
            password=password,
            e_gl_param=e_gl_param,
            e_net_param=e_net_param,
            **kwargs,
        )

    def disconnect(self, ifname=None, **kwargs):
        """Disconnect WiFi client(s)"""
        return self.lib.disconnect(ifname, retry=False, **kwargs)

    def scan(self, ifname="", params="", **kwargs):
        """Trigger a scan on the client"""
        return self.lib.scan(ifname, params, retry=False, **kwargs)

    def start_dhcp_client(self, ifname, cf=None, ipv4=True, ipv6=False, ipv6_stateless=False, **kwargs):
        """Starts dhcp client on Wi-Fi iface"""
        return self.lib.start_dhcp_client(ifname, cf=cf, ipv4=ipv4, ipv6=ipv6, ipv6_stateless=ipv6_stateless, **kwargs)

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
        **kwargs,
    ):
        """(Re)start dhclient on the interface"""
        ret = self.lib.refresh_ip_address(
            iface, ipv4, ipv6, ipv6_stateless, timeout, reuse, static_ip, clear_dhcp, **kwargs
        )
        if ret[0]:
            return ret
        # success output is empty, so lets get the ip
        return [0, str(self.lib.get_client_ips(iface, **kwargs)), ""]

    def get_mac(self, ifname="", **kwargs):
        """Get Wi-Fi MAC address"""
        return self.lib.get_mac(ifname, retry=False, **kwargs)

    def get_region(self, **kwargs):
        """Get client region code"""
        return self.lib.get_region(retry=False, **kwargs)

    def set_region(self, region, **kwargs):
        """Set regional domain (EU, US, UK, CA, JP, KR, PH)"""
        raise NotImplementedError("Set region domain is not supported")

    def pod_to_client(self, **kwargs):
        """Change pod to client.

        This is only possible for a specific clients."""
        return self.lib.pod_to_client(**kwargs)

    def client_to_pod(self, **kwargs):
        """Change client to pod

        This is only possible for a specific clients."""
        return self.lib.client_to_pod(**kwargs)

    def create_ap(self, channel, ifname="", ssid="test", extra_param="", timeout=120, dhcp=False, **kwargs):
        """Start hostapd on the client. Make sure to stop it at the end."""
        return self.lib.create_ap(int(channel), ifname, ssid, extra_param, int(timeout), dhcp, **kwargs)

    def disable_ap(self, ifname="", **kwargs):
        """Stop hostapd on the client"""
        return self.lib.disable_ap(ifname, **kwargs)

    def get_target_version(self, version: Literal["stable", "latest"]) -> str:
        """Retrieves the actual version for client from artifactory for specified "stable" or "latest"."""
        return self.lib.get_target_version(version=version)

    def upgrade(self, fw_path=None, restore_cfg=True, force=False, version=None, restore_files=None, **kwargs):
        """Upgrade device with FW from fw_path or download build version from the artifactory

        You can also pick FW version based on the latest or stable release."""
        results = self.lib.upgrade(fw_path, restore_cfg, force, version=version, **kwargs)
        return results

    def set_tb_nat(self, mode, **kwargs):
        """Set testbed's IPv6 NAT mode (NAT64 or NAT66)"""
        return self.lib.set_tb_nat(mode, **kwargs)

    def get_tb_nat(self, **kwargs):
        """Get testbed's IPv6 NAT mode (NAT64 or NAT66)"""
        return self.lib.get_tb_nat(**kwargs)

    def testbed_dhcp_reservation(self, **kwargs):
        """Create dhcp reservation for testbed devices"""
        return self.lib.testbed_dhcp_reservation(**kwargs)

    def limit_tx_power(self, state=True, value=None, **kwargs):
        """Limit Wi-Fi Tx power on the devices in the testbed"""
        return self.lib.limit_tx_power(state, value, **kwargs)

    def start_simulate_client(
        self, device_to_simulate, ifname="", ssid=None, psk=None, bssid=None, fake_mac=None, force=False
    ):
        """Start simulate device type. To list available devices use "adt-list-devices" command."""
        try:
            from lib.cloud.custbase import CustBase
            from lib.cloud.userbase import UserBase
        except (ImportError, ModuleNotFoundError) as err:
            return [1, "", err]

        custbase = CustBase(name="admin", role="admin", config=self.lib.config)
        userbase = UserBase(name="user", role="user", conf=self.lib.config)
        custbase.ub, userbase.cb = userbase, custbase
        custbase.initialize(), userbase.initialize()

        return self.lib.start_simulate_client(
            device_to_simulate,
            ifname=ifname,
            ssid=ssid,
            psk=psk,
            bssid=bssid,
            fake_mac=fake_mac,
            force=force,
            custbase=custbase,
            userbase=userbase,
        )

    def clear_adt(self, ifname="", **kwargs):
        """Clear client after finish simulate."""
        return self.lib.clear_adt(ifname, **kwargs)

    def get_clients_to_simulate(self):
        """Get available devices to simulate."""
        return self.lib.get_clients_to_simulate()

    def check_hackrf_status(self, **kwargs):
        """Check if HackRF is installed and connected."""
        return self.lib.check_hackrf_status(**kwargs)

    def hackrf_generate_radar_pulse(self, channel, region="us", vector=0, **kwargs):
        """Generate radar pulse with HackRF radio."""
        return self.lib.hackrf_generate_radar_pulse(channel, region, vector, **kwargs)

    def start_local_mqtt_broker(self, **kwargs):
        """Start local mqtt broker on the rpi-server."""
        return self.lib.start_mqtt_broker(**kwargs)

    def stop_local_mqtt_broker(self, **kwargs):
        """Stop local mqtt broker on the rpi-server."""
        return self.lib.stop_mqtt_broker(**kwargs)

    def get_temperature(self, **kwargs):
        """Get temperature from client device."""
        temp = self.lib.get_temperature(retry=False, **kwargs)
        stdout = self.lib.get_stdout(temp, **kwargs)
        if stdout:
            stdout = int(int(stdout) / 1000)
        response = [0, str(stdout), ""]
        return response

    def mocha_enable(self):
        """Client automatically connects to ap and periodically generates traffic (mocha mode)."""
        output = self.lib.mocha_enable()
        return output

    def mocha_disable(self):
        """Disables mocha mode."""
        output = self.lib.mocha_disable()
        return output

    def get_ssh_login_logs(self, last_hours: int = 1, max_lines_to_print: int = 100, **kwargs) -> list:
        """Get SSH login logs."""
        return self.lib.get_ssh_login_logs(last_hours, max_lines_to_print, **kwargs)
