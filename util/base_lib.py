import pingparsing
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.ssh.ssh_execute import SshCmd


class BaseLib(SshCmd):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.main_object = self.is_main_object(kwargs["dev"])

    """Common methods for client and pod"""

    def is_uprise_location(self):
        return "UPRISE" in self.config.get("capabilities", [])

    @staticmethod
    def is_main_object(device_obj):
        return getattr(device_obj, "main_object", False)

    def shell_list(self, **_kwargs):
        """List all device(s) configured"""
        return [0, f"{self.name}", ""]

    def get_ip_address_ping_check(self, ipv6, ip_address_v4="8.8.8.8", ip_address_v6="2001:ee2:1704:9807::1"):
        # We use testbed-internal IPv6 address for now, because there is no testbed-external IPv6 address
        # that can be reached from both NAT66 and NAT64 testbeds at the moment and we don't support IPv6
        # on LTE yet.
        if ipv6:
            ip_address = (
                self.config["wifi_check"].get("ip_check_v6")
                if self.config.get("wifi_check", {}).get("ip_check_v6")
                else ip_address_v6
            )
        else:
            ip_address = (
                self.config["wifi_check"].get("ip_check")
                if self.config.get("wifi_check", {}).get("ip_check")
                else ip_address_v4
            )
        return ip_address

    def which_ping(self, v6):
        # We assume that pod user is able to run ping even if it is not root
        # Also treat error / empty output as running as root, because id command is missing on client pod
        root = self.device_type == "Nodes" or self.run_command("id -u", skip_exception=True)[1].strip() in ("0", "")
        ping_ver = "ping6" if v6 else "ping"
        return ping_ver if root else f"sudo {ping_ver}"

    def ping_check(self, ipaddr="", count=1, fqdn_check=False, v6=False, **kwargs):
        ip_address = ipaddr if ipaddr else self.get_ip_address_ping_check(ipv6=v6)
        ping_ver = self.which_ping(v6)
        rdns = kwargs.pop("rdns", None)
        if rdns is None:
            # Skip reverse DNS lookup when ip_address is an IPv4 or IPv6 address
            rdns = ":" not in ip_address and not ip_address.replace(".", "").isdecimal()
        rdns = "" if rdns else "-n"
        log.info(f"Sending {count} {ping_ver}(s) to {ip_address}")
        result = self.run_command(f"{ping_ver} -c {count} -t 200 -W 5 {rdns} {ip_address}", **kwargs)
        if result[0] == 0 and result[1]:
            ping_results = pingparsing.PingParsing().parse(result[1]).as_dict()
            packet_loss_rate = ping_results.get("packet_loss_rate")
            # ping check failed when reach more than 70% packet loss rate
            if packet_loss_rate and (packet_loss_rate > 70):
                result[2] = f"Ping check failed, ping packet loss over 70% ({packet_loss_rate}%)"
                result[0] = 1
            else:
                result[1] = "Ping check finished successfully"
        elif result[0]:
            stdout = result[1].strip()
            summary = "" if not stdout else stdout.splitlines()[-1]
            result[2] = f"Ping check failed: {result[2].strip()} {summary}"
        # For easier debugging check if client is able to resolve domain
        if fqdn_check:
            fqdn_result = self.fqdn_check(count=count, v6=v6, **kwargs)
            if fqdn_result[0]:
                fqdn_result[2] = f"FQDN check failed: {fqdn_result[2].strip()}"
            else:
                fqdn_result[1] = "FQDN check finished successfully"
            result = self.merge_result(result, fqdn_result)
        # Clear stdout in case of error so that it doesn't get confused for success
        if result[0]:
            result[1] = ""
        return result

    def get_kernel_release(self, **kwargs) -> list[int, str, str]:
        """Get kernel release"""
        return self.strip_stdout_result(self.run_command("uname -r", **kwargs))


class Iface:
    def __init__(self, lib):
        self.lib = lib

    def get_iface_ip(self, iface):
        response = self.lib.run_command(f"ip -f inet addr show {iface}")
        if response[0] != 0:
            raise Exception(f"Failed to execute cmd for iface: {iface}")
        iface_info = self.lib.get_stdout(response)
        if not iface_info or "not exist" in iface_info:
            raise ValueError(f"No IP address assigned to iface: {iface}")
        iface_addr = iface_info.splitlines()[1].split()[1].split("/")[0]
        return iface_addr

    def get_iface_ipv6(self, iface, scope="link", prefixlen=False, **kwargs):
        response = self.lib.run_command(f"ip -f inet6 addr show {iface}", **kwargs)
        if response[0] != 0:
            raise Exception(f"Failed to execute cmd for iface: {iface}")
        iface_info = self.lib.get_stdout(response)
        if not iface_info or "not exist" in iface_info or scope not in iface_info:
            raise ValueError(f"No ipv6 address assigned to iface: {iface}")
        iface_addr = None
        for line in iface_info.splitlines():
            if scope not in line:
                continue
            iface_addr = line.split()[1] if prefixlen else line.split()[1].split("/")[0]
            break
        return iface_addr

    def get_iface_by_mac(self, mac):
        response = self.lib.run_command(f"grep -ri {mac} /sys/class/net/**")
        if response[0] != 0:
            raise ValueError(f"Interface with mac: {mac} not found")
        return response[1].split("/sys/class/net/")[1].split("/")[0]

    def get_subnet_mask(self, iface):
        response = self.lib.run_command(f"ip -f inet addr show {iface}")
        if response[0] != 0:
            raise Exception(f"Failed to execute cmd for iface: {iface}")
        iface_info = self.lib.get_stdout(response)
        if not iface_info:
            raise ValueError(f"No IP address assigned to iface: {iface}")
        subnet_mask = iface_info.splitlines()[1].split()[1].split("/")[1]
        return subnet_mask

    def get_iface_by_mask(self, ip, prefix=24):
        assert prefix == 24  # TODO: handle other prefixes
        pattern = ip[0 : ip.rfind(".")]
        sudo = "sudo" if "Clients" == self.lib.device_type else ""
        response = self.lib.run_command(f"{sudo} ifconfig | grep {pattern} -B 1 | head -n1")
        if response[0] != 0 or not response[1]:
            raise Exception(f"Failed to resolve iface for ip: {pattern}")
        ifname = self.lib.get_stdout(response).split()[0].rstrip(":")
        return ifname

    def get_mac(self, ifname):
        result = self.lib.run_command(f"cat /sys/class/net/{ifname}/address")
        result = self.lib.strip_stdout_result(result)
        return self.lib.get_stdout(result)

    def get_wan_port(self) -> str:
        wan_port = self.lib.ovsdb.get_str(
            table="Connection_Manager_Uplink",
            select="if_name",
            where="is_used==true",
        )
        return wan_port
