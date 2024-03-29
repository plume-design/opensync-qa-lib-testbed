import os
import re
import time
import random
import tempfile
from typing import Tuple, Dict, Union, List

import requests
import importlib
import functools

from collections import ChainMap
from datetime import datetime
from multiprocessing import Lock
from distutils.version import StrictVersion
from pathlib import Path

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.client.client_base import ClientBase
from lib_testbed.generic.util.common import CACHE_DIR
from lib_testbed.generic.client.models.generic.client_tool import ClientTool
from lib_testbed.generic.switch.switch_api_resolver import SwitchApiResolver
from lib_testbed.generic.util.base_lib import Iface
from lib_testbed.generic.util.config import FIXED_HOST_CLIENTS

UPGRADE_DIR = "/tmp/automation/"
UPGRADE_LOCAL_CACHE_DIR = CACHE_DIR / "client_upgrade_cache"
KERNEL_DIR = "/home/plume/kernel-packages/"


class ClientLib(ClientBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.iface = ClientIface(lib=self)
        self.tool = ClientTool(lib=self)

    @functools.cached_property
    def switch(self):
        return SwitchApiResolver(config=self.config)

    @functools.cached_property
    def key_mgmt(self):
        """Determine default WPA key management protocols for client"""
        if runtime_wpa_mode := self.config.get("runtime_wpa_mode"):
            if runtime_wpa_mode in ("psk2", "psk-mixed"):
                return "WPA-PSK"
            if runtime_wpa_mode == "sae":
                return "SAE"
            # Fallback to default key_mgmt selection for "sae-mixed" mode
        client_capab = self.get_wlan_information()[1]
        client_wpa3_capab = client_capab["wlan"][self.wlan_iface].get("wpa3", False)
        return ["SAE", "WPA-PSK"] if client_wpa3_capab else "WPA-PSK"

    def ping(self, host=None, v6=False, **kwargs):
        ping = self.which_ping(v6)
        if host:
            cmd = f"{ping} -c 1 -w 1 {host}"
            result = self.run_command(cmd, **kwargs)
        else:
            cmd = self.device.get_last_hop_cmd(f"{ping} -c1 -w1 {self.device.get_ip()}")
            result = self.run_command(cmd, skip_remote=True, **kwargs)
        return self.strip_stdout_result(result)

    def uptime(self, out_format="user", **kwargs):
        """Display uptime of client(s)"""
        if out_format == "user":
            result = self.run_command("uptime", **kwargs)
        elif out_format == "timestamp":
            result = self.run_command("cat /proc/uptime", **kwargs)
            if result[0] == 0:
                result[1] = result[1].split()[0].strip()
        else:
            return [1, "", f"Unsupported format {out_format}"]
        return self.strip_stdout_result(result)

    def version(self, short=False, **kwargs):
        """Get client image version"""
        result = self.run_command("cat /.version", **kwargs)
        if short and result[0] == 0:
            version = re.search(r"(\d+\.\d+[-,.]\d+)", result[1]).group()
            result[1] = version
        return self.strip_stdout_result(result)

    def deploy(self, **kwargs):
        param_to = self.get_tool_path()
        base_dir = Path(__file__).absolute().parents[0].as_posix()
        deploy_from = os.path.join(base_dir, "deploy")
        command = f"sudo mkdir -p {param_to}; sudo chown -R plume:plume {param_to}"
        response = self.run_command(command, **kwargs)
        assert self.result_ok(response)
        return self.put_file(file_name=f"{deploy_from}/*", location=param_to, **kwargs)

    def hw_info(self, **kwargs):
        """Get client hardware info"""
        result = self.run_command("cat /proc/cpuinfo", **kwargs)
        gen_info = self.strip_stdout_result(result)
        ret = ""
        for info in ["Hardware", "Revision", "Model", "model name", "machine"]:
            for line in gen_info[1].split("\n"):
                row = line.split(":")
                if info not in row[0].strip():
                    continue
                ret += f"{info.replace(' ', '_')}: {row[1].strip()}; "
                break
        # skip last "; "
        return [0, ret[:-2], ""]

    def get_wifi_power_management(self, **kwargs):
        """Get Wi-Fi client power save state"""
        mode = None
        ifname = self.get_wlan_iface(**kwargs)
        if not ifname:
            return [1, mode, "No wlan interface"]
        result = self.run_command(f'sudo iwconfig {ifname} | grep "Power Management"')
        if self.result_ok(result):
            mode = self.strip_stdout_result(result)[1].replace("Power Management:", "")
        return [0, mode, ""]

    def set_wifi_power_management(self, state, **kwargs):
        """Get Wi-Fi client power save state"""
        log.info(f"Set Wi-Fi power save: {state}")
        ifname = self.get_wlan_iface(**kwargs)
        if not ifname:
            return [1, "", "No wlan interface"]
        cmd = f"sudo iwconfig {ifname} power {state}"
        result = self.run_command(cmd)
        if result[0] and self.check_driver_crash():
            result = self.run_command(cmd)
        return result

    def reboot(self, **kwargs):
        """Reboot client(s)"""
        result = self.run_command("sudo reboot", **kwargs)
        # Change ret val from 255 to 0 due to lost connection after reboot.
        if result[0] == 255:
            result[0] = 0
        return result

    def put_dir(self, directory, location, timeout=5 * 60, **kwargs):
        as_sudo = kwargs.pop("as_sudo", True)
        as_sudo = "sudo" if as_sudo else ""
        command = (
            f"cd {directory}; tar -cf - *  |"
            + self.device.get_remote_cmd(f"{as_sudo} mkdir -p {location}; cd {location}; {as_sudo} tar -xof -")
            + " 2>/dev/null"
        )
        return self.run_command(command, **kwargs, timeout=timeout, skip_remote=True)

    def info(self, **kwargs):
        """
        Display all client(s) information

        Returns: (list) [[(int) ret, (dict) stdout, (str) stderr]]

        """
        arch_info = self.get_stdout(self.get_architecture(**kwargs))
        image_version = {"version": self.get_stdout(self.version(**kwargs))}
        client_model = {"client_model": self.get_client_model(**kwargs)}
        chariot_info = self.get_stdout(self.check_chariot(**kwargs))
        eth_info = self.get_stdout(self.get_eth_info(**kwargs), skip_exception=True)
        wlan_info = self.get_stdout(self.get_wlan_information(**kwargs), skip_exception=True)
        bt_info = self.get_stdout(self.get_bt_info(**kwargs), skip_exception=True)
        name = self.get_stdout(self.strip_stdout_result(self.run_command("hostname")), skip_exception=True)
        os_info = {"os": "Linux"}
        hostname = {"hostname": name}
        all_info = dict(
            ChainMap(
                arch_info,
                image_version,
                client_model,
                chariot_info,
                eth_info,
                wlan_info,
                bt_info,
                os_info,
                hostname.copy(),
            )
        )
        return [0, all_info.copy(), ""]

    def get_architecture(self, **kwargs):
        """
        Get type of architecture on client
        Args:
            **kwargs:

        Returns: (list) [[(int) ret, (dict) stdout, (str) stderr]]
        (dict) stdout: {'arch': (str) architecture'}

        """
        result = self.strip_stdout_result(self.run_command("uname -a", **kwargs))
        arch = self.get_stdout(result, skip_exception=True)
        architecture = dict()
        if "x86" in arch:
            architecture["arch"] = "x86"
        elif "arm" in arch:
            architecture["arch"] = "arm"
        else:
            architecture["arch"] = "unknown"
        return [0, architecture.copy(), ""]

    def check_chariot(self, **kwargs):
        """
        Get chariot status on client
        Returns:  (list) [[(int) ret, (dict) stdout, (str) stderr]]
        (dict) stdout: {'chariot': (bool) State}

        """
        result = self.strip_stdout_result(self.run_command("ps -ax | grep endpoin", **kwargs))
        status = self.get_stdout(result, skip_exception=True)
        chariot = dict()
        chariot["chariot"] = True if "endpoint" in status else False
        return [0, chariot.copy(), ""]

    def get_eth_info(self, timeout=20, **kwargs):
        """
        Get information from eth interface
        Args:
            timeout: (int) timeout to wait for dhcp
            **kwargs:

        Returns: (list) [[(int) ret, (dict) stdout, (str) stderr]]
        (dict) stdout: {'eth': {'eth_iface': {'mac': (str) mac_address, 'ip': (str) ip_address}}}

        """
        ifaces = self.get_stdout(
            self.strip_stdout_result(self.run_command("ls /sys/class/net | grep -e et -e en", **kwargs)),
            skip_exception=True,
        )
        eth_info = {"eth": {}}
        if not ifaces:
            return [0, eth_info, ""]
        ifaces = ifaces.strip("\nlo")
        for iface in ifaces.split("\n"):
            # our eth clients uses only tagged ifaces, so analyze only those with . in name, otherwise we will
            # restart dhcp clients for mgmt iface
            if "." not in iface:
                continue
            eth_info["eth"][iface] = {"eth": "true"}
            # get MAC address
            eth_info["eth"][iface]["mac"] = self.get_stdout(
                self.strip_stdout_result(self.run_command(f"cat /sys/class/net/{iface}/address", **kwargs))
            )
            # refresh IP if iface is up and get IP address
            up = self.get_stdout(self.strip_stdout_result(self.run_command(f"ip add show dev {iface}", **kwargs)))
            if "state UP" in up:
                self.refresh_ip_address(iface=iface, timeout=timeout, **kwargs)
                try:
                    eth_info["eth"][iface]["ip"] = self.iface.get_iface_ip(iface)
                except Exception:
                    pass
        return [0, eth_info.copy(), ""]

    @staticmethod
    def get_iw_supported_commands(iw_info):
        # get supported commands:
        iw_cmd = iw_info.split("Supported commands:")
        if len(iw_cmd) < 2:
            return []
        iw_cmd = iw_cmd[1]
        supported_cmd = []
        for line in iw_cmd.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("*"):
                break
            supported_cmd.append(line[2:])
        return supported_cmd

    @staticmethod
    def get_iw_supported_modes(iw_info):
        iw_out = iw_info.split("Supported interface modes:")
        if len(iw_out) < 2:
            return []
        iw_out = iw_out[1]
        supported_modes = []
        for line in iw_out.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("*"):
                break
            supported_modes.append(line[2:])
        return supported_modes

    @staticmethod
    def get_iw_supported_ciphers(iw_info):
        iw_out = iw_info.split("Supported Ciphers:")
        if len(iw_out) < 2:
            return []
        iw_out = iw_out[1]
        supported_ciphers = []
        for line in iw_out.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("*"):
                break
            supported_ciphers.append(line[2:])
        return supported_ciphers

    def get_wlan_information(self, **kwargs):
        """
        Get information from wlan interface
        Args:
            **kwargs:

        Returns: (list) [[(int) ret, (dict) stdout, (str) stderr]]
        (dict) stdout {'wlan': {'ifname': {'driver': (str) driver_name, 'mac': (str) (mac_addr), 'phy': (str) phy
        , 'FT': (bool) state, 'channels': (list)(int),'ip': (str) ip_address}}}

        """
        wlan_info = {"wlan": {}}
        output = [0, wlan_info, ""]
        # dev_ifaces = self.get_stdout(self.strip_stdout_result(self.run_command('ls /sys/class/net', **kwargs)))
        # iface = [dev_iface for dev_iface in dev_ifaces.split() if dev_iface != 'lo']
        iface = self.get_wlan_iface()
        if self.run_command(f"test -d /sys/class/net/{iface}/phy80211")[0] != 0:
            return output
        wlan_info["wlan"][iface] = {"wifi": "true"}
        # get Wi-Fi driver
        driver = self.get_stdout(
            self.strip_stdout_result(self.run_command(f"ls -ll  /sys/class/net/{iface}/device/driver"))
        )
        wlan_info["wlan"][iface]["driver"] = driver.split("/")[-1]
        # get MAC address
        wlan_info["wlan"][iface]["mac"] = self.get_stdout(
            self.strip_stdout_result(self.run_command(f"cat /sys/class/net/{iface}/address"))
        )
        # get phy index
        phy = self.get_stdout(self.strip_stdout_result(self.run_command(f"cat /sys/class/net/{iface}/phy80211/index")))
        wlan_info["wlan"][iface]["phy"] = f"phy{phy}"
        iw_info = self.get_stdout(self.strip_stdout_result(self.run_command(f"sudo iw phy{phy} info", **kwargs)))
        supported_cmd = self.get_iw_supported_commands(iw_info)
        ft_cmd = ["authenticate", "associate", "deauthenticate", "disassociate"]
        wlan_info["wlan"][iface]["FT"] = set(ft_cmd).issubset(set(supported_cmd))
        # get supported interface modes
        supported_modes = self.get_iw_supported_modes(iw_info)
        if "monitor" in supported_modes:
            wlan_info["wlan"][iface]["monitor"] = True
        # get supported ciphers
        supported_ciphers = self.get_iw_supported_ciphers(iw_info)
        if "GCMP-128 (00-0f-ac:8)" in supported_ciphers:
            wlan_info["wlan"][iface]["wpa3"] = True
        # get Wi-Fi channels
        bands = iw_info.split("Frequencies:")[1:]
        channels = []
        for band in bands:
            for line in band.split("\n"):
                if "DFS" in line:
                    continue
                if "MHz" in line and "disabled" not in line:
                    try:
                        channels.append(int(line[line.find("[") + 1 : line.find("]")]))
                    except ValueError:
                        pass
                if line and "*" not in line:
                    break
        wlan_info["wlan"][iface]["channels"] = channels
        # check if 11ac.ax.6e
        wlan_info["wlan"][iface]["802.11ac"] = False
        if "VHT" in iw_info:
            wlan_info["wlan"][iface]["802.11ac"] = True
        wlan_info["wlan"][iface]["802.11ax"] = False
        if "HE" in iw_info:
            wlan_info["wlan"][iface]["802.11ax"] = True
        wlan_info["wlan"][iface]["6e"] = False
        if re.search(r"6\d\d\d(\.\d+)? MHz", iw_info):
            wlan_info["wlan"][iface]["6e"] = True
        # get IP address
        ip = self.get_stdout(self.strip_stdout_result(self.run_command("hostname -I")))
        if ip:
            wlan_info["wlan"][iface]["ip"] = ip
        output = [0, wlan_info.copy(), ""]
        return output

    def get_bt_info(self, **kwargs) -> Tuple[int, Dict[str, Dict[str, Dict[str, Union[str, List[str]]]]], str]:
        """
        Get Bluetooth adapter information
        Args:
            **kwargs:

        Returns: (tuple) [ret, { bt: { hci<index>: { bt, addr, supports, current, name? } } }, stderr]

        """
        bt_info = {"bt": {}}

        # btmgmt fails silently if no interactive stdin is present or is disconnected
        # ( https://patchwork.kernel.org/project/bluetooth/patch/20200527050228.117532-1-stimim@google.com/ ),
        # that is why the workaround using pipe is used.
        response = self.get_stdout(
            self.strip_stdout_result(self.run_command("yes | btmgmt info", **kwargs)), skip_exception=True
        )
        # RegExp match based on BlueZ tools/btmgmt.c:info_rsp()
        for match in re.finditer(
            r"(?P<interface>hci\d+):\tPrimary controller\n"
            r"\taddr (?P<bdaddr>[\dA-F:]+) version \d+ manufacturer \d+ class 0x[\da-f]{6}\n"
            r"\tsupported settings: (?P<supports>.+)\n"
            r"\tcurrent settings: (?P<config>.*)\n"
            r"\tname (?P<name>.*)\n",
            response,
        ):
            info = {
                "bt": "true",
                "addr": match.group("bdaddr").lower(),
                "supports": match.group("supports").strip().split(" "),
                "config": match.group("config").strip().split(" "),
            }
            if match.group("name"):
                info["name"] = match.group("name")

            bt_info["bt"][match.group("interface")] = info

        return 0, bt_info, ""

    def prepare_bt(self, iface: str = None, **kwargs) -> Tuple[int, str, str]:
        """
        Prepare bluetooth adapter for scanning BLE packets with latest BlueZ

        Args:
            iface: (str) Bluetooth interface name to use instead of the default adapter.
            **kwargs:

        Returns: (tuple) [ret, adapter, stderr]

        """
        if iface is None:
            bt_info = self.get_bt_info(**kwargs)[1].get("bt")
            if not bt_info:
                raise ValueError("No Bluetooth adapters available")
            iface = list(bt_info.keys())[0]

        if kwargs.get("new_tools"):
            required_settings = ["powered", "le"]

            # btmgmt fails silently if no interactive stdin is present or is disconnected
            # ( https://patchwork.kernel.org/project/bluetooth/patch/20200527050228.117532-1-stimim@google.com/ ),
            # that is why the workaround using pipe is used.
            cmd = "sudo btmgmt"
            bt = self.get_bt_info()[1]

            # btmgmt uses the default adapter by default, otherwise check if the specified adapter exists
            if iface:
                if iface not in bt["bt"]:
                    raise ValueError(
                        f'Specified Bluetooth interface "{iface}" is not available ({", ".join(bt["bt"])})'
                    )
            else:
                iface = next(iter(bt["bt"]))
            cmd += f' --index {iface.lstrip("hci")}'

            log.info("Turn on Bluetooth on client")

            if not all(ss in bt["bt"][iface]["supports"] for ss in required_settings):
                raise EnvironmentError(f"Bluetooth adapter {iface} does not support all of {required_settings}")

            self.run_command(f"{cmd} power off", **kwargs)
            self.run_command(f"{cmd} le on", **kwargs)
            self.run_command(f"{cmd} power on", **kwargs)

            cfg = self.get_bt_info()[1]["bt"][iface]["config"]
            log.debug(f'Bluetooth interface {iface} prepared: {", ".join(cfg)}')

            if not all(ss in cfg for ss in required_settings):
                raise EnvironmentError(f"Bluetooth adapter {iface} could not be configured to {required_settings}")

        else:
            log.info(f"Turn on Bluetooth ({iface}) on client")
            # Initialize BT device using Kernel+BlueZ driver initialization
            # sequence, so the driver sets status UP RUNNING
            self.run_command(f"sudo hciconfig {iface} reset", **kwargs)
            # Inject custom config (using raw BT controller reset + config HCI commands)
            # < HCI Command: Reset (0x03|0x0003) plen 0
            self.run_command("sudo hcitool cmd 0x03 0x0003", **kwargs)
            # < HCI Command: Set Event Filter (0x03|0x0005) plen 1
            #         Type: Clear All Filters (0x00)
            self.run_command("sudo hcitool cmd 0x03 0x0005 00", **kwargs)
            # < HCI Command: Write Inquiry Mode (0x03|0x0045) plen 1
            #         Mode: Inquiry Result with RSSI or Extended Inquiry Result (0x02)
            self.run_command("sudo hcitool cmd 0x03 0x0045 02", **kwargs)
            # < HCI Command: Set Event Mask (0x03|0x0001) plen 8
            #         # Enable all supported events (0xFFFFFFFFFFFFFFFF-0xc24007f800000000)
            #         Mask: 0x3dbff807fffbffff
            self.run_command("sudo hcitool cmd 0x03 0x0001 ff ff fb ff 07 f8 bf 3d", **kwargs)
            # The following command is the same as "sudo hcitool lewlclr"
            # < HCI Command: LE Clear White List (0x08|0x0010) plen 0
            self.run_command("sudo hcitool cmd 0x08 0x0010", **kwargs)
            # Now the command "hcitool lescan [--duplicates]" will work, but note that
            # HCI adapter must be re-configured using "hciconfig hci0 reset" before any
            # other kind of usages - driver state and BT adapter configs are out of sync!

        return 0, iface, ""

    def get_wlan_iface(self, **kwargs):
        """
        Get all WLAN interfaces, if force=True get interface name directly from device
        Returns: (list) interfaces

        """
        if self.device.config.get("wifi", False) is False:
            return ""
        if iface := self.device.config.get("iface"):
            if not hasattr(self, "wlan_iface"):
                self.wlan_iface = iface
            return iface
        force = kwargs.pop("force", False)
        # Store interface name to avoid additional ssh calls
        iface = (
            self.wlan_iface
            if hasattr(self, "wlan_iface") and not force
            else self.get_stdout(
                self.strip_stdout_result(self.run_command("ls /sys/class/net | grep wl", **kwargs)), skip_exception=True
            )
        )
        if iface and not hasattr(self, "wlan_iface"):
            self.wlan_iface = iface
        return iface

    def get_eth_iface(self, **kwargs):
        """
        Get all eth interfaces if force=True get interface name directly from device
        Returns: (list) interfaces

        """
        if self.device.config["name"] not in FIXED_HOST_CLIENTS and self.device.config.get("eth", False) is False:
            return ""
        if iface := self.device.config.get("iface"):
            if not hasattr(self, "eth_iface"):
                self.eth_iface = iface
            return iface
        force = kwargs.pop("force", False)
        # Store interface name to avoid additional ssh calls
        iface = (
            self.eth_iface
            if hasattr(self, "eth_iface") and not force
            else self.get_stdout(
                self.strip_stdout_result(self.run_command('ls /sys/class/net | grep "et\\|en"', **kwargs)),
                skip_exception=True,
            ).split("\n")[0]
        )
        if iface and not hasattr(self, "eth_iface"):
            self.eth_iface = iface
        return iface

    def join_ifaces(self, **kwargs):
        """
        Get all interfaces from clients
        Returns: (list)

        """
        wlan_interface = self.get_wlan_iface(**kwargs)
        eth_interface = self.get_eth_iface(**kwargs)
        interface = ""
        if wlan_interface and eth_interface:
            interface = ",".join([wlan_interface, eth_interface])
        elif wlan_interface and not eth_interface:
            interface = wlan_interface
        elif eth_interface and not wlan_interface:
            interface = eth_interface
        return interface

    def eth_connect(
        self,
        pod,
        port_alias=None,
        ifname=None,
        dhclient=True,
        ipv4=True,
        ipv6=False,
        ipv6_stateless=False,
        timeout=20,
        **kwargs,
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
        result = self.run_command(f"sudo ip link set {ifname} up", **kwargs)
        if result[0]:
            return result
        pod.wait_eth_connection_ready()
        port = self.switch.connect_eth_client(pod_name, self.get_nickname(), port_alias)
        result = [0, f"connected to '{port}'", ""]
        # Issue router solicitation once wired client is connected. Previously this was done when the interface was
        # brought up, but now we bring it up almost 30 seconds earlier, so the exponential backoff could have already
        # increased the period between automatic solicitations to values that are above what we are willing to wait
        # for in SLAAC tests.
        self.run_command(f"rdisc6 {ifname}", **dict(kwargs, skip_exception=True))
        if dhclient:
            dhcp_result = self.start_dhcp_client(
                ifname, ipv4=ipv4, ipv6=ipv6, ipv6_stateless=ipv6_stateless, timeout=timeout, **kwargs
            )
            result = self.merge_result(result, dhcp_result)
        return result

    def eth_disconnect(self, ifname=None, keep_down=False, disable_unused_ports=True, **kwargs):
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
        # We need to take the interface down (and later bring it back up) to clear IPv6 autoconfigured settings.
        res2 = self.run_command(f"sudo ip link set {ifname} down", **kwargs)
        self.switch.disconnect_all_pods_from_client_vlan(my_blackhole_vlan, disable_unused_ports=disable_unused_ports)
        result = self.merge_result(res1, res2)
        # Testebed ethernet clients are expected to have their interface up and IPv4 dhclient running.
        if not keep_down:
            self.run_command(f"sudo ip link set {ifname} up", skip_exception=True)
            self.start_dhcp_client(ifname, clear_dhcp=False, no_wait=True, skip_exception=True)
        return result

    def _check_eth_connect_parameters(self, ifname):
        if not self.device.config.get("eth"):
            return [1, "", "only ethernet clients can have ethernet interface dis/connected"]
        my_blackhole_vlan = self.device.config.get("vlan")
        if not my_blackhole_vlan:
            return [2, "", "only dynamic ethernet clients (those with 'vlan' in testbed config) can be dis/connected"]
        ifname = ifname if ifname else self.get_eth_iface(skip_exception=True)
        if not ifname:
            return [3, "", "client doesn't have an ethernet interface"]
        return ifname, my_blackhole_vlan

    def wifi_winfo(self, ifname, **kwargs):
        ifname = ifname if ifname else self.get_wlan_iface()
        command = f"sh -c 'sudo iw dev {ifname} link; sudo iw dev {ifname} info'"
        if not ifname:
            return [1, "", "Missing wlan interface"]
        return self.run_command(command, **kwargs)

    def fqdn_check(self, count=1, v6=False, show_log: bool = True, **kwargs):
        timeout = kwargs.pop("timeout", 20)
        if show_log:
            log.info("Check fqdn resolving")
        domain_type = "aaaa" if v6 else "a"
        # https://www.iana.org/domains/root/servers
        fqdn_check_domain = self.config.get("wifi_check", {}).get("fqdn_check_domain", "www.iana.org")
        dns = "" if v6 else f"@{self.config.get('wifi_check', {}).get('fqdn_check_server', '198.41.0.4')}"
        result = self.run_command(
            f"dig -t {domain_type} {dns} {fqdn_check_domain} +noedns | grep -v '^;' "
            f"| grep {domain_type.upper()} | awk '{{print $5}}' | head -n 1",
            timeout=timeout,
            **kwargs,
        )
        # Clear stdout in case of error so that it doesn't get confused for success
        if result[0]:
            result[1] = ""
            return result
        ip_address = self.get_stdout(result).strip()
        if not ip_address:
            return [99, "", "Dig did not return IP address"]
        return self.ping_check(ip_address, count=count, v6=v6, fqdn_check=False, rdns=True, show_log=show_log, **kwargs)

    def fqdn_type65(self, domain, **kwargs):
        cmd = f"dig -t TYPE65 {domain}"
        return self.run_command(cmd)

    def wifi_monitor(self, channel, ht, ifname, **kwargs):
        ifname = ifname if ifname else self.get_wlan_iface()

        command = (
            f"sh -c 'sudo ip link set {ifname} down; sudo iw {ifname} set type monitor; "
            f"sudo ip link set {ifname} up; sudo iw {ifname} set channel {channel} {ht}; "
            f"iw {ifname} info | grep monitor'"
        )

        if not ifname:
            return [1, "", "Missing wlan interface"]
        result = self.strip_stdout_result(self.run_command(command, **kwargs))
        if not result[1] and not result[2]:
            if not result[0]:
                result[0] = 1
            result[2] = "Can not change interface state to monitor mode"
        return result

    def wifi_station(self, ifname, **kwargs):
        ifname = ifname if ifname else self.get_wlan_iface()

        command = (
            f"sh -c 'sudo ip link set {ifname} down; sudo iw {ifname} set type managed; "
            f"iw {ifname} info | grep managed'"
        )

        # Run command only for Wi-Fi clients
        if not ifname:
            return [1, "", "Missing wlan interface"]

        result = self.strip_stdout_result(self.run_command(command, **kwargs))
        if not result[1] and not result[2]:
            if not result[0]:
                result[0] = 1
            result[2] = "Can not change interface state to station mode"
        return result

    def get_mac(self, ifname="", **kwargs):
        """Get Wi-Fi MAC address"""
        ifname = ifname if ifname else self.join_ifaces().split(",")[-1]  # TODO: replace self.join_ifaces()
        command = f"cat /sys/class/net/{ifname}/address"

        client_mac = self.strip_stdout_result(self.run_command(command, **kwargs))

        if not client_mac[0] and not getattr(self, f"{ifname}_mac", False):
            setattr(self, f"{ifname}_mac", self.get_stdout(client_mac, skip_exception=True))
        return client_mac

    def get_wpa_supplicant_base_path(self, ifname=None, **kwargs):
        if not ifname:
            ifname = self.get_wlan_iface(**kwargs)
        if not ifname:
            return None
        return f"/tmp/wpa_supplicant_{ifname}"

    def get_wpa_supplicant_file(self, ifname=None, lines=10000, convert_timestamps=True, extension="log", **kwargs):
        path = self.get_wpa_supplicant_base_path(ifname=ifname, **kwargs)
        if path is None:
            return ""
        out = self.run_command(f"sudo tail -n{lines} {path}.{extension}", **kwargs)
        if not convert_timestamps:
            return out[1]

        stdout = ""
        for line in out[1].splitlines(keepends=True):
            try:
                sline = line.split(":", maxsplit=1)
                stdout += f"[{datetime.utcfromtimestamp(float(sline[0])).ctime()}]:{sline[1]}"
            except Exception:
                stdout += line

        return stdout

    def connect(  # noqa: C901
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
        eap=None,
        identity=None,
        password=None,
        **kwargs,
    ):
        """
        Connect client(s) to network starting own wpa_supplicant
        Args:
            ssid: ssid
            psk: password
            ifname: interface name
            bssid: bssid if needed
            key_mgmt (str or list of str): WPA-PSK, WPA-EAP, FT-PSK, FT-EAP, SAE, ... or NONE for open network
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
            retry (int) number of connect retries in case of Wi-Fi driver crash on the client
            eap (str): which enterprise authentication method to use (e.g. PEAP, TTLS, PWD, ...).
            identity (str): user name or id used for EAP authentication.
            password (str): password used for EAP authentication.
            **kwargs:

        Returns: (list) merged clients response

        """
        if ssid is None:
            name = self.get_network_name()
            ssid, _ = self.get_network(name)

        if psk is None and not eap:
            name = self.get_network_name()
            _, psk = self.get_network(name)

        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)
        if not ifname:
            return [1, "", "Missing wlan interface"]

        # Get default key_mgmt when function arg - key_mgmt is not specified
        key_mgmt = key_mgmt if key_mgmt else self.key_mgmt
        # Support for specifying more than one acceptable key management method
        key_mgmt = [key_mgmt.upper()] if isinstance(key_mgmt, str) else [m.upper() for m in key_mgmt]

        wpa3_eaps = {"WPA-EAP-SHA256", "FT-EAP-SHA384", "WPA-EAP-SUITE-B", "WPA-EAP-SUITE-B-192"}
        if eap:
            eaps = {"WPA-EAP", "FT-EAP"}.union(wpa3_eaps)
            if not eaps.intersection(key_mgmt):
                return [1, "", f"'key_mgmt' needs to be one of {eaps} for eap='{eap}', not '{key_mgmt}'"]
            if psk:
                return [1, "", "'password' parameter needs to be used for EAP authentication, not 'psk'"]

        wpa3s = {"SAE", "WPA-PSK-SHA256", "FT-SAE"}.union(wpa3_eaps)
        if wpa3s.intersection(key_mgmt) and "ieee80211w" not in e_net_param:
            pmf_modes = {"disabled": 0, "enabled": 1, "required": 2}
            pmf_value_mode = pmf_modes.get(pmf_mode)
            assert pmf_value_mode is not None, f"Incorrect PMF mode. Allowed modes: {pmf_modes.keys()}"
            pmf_param = f"ieee80211w={pmf_value_mode}"
            e_net_param = ",".join(e_net_param.split(",") + [pmf_param])
            # 6G band needs more time to associate - increasing the timeout to improve stability
            timeout *= 2

        if not wps:
            # create wpa_supp conf
            bssid_info = f"bssid={bssid}\n" if bssid else ""
            extra_param = "\n".join(e_gl_param.split(","))
            extra_param += "\nsae_pwe=2" if "SAE" in key_mgmt else ""
            extra_net_param = "\n    ".join(e_net_param.split(","))
            wpa_supp_psk = ""
            eap_params = ""
            # WPA-PSK, FT-PSK, WPA-PSK-SHA256, SAE, FT-SAE
            if psk:
                wpa_supp_psk = f'psk="{psk}"'
            elif eap:
                identity = f'identity="{identity}"' if identity else ""
                password = f'password="{password}"' if password else ""
                eap_params = f"eap={eap}\n    {identity}\n    {password}"
            else:
                key_mgmt = ["NONE"]
            security = f"{wpa_supp_psk}\n    proto={proto}\n    key_mgmt={' '.join(key_mgmt)}\n    {eap_params}"
            wpa_supp_conf = f"""ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country={country}
{extra_param}

network={{
    ssid="{ssid}"
    {security}
    scan_ssid=1
    priority=1
    {bssid_info}
    {extra_net_param}
}}
"""
            log.info(
                f"Connect clients {self.device.name} iface: {ifname} to ssid: {ssid}, bssid: {bssid}, "
                f"key mgmt: {key_mgmt}"
            )
        else:
            wpa_supp_conf = f"""ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
ctrl_interface_group=0
update_config=1
country={country}
"""

            log.info(f"Starting WPS PBC session on {ifname} iface")

        # first check if old supplicant works and remove old wpa_supplicant files
        base_path = self.get_wpa_supplicant_base_path(ifname)
        self.disconnect(ifname, clear_dhcp=True, **kwargs)

        # need to rm with sudo, since wpa_supplicant is started as root
        command = f"sudo rm {base_path}*"
        # Run command only for Wi-Fi clients
        self.run_command(command, **kwargs)

        # copy wpa_supplicant.conf to the client
        user_name = self.config.get("user_name", "").replace(" ", "")
        with tempfile.NamedTemporaryFile(prefix=f"wpa_supp_conf_{user_name}_", suffix=".conf", delete=True) as wpa_conf:
            local_conf_file_path = wpa_conf.name
            local_conf_file_name = os.path.basename(local_conf_file_path)
            wpa_conf.write(wpa_supp_conf.encode())
            wpa_conf.seek(0)
            ret = self.put_file(local_conf_file_path, "/tmp")
        if ret[0]:
            log.error("Cannot copy wpa_supplicant config to the client")
            return ret
        self.run_command(f"mv /tmp/{local_conf_file_name} {base_path}.conf")

        # WPA Enterprise on Raspberry Pi doesn't work with Buster kernel and nl80211 driver. An updated
        # wpa_supplicant is supposed to fix the issue (https://w1.fi/cgit/hostap/commit/?id=cb28bd52e1f),
        # but switching to the old wext drivers also works.
        driver = "wext" if eap and self.config_type() == "rpi" else "nl80211"

        # start wpa_supplicant in background with logs redirected to /tmp/wpa_supplicant_<ifname>.log
        command = (
            f"sudo wpa_supplicant -D {driver} -i {ifname} -c {base_path}.conf -P {base_path}.pid "
            f"-f {base_path}.log -t -B -d"
        )
        result = self.run_command(command, **kwargs)
        # in case of failure print wpa_supplicant.log and exit
        if result[0]:
            log.error("Unable to start wpa_supplicant")
            return self._retry_connect_after_driver_crash(
                command,
                result,
                ssid=ssid,
                psk=psk,
                ifname=ifname,
                bssid=bssid,
                key_mgmt=key_mgmt,
                timeout=timeout,
                dhclient=dhclient,
                e_gl_param=e_gl_param,
                e_net_param=e_net_param,
                country=country,
                ipv4=ipv4,
                ipv6=ipv6,
                ipv6_stateless=ipv6_stateless,
                wps=wps,
                proto=proto,
                pmf_mode=pmf_mode,
                retry=retry,
                **kwargs,
            )
        # wait for an association
        _timeout = time.time() + timeout
        result = []
        if wps:
            command = f"sudo wpa_cli -i {ifname} wps_pbc"
            result = self.run_command(command, **kwargs)

        while time.time() < _timeout:
            command = f"sudo wpa_cli -i {ifname} status"
            result = self.run_command(command, **kwargs)
            if "wpa_state=COMPLETED" in result[1]:
                result[1] = re.findall(r"(bssid=.*)\n", result[1])[0] + "\nwpa_state=COMPLETED"
                break
            else:
                time.sleep(5)
        else:
            # wpa_cli satus always has 0 as a return code does not matter if client is connected or not
            result[0] = 1

        # in case of failure print wpa_supplicant.log and exit
        if result[0]:
            return self._retry_connect_after_driver_crash(
                command,
                result,
                ssid=ssid,
                psk=psk,
                ifname=ifname,
                bssid=bssid,
                key_mgmt=key_mgmt,
                timeout=timeout,
                dhclient=dhclient,
                e_gl_param=e_gl_param,
                e_net_param=e_net_param,
                country=country,
                ipv4=ipv4,
                ipv6=ipv6,
                ipv6_stateless=ipv6_stateless,
                wps=wps,
                proto=proto,
                pmf_mode=pmf_mode,
                retry=retry,
                **kwargs,
            )
        if dhclient:
            dhcp_result = self.start_dhcp_client(ifname, ipv4=ipv4, ipv6=ipv6, ipv6_stateless=ipv6_stateless, **kwargs)
            result = self.merge_result(result, dhcp_result)
        return result

    @staticmethod
    def _is_crash_in_txt(txt):
        return (
            "brcmf_cfg80211_scan: scan error (-110)" in txt
            or "brcmf_cfg80211_scan: scan error (-52)" in txt
            or "brcmf_cfg80211_get_tx_power: error (-110)" in txt
            or ("Exception stack" in txt and "Workqueue" in txt and "Hardware name" in txt)
            or "Scan failed! ret -5" in txt
        )

    def check_driver_crash(self):
        dmesg_output = self.run_command("dmesg -T | tail -n 1000", skip_exception=True)[1]
        if not self._is_crash_in_txt(dmesg_output):
            return False
        log.info("BRCM driver crash detected on the Wi-Fi client, rebooting...")
        short_dmesg = "\n".join(dmesg_output.splitlines()[-50:])
        log.info(f"\n\nDMESG OUTPUT: \n\n:{short_dmesg}")
        self.reboot()
        time.sleep(5)
        self.wait_available(5 * 60)
        # deep breath
        time.sleep(30)
        log.info("Client rebooted")
        return True

    def _retry_connect_after_driver_crash(self, command, result, **kwargs):
        if not self.check_driver_crash():
            self.last_cmd["command"] = command  # Update the command cache for returned result
            return result
        retry = kwargs.pop("retry") - 1
        if retry:
            return self.connect(retry=retry, **kwargs)
        else:
            self.last_cmd["command"] = command  # Update the command cache for returned result
            return [-1, "", "Retries exhausted for connecting client"]

    def start_dhcp_client(
        self,
        ifname,
        cf=None,
        ipv4=True,
        ipv6=False,
        ipv6_stateless=False,
        timeout=20,
        clear_dhcp=True,
        no_wait=False,
        **kwargs,
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
            no_wait (bool) should dhclient be started with the -nw (no wait) option

        Returns: (list) clients response
        """
        # Extend timeout for eth client since wait_eth_connection_ready() is already deprecated
        # Timeout is extended when arg is set to default value == 20 sec
        if self.device.config.get("eth") and timeout == 20:
            timeout = 600
        result = self._check_dhclient_parameters(ifname, ipv4, ipv6, ipv6_stateless)
        if len(result) == 3:
            return result
        ifname, ipv4, ipv6, ipv6_stateless = result

        if clear_dhcp:
            self.stop_dhcp_client(ifname, clear_cache=True)
        if cf:
            command = f"echo '{cf}' > /tmp/dhclient_{ifname}.conf"
            self.run_command(command, **kwargs)
            cf = f"-cf /tmp/dhclient_{ifname}.conf"
        else:
            cf = ""
        nw = "-nw" if no_wait else ""

        out = [0, "", ""]
        if ipv4:
            log.info(f"Starting IPv4 dhclient for {ifname}")
            # -df path is not an issue, it is according to the ifup
            command = (
                f"sudo dhclient -v {nw} -4 -pf /var/run/dhclient.{ifname}.pid {cf} "
                f"-lf /var/lib/dhcp/dhclient.{ifname}.leases "
                f"-I -df /var/lib/dhcp/dhclient6.{ifname}.leases {ifname}"
            )
            start_time = time.time()
            ret = self._wait_for_dhcp_lease(cmd=command, timeout=timeout, **kwargs)
            if ret[0]:
                if not ret[2]:
                    ret[2], ret[1] = ret[1], ""
                ret[2] = f"Unable to get IPv4: {ret[2].split('https://www.isc.org/software/dhcp/')[-1]}"
            else:
                log.info(f"Getting IPv4 address took: {time.time() - start_time:.2f} sec")
                # Remain quiet when dhclient suceeds
                ret[1] = ret[2] = ""
            out = self.merge_result(out, ret)

        if ipv6:
            log.info("Starting router solicitation")
            ret = self.run_command(f"rdisc6 {ifname}", **kwargs)
            # dhclient can still succeed if client somehow has default route,
            # despite not receiveing RA in response to rdisc6's solicitation
            if ret[0] and not self.run_command("ip -6 route show default", **kwargs)[1]:
                # Even when without default route we still cannot raise an error,
                # some tests intentionally disable router advertisment but expect
                # dhclient to succeed by contacting all routers multicast address
                # directly. But we can complain loudly in that case.
                if not ret[2]:
                    ret[2], ret[1] = ret[1], ""
                log.error("Unable to get RA, dhclient will almost certainly fail: %s", ret[2])
                ret[0] = 0
                ret[2] = f"Unable to get RA: {ret[2]}"
            elif ret[0]:
                log.warning("Unable to get RA, dhclient will likely fail: %s%s", ret[1], ret[2])
                ret[0] = 0
                ret[1] = ""
            else:
                # Remain quiet when rdisc6 suceeds
                ret[1] = ret[2] = ""
            out = self.merge_result(out, ret)

            log.info(f"Starting IPv6 dhclient for {ifname}")
            stateless = "-S " if ipv6_stateless else ""
            # -df path is not an issue, it is according to the ifup
            command = (
                f"sudo dhclient -v {nw} -6 {stateless} -pf /var/run/dhclient6.{ifname}.pid "
                f"{cf} -lf /var/lib/dhcp/dhclient6.{ifname}.leases "
                f"-I -df /var/lib/dhcp/dhclient.{ifname}.leases {ifname}"
            )
            start_time = time.time()
            ret = self._wait_for_dhcp_lease(cmd=command, timeout=timeout, **kwargs)
            if ret[0]:
                if not ret[2]:
                    ret[2], ret[1] = ret[1], ""
                ret[2] = f"Unable to get IPv6: {ret[2].split('https://www.isc.org/software/dhcp/')[-1]}"
            else:
                log.info(f"Getting IPv6 address took: {time.time() - start_time:.2f} sec")
                # Remain quiet when dhclient suceeds
                ret[1] = ret[2] = ""
            out = self.merge_result(out, ret)
        return out

    def _wait_for_dhcp_lease(self, cmd: str, timeout: int, dhclient_timeout: int = 20, **kwargs):
        # By default, dhclient timeout is set to sixty seconds (dhclient_timeout).
        # This arg can be increased in dhclient.conf. To avoid doing it we start a loop inside a script.
        ret = [0, "", ""]
        time_to_wait = timeout + time.time()
        while time_to_wait > time.time():
            ret = self.run_command(f"timeout {dhclient_timeout} {cmd}", timeout=dhclient_timeout + 20, **kwargs)
            if not ret[0]:
                break
        return ret

    def _check_dhclient_parameters(self, ifname, ipv4, ipv6, ipv6_stateless):
        if not ipv4 and not ipv6:
            return [1, "", "Specify at least one of ipv4 or ipv6"]
        if not ipv6 and ipv6_stateless:
            return [2, "", "Inappropriate IPv6 configuration, enable ipv6 to use ipv6_stateless mode"]
        ifname = ifname if ifname else self.get_wlan_iface(skip_exception=True)
        ifname = ifname if ifname else self.get_eth_iface(skip_exception=True)
        if not ifname:
            return [3, "", "Missing interface"]
        return ifname, ipv4, ipv6, ipv6_stateless

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
        time.sleep(1.2)

        # since we kill all types, we could have false negative responses, so returning 0
        return [0, "", ""]

    def disconnect(self, ifname=None, clear_dhcp=False, **kwargs):
        """
        Kills the wpa_supplicant and dhclient (if exists) based on the pid file in name
        Args:
            ifname: (str) wlan iface name
            clear_dhcp: (str) clear dhcp cache and configuration files

        Returns: (list) merged clients response
        """
        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)
        if not ifname:
            return [1, "", "Missing wlan interface"]

        wpa_path_ifname = f"/tmp/wpa_supplicant_{ifname}.pid"
        wpa_supp_process = self.run_command(
            f"ps aux | grep wpa_supplicant | grep {ifname} | grep -v grep" f" | awk '{{print $2}}'", **kwargs
        )
        if not wpa_supp_process[1]:
            return [0, f"Wpa supplicant not running for ifname: {ifname}", ""]

        log.info(f"Disconnect client: {self.get_name()}, ifname: {ifname}")

        # Stop dhclient
        self.stop_dhcp_client(ifname, clear_cache=clear_dhcp, **kwargs)

        # Stop wpa_supplicant
        wpa_supp_pid = self.get_stdout(wpa_supp_process).strip()
        response = self.run_command(f"sudo kill {wpa_supp_pid}", **kwargs)
        if response[0] and "Usage:" not in response[2]:
            log.warning(f"Unable to kill wpa_supplicant for {self.device.name}, error: {response[2]}")

        # Remove wpa supplicant log file
        if self.result_ok(self.run_command(f"ls {wpa_path_ifname}", **kwargs)):
            command = f"sudo rm {wpa_path_ifname}"
            self.run_command(command, **kwargs)
        return [0, "", ""]

    def scan(self, ifname="", params="", flush=True, **kwargs):
        """
        Trigger flush scan on the client
        Args:
            ifname: (str) interface name
            params: (str) arguments for 'iw scan' command
            flush: (bool) flush scan

        Returns: (list) clients response scan response
        """
        ifname = ifname if ifname else self.get_wlan_iface()
        if not ifname:
            return [1, "", "Missing wlan interface"]
        # make sure interface is up
        command = f"sudo ifconfig {ifname} up"
        self.run_command(command, **kwargs)
        flush_cmd = "flush" if flush else ""
        command = f"sudo iw {ifname} scan {flush_cmd} {params}"

        # Sometimes if device is connected to network we are getting 'Device or resource busy (-16)'
        timeout = time.time() + 60
        output = ""
        while timeout > time.time():
            output = self.run_command(command, **kwargs)
            if output[0] == 0:
                break
            time.sleep(5)
        return output

    def client_type(self, **kwargs):
        """Display type of client(s)"""
        result = self.run_command("cat /proc/cmdline | grep -o board=[^[:space:]]* | cut -d'=' -f2 | head -1", **kwargs)
        return self.strip_stdout_result(result)

    def config_type(self, **kwargs):
        """Return type of client based on config value"""
        return self.device.config["type"]

    def get_client_ips(self, interface=None, ipv6_prefix=None, **kwargs):
        interface = interface if interface else self.get_wlan_iface()
        interface = interface if interface else self.get_eth_iface()
        ip_adds = {"ipv4": False, "ipv6": False}
        result = self.get_stdout(self.run_command(f"ip --oneline address show dev {interface}", **kwargs))
        if result and re.search("inet", result.strip()):
            for ip_entry in result.splitlines():
                # inet 192.168.24.12 peer 192.168.24.1/32 scope global ppp0\    valid_lft forever preferred_lft forever
                # inet6 fe80::dea6:32ff:fe0e:6670/64 scope link \       valid_lft forever preferred_lft forever
                if "inet " in ip_entry and (ipv4_address := re.search("(?<=inet).+(?=/)", ip_entry)):
                    ip_adds["ipv4"] = ipv4_address.group().strip().split(" peer ")[0]
                if ipv6_prefix and ipv6_prefix not in ip_entry:
                    continue
                if "inet6 " in ip_entry and (ipv6_address := re.search("(?<=inet6).+(?=/)", ip_entry)):
                    ip_adds["ipv6"] = ipv6_address.group().strip().split(" peer ")[0]
                if (
                    "inet6 " in ip_entry
                    and "global" in ip_entry
                    and "mngtmpaddr" not in ip_entry
                    and (ipv6_address := re.search("(?<=inet6).+(?=/)", ip_entry))
                ):
                    ip_adds["ipv6_global"] = ipv6_address.group().strip().split(" peer ")[0]
        if ipv6_global := ip_adds.pop("ipv6_global", ""):
            ip_adds["ipv6"] = ipv6_global
        return ip_adds

    def ping_v4_v6_arp(self, destination, version, wlan_test, count="8", **kwargs):
        ping_cmd = ""
        if version == "v4":
            ping_cmd = f"sudo /bin/ping -I {wlan_test} -c {count} {destination}"

        elif version == "v6":
            ping_cmd = f"sudo /bin/ping6 -c {count} -I {wlan_test} {destination}"

        elif version == "arp":
            ping_cmd = f"sudo /usr/sbin/arping -I {wlan_test} -c {count} {destination}"
        result = self.run_command(ping_cmd, **kwargs)
        return self.strip_stdout_result(result)

    def ping_ndisc6(self, destination, ifname=None, **kwargs):
        ifname = ifname if ifname else self.get_wlan_iface()
        result = self.run_command(f"sudo /usr/bin/ndisc6 {destination} {ifname}", **kwargs)
        return self.strip_stdout_result(result)

    def restart_networking(self, **kwargs):
        result = self.run_command("sudo /etc/init.d/networking restart > /dev/null 2>&1 &", **kwargs)
        time.sleep(10)
        result = self.merge_result(result, self.wait_available(60, **kwargs))
        if not self.result_ok(result):
            return False
        return True

    def start_continuous_flood_ping(self, ifname, file_path="/tmp/ping.log", target="8.8.8.8", **kwargs):
        self.run_command("sudo killall ping", **kwargs)
        cmd_output = self.run_command(f"/bin/ping -f -I {ifname} {target} > {file_path} 2>&1 &")
        if not cmd_output[0] == 0:
            raise ValueError("Failed to start flood ping as background proc")
        proc_output = self.run_command("ps -aux | grep ping")
        proc_id = re.sub(r"root\s*(\d)", r"\1", proc_output[1]).split()[0]
        log.info(f"Flood ping started as process -> {proc_id}")
        return proc_id

    def stop_continuous_flood_ping(self, proc_id, file_path="/tmp/ping.log", **kwargs):
        response = {"result": False, "all_pings": None, "success_ping": None, "missed_ping": None, "max_time": None}
        log.info(f"Stopping flood ping process -> {proc_id}")
        # flood ping process does not close file handle without SIGINT - results in missing summary stats in file
        self.run_command(f"kill -SIGINT {proc_id}")
        cmd_output = self.run_command(f"cat {file_path}", **kwargs)
        self.run_command("rm /tmp/ping.log", **kwargs)
        self.run_command("killall ping", **kwargs)
        if cmd_output[0] != 0:
            return response
        tx, rx, perc_loss = [_str.lstrip() for _str in cmd_output[1].split("\n")[3].split(",")][:3]
        rtt_metrics = [st.lstrip() for st in cmd_output[1].split("\n")[4].split(",")][0].split(" = ")[1]
        ping_min, ping_avg, ping_max, ping_dev = rtt_metrics.split("/")
        response["all_pings"] = int(tx.split()[0])
        response["missed_ping"] = response["all_pings"] - int(rx.split()[0])
        response.update(
            {
                "result": True,
                "ping_loss_perc": round(((response["missed_ping"] / int(tx.split()[0])) * 100), 5),
                "max_time": float(ping_max),
                "success_ping": response["all_pings"] - response["missed_ping"],
            }
        )
        return response

    def start_continuous_ping(self, ifname, file_path="/tmp/ping.log", wait="1", target="8.8.8.8", **kwargs):
        self.run_command("sudo killall ping", **kwargs)
        cmd_output = self.run_command(f"/bin/ping -I {ifname} -W {wait} {target} > {file_path} 2>&1 &")
        if not cmd_output[0] == 0:
            return False
        return True

    def stop_continuous_ping(self, file_path="/tmp/ping.log", target="8.8.8.8", threshold=2, **kwargs):
        response = {"result": False, "all_pings": None, "success_ping": None, "missed_ping": None, "max_time": None}
        self.run_command("killall ping", **kwargs)
        cmd_output = self.run_command(f"cat {file_path}", **kwargs)
        self.run_command("rm /tmp/ping.log", **kwargs)
        if cmd_output[0] != 0:
            return response
        ping_res = cmd_output[1].strip()
        if len(ping_res) == 0:
            return response
        ping_list = ping_res.split("\n")[1:-1]
        all_pings = int(ping_list[-1].split("=")[1].split()[0])

        successful_ping_list = []
        for ping in ping_list:
            if target in ping:
                successful_ping_list.append(ping)

        successful_ping = len(successful_ping_list)
        missed_pings = all_pings - successful_ping

        new_time_list = []
        for row in successful_ping_list:
            time_list = row.split()[-2:]
            time_ping = f"{time_list[0].split('=')[1]}{time_list[1]}"
            new_time_list.append(time_ping)
        max_time = max(new_time_list)

        if missed_pings < int(threshold):
            response["result"] = True

        response["all_pings"] = all_pings
        response["success_ping"] = successful_ping
        response["missed_ping"] = missed_pings
        response["max_time"] = max_time
        return response

    def set_hostname(self, new):
        """
        Change client hostname
        Args:
            new: (str) New client hostname
        Returns:

        """
        old_name = self.get_stdout(self.strip_stdout_result(self.run_command("hostname")))
        return self.run_command(
            f"sudo hostname {new}; "
            f'sudo -h localhost sed -i "s/{old_name}/{new}/g" /etc/hosts; '
            f'sudo -h localhost sed -i "s/{old_name}/{new}/g" /etc/hostname'
        )

    def set_tx_power(self, tx_power, ifname="", **kwargs):
        """
        Set client Tx power for iface

        Args:
            tx_power: (int) Tx power value to set (dBm)
            ifname: (str) client interface name

        Returns:

        """
        ifname = ifname if ifname else self.get_wlan_iface()
        if not ifname:
            return [1, "", "Missing wlan interface"]
        txpower = tx_power * 100
        command = f"sudo iw {ifname} set txpower fixed {txpower}"
        return self.run_command(command, **kwargs)

    def get_tx_power(self, ifname="", **kwargs):
        """
        Get client Tx power for iface

        Args:
            ifname: (str) client interface name

        Returns:

        """
        ifname = ifname if ifname else self.get_wlan_iface()
        if not ifname:
            return [1, "", "Missing wlan interface"]
        out = self.run_command(f"sudo iw {ifname} info | grep txpower", **kwargs)
        if out[0]:
            return out
        # example: "     txpower 22.00 dBm"
        out[1] = str(int(float(out[1].split()[1])))
        return out

    def get_max_tx_power(self, ifname="", **kwargs):
        """
        Get max Tx power value from iw
        Args:
            ifname: (str) name of Wi-Fi interface
            **kwargs:

        Returns: (str) max Tx power [dBm]
        """
        ifname = ifname if ifname else self.get_wlan_iface()
        if not ifname:
            return [1, "", "Missing wlan interface"]

        old_value = self.get_tx_power(ifname, **kwargs)
        if old_value[0]:
            return old_value
        # set some crazy value, Tx power is limited to max by driver in such case
        self.set_tx_power(40, ifname)
        response = self.get_tx_power(ifname, **kwargs)
        self.set_tx_power(old_value[1], ifname, **kwargs)
        return response

    def get_min_tx_power(self, ifname="", **kwargs):
        """
        Get max Tx power value from iw
        Args:
            ifname: (str) name of Wi-Fi interface
            **kwargs:

        Returns: (str) max Tx power [dBm]
        """
        # OK, we know it is 0
        return [0, "0", ""]

    def get_frequency(self, ifname, **kwargs):
        """
        Provide operating frequency for client iface when connected to AP
        Args:
            ifname: (str) name of wlan interface

        Returns: (int) frequency in MHz

        """
        ifname = ifname if ifname else self.get_wlan_iface()
        freq = None
        wifi_info = self.get_stdout(self.run_command(f"sudo iw {ifname} link", **kwargs)).splitlines()
        for line in wifi_info:
            if "freq:" in line:
                freq = line.split(":")[1].strip()
                break

        return [0, freq, ""] if freq else [1, "", f"Frequency on {ifname} not found"]

    def pod_to_client(self, **kwargs):
        """
        Change pod to client
        Returns:

        """
        raise NotImplementedError("This method is implemented for specific client only")

    def client_to_pod(self, **kwargs):
        """
        Change client to pod
        Returns:

        """
        raise NotImplementedError("This method is implemented for specific client only")

    def create_ap(
        self, channel, ifname="", ssid="test", extra_param="", timeout=120, dhcp=False, country="US", **kwargs
    ):
        """
        Create access point on the client.
        Args:
            channel: (int) access point channel
            ifname: (str) name of interface
            ssid: (str) network SSID
            extra_param: (str) whatever you have in mind to include in a config
            timeout: (int) timeout for hostapd to go into AP-ENABLED state
            dhcp: (bool) start DHCP server
            country: (str) country code

        Returns: (list) [status, std_out, std_err]

        """
        ifname = ifname if ifname else self.get_wlan_iface()
        if not ifname:
            log.info("No WiFi interface, probably previous hostapd not stopped")
            # make sure that hostapd is not running
            self.disable_ap(ifname, **kwargs)
            ifname = ifname if ifname else self.get_wlan_iface()

        if not ifname:
            return [1, "No WiFi interface on the device", "No WiFi interface on the device"]

        hw_mode = "g" if 1 <= channel <= 13 else "a"
        dfs_params = ""
        if 52 <= channel <= 144:
            dfs_params = "ieee80211d=1\nieee80211h=1"

        extra_param = extra_param if extra_param else ""
        cc_code = f"country_code={country}\n" if country else ""
        hostapd_cfg = f"""ctrl_interface=/var/run/hostapd
interface={ifname}
ssid={ssid}

hw_mode={hw_mode}
channel={channel}
{cc_code}
{dfs_params}
{extra_param}"""

        # in case we need DHCP and provide internet access to the AP clients we need to move out Wi-Fi iface
        # out of its network namespace
        ns_out = False
        if dhcp:
            self.move_iface_out_of_network_namespace()
            ns_out = True
            # for Tb client we need to forward traffic over mgmt iface to have internet access
            if "rpi_server" not in self.version(short=False, skip_ns=ns_out)[1]:
                # add route over mgmt iface
                # get to know eth iface name
                uplink_iface = None
                for route in self.run_command("sudo ip r", skip_ns=ns_out)[1].splitlines():
                    if "192.168.4.0" in route:
                        uplink_iface = route.split(" ")[2]
                        break
                if not uplink_iface:
                    return [2, "Cannot get uplink iface on the client", "Cannot get uplink iface on the client"]

                res = self.run_command(
                    f'sudo sh -c "ip r add default via 192.168.4.1 dev {uplink_iface} proto static metric 100'
                    f'; echo nameserver 8.8.8.8 | sudo tee /etc/resolv.conf"',
                    skip_ns=ns_out,
                )
                if res[0]:
                    return res

        self.run_command(f"sudo rm /tmp/hostapd_{ifname}.conf; sudo rm /tmp/hostapd_{ifname}.log", skip_ns=ns_out)
        # save hostap.conf on the client
        command = f"echo '{hostapd_cfg}' > /tmp/hostapd_{ifname}.conf"
        self.run_command(command, skip_ns=ns_out, **kwargs)

        command = (
            f"sudo hostapd -d -f /tmp/hostapd_{ifname}.log -t -B -P /tmp/hostapd_{ifname}.pid"
            f" /tmp/hostapd_{ifname}.conf"
        )
        response = self.run_command(command, skip_ns=ns_out, **kwargs)

        # Validate hostapd
        wait = timeout + time.time()
        while wait > time.time():
            response = self.run_command(f"sudo cat /tmp/hostapd_{ifname}.log", skip_ns=ns_out, **kwargs)
            if re.search("AP-ENABLED", response[1], re.IGNORECASE):
                break
            elif re.search("Wait for CAC to complete", response[1], re.IGNORECASE):
                time.sleep(60)
                break
            time.sleep(5)
        # store last command in case we need return later "response"
        last_cmd = self.last_cmd
        # Sometimes even though hostapd start successfully we can't start him with expected configuration
        # due to BSS overlapping
        overlapping_check = self.run_command(
            f'sudo cat /tmp/hostapd_{ifname}.log | grep "operation not permitted"', skip_ns=ns_out, **kwargs
        )
        if not overlapping_check[0]:
            return [5, "", overlapping_check[1]]

        if response[0]:
            self.last_cmd = last_cmd
            return response

        if not dhcp:
            self.last_cmd = last_cmd
            return response

        dhcpd_conf = """# dhcpd.conf
ddns-update-style none;

deny client-updates;
default-lease-time 600;
max-lease-time 7200;

authoritative;

subnet 192.168.100.0 netmask 255.255.255.0 {
    range 192.168.100.10 192.168.100.50;
    option routers 192.168.100.1;
    option subnet-mask 255.255.255.0;
    option domain-name-servers 8.8.8.8, 1.1.1.1;
}

"""
        # save dhcpd.conf on the client
        command = f"echo '{dhcpd_conf}' > /tmp/dhcpd_{ifname}.conf"
        self.run_command(command, skip_ns=ns_out, **kwargs)

        # set the IP address on the Wi-Fi iface
        ret = self.run_command(f"sudo ifconfig {ifname} 192.168.100.1", skip_ns=ns_out, **kwargs)
        response = self.merge_result(response, ret)
        ret = self.run_command(
            f"sudo dhcpd -4 -q -cf /tmp/dhcpd_{ifname}.conf -pf /tmp/dhcpd_{ifname}.pid", skip_ns=ns_out, **kwargs
        )
        response = self.merge_result(response, ret)
        return response

    def disable_ap(self, ifname="", **kwargs):
        ns_out = True if self.get_netns_status()[1] != "active" else False
        kwargs["skip_ns"] = ns_out
        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)
        if not ifname:
            return [1, "", "Cannot find any WiFi interface on the device"]
        hostapd_path = f"/tmp/hostapd_{ifname}.pid"
        command = f"sudo ps aux | grep -P {hostapd_path} | grep -v grep"
        response = self.run_command(command, **kwargs)
        if not response[1]:
            self.recover_namespace_service(**kwargs)
            return [0, f"Hostapd not running for ifname: {ifname}", ""]

        command = f"sudo ps aux | grep -P {hostapd_path} | grep -v grep | awk '{{print $2}}' | " f"xargs sudo kill"

        response = self.run_command(command, **kwargs)
        if response[0] and "Usage:" not in response[2]:
            log.warning(f"Unable to kill hostapd for {self.device.name}, error: {response[2]}")

        # Remove hostapd log file
        if self.result_ok(self.run_command(f"ls {hostapd_path}", **kwargs)):
            command = f"sudo rm {hostapd_path}"
            self.run_command(command, **kwargs)

        # stop dhcpd server if it was running
        dhcpd_path = f"/tmp/dhcpd_{ifname}.pid"
        command = f"sudo ps aux | grep -P {dhcpd_path} | grep -v grep"
        response = self.run_command(command, **kwargs)
        if not response[1]:
            self.recover_namespace_service(**kwargs)
            return [0, f"DHCPD not running for ifname: {ifname}", ""]

        command = f"sudo ps aux | grep -P {dhcpd_path} | grep -v grep | awk '{{print $2}}' | " f"xargs sudo kill"

        response = self.run_command(command, **kwargs)
        if response[0] and "Usage:" not in response[2]:
            log.warning(f"Unable to kill dhcpd for {self.device.name}, error: {response[2]}")

        self.recover_namespace_service(**kwargs)
        return [0, "", ""]

    def refresh_ip_address(
        self,
        iface=None,
        ipv4=True,
        ipv6=False,
        ipv6_stateless=False,
        timeout=10,
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

        dhclient = ""
        if reuse:
            cur_dhclient = self.run_command(
                f"sudo ps aux | grep $(cat /var/run/dhclient.{iface}.pid) | grep -v grep", **kwargs
            )
            if cur_dhclient[0]:
                if reuse_only:
                    return [1, "", "No dhclient running, nothing to restart"]
                log.warning("Cannot get running dhclient. Starting with default parameters")
            else:
                dhclient = cur_dhclient[1][cur_dhclient[1].find("dhclient") :]

        if clear_dhcp:
            self.stop_dhcp_client(iface, clear_cache=not reuse)
        if static_ip:
            return self.set_ip_address(static_ip, iface=iface)
        if reuse and dhclient:
            return self.run_command(f"timeout {timeout} sudo {dhclient}", timeout=timeout + 20)

        return self.start_dhcp_client(
            iface, ipv4=ipv4, ipv6=ipv6, ipv6_stateless=ipv6_stateless, timeout=timeout, clear_dhcp=False
        )

    def set_mac(self, interface, new_mac, **kwargs):
        self.run_command(f"sudo ifconfig {interface} down", **kwargs)
        ret = self.run_command(f"sudo ifconfig {interface} hw ether {new_mac}", **kwargs)
        # short pause is needed here, otherwise we are not able to read the address right after
        time.sleep(1)
        setattr(self, f"{interface}_mac", new_mac)
        return ret

    def set_ip_address(self, ip, netmask="255.255.255.0", iface=None, **kwargs):
        iface = iface if iface else self.get_wlan_iface(skip_exception=True)
        iface = iface if iface else self.get_eth_iface(skip_exception=True)
        assert iface, "No interface found"
        netmask = "" if ip == "0.0.0.0" else f" netmask {netmask}"
        return self.run_command(f"sudo ifconfig {iface} {ip}{netmask}", **kwargs)

    def get_region(self, **kwargs):
        # sometimes there is global configuration and for each phy, so get the last one, which is valid for Wi-Fi iface
        out = self.run_command("sudo iw reg get | grep country | tail -n 1", **kwargs)
        if out[0]:
            return out
        out[1] = out[1].replace("country ", "").strip()
        return out

    def upgrade(self, fw_path=None, restore_cfg=True, force=False, http_address="", version=None, **kwargs):
        """
        Upgrade Brix clients to target firmware if fw_path=None download the latest build version from the artifactory
            Args:
                fw_path: (str) Path to the image
                force: (bool) Flash image even though the same firmware is already on the device
                restore_cfg: (bool) Restore a client configuration (hostname, dhcpd.conf)
                http_address: (str) Start download image directly from provided HTTP server address
                version: (str) version to download from the artifactory (or get latest or stable version)
                **kwargs:

            Returns: (ret_val, std_out, str_err)

        """
        # to have Internet access over mgmt iface we need to jump out from the network namespace
        netns = self.device.config.get("host", {}).pop("netns", "")
        self.run_command("rm -R %s" % UPGRADE_DIR)
        # short sleep to spread threads in time
        time.sleep(random.randint(1, 50) / 10)
        linux_upgrade = LinuxClientUpgrade(lib=self)
        if http_address:
            fw_path = linux_upgrade.download_image_from_url(http_address)
        if fw_path and not os.path.isabs(fw_path):
            fw_path = os.path.abspath(fw_path)
        ret = linux_upgrade.start_upgrade(fw_path, force, version, **kwargs)
        if netns:
            self.device.config["host"]["netns"] = netns
        return ret

    def start_mqtt_broker(self, **kwargs):
        # It is designed for rpi server only
        raise NotImplementedError("Rpi-server only")

    def stop_mqtt_broker(self, **kwargs):
        # It is designed for rpi server only
        raise NotImplementedError("Rpi-server only")

    def set_tb_nat(self, mode, **kwargs):
        # It is designed for rpi server only
        raise NotImplementedError("Rpi-server only")

    def get_tb_nat(self, **kwargs):
        # It is designed for rpi server only
        raise NotImplementedError("Rpi-server only")

    def testbed_dhcp_reservation(self, **kwargs):
        # It is designed for rpi server only
        raise NotImplementedError("Rpi-server only")

    def limit_tx_power(self, state, **kwargs):
        # It is designed for rpi server only
        raise NotImplementedError("Rpi-server only")

    def start_selenium_server(
        self, port=4444, server_path="/usr/bin/selenium-server-standalone-3.141.59.jar", **kwargs
    ):
        response = self.run_command(
            f"export MOZ_HEADLESS=1; " f"java -jar {server_path} -port {port} &> /dev/null &", **kwargs
        )
        return response

    def change_driver_settings(self, ifname, settings, **kwargs):
        ifname = ifname if ifname else self.get_wlan_iface(skip_exception=True)
        ifname = ifname if ifname else self.get_eth_iface(skip_exception=True)
        assert ifname, "No interface found"
        command = f"ethtool -K {ifname} "
        for key, value in settings.items():
            command += f"{key} {value} "
        response = self.run_command(command, **kwargs)
        return response

    def start_simulate_client(self, device_to_simulate, ifname, ssid, psk, bssid, fake_mac):
        try:
            module = importlib.import_module("lib.util.adtlib.adtlib")
        except ModuleNotFoundError as err:
            return [1, "", err]
        ifname = ifname if ifname else self.get_wlan_iface(skip_exception=True)
        ifname = ifname if ifname else self.get_eth_iface(skip_exception=True)
        assert ifname, "No interface found"
        adt_lib = getattr(module, "AdtLib")()
        device_mac = self.get_stdout(self.get_default_mac_address(ifname))
        adt_lib.set_device(
            device_object=self, client_name=self.get_nickname(), interface_name=ifname, default_mac=device_mac
        )
        device_type = "wireless" if self.device.config.get("wifi") else "ethernet"
        device_cfg = adt_lib.get_device_cfg_by_name(device_type, device_to_simulate, skip_exception=True)
        if not device_cfg:
            return [
                5,
                "",
                f"Not found any device config for {device_to_simulate}.\n "
                f'To find all possible devices to simulate, use "adt-list-devices" command',
            ]
        adt_lib.simulate_iot_device(device_cfg, ssid=ssid, password=psk, bssid=bssid, fake_mac=fake_mac)
        return [
            0,
            f"{device_to_simulate} is simulated with following MAC address: {adt_lib.new_client_mac}\n"
            f'To clear client state, use "clear-adt" command',
            "",
        ]

    def get_clients_to_simulate(self):
        try:
            module = importlib.import_module("lib.util.adtlib.adtlib")
        except ModuleNotFoundError as err:
            return [1, "", err]
        adt_lib = getattr(module, "AdtLib")()
        device_type = "wireless" if self.device.config.get("wifi") else "ethernet"
        devices_to_list = "\n".join(adt_lib.get_available_devices(device_type))
        return [0, devices_to_list, ""]

    def clear_adt(self, ifname, **kwargs):
        ifname = ifname if ifname else self.get_wlan_iface(skip_exception=True)
        ifname = ifname if ifname else self.get_eth_iface(skip_exception=True)
        self.disconnect(ifname)
        if self.device.config["type"] == "rpi":
            log.info("Rebooting rpi client to fix MAC address issue")
            self.reboot()
            return self.wait_available(timeout=120)
        device_mac = self.get_stdout(self.get_default_mac_address(ifname))
        return self.set_mac(ifname, device_mac, **kwargs)

    def get_default_mac_address(self, ifname, **kwargs):
        cmd = f"ethtool -P {ifname}"
        result = self.run_command(cmd + " | awk '{print $3}'", **kwargs)
        return self.strip_stdout_result(result)

    def restore_mac_address(self, ifname, **kwargs):
        response = self.get_default_mac_address(ifname, **kwargs)
        default_mac = self.get_stdout(response, **kwargs)
        return self.set_mac(ifname, default_mac, **kwargs)

    def check_hackrf_status(self, **kwargs):
        """
        Check if HackRF is installed and connected
        Returns: (list) [ret_code, stdout, stderr]
        """
        return self.run_command("hackrf_info", **kwargs)

    def hackrf_generate_radar_pulse(self, channel, region="us", vector=0, **kwargs):
        """
        Generate radar pulse with HackRF radio connected to the client
        Args:
            channel: (int) channel to generate pulse
            region: (str) eu/us
            vector: (int) 0-4 for us, 0-5 for eu
            **kwargs:

        Returns: (list) [ret_code, stdout, stderr]
        """
        if self.check_hackrf_status()[0]:
            return [1, "", "No HackRf radio found"]
        version = self.get_stdout(
            self.run_command(f"head -n2 {self.get_tool_path()}/radar", **kwargs),
            skip_exception=True,
            **kwargs,
        )
        if "version: 1.0.3" not in version:
            self.deploy()

        ret = self.run_command(
            f"python2 {self.get_tool_path()}/radar -c {channel} -r {region}" f" -v {vector} pulse",
            timeout=35,
            **kwargs,
        )
        return ret

    def get_ble_pair_token(self, serial_id, timeout=180, **kwargs):
        """
        Run a plume_ble_config.py script on a client to get pair token from pointed device.
        Prerequisite: The target device must be in connectable BLE mode.
        Args:
            serial_id: (str) get pair BLE token from pointed device
            timeout: (int) timeout for command execution

        Returns:

        """
        script_output = self.run_command(
            "sudo /tools/bt/plume_ble_config.py "
            f"--scan --connectable --token-change --sn={serial_id} --timeout={timeout}",
            timeout=timeout + 20,
            **kwargs,
        )
        if script_output[0]:
            return script_output

        # Parse output to get only token
        pair_token = re.search("with pairing token\\W+(\\w+)", script_output[1])
        if pair_token is None or not pair_token.groups():
            return [9, "", f"Can not parse pair token from\n{script_output[1]}"]
        script_output[1] = pair_token.group(1)
        return script_output

    def send_cfg_via_ble(self, serial_id, ble_pin, cfg_data, timeout=180, **kwargs):
        """
        Send cfg via plume_ble_config.py script
        Args:
            serial_id: (str)
            ble_pin: (str) can get from custbase: get_ble_pairing_pin()
            cfg_data: (str) json data
            timeout: (int) timeout for command execution

        Returns:

        """
        script_output = self.run_command(
            f"sudo /tools/bt/plume_ble_config.py --sn={serial_id} --passkey={ble_pin} "
            f"--timeout={timeout} -d '{cfg_data}'",
            timeout=timeout + 20,
            **kwargs,
        )
        return script_output

    def move_iface_out_of_network_namespace(self):
        """
        Moves Wi-Fi iface out of network namespace by stopping its service

        Returns: (list) [status, std_out, std_err]

        """
        netns = self.device.config.get("host", {}).get("netns")
        ret = self.run_command(f"sudo systemctl stop {netns}.service")
        return ret

    def get_temperature(self, **kwargs):
        """
        Get current client temperature
        Returns:

        """
        response = self.run_command("cat /sys/class/thermal/thermal_zone0/temp", **kwargs)
        return response

    def get_netns_status(self, **kwargs):
        netns_status = self.run_command(
            f"sudo systemctl status {self.get_client_namespace()}" + " | grep 'Active:'  | awk '{print $2}'",
            skip_ns=True,
            **kwargs,
        )
        return self.strip_stdout_result(netns_status)

    def get_client_namespace(self):
        return self.device.config.get("host", {}).get("netns")

    def recover_namespace_service(self, **kwargs):
        kwargs.pop("skip_ns", False)
        if self.get_wlan_iface(force=True, skip_ns=False, **kwargs):
            return [0, "Network namespace is up and running", ""]

        uptime_result = self.get_stdout(self.uptime(timeout=20, skip_ns=True, **kwargs), skip_exception=True)
        if not uptime_result:
            return [1, "Cannot access the device", "Cannot access the device"]

        log.info("Client has management access even though can not reach client namespace")
        log.info("Try recovery client namespace...")
        client_namespace = self.get_client_namespace()
        if not client_namespace:
            return [0, "", ""]
        # Log namespace status to find True reason what was going on
        namespace_status = self.run_command(f"sudo systemctl status {client_namespace}.service", skip_ns=True, **kwargs)
        log.info(f"Namespace status:\n{namespace_status[1]}")
        # Before restart namespace service make sure wpa-supplicant process is killed
        self.disconnect(ifname="", skip_ns=True, **kwargs)
        self.run_command(f"sudo systemctl restart {client_namespace}.service", skip_ns=True, **kwargs)
        timeout = time.time() + 60
        while timeout > time.time():
            if self.get_stdout(
                self.uptime(timeout=10, skip_ns=False, **kwargs), skip_exception=True
            ) and self.get_wlan_iface(force=True, skip_ns=False, **kwargs):
                return [0, "Network namespace successfully restored", ""]
            time.sleep(2)
        return [2, "Cannot restore network namespace", "Cannot restore network namespace"]

    def check_wireless_client(self):
        if not self.device.config.get("wifi"):
            return True
        return True if self.get_wlan_iface() else False

    def make_dir(self, path, **kwargs):
        response = self.run_command(f"mkdir -p {path}", **kwargs)
        return response

    def remove_dir(self, path, **kwargs):
        response = self.run_command(f"rm -r {path}", **kwargs)
        return response

    def remove_file(self, path, **kwargs):
        return self.remove_dir(path, **kwargs)

    def list_files(self, path, **kwargs):
        response = self.run_command(f"ls -1 {path}", **kwargs)
        if response[0]:
            response[2] = f"{response[1]}\n{response[2]}"
            response[1] = ""
        return response

    def get_pid_by_cmd(self, cmd, **kwargs):
        response = self.run_command(f'ps aux | grep "{cmd}" | grep -v "grep"' + " | awk '{print $2}'", **kwargs)
        if response[0] or not response[1]:
            return response
        response = self.get_stdout(response, **kwargs)
        return [0, response.splitlines()[0], ""]

    def mocha_enable(self, ssid=None, psk=None, ifname=None, bssid=None, key_mgmt=None, **kwargs):
        """
        Connects client(s) to network and generates traffic every 30 minutes.
        Args:
            ssid: ssid
            psk: password
            ifname: interface name
            bssid: bssid if needed
            key_mgmt: WPA-PSK, WPA-EAP, FT-PSK, FT-EAP, SAE, ... or NONE for open network
            **kwargs:
        """
        outputs = []

        wlan_ifname = ifname if ifname else self.get_wlan_iface(**kwargs)

        crontab_cmd = (
            r'crontab -l | { cat; echo "*/30 * * * * '
            r"sudo ip netns exec nswifi1 "
            r"wget --output-document=/tmp/10_mb.txt http://192.168.7.1:8082/10_mb.txt; "
            r'sudo rm /tmp/10_mb.txt"; } | crontab -'
        )

        copy_wpa_conf_cmd = f"sudo cp /tmp/wpa_supplicant_{wlan_ifname}.conf /etc/wpa_supplicant/wpa_supplicant.conf"

        outputs.append(self.connect(ssid, psk, wlan_ifname, bssid, key_mgmt))
        outputs.append(self.run_command(copy_wpa_conf_cmd, skip_ns=True))
        outputs.append(self.run_command(crontab_cmd, skip_ns=True))

        proper_output = [0, "Mocha test mode enabled", ""]

        for output in outputs:
            if output[0] != 0:
                proper_output = output
                break

        return proper_output

    def mocha_disable(self, ifname=None, **kwargs):
        """
        Disconnects client(s) from network and stops automatic traffic.
        Args:
            ifname: interface name
            **kwargs:
        """
        outputs = []

        basic_wpa_supplicant_cfg = """ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
                                      update_config=1
                                      network={
                                               ssid=""
                                               proto=RSN
                                               key_mgmt=WPA-PSK
                                               scan_ssid=1
                                               psk=""
                                               priority=1
                                               #bssid=AA:BB:CC:DD:EE:FF
                                               }"""

        download_and_rm_file_old_cmd = (
            "sudo ip netns exec nswifi1 "
            "wget -o /tmp/10_mb.txt http://192.168.7.1:8082/10_mb.txt; sudo rm /tmp/10_mb.txt"
        )
        download_and_rm_file_new_cmd = (
            "sudo ip netns exec nswifi1 "
            "wget --output-document=/tmp/10_mb.txt http://192.168.7.1:8082/10_mb.txt; sudo rm /tmp/10_mb.txt"
        )

        crontab_rm_old_cmd = f'crontab -l | grep -v "{download_and_rm_file_old_cmd}"  | crontab -'
        crontab_rm_new_cmd = f'crontab -l | grep -v "{download_and_rm_file_new_cmd}"  | crontab -'

        set_basic_wpa_supp_cfg = f'echo "{basic_wpa_supplicant_cfg}" | sudo tee /etc/wpa_supplicant/wpa_supplicant.conf'

        wlan_ifname = ifname if ifname else self.get_wlan_iface(**kwargs)

        outputs.append(self.run_command(crontab_rm_old_cmd, skip_ns=True))
        outputs.append(self.run_command(crontab_rm_new_cmd, skip_ns=True))
        outputs.append(self.run_command(set_basic_wpa_supp_cfg, skip_ns=True))
        outputs.append(self.disconnect(wlan_ifname))
        outputs.append(self.run_command("rm -f ~/10_mb.txt*"))

        proper_output = [0, "Mocha test mode disabled", ""]

        for output in outputs:
            if output[0] != 0:
                proper_output = output
                break

        return proper_output

    def get_client_model(self, **kwargs) -> str:
        cmd = "cat /sys/firmware/devicetree/base/model"

        client_model = self.strip_stdout_result(self.run_command(cmd, **kwargs))

        if client_model[0] != 0:
            client_model = self.get_client_model_from_dmidecode()
        else:
            client_model = self.get_stdout(client_model)

        return client_model

    def get_client_model_from_dmidecode(self, **kwargs) -> str:
        linux_client_map = {
            "GIGABYTE": "Brix",
            "Shuttle Inc.": "Shuttle",
            "Intel Corporation": "NUC",
        }

        cmd = "dmidecode -t 2"

        dmi_output = self.run_command(cmd, **kwargs)

        try:
            manufacturer = re.sub(
                r"Manufacturer: ", "", re.search(r"Manufacturer: .*\n", dmi_output[1]).group(0)
            ).strip()
            client_model = linux_client_map[manufacturer]

        except (KeyError, AttributeError):
            client_model = "Unknown"

        return client_model

    def get_wlan_model(self, **kwargs):
        cmd = "lspci"
        lspci_output = self.run_command(cmd, **kwargs)
        if lspci_output[0]:
            return "unknown"
        if re.search(r"..:.... Network controller: ", lspci_output[1]):
            model = re.sub(
                r"..:.... Network controller: ",
                "",
                re.search(r"..:.... Network controller: .*\n", lspci_output[1]).group(0),
            ).strip()
        else:
            model = re.sub(
                r"..:.... PCI bridge: ", "", re.search(r"..:.... PCI bridge: .*\n", lspci_output[1]).group(0)
            ).strip()

        return model


class ClientIface(Iface):
    pass


class LinuxClientUpgrade:
    lock = Lock()

    def __init__(self, lib):
        self.lib = lib
        self.client_name = self.lib.get_nickname()
        self.upgrade_thread = self.get_upgrade_thread()
        self.current_version = ""

    def get_version(self):
        version = self.lib.version(short=True, skip_logging=True)
        if version[0]:
            return "0.0.0"
        return version[1]

    def get_upgrade_thread(self):
        upgrade_thread = False
        with self.lock:
            tmp_list_dir = self.lib.get_stdout(self.lib.run_command("ls /tmp"), skip_exception=True)
            if "automation" not in tmp_list_dir:
                timeout = 40 + time.time()
                while timeout > time.time():
                    # Create directory for upgrade
                    result = self.lib.run_command(
                        f"mkdir -m 1777 {UPGRADE_DIR}; " f"sudo chown -R $USER:$USER {UPGRADE_DIR}", timeout=10
                    )
                    if result[0] == 0:
                        upgrade_thread = True
                        break
                    time.sleep(5)
                if not upgrade_thread:
                    print(f"Can not create a upgrade directory for {self.client_name}")
        return upgrade_thread

    def download_image(self, fw_path, download_urls):
        expected_files = [file_name.split("/")[-1] for file_name in download_urls]
        with self.lock:
            files_list = os.listdir(fw_path)
            if expected_files[0] not in files_list:
                # TODO: delete unfinished files
                for download_url in download_urls:
                    print(f"Starting downloading the Brix client image from {download_url}")
                    wget_result = os.system(
                        f"wget {download_url} -P {fw_path} --show-progress --progress=bar:force 2>&1"
                    )
                    if wget_result != 0:
                        raise Exception(f"Download {download_url} url finished unsuccessfully")

    def download_image_from_url(self, http_address):
        fw_path = UPGRADE_LOCAL_CACHE_DIR / "upgrade_brix"
        os.makedirs(fw_path, exist_ok=True)
        assert ".deb" in http_address, f"Incorrect file to download. Please provide deb package: {http_address}"
        download_urls = [http_address]
        self.download_image(fw_path, download_urls)
        files_name = [file_name.split("/")[-1] for file_name in download_urls]
        image_name = [file_name for file_name in files_name if re.search(r".deb", file_name)]
        fw_path = os.path.join(fw_path, image_name[0])
        return fw_path

    def wait_for_finish_upgrade(self, target_version):
        # Wait for finish upgrade for the another thread
        timeout = time.time() + 2000
        cur_version = self.get_version()
        while timeout > time.time():
            tmp_list_dir = self.lib.get_stdout(self.lib.run_command("ls /tmp", skip_logging=True), skip_exception=True)
            if "automation" not in tmp_list_dir:
                cur_version = self.get_version()
                if cur_version == target_version:
                    return [0, "Upgrade finished successfully by different namespace client", ""]
                elif cur_version != "0.0.0":
                    break
            time.sleep(20)
        return [
            6,
            "",
            f"Upgrade finished unsuccessfully. " f"Current version: {cur_version}. Expected version: {target_version}",
        ]

    def start_upgrade(self, fw_path=None, force=False, version=None, **kwargs):
        """
        Upgrade Brix client to the target firmware, if fw_path=None download the latest build version from the
        artifactory
        Args:
            fw_path: (str) Path to image
            force: (bool) Flash image even though the same firmware is already on the device
            version: (str) version to download from the artifactory (or get latest or stable version)
            **kwargs:

        Returns: (ret_val, std_out, str_err)

        """
        # make sure that current date is set
        current_date = str(datetime.timestamp(datetime.now())).split(".")[0]
        self.lib.run_command(f"sudo date +%s -s @{current_date}")

        self.current_version = self.get_version()
        if StrictVersion("1.0.3") > StrictVersion(self.current_version):
            return [2, "", "Upgrade is supported > 1.0.3. Upgrade your device manually"]

        if fw_path is None:
            download_url = self.get_latest_brix_upgrade_url(version=version)
            expected_file = download_url.split("/")[-1]
            target_version = re.findall(r"(\d+\.\d+[-,.]\d+)", expected_file)[0]
        else:
            download_url = None
            target_version = re.findall(r"(\d+\.\d+[-,.]\d+)", str(fw_path))[0]

        if StrictVersion(self.current_version) >= StrictVersion(target_version) and force is False:
            return [
                3,
                "",
                f"Target firmware version: {target_version} is the same "
                f"or older as on the device: {self.current_version}.\n"
                f"If you want to downgrade or reinstall the same "
                f"version, run command with force=True.\n",
            ]

        # Wait for finish upgrade for others namespaces on the same device
        if not self.upgrade_thread:
            print("Upgrade already started in different namespace client on same device")
            return self.wait_for_finish_upgrade(target_version)

        # Always clean up after upgrade, regardless if it fails.
        # Other clients might be waiting for us to finish.
        try:
            return self._start_upgrade(fw_path, force, download_url, target_version, **kwargs)
        finally:
            self.lib.run_command(f"rm -rf {UPGRADE_DIR}")

    def _start_upgrade(self, fw_path, force, download_url, target_version, **kwargs):
        if fw_path is None:
            fw_path = UPGRADE_LOCAL_CACHE_DIR / "upgrade_brix"
            expected_file = download_url.split("/")[-1]
            os.makedirs(fw_path, exist_ok=True)
            self.download_image(fw_path, [download_url])
            fw_path = os.path.join(fw_path, expected_file)

        if not fw_path.endswith(".deb"):
            return [11, "", f"Path should specify path to .deb package, not '{fw_path}'"]

        if not os.path.exists(fw_path):
            return [4, "", f"'{fw_path}' .deb upgrade package does not exist"]

        # add route over mgmt iface
        res = self.lib.run_command(
            'sudo sh -c "ip r add default via 192.168.4.1  proto static  metric 100'
            '; echo nameserver 8.8.8.8 | sudo tee /etc/resolv.conf"'
        )
        if res[0]:
            return res

        # first ping sometimes fails in case dead device was removed
        self.lib.ping_check(count=2, fqdn_check=False, v6=False)

        if self.lib.ping_check(count=3, fqdn_check=False, v6=False)[0]:
            return [8, "", f"{self.client_name} has no internet access, upgrade not possible"]

        image_name = fw_path.split("/")[-1]
        print(f'Putting image to "{UPGRADE_DIR}" directory on the {self.client_name} device')
        result = self.lib.put_file(fw_path, UPGRADE_DIR, timeout=30 * 60)
        if result[0] != 0:
            return result

        print("updating package database")
        # Ignore apt-get update failures, Ookla recently broke its old repository, causing apt-get update to fail.
        self.lib.run_command("sudo apt-get -y update", timeout=180, **kwargs)

        upgrade_dir = os.path.join(UPGRADE_DIR, image_name)
        print(f"Upgrading {self.client_name} client to the {target_version} version")
        upgrade_result = self.install_packages(packages=[upgrade_dir], force=force, timeout=1800, **kwargs)
        if upgrade_result[0] != 0:
            return upgrade_result

        # apt-get install doesn't fail if our post-install script fails, so manually check if it succeeded.
        # The last thing our post-install script does is to update the version file, so we can check that.
        cur_version = self.get_version()
        if cur_version != target_version:
            return [
                6,
                upgrade_result[1],
                f"Upgrade finished unsuccessfully. "
                f"Current version: {cur_version}. Expected version: {target_version}",
            ]

        kernel_result = self.upgrade_kernel(force=force, **kwargs)
        upgrade_result = self.lib.merge_result(upgrade_result, kernel_result)
        self.lib.reboot()
        time.sleep(5)
        self.wait_for_reboot()
        return upgrade_result

    def install_packages(self, *, packages, force, timeout, **kwargs):
        reinstall = "--reinstall --allow-downgrades" if force else ""
        packages = " ".join(packages)
        return self.lib.run_command(
            f'sudo DEBIAN_FRONTEND="noninteractive" apt-get -y'
            f' --allow-unauthenticated -o DPkg::Options::="--force-confnew"'
            f" install {reinstall} {packages}",
            timeout=timeout,
            **kwargs,
        )

    def upgrade_kernel(self, *, force, **kwargs):
        packages = self.lib.run_command(f"ls -A1 {KERNEL_DIR}linux-*.deb")[1].split()
        installed_version = self.lib.run_command("uname -r")[1].strip()
        installed_version = "ignore installed version" if force else installed_version
        new_packages = [package for package in packages if installed_version not in package]
        if not new_packages:
            return [0, "", ""]
        print("installing kernel packages")
        return self.install_packages(packages=new_packages, force=force, timeout=180, **kwargs)

    def wait_for_reboot(self):
        time_to_wait = time.time() + 300
        while time.time() < time_to_wait:
            uptime = self.lib.get_stdout(
                self.lib.uptime(out_format="timestamp", skip_logging=True), skip_exception=True
            )
            if uptime:
                uptime = float(uptime)
                uptime = int(uptime / 60)
                if uptime < 5:
                    break
            time.sleep(10)

    def get_latest_brix_upgrade_url(self, build_name="build_debian_packages_brix", version=None):
        """
        Get the latest Brix image
        Args:
            build_name: (str) build name, default: "build_rpi_c_plume"
            version: (str) version to download from the artifactory (or get latest or stable version)

        Returns: (str) Url of brix-upgrade .deb package

        """
        if version is None:
            version = "latest"
        artifactory_url = self.lib.config["artifactory"]["url"]
        project_url = os.path.join(artifactory_url, "api", "build", build_name)
        build_info_url = os.path.join(artifactory_url, "api", "search", "buildArtifacts")
        if version == "latest":
            all_builds = requests.get(project_url)
            all_builds.raise_for_status()
            all_builds = all_builds.json()
            all_builds = [int(build_number["uri"].strip("/")) for build_number in all_builds["buildsNumbers"]]
            last_build = max(all_builds)
        elif version == "stable":
            last_build = int(self.lib.device.config["capabilities"]["fw_version"].split(".")[-1])
        else:
            try:
                last_build = int(version.split(".")[-1])
            except Exception as e:
                log.error(f"Cannot get build number from {version}")
                raise e

        data = '{ "buildName":"' + build_name + '", "buildNumber":"' + str(last_build) + '" }'
        headers = {"Content-Type": "application/json"}
        build_info = requests.post(
            build_info_url,
            headers=headers,
            data=data,
            auth=(self.lib.config["artifactory"]["user"], self.lib.config["artifactory"]["password"]),
        )
        build_info.raise_for_status()
        build_info = build_info.json()
        download_urls = list()
        for build_url in build_info.get("results", []):
            download_url = build_url.get("downloadUri", "")
            if download_url.endswith(".deb"):
                download_urls.append(download_url)
                break
        if len(download_urls) != 1:
            raise RuntimeError(f"couldn't find unambiguous brix-upgrade download url in build_info:\n{build_info}\n")
        return download_urls[0]
