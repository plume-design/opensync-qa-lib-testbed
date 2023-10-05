import os
import json
import traceback
from typing import TYPE_CHECKING

from lib_testbed.generic.pod.pod import Pod
from lib_testbed.generic.util import config
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.opensyncexception import OpenSyncException


class PodTool:
    def __init__(self, lib):
        """Class representing the pod tool."""
        self.lib = lib
        if TYPE_CHECKING:
            from lib_testbed.generic.pod.generic.pod_lib import PodLib

            self.lib = PodLib()

    def get_name(self):
        return self.lib.get_name()

    def list(self, **kwargs):
        """List all configured pods"""
        return self.lib.shell_list(**kwargs)

    def run(self, command, *args, **kwargs):
        """Run a command. Print out exit code, stdout and stderr

        Example: pod gw "ls -al"

        :return: list of stdout"""
        result = self.lib.run_command(command, *args, retry=False, **kwargs)
        return self.lib.strip_stdout_result(result)

    def ssh(self, params="", **kwargs):
        """Start interactive ssh session.

        Optionally the argument params is a command to be executed. If a
        command is specified as params, then stdout is printed out"""
        return self.lib.ssh(params, retry=False, **kwargs)

    def version(self, **kwargs):
        """Display firmware version of node(s)"""
        return self.lib.version(retry=False, **kwargs)

    def reboot(self, **kwargs):
        """Reboot node(s)"""
        return self.lib.reboot(retry=False, **kwargs)

    def ping(self, host=None, **kwargs):
        """Ping given host. If no host is given, then the pod pings itself."""
        return self.lib.ping(host, retry=False, **kwargs)

    def ping_check(self, ipaddr: str = "", count: int = 1, fqdn_check: bool = False, v6: bool = False, **kwargs):
        """Check client(s) wireless connectivity (ICMP).

        The default address for is 8.8.8.8 for v4 and google.com for v6.
        Optional fqdn_check is performed - the information about it is
        displayed in the debug mode (-D flag)."""
        return self.lib.ping_check(count=count, fqdn_check=fqdn_check, v6=v6, ipaddr=ipaddr, retry=False, **kwargs)

    def uptime(self, **kwargs):
        """Get uptime from pod(s)"""
        return self.lib.uptime(retry=False, **kwargs)

    def get_file(self, remote_pth: str, local_pth: str, **kwargs):
        """Copy a file/directory from node(s) using scp"""
        return self.lib.get_file(remote_pth, local_pth, **kwargs)

    def put_file(self, local_pth: str, remote_pth: str, **kwargs):
        """Copy a file/directory onto device(s) using scp"""
        return self.lib.put_file(local_pth, remote_pth, **kwargs)

    def deploy(self, **kwargs):
        """Deploy files to node(s)"""
        return self.lib.deploy(**kwargs)

    def restart(self, **kwargs):
        """Restart managers on node(s)"""
        return self.lib.restart(**kwargs)

    def check(self, **kwargs):
        """Pod health check"""
        return self.lib.check(**kwargs)

    def enable(self, **kwargs):
        """Enable agent and wifi radios on node(s)"""
        return self.lib.enable(**kwargs)

    def disable(self, **kwargs):
        """Disable agent and wifi radios on node(s)"""
        return self.lib.disable(**kwargs)

    def info(self):
        """Node connection information"""
        return self.lib.info()

    def get_model(self, **kwargs):
        """Get node(s) model"""
        return self.lib.get_model(retry=False, **kwargs)

    def bssid(self, bridge: str = "", **kwargs):
        """Display BSSID of node bridge = <br-wan|br-home>-, default both"""
        result = self.lib.bssid(bridge, retry=False, **kwargs)
        if not result[0]:
            all_macs = result[1].split("\n")
            ifname_mac = ""
            for mac in all_macs:
                ifname = self.lib.ovsdb.get_str(
                    table="Wifi_VIF_State", select="if_name", where=[f"mac=={mac}"], retry=False
                )
                ifname_mac += f"{ifname}: {mac}\n"
            result[1] = ifname_mac
        return result

    def get_serial_number(self, **kwargs):
        """Get node(s) serial number"""
        return self.lib.get_serial_number(retry=False, **kwargs)

    def connected(self, **kwargs):
        """Returns cloud connection state"""
        return self.lib.connected(retry=False, **kwargs)

    def get_ovsh_table_tool(self, table: str, **kwargs):
        """Get ovsh table from pods locally tool format. Table name
        must be provided, e.g. AWLAN_Node."""
        return self.lib.get_ovsh_table_tool(table, retry=False, **kwargs)

    def start_wps_session(self, if_name: str = None, psk: str = None, *args, **kwargs):
        """Start WPS session.

        If interface name is not provided, then the first interface
        from a list is taken."""
        if if_name is None:
            if_name = [iface for iface in self.lib.iface.get_all_home_bhaul_ifaces() if "home" in iface][0]

        key = None
        wps_keys = self.lib.get_wps_keys(if_name, retry=False, **kwargs)
        if psk is None:
            key = list(wps_keys.items())[0][0]
        else:
            for k, v in wps_keys.items():
                if psk == v:
                    key = k
                    break

        if psk is not None and key is None:
            for k, v in wps_keys.items():
                if psk == k:
                    key = k
                    break

        if key is None:
            raise Exception(f'Psk "{psk}" is not set on the pod.')

        result = self.lib.start_wps_session(if_name=if_name, key_id=key, retry=False, **kwargs)
        return [0 if result else 1, str(result), ""]

    def wait_available(self, timeout=5, **kwargs):
        """Wait for device(s) to become available"""
        return self.lib.wait_available(int(timeout), **kwargs)

    def role(self):
        """Node role: return gw or leaf"""
        return self.lib.role()

    def get_logs(self, directory=None):
        """Download logs from pod(s).

        Optionally provide a directory to store the logs."""
        return self.lib.get_logs(directory)

    def upgrade(self, image, *args, **kwargs):
        """Upgrade node firmware, Optional: -p=<encyp_key>, -e-> erase certificates, -n->skip version check

        Upgrading from file:
                    pod <gw|l1|l2|all> upgrade <image_location> <optional>
        Upgrading from artifactory:
            Newest version:
                    pod <gw|l1|l2|all> upgrade <version|master|native-version> <optional>
                        eg.
                            pod gw upgrade master
                            pod all upgrade 4.2.0
                            pod gw upgrade native-5.8.0

            Requested build:
                    pod <gw|l1|l2|all> upgrade <version|master|fbb|native-version>-<build_num> <optional>
                        e.g.
                            pod all upgrade master-1777
                            pod l1 upgrade 4.2.0-15
                            pod gw upgrade fbb-13422
                            pod gw upgrade native-5.8.0-12
        """
        custbase = None
        deployment_file = None
        try:
            loc_deployment = config.get_deployment(self.lib.config)
            deployment_file = config.find_deployment_file(loc_deployment)
        except (KeyError, OpenSyncException):
            log.info("Could not get deployment")
        if deployment_file:
            self.lib.config["deployment_file"] = deployment_file
            self.lib.config[config.TBCFG_PROFILE] = os.path.basename(deployment_file).split(".")[0]
            deployment_data = config.load_file(deployment_file)
            if deployment_data:
                config.update_config_with_admin_creds(deployment_data)
                self.lib.config = config.merge(self.lib.config, deployment_data)
        try:
            from lib.cloud.custbase import CustBase

            custbase = CustBase(self.lib.config)
        except (ModuleNotFoundError, OpenSyncException):
            pass
        if custbase:
            try:
                custbase.initialize()
                custbase.clear_target_matrix()
            except Exception:
                pass
        return self.lib.upgrade(image, *args, **kwargs)

    def recover(self):
        """Recover pod to allow management access"""
        prev_log_level = log.getEffectiveLevel()
        log.setLevel(log.DEBUG)
        result = self.lib.recover()
        log.setLevel(prev_log_level)
        return result

    def sanity(self, *args):
        """Run sanity on selected pods, add arg --nocolor for simple output"""

        def print_sanity_output(sanity_out):
            """
            User-friendly sanity output print
            Args:
                sanity_out: dict from node_sanity
            """
            from termcolor import colored

            if sanity_out["gw_pod"]:
                print(f"GW pod: {sanity_out['gw_pod']}")
            for i in range(len(sanity_out["serial"])):
                print(f"Sanity check for: {sanity_out['serial'][i]}")
                for line in sanity_out["out"][i]:
                    if line[1] == "INFO":
                        level = colored(line[1], "green")
                    elif line[1] == "Warning":
                        level = colored(line[1], "yellow")
                    elif line[1] == "ERROR":
                        level = colored(line[1], "red", attrs=["bold", "blink"])
                    else:
                        level = colored(line[1], "white")
                    tname = colored(line[0], "magenta")
                    message = colored(line[2], "white")
                    print(f"{tname: >25}- {level: <12}: {message}")
                print(" ")

        resposne = self.lib.sanity("--lib", *args)
        print_sanity_output(resposne)
        status = 1 if not resposne["ret"] else 0
        return [status, resposne["health"], ""]

    def get_crash(self):
        """Get crash log file from node"""
        return self.lib.get_crash()

    def get_ips(self, iface):
        """Get ipv4 and ipv6 address for desired interface"""
        return self.lib.get_ips(iface, retry=False)

    def set_region(self, region, **kwargs):
        """Set DFS regional domain (EU, US, UK, CA, JP, KR, PH, AU) (for Caesar, also: NZ, SG, IL, HK)"""
        return self.lib.set_region(region=region, retry=False, **kwargs)

    def get_region(self, **kwargs):
        """Get DFS regional domain"""
        return self.lib.get_region(retry=False, **kwargs)

    def trigger_radar(self, **kwargs):
        """Trigger radar event"""
        return self.lib.trigger_radar_detected_event(retry=False, **kwargs)

    def simulate_clients(self, count=1, **kwargs):
        """Simulate ethernet clients"""
        if isinstance(count, str):
            count = int(count)
        return self.lib.simulate_clients(count, **kwargs)

    def local_mqtt_broker(self, **kwargs):
        """Redirect stats to local mqtt broker"""
        return self.lib.redirect_stats_to_local_mqtt_broker(skip_storage=True, **kwargs)

    def get_radio_temperatures(self, **kwargs):
        """Get radio temperatures from device"""
        radio_idxs = self.lib.capabilities.get_wifi_indexes()
        radio_temps = []
        for radio_band, radio_idx in radio_idxs.items():
            radio_temp = self.lib.get_stdout(
                self.lib.strip_stdout_result((self.lib.get_radio_temperature(radio_idx, **kwargs)))
            )
            radio_temps.append(f"{radio_band}: {radio_temp}°C")
        temp_to_print = "\n".join(radio_temps)
        return [0, temp_to_print, ""]

    def get_wano_config(self, **kwargs):
        """Get WANO configuration from node, in JSON format."""
        return self.lib.get_wano_cfg(retry=False, **kwargs)

    def set_wano_config(self, config, **kwargs):
        """Set WANO configuration on node. Config needs to be in JSON format."""
        try:
            wano_cfg = json.loads(config)
        except Exception:
            return [1, "", traceback.format_exc()]
        return self.lib.set_wano_cfg(wano_cfg, **kwargs)

    def list_builds(self, requested_version):
        """List of builds of desired version

        pod <gw|l1|l2|all> list-builds <version|master|native-version>
        eg.
            pod gw list-builds 4.2.0
            pod l1 list-builds master
            pod l1 list-builds native-5.8.0
        """
        return self.lib.list_builds(requested_version)

    def is_fuse_burned(self):
        """Checks if device firmware fuse is burned.

        True - firmware fuse is burned (is locked), False - firmware fuse is not burned (is unlocked)."""
        is_fuse = self.lib.is_fw_fuse_burned(retry=False)
        return [0, str(is_fuse), ""]

    def eth_connect(self, pod_name, **kwargs):
        """Connect Specified pod to Ethernet pod."""
        return self.lib.eth_connect(pod_name=pod_name)

    def eth_disconnect(self, **kwargs):
        """Disconnect pod from Ethernet ports."""
        return self.lib.eth_disconnect()
