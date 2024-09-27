import re
import time
from typing import Union
from lib_testbed.generic.util.logger import log
import lib_testbed.generic.util.common as common_util
from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.pod.generic.pod_lib import PodLib as PodLibGeneric

MANAGER_RESTART_TIMEOUT = 80  # default for DM Manager, and other non-SM Managers


class PodLib(PodLibGeneric):
    # In whole framework to get temperature we use radio index since prefix of phy radio is the same on qca/brcm
    # MTK platform has different prefix for every phy radio.
    # Therefore, we need to update all calls to temperatures in framework
    # optional
    def get_radio_temperature(self, radio_index, **kwargs):
        ret = self.run_command(f"cat /sys/class/ieee80211/phy{radio_index}/hwmon{radio_index+1}/temp1_input", **kwargs)
        ret[1] = str(int(ret[1]) // 1000)
        return ret

    # optional
    def get_driver_data_rate(self, ifname, mac_address, **kwargs):
        """
        Get current data rate from driver
        Args:
            ifname: (str) Name of interface
            mac_address: (str) MAC address of connected client interface
        Returns: list (ret, stdout, stderr) stdout as (dict) {'data_rate': (str), 'bytes': (int), 'rssi': (list)}

        """
        driver_data_rate = self.run_command(f"iwpriv {ifname} get McsStatsRx={mac_address};dmesg -c", **kwargs)
        if driver_data_rate[0]:
            return driver_data_rate
        data_rate_table = list()
        for line in driver_data_rate[1].splitlines():
            if "bw" not in line:
                continue
            # [ 8105.552000] idx=22   bw=0 nss=1 mcs=7 : avg_snr=0 bytes=0 msdu=0 mpdu=0 ppdu=0 retry=0
            _, _, bw, nss, mcs, _, dbytes, *_ = re.findall(r"(\d+(?:\.\d+)?)", line)
            drate = f"[{bw} {nss} {mcs}]"
            data_rate_table.append({"data_rate": drate, "bytes": dbytes, "rssi": "unknown"})
        driver_data_rate[1] = data_rate_table
        return driver_data_rate

    # mandatory for DFS testing: tests/dfs
    def trigger_single_radar_detected_event(
        self, phy_radio_name, segment_id: int = None, chirp: int = None, freq_offest: int = None, **kwargs
    ):
        """
        Trigger radar detected event
        Args:
            phy_radio_name: (str): Phy radio name
            segment_id: (int): Segment ID - optional
            chirp: (int) Chirp information - optional
            freq_offest: (int) Frequency offset - optional
            **kwargs:

        Returns: list(retval, stdout, stderr)

        """
        if segment_id or chirp or freq_offest:
            raise NotImplementedError

        self.run_command(f"echo -n 1 > /sys/kernel/debug/ieee80211/{phy_radio_name}/mt76/radar_trigger", **kwargs)
        return [0, "", ""]

    # optional
    def get_boot_partition(self, **kwargs):
        """
        Get boot partition name
        Args:
            **kwargs:

        Returns: list(retval, stdout, stderr)
        """
        response = self.run_command(
            "cat /proc/cmdline | awk '{print $NF}' | sed 's/=/ /g' | awk '{print $2}'", **kwargs
        )
        return response

    # mandatory for tests/device/test_07_fcach_flush.py
    def get_connection_flows(self, ip, **kwargs):
        """
        Get connection flow id for specific IP address
        Args:
            ip: (str) IP address
            **kwargs:

        Returns: (list) flow list

        """
        response = self.run_command("cat /proc/net/nf_conntrack | grep OFFLOAD", **kwargs)
        dump = self.get_stdout(response, skip_exception=True)
        if not dump:
            return []
        flows = []
        for line in dump.splitlines():
            # entries has hex address as an id
            if ip in line:
                flows.append(line)
        log.info(f"{self.get_nickname()} flows for {ip}: {flows}")
        return flows

    # mandatory if device supports switching regulatory domains and device has 2 wifi radios
    def set_region_two_radios_model(self, region, **kwargs):
        res = [0, "", ""]
        phy_radios = self.capabilities.get_phy_radio_ifnames(return_type=list)
        for phy_radio in phy_radios:
            res = self.merge_result(res, self.run_command(f"iwpriv {phy_radio} set CountryCode={region}"))
        return res

    # mandatory if device supports switching regulatory domains and device has 3 wifi radios
    def set_region_three_radios_model(self, region, **kwargs):
        res = [0, "", ""]
        phy_radios = self.capabilities.get_phy_radio_ifnames(return_type=list)
        for phy_radio in phy_radios:
            res = self.merge_result(res, self.run_command(f"iwpriv {phy_radio} set CountryCode={region}"))
        return res

    # optional
    def trigger_crash(self, **kwargs):
        """
        Trigger crash on the platform
        Args:
            **kwargs:

        Returns: list [retval, stdout, stderr]

        """
        # close stdout/stderr/stdin, so ssh won't except any data
        result = self.run_command("(echo c > /proc/sysrq-trigger) < /dev/null > /dev/null 2>&1 &", **kwargs)
        time.sleep(20)
        self.wait_available(timeout=120)
        return result

    # optional
    def get_tx_power(self, interface, **kwargs):
        """
        Get current Tx power in dBm
        Args:
            interface: (str) Wireless interface

        Returns: raw output [(int) ret, (std) std_out, (str) str_err]

        """
        self.last_cmd["command"] = "unknown"
        self.last_cmd["name"] = "unknown"
        # Tx power doesn't appear in iwconfig
        return [0, "", ""]

    # MTK doesn't support manipulate of Tx power:
    # root@opensync:~# iwconfig rai0 txpower 11dbm
    # Error for wireless request "Set Tx Power" (8B26) :
    #     SET failed on device rai0 ; Operation not supported.
    # optional
    def decrease_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Decrease value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns:

        """
        self.last_cmd["command"] = "unknown"
        self.last_cmd["name"] = "unknown"
        return [0, "", ""]

    # optional
    def increase_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Increase value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns:

        """
        self.last_cmd["command"] = "unknown"
        self.last_cmd["name"] = "unknown"
        return [0, "", ""]

    # optional
    def set_tx_power(self, tx_power, interfaces=None, **kwargs):
        """
        Set current Tx power in dBm
        Args:
            interfaces: (str) or (list) Name of wireless interfaces
            tx_power: (int) Tx power in dBm.

        Returns:

        """
        self.last_cmd["command"] = "unknown"
        self.last_cmd["name"] = "unknown"
        return [0, "", ""]

    def check_traffic_acceleration(
        self,
        ip_address,
        expected_protocol=6,
        multicast=False,
        flow_count=1,
        flex=False,
        map_t=False,
        dumps=5,
        **kwargs,
    ) -> bool:
        """
        Check traffic was accelerated
        Args:
            ip_address: (list) IP addresses to check
            expected_protocol: (int) expected protocol id. 6 for TCP, 17 for UDP
            multicast: (bool) True to check for acceleration of multicast traffic
            flow_count: (int) minimum number of expected accelerated flows (connections)
            flex: (bool) True to check for acceleration of Flex traffic
            map_t: (bool): True if checking acceleration of MAP-T traffic
            dumps: (int): How many traffic dumps / samples to check
             acceleration data
            **kwargs:

        Returns: bool()

        """
        return self.check_traffic_acceleration_nf_conntrack(
            ip_address=ip_address,
            expected_protocol=expected_protocol,
            multicast=multicast,
            flow_count=flow_count,
            flex=flex,
            map_t=map_t,
            dumps=dumps,
        )

    def get_connection_flows_nf_conntrack(self, ip_addresses: list, **kwargs) -> list:
        response = self.run_command("cat /proc/net/nf_conntrack | grep OFFLOAD", **kwargs)
        nf_conntrack_dump = self.get_stdout(response, skip_exception=True)
        return self.parse_nf_conntrack_flows(nf_conntrack_dump, ip_addresses)

    # TODO: Update this method to parse all relevant values from the flow entry,
    #  then do a cleanup for check_traffic_acceleration_nf_conntrack()
    @staticmethod
    def parse_nf_conntrack_flows(nf_conntrack_dump: str, ip_addresses: list) -> list:
        ip_addresses = [common_util.get_full_ipv6_address(addr) if ":" in addr else addr for addr in ip_addresses]
        connection_flow_list = list()
        for connection_flow in nf_conntrack_dump.splitlines():
            if any(ip_address in connection_flow for ip_address in ip_addresses):
                connection_flow_list.append(connection_flow)
        return connection_flow_list

    def check_traffic_acceleration_nf_conntrack(
        self,
        ip_address,
        expected_protocol=6,
        multicast=False,
        flow_count=1,
        flex=False,
        map_t=False,
        dumps=5,
        nf_conntrack_dump_file: str = None,
        **kwargs,
    ) -> bool:
        """
        Check traffic was accelerated
        Args:
            ip_address: (list) IP addresses to check
            expected_protocol: (int) expected protocol id. 6 for TCP, 17 for UDP
            multicast: (bool) True to check for acceleration of multicast traffic
            flow_count: (int) minimum number of expected accelerated flows (connections)
            flex: (bool) True to check for acceleration of Flex traffic
            map_t: (bool): True if checking acceleration of MAP-T traffic
            dumps: (int): How many traffic dumps / samples to check
            nf_conntrack_dump_file: (str) Path to ecm dump file - if provided then consider this file instead of collecting
             acceleration data
            **kwargs:

        Returns: bool()

        """
        parsed_connections_dump = list()
        if not nf_conntrack_dump_file:
            for i in range(dumps):
                connection_flows = self.get_connection_flows_nf_conntrack(ip_address, **kwargs)
                parsed_connections_dump.extend(connection_flows)
                time.sleep(4)
        else:
            nf_conntrack_dump = self.get_stdout(self.run_command(f"cat {nf_conntrack_dump_file}"))
            parsed_connections_dump.extend(self.parse_nf_conntrack_flows(nf_conntrack_dump, ip_address))

        status = False
        for connection_flow in parsed_connections_dump:
            # Check the protocol
            tcp_or_udp = False  # tcp is false, udp is true
            elements = connection_flow.split(" ")
            for line in elements:
                if "udp" in line:
                    tcp_or_udp = True

            if not tcp_or_udp and expected_protocol == 6:  # tcp
                status = True
            elif tcp_or_udp is True and expected_protocol == 17:  # udp
                status = True

        return status

    def kill_manager(self, wait_for_restart=False, soft_kill=False, **kwargs):
        """
        Kill and restart service managers - Override for MTK, requires 'ps ux', 'kill -11'
        Args:
            wait_for_restart: (bool) wait till manager is started again
            soft_kill: (bool) gently kill the process otherwise use SIGSEGV
            **kwargs:
        Returns: list [retval, stdout, stderr]
        """
        active_managers = self.get_managers_list(**kwargs)
        assert active_managers, "No managers appear to be running"
        for manager in active_managers:
            initial_pid = active_managers[manager]
            kill_cmd = "kill" if soft_kill else "kill -11"
            log.info(f"Killing process for {manager} manger: {kill_cmd} {initial_pid}")
            self.run_command(f"{kill_cmd} {initial_pid}")

            if wait_for_restart:
                time_to_restart = MANAGER_RESTART_TIMEOUT
                if manager == "sm":
                    time_to_restart = self.device.config["capabilities"]["kpi"]["sm_restart"]
                log.info(f"Wait up to {time_to_restart} sec for OpenSync manager restart...")
                time.sleep(time_to_restart)

                log.info(f"Check if {manager} manger has been restarted")
                active_managers = self.get_managers_list(**kwargs)
                new_pid = active_managers.get(manager)
                assert new_pid, f"No managers restarted within timeout period. Active managers:\n{active_managers}"
                assert new_pid != initial_pid, f"{manager} manager has not restarted, PID unchanged: {new_pid}"
                log.info(f"{manager} manager: restart verified")
        return [0, active_managers, ""]

    def get_managers_list(self, managers_name: Union[str, list] = None, **kwargs):
        """
        Get managers list
        Args:
            managers_name: (str) or (list) Get PID number from provided managers if None get list of all managers
            **kwargs:

        Returns: (dict) {manager_name: pid}

        """
        manager_list = dict()
        osp = self.get_stdout(self.get_opensync_path())

        if not managers_name:
            managers_name = self.run_command(f"ls {osp}/bin | awk '/^.*m$/'", **kwargs)[1].split("\n")
        else:
            managers_name = managers_name if isinstance(managers_name, list) else [managers_name]

        manager_paths = [f"{osp}/bin/{manager_name}" for manager_name in managers_name]
        for manager_path in manager_paths:
            matched_processes = self.get_stdout(self.run_command(f"ps | grep {manager_path}", **kwargs)).split("\n")[
                :-1
            ]
            manager_processes = [process_name for process_name in matched_processes if "grep" not in process_name]
            for process in manager_processes:
                manager_pid = [int(pid) for pid in process.split() if pid.isdigit()][0]
                manager_name = manager_path.split("/")[-1]
                manager_list[manager_name] = manager_pid
        return manager_list

    def is_fw_fuse_burned(self, **kwargs):
        """Returns True when device firmware fuse is burned (is locked) and False otherwise."""
        response = self.run_command("pmf -fuse verify", **kwargs)
        match = re.search(r"(Secure[_-][bB]oot)(\ *\w+\s+)(:\sERROR NOT SET)", self.get_stdout(response, **kwargs))
        return match is None

    def get_client_snr(self, ifname: str, client_mac: str, **kwargs) -> [int, str, str]:
        """
        Get SNR level of the connected client.
        Args:
            ifname: (str) Name of interface where is associated a client
            client_mac: (str) Client mac address
            **kwargs:

        Returns: [int, str, str]

        """
        cmd = (
            f"noise=`iw dev {ifname} survey dump | awk '/noise/ "
            + "{print $2}' | head -n 1`;"
            + f" rssi=`iw {ifname} station get {client_mac} | awk '/signal avg/"
            + " {print $3}'`; echo `expr $rssi - $noise`"
        )

        output = self.run_command(cmd, **kwargs)
        return self.strip_stdout_result(output)

    def run_traffic_acceleration_monitor(self, samples: int = 5, interval: int = 5, delay: int = 20, **kwargs) -> dict:
        """
        Start making traffic acceleration statistics dumps on the pod in the background
        Args:
            samples: (int) number of statistic dumps
            interval: (int) seconds apart
            delay: (int) seconds after the method is called.
            **kwargs:

        Returns: Return (dict) dict(sfe_dump=dict(dump_file="", pid="")) Acceleration statistics dumps details.

        """
        return self._run_traffic_acceleration_monitor(
            acc_name="nf_conntrack",
            acc_tool="cat /proc/net/nf_conntrack | grep OFFLOAD",
            samples=samples,
            interval=interval,
            delay=delay,
        )

    def check_traffic_acceleration_dump(
        self,
        acceleration_dump: dict,
        ip_address: list,
        expected_protocol: int = 6,
        multicast: bool = False,
        flow_count: int = 1,
        flex: bool = False,
        map_t: bool = False,
        **kwargs,
    ) -> bool:
        """
        Check traffic was accelerated
        Args:
            acceleration_dump: (dict) Acceleration dump details from run_traffic_acceleration_monitor()
            ip_address: (list) IP addresses to check
            expected_protocol: (int) expected protocol id. 6 for TCP, 17 for UDP
            multicast: (bool) True to check for acceleration of multicast traffic
            flow_count: (int) minimum number of expected accelerated flows (connections)
            flex: (bool) True to check for acceleration of Flex traffic
            map_t: (bool): True if checking acceleration of MAP-T traffic
            **kwargs:

        Returns: bool()

        """
        acceleration_status = True
        for acc_name, acc_monitor_details in acceleration_dump.items():
            acc_dump_file = acc_monitor_details["dump_file"]
            match acc_name:
                case "nf_conntrack":
                    acceleration_status &= self.check_traffic_acceleration_nf_conntrack(
                        ip_address=ip_address,
                        expected_protocol=expected_protocol,
                        multicast=multicast,
                        flow_count=flow_count,
                        flex=flex,
                        map_t=map_t,
                        nf_conntrack_dump_file=acc_dump_file,
                    )
                case _:
                    raise OpenSyncException(
                        f"Unknown acceleration tool: {acc_name}. Allowed tools for MTK: nf_conntrack"
                    )
        return acceleration_status

    def get_client_tx_rate(self, ifname: str, client_mac: str, **kwargs):
        """
        Get SNR level of the connected client.
        Args:
            ifname: (str) Name of interface where is associated a client
            client_mac: (str) Client mac address
            **kwargs:
        Returns: int
        """
        cmd = f"iw dev {ifname} station get {client_mac} " '| awk "/tx bytes/{{printf "%f", $3 * 8 / 10**6}}"'

        output = self.run_command(cmd, **kwargs)
        return output

    def get_client_pmk(self, client_mac, **kwargs):
        iface_list = " ".join(self.capabilities.get_home_ap_ifnames(return_type=list))
        cmd = (
            f"sh -c 'for iface in {iface_list}; do hostapd_cli -i $iface "
            f"-p /var/run/hostapd-$(cat /sys/class/net/$iface/phy80211/name) pmksa | grep {client_mac} "
            f"| cut -c 21-52 | grep -v FAIL; done'"
        )
        # due to many ifaces ret code might be invalid
        pmk = self.get_stdout(self.strip_stdout_result(self.run_command(cmd, **kwargs)), skip_exception=True)
        return [0 if pmk else 1, pmk, f"No PMK for {client_mac}" if not pmk else ""]
