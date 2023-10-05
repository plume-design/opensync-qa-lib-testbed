import functools
import itertools
import json
import re
import time

import yaml

from lib_testbed.generic.util.logger import log
import lib_testbed.generic.util.common as common_util
from lib_testbed.generic.pod.generic.pod_lib import PodLib as PodLibGeneric

FLOW_CACHE_ENTRY_SDK_5_02 = re.compile(
    r"""
    ^(?P<flow_addr>(0x)?[a-f\d]+)           # flow address \  Flow
    @(?P<flow_id>\d+)\s+                    # @flow id     /  Object
    (?P<idle>\d+):\s*                       # idle:
    (?P<swhit>\d+)\s+                       # +swhit
    (?P<SW_TotHits>\d+):\s*                 # SW_TotHits:
    (?P<TotalBytes>\d+)\s+                  # TotalBytes
    (?P<HW_tpl>0x[a-f\d]+)\s+               # HW_tpl
    (?P<Fhw_idx>\d+)\s+                     # Fhw_idx
    (?P<HW_TotHits>\d+)\s+                  # HW_TotHits
    (?P<DlConntrack>[(\w\d)]+)\s+           # DlConntrack
    (?P<PdConntrack>[(\w\d)]+)\s+           # PdConntrack
    (?P<L1>\w+)\s+                          # L1-
    (?P<Info>\d+)\s+                        # Info
    (?P<Prot>\d+)\s+                        # Prot
    <(?P<src_addr_port>[a-f.:\d]+)>\s*      # SourceIpAddress:Port
    <(?P<dst_addr_port>[a-f.:\d]+)>\s+      # DestinIpAddress:Port
    (?P<Vlan0>0x[a-f\d]+)\s+                # Vlan0(mcast)
    (?P<Vlan1>0x[a-f\d]+)\s+                # Vlan1(mcast)
    (?P<tag>\d+)\s+                         # tag#
    (?P<IqPrio>\d+)\s+                      # IqPrio
    (?P<SkbMark>0x[a-f\d]+)                 # SkbMark
    # nflist has two more fields, TCP_PURE_ACK and LLC, while mcastlist has a bunch more,
    # but the latter writes those extra fields as a separate line, so we just ignore them.
    """,
    re.VERBOSE | re.MULTILINE,
)

FLOW_CACHE_ENTRY_SDK_5_04 = re.compile(
    r"""
    ^\s*
    (?P<flow_id>\d+)\s+                     # Flow
    (?P<U_M>[UM-])\s+                       # U/M, mostly guessing what we'll see here
    (?P<M_C>[MC-])\s+                       # M/C, mostly guessing what we'll see here
    (?P<idle>\d+):\s*                       # idle:
    (?P<swhit>\d+)\s+                       # +swhit
    (?P<SW_TotHits>\d+):\s*                 # SW_TotHits:
    (?P<TotalBytes>\d+)\s+                  # TotalBytes
    (?P<HW_tpl>0x[a-f\d]+)\s+               # HW_tpl
    (?P<Fhw_idx>\d+)\s+                     # Fhw_idx
    (?P<HW_Hits>\d+)\s+                     # HW_Hits
    (?P<HW_TotHits>\d+)\s+                  # HW_TotHits
    (?P<L1>\w+)\s+                          # L1-
    (?P<Info>\d+)\s+                        # Info
    (?P<Prot>\d+)\s+                        # Prot
    <(?P<src_addr_port>[a-f.:\d]+)>\s*      # SourceIpAddress:Port
    <(?P<dst_addr_port>[a-f.:\d]+)>\s+      # DestinIpAddress:Port
    (?P<Vlan0>0x[a-f\d]+)\s+                # Vlan0(mcast)
    (?P<Vlan1>0x[a-f\d]+)\s+                # Vlan1(mcast)
    (?P<tag>\d+)\s+                         # tag#
    (?P<ToS>[a-f\d]+)\s+                    # ToS
    (?P<IqPrio>\d+)\s+                      # IqPrio
    (?P<SkbMark>0x[a-f\d]+)                 # SkbMark
    # nflist has eight more fields, while mcastlist has a bunch more, but they are not shared
    # and the latter writes those extra fields as a separate line, so we just ignore them.
    """,
    re.VERBOSE | re.MULTILINE,
)


class PodLib(PodLibGeneric):
    def get_radio_temperature(self, radio_index, **kwargs):
        ret = self.run_command(f"wl -i wl{radio_index} phy_tempsense", **kwargs)
        # example output: "70 (0x46)"
        ret[1] = ret[1].split(" ")
        ret[1] = ret[1][0] if len(ret[1]) == 2 else "-1"
        return ret

    def get_tx_power(self, interface, **kwargs):
        """
        Get current Tx power in dBm
        Args:
            interface: (str) Wireless interface

        Returns: raw output [(int) ret, (std) std_out, (str) str_err]

        """
        cmd = "wl -i %s txpwr | awk '{print $1}'" % interface
        response = self.strip_stdout_result(self.run_command(cmd, **kwargs))
        return response

    def decrease_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Decrease value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns:

        """
        percent_ratio = percent_ratio / 100
        all_interfaces = self.iface.get_all_home_bhaul_ifaces()
        cmd = ""
        for interface in all_interfaces:
            current_tx_power = float(self.get_stdout(self.get_tx_power(interface)))
            expect_tx_power = int(current_tx_power - (current_tx_power * percent_ratio))
            if expect_tx_power < 2:
                expect_tx_power = 2
            cmd += f"wl -i {interface} txpwr1 {expect_tx_power}; "
        response = self.run_command(cmd, **kwargs)
        return response

    def increase_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Increase value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns:

        """
        percent_ratio = percent_ratio / 100
        all_interfaces = self.iface.get_all_home_bhaul_ifaces()
        cmd = ""
        for interface in all_interfaces:
            current_tx_power = float(self.get_stdout(self.get_tx_power(interface)))
            expect_tx_power = int(current_tx_power + (current_tx_power * percent_ratio))
            cmd += f"wl -i {interface} txpwr1 {expect_tx_power}; "
        response = self.run_command(cmd, **kwargs)
        return response

    def set_tx_power(self, tx_power, interfaces=None, **kwargs):
        """
        Set current Tx power in dBm
        Args:
            interfaces: (str) or (list) Name of wireless interfaces
            tx_power: (int) Tx power in dBm.

        Returns:

        """
        if not interfaces:
            interfaces = self.iface.get_all_home_bhaul_ifaces()
        if isinstance(interfaces, str):
            interfaces = [interfaces]
        cmd = ""
        for interface in interfaces:
            cmd += f"wl -i {interface} txpwr1 {tx_power}; "
        response = self.run_command(cmd, **kwargs)
        return response

    def get_client_tx_rate(self, ifname, client_mac, **kwargs):
        result = self.run_command(f"wl -i {ifname} sta_info {client_mac}")
        std_out_lines = result[1].splitlines()
        for i, line in enumerate(std_out_lines):
            if "rx nrate" not in line:
                continue
            # TX Rate entry appears in a next line
            tx_rate_entry = std_out_lines[i + 1]
            result[1] = re.search(r"\d+", tx_rate_entry).group()
            break
        return result

    def get_driver_data_rate(self, ifname, mac_address, **kwargs):  # noqa
        ht_data_rate = [
            13500,
            27000,
            40500,
            54000,
            81000,
            108000,
            121500,
            135000,
            27000,
            54000,
            81000,
            108000,
            162000,
            216000,
            243000,
            270000,
        ]
        data_rate_table = []
        result = self.run_command(f"wl -i {ifname} sta_info {mac_address}", **kwargs)
        drate = ""
        dbytes = ""
        rssi = ""
        if result[0]:
            return result

        rx_rate = False
        last_rate = 1000
        for line in result[1].splitlines():
            if "rate of last rx pkt:" in line:
                last_rate = int(line.split(":")[1].split()[0].strip())
                continue
            if "rx nrate" in line:
                rx_rate = True
                continue
            if rx_rate:
                rx_rate = False  # noqa
                if "legacy rate" in line:
                    drate = line[line.index("legacy rate") + len("legacy rate") : line.index("Mbps")].strip() + "M"
                elif "vht" in line:
                    mcs = int(line[line.index("mcs") + len("mcs") : line.index("Nss")].strip())
                    mcs = mcs % 8
                    nss = int(line[line.index("Nss") + len("Nss") : line.index("Tx")].strip())
                    bw = line.split()[[i for i, s in enumerate(line.split()) if "bw" in s][0]].replace("bw", "")
                    if bw == "20":
                        bw = 0
                    elif bw == "40":
                        bw = 1
                    elif bw == "80":
                        bw = 2
                    else:
                        bw = 3
                    drate = f"[{bw} {nss} {mcs}]"
                elif "mcs index" in line:
                    mcs_raw = int(line[line.index("index") + len("index") : line.index("stf")].strip())
                    mcs = mcs_raw % 8
                    mod = int(line.split()[[i for i, s in enumerate(line.split()) if "mode" in s][0] + 1])
                    if mod == 0:
                        nss = 1
                    elif mod == 3:
                        nss = 2
                    else:
                        nss = 8
                    if last_rate < ht_data_rate[mcs_raw]:
                        bw = 0
                    else:
                        bw = 1
                    drate = f"[{bw} {nss} {mcs}]"
                break
            if "rx data bytes" in line:
                dbytes = int(line.split(":")[1].strip())
                continue
            if "per antenna average rssi of rx data frames:" in line:
                rssi = line.split(":")[1].strip().split()
        data_rate_table.append({"data_rate": drate, "bytes": dbytes, "rssi": rssi})
        result[1] = data_rate_table
        return result

    def trigger_single_radar_detected_event(self, phy_radio_name, **kwargs):
        """
        Trigger radar detected event
        Args:
            phy_radio_name: (str): Phy radio name
            **kwargs:

        Returns: list(retval, stdout, stderr)

        """
        ret_1 = self.run_command(f"wl -i {phy_radio_name} radar 1", **kwargs)
        ret_2 = self.run_command(f"wl -i {phy_radio_name} radar 2", **kwargs)
        # any resp with 0 is a success
        for i, ret in zip(range(1, 3), [ret_1, ret_2]):
            log.info(f"Response for radar against {phy_radio_name} radar {i} -> {ret}")
        response = ret_2 if ret_1[0] else ret_1
        return response

    def get_boot_partition(self, **kwargs):
        """
        Get boot partition name
        Args:
            **kwargs:

        Returns: list(retval, stdout, stderr)

        """
        response = self.run_command('bcm_bootstate | grep "Booted Partition" | sed "s/.*://"', **kwargs)
        return response

    def trigger_crash(self, **kwargs):
        """
        Trigger crash on the platform
        Args:
            **kwargs:

        Returns: list [retval, stdout, stderr]

        """
        # ends immediately with crash and reboot, so sleep here otherwise command ends with timeout exception
        result = self.run_command("sh -c 'sleep 3; echo c > /proc/sysrq-trigger' > /dev/null 2>&1 &", **kwargs)
        time.sleep(20)
        self.wait_available(timeout=120)
        return result

    def get_connection_flows(self, ip, **kwargs):
        """
        Get connection flow id for specific IP address
        Args:
            ip: (str) IP address
            **kwargs:

        Returns: (list) flow list

        """
        # bcm always uses 3 digits for IP, ex 192.168.200.24 is 192.168.200.024
        out_ip = [f"{int(value):03d}" for value in ip.split(".")]
        out_ip = ".".join(out_ip)

        br_list = self.run_command("cat /proc/fcache/brlist", **kwargs)
        nf_list = self.run_command("cat /proc/fcache/nflist", **kwargs)
        response = self.merge_result(br_list, nf_list)
        dump = self.get_stdout(response, **kwargs)
        if not dump:
            return []
        flows = []
        for line in dump.splitlines():
            # skip title bar
            if line.startswith("Flow"):
                continue
            if out_ip in line:
                flows.append(line.split()[0])
        log.info(f"{self.get_nickname()} flows for {ip}: {flows}")
        return flows

    def set_region(self, region, **kwargs):
        if not self.capabilities.is_regulatory_domain_managed():
            log.error("Model does not support changing region")
            return [1, "", "Model does not support region modifications"]
        num_of_radios = len(self.capabilities.get_phy_radio_ifnames(return_type=list))
        if not 2 <= num_of_radios <= 3:
            raise Exception(f"DUT with {num_of_radios} is not supported")

        match [region, num_of_radios]:
            case ["EU", 2]:
                region = ("E0", "EU")
                rev_num = (914, 13)
            case ["EU", 3]:
                region = "E0"
                rev_num = 763
            case ["US", (2 | 3)]:
                rev_num = 0
            case ["UK", 2]:
                region = "GB"
                rev_num = 0
            case ["UK", 3]:
                region = "GB"
                rev_num = 36
            case ["CA", 2]:
                rev_num = 860
            case ["CA", 3]:
                rev_num = 886
            case ["JP", 2]:
                rev_num = 879
            case ["JP", 3]:
                rev_num = 914
            case ["KR", (2 | 3)]:
                rev_num = 936
            case ["KW", 3]:
                rev_num = 763
            case ["PH", (2 | 3)]:
                rev_num = 990
            case ["AU", (2 | 3)]:
                rev_num = 912
            case _:
                raise AssertionError(
                    f"Region {region} is not supported! Supported regions: EU, US, UK, CA, JP, KR, KW, PH, AU."
                )

        self.enter_factory_mode(**kwargs)
        try:
            log.info(f"Set {region} region for node {self.get_nickname()}")
            res = [0, "", ""]
            for radio_id in range(num_of_radios):
                region = region[radio_id] if isinstance(region, tuple) else region
                res = self.merge_result(res, self.run_command(f"pmf -ccode{radio_id} -fw {region}"))

            for reg_revision in range(num_of_radios):
                rev_num = rev_num[reg_revision] if isinstance(rev_num, tuple) else rev_num
                self.run_command(f"pmf -regrv{reg_revision} -fw {rev_num}")
            self.run_command("pmf --commit")
        finally:
            self.exit_factory_mode(**kwargs)
        timeout = time.time() + 120
        while time.time() < timeout:
            if self.run_command("pmf -r -ccode0")[1]:
                break
            time.sleep(2)
        else:
            assert False, "Cannot get country code information after reboot"

        for radio_id in range(num_of_radios):
            assert region in self.run_command(f"pmf -r -ccode{radio_id}")[1]
        return res

    def _get_archer_flows(self, ip_addresses, **kwargs):
        """
        Get Archer connection flow dump from device

        Args:
            ip_addresses: (list of str) limit flows to those coming from or going to specified addresses
            **kwargs:

        Returns: (list of str) list of connection flows

        """
        connection_flows = self.run_command("dmesg -c > /dev/null && archer flows --all && dmesg -c", **kwargs)
        connection_flows = self.get_stdout(connection_flows, skip_exception=True)
        if not connection_flows:
            return []
        connection_flows = connection_flows.split("***** FLOW *****")[1:]
        ip_addresses = {self.parse_ip_address_for_accelerator(ip_address) for ip_address in ip_addresses}
        connection_flow_list = list()
        for connection_flow in connection_flows:
            if not any(ip_address in connection_flow for ip_address in ip_addresses):
                continue
            connection_flow_list.append(connection_flow)
        return connection_flow_list

    @functools.cached_property
    def flow_cache_entry(self):
        """
        Return regular expression pattern matching common FlowCache entry fields
        """
        result = self.run_command("cat /etc/patch.version")
        contents = self.get_stdout(result)
        sdk_version = yaml.safe_load(contents)
        if sdk_version["version"] >= "5" and sdk_version["release"] >= "04":
            return FLOW_CACHE_ENTRY_SDK_5_04
        else:
            return FLOW_CACHE_ENTRY_SDK_5_02

    def _get_parsed_connection_flows(self, ip_addresses, multicast=False, **kwargs):
        """
        Get flow cache entries from pod and parse them into dicts

        Args:
            ip_adresses: (list of str) limit flows to those coming from or going to specified addresses
            multicast: (bool) look for multicast traffic flows
            **kwargs:

        Returns: (list of dict) connection flows parsed into dicts with keys matching cache flow column headers
        """
        if multicast:
            cmd = "cat /proc/fcache/misc/mcastlist"
        else:
            cmd = "cat /proc/fcache/nflist /proc/fcache/brlist"
        for _ in range(3):
            cached_flows = self.run_command(cmd)
            cached_flows = self.get_stdout(cached_flows, skip_exception=True)
            if cached_flows:
                break
        else:
            return []
        ip_addresses = {self.parse_ip_address_for_accelerator(ip_address) for ip_address in ip_addresses}
        cached_flow_list = list()
        for line in cached_flows.splitlines():
            match = self.flow_cache_entry.match(line)
            if match is None:
                continue
            cached_flow = match.groupdict()
            cached_flow["src_addr"], cached_flow["src_port"] = cached_flow["src_addr_port"].rsplit(":", 1)
            cached_flow["dst_addr"], cached_flow["dst_port"] = cached_flow["dst_addr_port"].rsplit(":", 1)
            if cached_flow["src_addr"] not in ip_addresses and cached_flow["dst_addr"] not in ip_addresses:
                continue
            for decimal_field in (
                "flow_id",
                "idle",
                "swhit",
                "SW_TotHits",
                "TotalBytes",
                "Fhw_idx",
                "HW_TotHits",
                "Info",
                "Prot",
                "src_port",
                "dst_port",
                "tag",
                "IqPrio",
            ):
                cached_flow[decimal_field] = int(cached_flow.get(decimal_field, "0"), 10)
            for hexadecimal_field in ("flow_addr", "HW_tpl", "Vlan0", "Vlan1", "SkbMark"):
                cached_flow[hexadecimal_field] = int(cached_flow.get(hexadecimal_field, "0"), 16)
            cached_flow_list.append(cached_flow)
        return cached_flow_list

    def check_traffic_acceleration(  # noqa: C901
        self, ip_address, expected_protocol=6, multicast=False, flow_count=1, flex=False, **kwargs
    ):  # noqa C901
        """
        Check traffic was accelerated
        Args:
            ip_address: (list) IP addresses to check
            expected_protocol: (int) expected protocol id. 6 for TCP, 17 for UDP
            multicast: (bool) True to check for acceleration of multicast traffic
            flow_count: (int) minimum number of expected accelerated flows (connections)
            flex: (bool) True to check for acceleration of Flex traffic
            **kwargs:

        Returns: bool()

        """
        # Get archer flows
        all_archer_flows = list()
        all_cached_flows = list()
        for i in range(0, 5):
            if not (multicast or flex):
                all_archer_flows.extend(self._get_archer_flows(ip_address, **kwargs))
            all_cached_flows.extend(self._get_parsed_connection_flows(ip_address, multicast=multicast, **kwargs))
            time.sleep(4)

        status = True
        # Verify archer-flows
        grouped_archer_flows = self.group_flows_by_id(id_name="table_index ", connection_flows=all_archer_flows)
        archer_accelerated_flows = 0
        for flow_id, archer_flows in grouped_archer_flows.items():
            packet_counts = []
            byte_counts = []
            for archer_flow in archer_flows:
                if ip_protocol := common_util.get_digits_value_from_text(
                    value_to_take="ip_protocol", text_response=archer_flow
                ):
                    if expected_protocol != ip_protocol:
                        # Ignore flows for protocol we don't care about, e.g. for iperf control connection
                        # (which is always TCP) when testing UDP.
                        continue
                flow_packets = common_util.get_digits_value_from_text(
                    value_to_take="packets ", text_response=archer_flow
                )
                flow_bytes = common_util.get_digits_value_from_text(value_to_take="bytes ", text_response=archer_flow)
                packet_counts.append(flow_packets)
                byte_counts.append(flow_bytes)

            if packet_counts != sorted(packet_counts):
                log.warning(
                    f"Number of packets in Archer flow on {self.get_nickname()} device decreased with time:\n"
                    + "\n\n".join(archer_flows)
                )
            if byte_counts != sorted(byte_counts):
                log.warning(
                    f"Number of bytes in Archer flow on {self.get_nickname()} device decreased with time:\n"
                    + "\n\n".join(archer_flows)
                )
            # flow is accelerated if number of packets and bytes in flow increased during observation
            if (
                packet_counts
                and packet_counts[0] < packet_counts[-1]
                and byte_counts
                and byte_counts[0] < byte_counts[-1]
            ):
                archer_accelerated_flows += 1

        # Verify cached flows
        grouped_cached_flows = self._group_flowcache_flows_by_id(all_cached_flows)
        flow_cache_accelerated_flows = 0
        for flow_id, cached_flows in grouped_cached_flows:
            total_hit_counts = []
            for cached_flow in cached_flows:
                if cached_flow["idle"] != 0:
                    continue
                if expected_protocol != cached_flow["Prot"]:
                    # Ignore flows for protocol we don't care about, e.g. for iperf control connection
                    # (which is always TCP) when testing UDP.
                    continue
                tot_hits = cached_flow["SW_TotHits"] + cached_flow["HW_TotHits"]
                # exclude flows if they have less than 20 total hits
                if tot_hits < 20:
                    continue
                total_hit_counts.append(tot_hits)

            if total_hit_counts != sorted(total_hit_counts):
                log.warning(
                    f"Number of packets in Flow Cache on {self.get_nickname()} device decreased with time:\n"
                    + "\n".join(json.dumps(flow) for flow in cached_flows)
                )
            # flow is accelerated if number of software or hardware accelerated hits increased during observation
            if total_hit_counts and total_hit_counts[0] < total_hit_counts[-1]:
                flow_cache_accelerated_flows += 1

        if archer_accelerated_flows < flow_count and not (multicast or flex):
            log.error(
                f"found only {archer_accelerated_flows} accelerated Archer flows (less than expected "
                f"{flow_count}) for {ip_address} ip addresses on {self.get_nickname()} device"
            )
            status = False
        elif not (multicast or flex):
            log.info(f"found {archer_accelerated_flows} offloaded flows on {self.get_nickname()} device")

        if flow_cache_accelerated_flows < flow_count:
            log.error(
                f"found only {flow_cache_accelerated_flows} accelerated Flow Cache flows (less than expected "
                f"{flow_count}) for {ip_address} ip addresses on {self.get_nickname()} device"
            )
            status = False
        else:
            log.info(f"found {flow_cache_accelerated_flows} accelerated flows on {self.get_nickname()} device")

        return status

    @staticmethod
    def group_flows_by_id(id_name, connection_flows):
        grouped_connection_flows = dict()
        for connection_flow in connection_flows:
            connection_flow_id = common_util.get_digits_value_from_text(
                value_to_take=id_name, text_response=connection_flow
            )
            if not connection_flow_id:
                continue
            if not grouped_connection_flows.get(connection_flow_id):
                grouped_connection_flows.update({connection_flow_id: list()})

            grouped_connection_flows[connection_flow_id].append(connection_flow)
        return grouped_connection_flows

    @staticmethod
    def _group_flowcache_flows_by_id(parsed_flows):
        def flow_by_id(parsed_flow):
            return parsed_flow["flow_id"]

        parsed_flows.sort(key=flow_by_id)
        return itertools.groupby(parsed_flows, key=flow_by_id)

    @staticmethod
    def parse_ip_address_for_accelerator(ip_address):
        if ":" in ip_address:
            parsed_address = common_util.get_full_ipv6_address(abbreviated_ipv6_addr=ip_address)
        else:
            # bcm always uses 3 digits for IP, ex 192.168.200.24 is 192.168.200.024
            parsed_address = [value.zfill(3) for value in ip_address.split(".")]
            parsed_address = ".".join(parsed_address)
        return parsed_address

    def is_fw_fuse_burned(self, **kwargs):
        """Returns True when device firmware fuse is burned (is locked) and False otherwise."""
        response = self.run_command("pmf -fuse verify", **kwargs)
        match = re.search(r"(Secure boot)(\ *)(: UNSECURE; JTAG:UNLOCKED)", self.get_stdout(response, **kwargs))
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
            f"rssi=$(wl -i {ifname} sta_info {client_mac} | awk '/smoothed rssi/ "
            + "{print $3}')"
            + f";noise=$(wl -i {ifname} noise);echo `expr $rssi  - $noise`"
        )

        output = self.run_command(cmd, **kwargs)
        return self.strip_stdout_result(output)

    def get_beacon_interval(self, ifname: str, **kwargs) -> [int, str, str]:
        """
        Get Beacon Internal from the Wi-Fi driver.
        Args:
            ifname: (str) Name of interface
            **kwargs:

        Returns: [int, str, str]

        """
        return self.run_command(f"wl -i {ifname} bi", **kwargs)
