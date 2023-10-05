import functools
import re
import time
import xmltodict
from lib_testbed.generic.util.logger import log
import lib_testbed.generic.util.common as common_util
from lib_testbed.generic.pod.generic.pod_lib import PodLib as PodLibGeneric


class PodLib(PodLibGeneric):
    def get_radio_temperature(self, radio_index, **kwargs):
        ret = self.run_command(f"cat /sys/class/net/wifi{radio_index}/thermal/temp", **kwargs)
        return ret

    def get_radios_interference(self, **kwargs):
        ret = {}
        for radio in self.capabilities.get_phy_radio_ifnames(return_type=list):
            survey = self.run_plume_or_opensync_stats_extra(
                f"plume {radio} survey_bss | " f"awk '/raw/ {{print 100*($10-b)/($NF-t); b=$10; t=$NF; }}'", **kwargs
            )
            ret[radio] = int(float(survey[1])) if survey[0] == 0 else -1
        return ret

    def get_tx_power(self, interface, **kwargs):
        """
        Get current Tx power in dBm
        Args:
            interface: (str) Wireless interface

        Returns: raw output [(int) ret, (std) std_out, (str) str_err]

        """
        cmd = "iwconfig %s | grep Tx-Power | awk '{print $4}'" % interface
        response = self.strip_stdout_result(self.run_command(cmd, **kwargs))
        if not response[0]:
            response[1] = response[1].split(":")[-1] if ":" in response[1] else response[1].split("=")[-1]
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
            current_tx_power = int(self.get_stdout(self.get_tx_power(interface)))
            expect_tx_power = int(current_tx_power - (current_tx_power * percent_ratio))
            if expect_tx_power < 1:
                expect_tx_power = 1
            cmd += f"iwconfig {interface} txpower {expect_tx_power}dbm; "
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
            current_tx_power = int(self.get_stdout(self.get_tx_power(interface)))
            expect_tx_power = int(current_tx_power + (current_tx_power * percent_ratio))
            cmd += f"iwconfig {interface} txpower {expect_tx_power}dbm; "
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
            cmd += f"iwconfig {interface} txpower {tx_power}dbm; "
        response = self.run_command(cmd, **kwargs)
        return response

    def get_client_tx_rate(self, ifname, client_mac, **kwargs):
        result = self.run_command(f"wlanconfig {ifname} list sta | grep {client_mac}" + " | awk '{print $5}'", **kwargs)
        tx_rate = re.search(r"\d+", result[1])
        if not tx_rate or result[0]:
            return result
        result[1] = tx_rate.group()
        return result

    def get_driver_data_rate(self, ifname, mac_address, **kwargs):
        """
        Get current data rate from driver
        Args:
            ifname: (str) Name of interface
            mac_address: (str) MAC address of connected client interface
        Returns: list (ret, stdout, stderr) stdout as (dict) {'data_rate': (str), 'bytes': (int), 'rssi': (list)}

        """
        data_rate_table = list()
        drate = ""
        result = self.run_plume_or_opensync_stats_extra(f"plume {ifname} peer_rx_stats {mac_address}", **kwargs)
        if result[0] == 127:
            # Since QSDK11 there is no tool on the FW site to get stats directly from the driver
            raise NotImplementedError
        elif result[0]:
            return result

        for line in result[1].splitlines():
            if "CCK" not in line and "OFDM" not in line and "MHz |" not in line:
                continue
            rssi = []
            if "MHz |" in line:
                splitline = line.split("|")
                bw = splitline[0].strip()
                nss = splitline[1].strip()
                mcs = splitline[2].strip()
                if bw == "20MHz":
                    bw = 0
                elif bw == "40MHz":
                    bw = 1
                elif bw == "80MHz":
                    bw = 2
                else:
                    bw = 3
                drate = f"[{bw} {nss} {mcs}]"
                dbytes = int(splitline[4].strip())
                rssi.append(splitline[10].strip())

                for index in range(4):
                    p20 = splitline[11 + index * 4].strip()
                    e20 = splitline[11 + index * 4].strip()
                    e40 = splitline[11 + index * 4].strip()
                    e80 = splitline[11 + index * 4].strip()
                    rssi.append(dict(p2=p20, e20=e20, e40=e40, e80=e80))
            else:
                splitline = line.split("|")
                if "CCK" in splitline[0]:
                    drate = "".join(splitline[0].strip().split()[-2:])
                elif "OFDM" in splitline[0]:
                    drate = splitline[0].strip().split()[-1]
                dbytes = int(splitline[2].strip())
                rssi.append(splitline[7].strip())

                for index in range(4):
                    p20 = splitline[8 + index * 4].strip()
                    e20 = splitline[8 + index * 4].strip()
                    e40 = splitline[8 + index * 4].strip()
                    e80 = splitline[8 + index * 4].strip()
                    rssi.append(dict(p2=p20, e20=e20, e40=e40, e80=e80))

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
        response = self.run_command(f"radartool -i {phy_radio_name} bangradar", **kwargs)
        return response

    def get_boot_partition(self, **kwargs):
        """
        Get boot partition name
        Args:
            **kwargs:

        Returns: list(retval, stdout, stderr)
        """
        response = self.run_command('cat /proc/cmdline | sed -r "s/ubi.mtd=([a-zA-Z0-9]+).*/\\1/g"', **kwargs)
        return response

    def trigger_crash(self, **kwargs):
        """
        Trigger crash on the platform
        Args:
            **kwargs:

        Returns: list [retval, stdout, stderr]

        """
        result = self.run_command(f"ls {self.get_node_deploy_path()}/crash_qca.ko", **kwargs)
        if result[0]:
            log.info("Deploying tools...")
            deploy_status = self.deploy()
            if deploy_status[0] != 0:
                err_msg = f"Deploy to POD has failed! {deploy_status[2]}"
                return [1, err_msg, err_msg]

        # insmod ends immediately with crash and reboot, so sleep here otherwise command ends with timeout exception
        result = self.run_command(
            f"sh -c 'sleep 3; insmod {self.get_node_deploy_path()}/crash_qca.ko' > /dev/null 2>&1 &", **kwargs
        )
        time.sleep(20)
        self.wait_available(timeout=120)
        return result

    @functools.cached_property
    def qsdk_version(self):
        response = self.run_command("sed -n 's/.*CONFIG_QSDK_VERSION=//p' /usr/opensync/etc/kconfig")
        if response[0]:
            return 0
        version = self.get_stdout(response)
        return int(version, 16)

    def get_connection_flows(self, ip, **kwargs):
        """
        Get connection flow id for specific IP address
        Args:
            ip: (str) IP address
            **kwargs:

        Returns: (list) flow list

        """
        if self.qsdk_version >= 0x1100:
            return self.get_connection_flows_ecm(ip, **kwargs)
        return self.get_connection_flows_sfe(ip, **kwargs)

    def check_traffic_acceleration(
        self, ip_address, expected_protocol=6, multicast=False, flow_count=1, flex=False, **kwargs
    ):
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
        # On QSDK 11.00 and newer check for flows in both ECM and SFE
        if self.qsdk_version >= 0x1100:
            ecm_ok = self.check_traffic_acceleration_ecm(
                ip_address,
                expected_protocol=expected_protocol,
                multicast=multicast,
                flow_count=flow_count,
                flex=flex,
                **kwargs,
            )
            if not ecm_ok:
                return False
        return self.check_traffic_acceleration_sfe(
            ip_address,
            expected_protocol=expected_protocol,
            multicast=multicast,
            flow_count=flow_count,
            flex=flex,
            **kwargs,
        )

    def get_connection_flows_sfe(self, ip, **kwargs):
        """
        Get connection flow id for specific IP address
        Args:
            ip: (str) IP address
            **kwargs:

        Returns: (list) flow list

        """
        response = self.run_command("sfe_dump", **kwargs)
        dump = self.get_stdout(response, **kwargs)
        if not dump:
            return []
        sfe_dump = xmltodict.parse("<sfe_dump>\n" + dump + "\n</sfe_dump>")["sfe_dump"]
        flows = []
        if sfe_dump["sfe_ipv4"].get("connections"):
            # in case of single element direct dict is returned
            if type(sfe_dump["sfe_ipv4"]["connections"].get("connection")) == list:
                out = sfe_dump["sfe_ipv4"]["connections"].get("connection", [])
            else:
                out = [sfe_dump["sfe_ipv4"]["connections"]["connection"]]
            for connection in out:
                if connection["@src_ip"] != ip:
                    continue
                flows.append(connection["@src_dev"])
        log.info(f"{self.get_nickname()} flows for {ip}: {flows}")
        return flows

    def set_region_two_radios_model(self, region, **kwargs):
        log.error("Model does not support changing region")
        return [1, "", "Model does not support region modifications"]

    def set_region_three_radios_model(self, region, **kwargs):
        assert region in self.DFS_REGION_MAP, f"Region {region} is not supported"
        log.info(f"Set {region} region for node {self.get_nickname()}")
        res = self.run_command("fw_setenv plume_development 1")
        for radio in ["rgdmn0", "rgdmn1", "rgdmn2"]:
            res = self.merge_result(res, self.run_command(f"pmf -fw {self.DFS_REGION_MAP[region]} -{radio} {region}"))

        log.info("Rebooting pod")
        self.reboot()
        time.sleep(10)
        self.wait_available(timeout=2 * 60)
        timeout = time.time() + 120
        while time.time() < timeout:
            if self.run_command("pmf -r -rgdmn0")[1]:
                break
            time.sleep(2)
        else:
            assert False, "Cannot get country code information after reboot"

        for radio in ["rgdmn0", "rgdmn1", "rgdmn2"]:
            assert self.DFS_REGION_MAP[region].lower() in self.run_command(f"pmf -r -{radio}")[1].lower()
        return res

    def get_connection_flows_sfe_dump(self, ip_address="", **kwargs):
        """
        Get connection flow dump from device
        Args:
            ip_address: (str) optional, get entries only for target IP address
            **kwargs:

        Returns: list() list of connection flows

        """
        # Update interface id with 0000 prefix
        if ":" in ip_address:
            ip_address = common_util.get_full_ipv6_address(abbreviated_ipv6_addr=ip_address)
        connection_flows = self.run_command("sfe_dump", **kwargs)
        connection_flows = self.get_stdout(connection_flows, **kwargs)
        connection_flows = xmltodict.parse("<sfe_dump>\n" + connection_flows + "\n</sfe_dump>")["sfe_dump"]
        connection_flow_list = list()
        for connection_type in ["sfe_ipv4", "sfe_ipv6"]:
            if not (connection_type_flows := connection_flows[connection_type].get("connections")):
                continue
            if isinstance(connection_type_flows["connection"], dict):
                connection_type_flows["connection"] = [connection_type_flows["connection"]]
            for connection_flow in connection_type_flows["connection"]:
                connection_flow = dict(connection_flow)
                client_flow = re.search(ip_address, str(connection_flow))
                if ip_address and not client_flow:
                    continue
                connection_flow_list.append(connection_flow)
        return connection_flow_list

    def check_traffic_acceleration_sfe(
        self, ip_address, expected_protocol=6, multicast=False, flow_count=1, flex=False, **kwargs
    ):
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
        # QCA platforms handle end-to-end tracking, so just one IP needs to be checked
        ip_address = ip_address[0]
        all_connection_flows = list()
        for i in range(5):
            connection_flows = self.get_connection_flows_sfe_dump(ip_address, **kwargs)
            all_connection_flows.extend(connection_flows)
            time.sleep(4)
        assert all_connection_flows, (
            f"Not found any connection flows for {ip_address} address, " f"for {self.get_nickname()} device"
        )
        status = True
        # <L4_protocol> should be equal to 6 for tcp or 17 for udp
        # With each iteration, the value of src_rx_pkts, src_rx_bytes, dest_rx_pkts, and dest_rx_bytes should increase.
        for connection_flow in all_connection_flows:
            connection_protocol = connection_flow.get("@protocol", 0)
            if expected_protocol != int(connection_protocol):
                # Ignore flows for protocol we don't care about, e.g. for iperf control connection
                # (which is always TCP) when testing UDP.
                continue
            for key_to_check in ["@src_rx_pkts", "@src_rx_bytes", "@dest_rx_pkts", "@dest_rx_bytes"]:
                value = connection_flow.get(key_to_check, 0)
                if not value:
                    log.error(
                        f"Value of {key_to_check} did not increased of the connection flow,"
                        f" for {self.get_nickname()} device"
                    )
                    status = False
        return status

    def get_connection_flows_ecm(self, ip, **kwargs):
        """
        Get connection flow id for specific IP address
        Args:
            ip: (str) IP address
            **kwargs:

        Returns: (list) flow list

        """
        # if no flows, then grep returns 1
        response = self.run_command(f"ecm_dump.sh | grep {ip}", **kwargs)
        dump = self.get_stdout(response, skip_exception=True)
        if not dump:
            return []
        flows = dump.splitlines()
        log.info(f"{self.get_nickname()} has {len(flows)} flows for {ip}")
        return flows

    def get_connection_flows_ecm_dump(self, ip_address="", **kwargs):
        """
        Get connection flow dump from device
        Args:
            ip_address: (str) optional, get entries only for target IP address
            **kwargs:

        Returns: list() list of connection flows

        """
        connection_flows = self.run_command("ecm_dump.sh", **kwargs)
        connection_flows = self.get_stdout(connection_flows, **kwargs)
        all_connection_ids = list(set(re.findall(r"conns.conn.\d+", connection_flows)))
        connection_flow_list = list()
        if ":" in ip_address:
            ip_address = common_util.get_full_ipv6_address(abbreviated_ipv6_addr=ip_address)
        # Group flows into list
        for connection_id in all_connection_ids:
            connection_flow = "\n".join(
                [flow_entry for flow_entry in connection_flows.splitlines() if connection_id in flow_entry]
            )
            client_flow = re.search(ip_address, connection_flow)
            if ip_address and not client_flow:
                continue
            connection_flow_list.append(connection_flow)
        return connection_flow_list

    def check_traffic_acceleration_ecm(  # noqa: C901
        self, ip_address, expected_protocol=6, multicast=False, flow_count=1, flex=False, **kwargs
    ):
        """
        Check traffic was accelerated
        Args:
            ip_address: (list) IP addresses
            expected_protocol: (int) - Not required for ecm. Added to have consistent func signature
            multicast: (bool) True to check for acceleration of multicast traffic
            flow_count: (int) minimum number of expected accelerated flows (connections)
            flex: (bool) True to check for acceleration of Flex traffic
            **kwargs:

        Returns: bool

        """
        # QCA platforms handle end-to-end tracking, so just one IP needs to be checked
        ip_address = ip_address[0]
        all_connection_dumps = list()
        for i in range(5):
            connection_flows = self.get_connection_flows_ecm_dump(ip_address, **kwargs)
            all_connection_dumps.append(connection_flows)
            time.sleep(4)

        status = True
        flows = {}
        pr_accel_flows_counter = []
        # first dump contains data before traffic starts, so skip it
        for all_connection_flows in all_connection_dumps[1:]:
            # There should be at least 4 flows where all the pr.accel classifiers are "wanted"
            flow_with_all_wanted_pr_accel = 0
            for connection_flow in all_connection_flows:
                flow_id = common_util.get_digits_value_from_text("conns.conn.", connection_flow)
                slow_path_packets = common_util.get_digits_value_from_text("slow_path_packets=", connection_flow)
                log.info(f"slow_path_packets for flow id {flow_id}: {slow_path_packets}")
                if f"{flow_id}_slow_packets" not in flows:
                    flows[f"{flow_id}_slow_packets"] = slow_path_packets
                if f"{flow_id}_slow_packets_delta" not in flows:
                    flows[f"{flow_id}_slow_packets_delta"] = []
                flows[f"{flow_id}_slow_packets_delta"].append(slow_path_packets - flows[f"{flow_id}_slow_packets"])
                if f"{flow_id}_pr_accel_counts" not in flows:
                    flows[f"{flow_id}_pr_accel_counts"] = []
                all_wanted_pr_accel = True
                for row in connection_flow.splitlines():
                    if "pr.accel" not in row:
                        continue
                    if "denied" in row:
                        log.info(f"Got: denied for {row}, but checking if all 4 data flows are accelerated")
                    if "wanted" not in row:
                        all_wanted_pr_accel = False
                if all_wanted_pr_accel:
                    flow_with_all_wanted_pr_accel += 1
            pr_accel_flows_counter.append(flow_with_all_wanted_pr_accel)

        for flow_id in flows:
            if "_delta" not in flow_id:
                continue
            log.info(f"All new reported slow packets between dumps: [{flow_id}] : {flows[flow_id]}")
            if max(flows[flow_id]) > 100:
                log.error("Too many new slow packets, acceleration is not working")
                status = False
        max_pr_accel = max(pr_accel_flows_counter)
        log.info(f"Number of flows where all the pr.accel classifiers are 'wanted': {max_pr_accel}")
        if not flows:
            log.info("No flows were cached")
        if max_pr_accel < flow_count:
            log.error(
                f"There were less than {flow_count} flows where all the pr.accel classifiers were 'wanted': "
                f"{max_pr_accel}"
            )
            status = False
        return bool(flows) and status

    def is_fw_fuse_burned(self, **kwargs):
        """Returns True when device firmware fuse is burned (locked) and False otherwise."""
        response = self.run_command(
            'pmf -fuse verify | grep "Authentication enabled" | grep "ERROR NOT SET" | wc -l', **kwargs
        )
        return self.get_stdout(response, **kwargs).strip() == "0"

    def get_client_snr(self, ifname: str, client_mac: str, **kwargs) -> [int, str, str]:
        """
        Get SNR level of the connected client.
        Args:
            ifname: (str) Name of interface where is associated a client
            client_mac: (str) Client mac address
            **kwargs:

        Returns: [int, str, str]

        """
        output = self.run_command(f"wlanconfig {ifname} list | grep {client_mac} -A 13", **kwargs)
        if output[0]:
            return output
        client_details = re.sub(r"\t", "", output[1])
        snr_value = common_util.get_digits_value_from_text(value_to_take="SNR:", text_response=client_details)
        if not snr_value:
            return [1, "", f"Can not get SNR value for {client_mac}"]
        return [0, str(snr_value), ""]

    def get_beacon_interval(self, ifname: str, **kwargs) -> [int, str, str]:
        """
        Get Beacon Internal from the Wi-Fi driver.
        Args:
            ifname: (str) Name of interface
            **kwargs:

        Returns: [int, str, str]

        """
        output = self.run_command(f"iwpriv {ifname} get_bintval", **kwargs)
        if output[0]:
            return output
        bi_value = common_util.get_digits_value_from_text(value_to_take="get_bintval:", text_response=output[1])
        if not bi_value:
            return [1, "", f"Can not get Beacon Interval value"]
        return [0, str(bi_value), ""]
