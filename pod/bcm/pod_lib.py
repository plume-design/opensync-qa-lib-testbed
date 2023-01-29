import re
import time
from lib_testbed.generic.util.logger import log
import lib_testbed.generic.util.common as common_util
from lib_testbed.generic.pod.generic.pod_lib import PodLib as PodLibGeneric


class PodLib(PodLibGeneric):

    def get_radio_temperature(self, radio_index, **kwargs):
        ret = self.run_command(f'wl -i wl{radio_index} phy_tempsense', **kwargs)
        # example output: "70 (0x46)"
        ret[1] = ret[1].split(' ')
        ret[1] = ret[1][0] if len(ret[1]) == 2 else '-1'
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
        cmd = ''
        for interface in all_interfaces:
            current_tx_power = float(self.get_stdout(self.get_tx_power(interface)))
            expect_tx_power = int(current_tx_power - (current_tx_power * percent_ratio))
            if expect_tx_power < 2:
                expect_tx_power = 2
            cmd += f'wl -i {interface} txpwr1 {expect_tx_power}; '
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
        cmd = ''
        for interface in all_interfaces:
            current_tx_power = float(self.get_stdout(self.get_tx_power(interface)))
            expect_tx_power = int(current_tx_power + (current_tx_power * percent_ratio))
            cmd += f'wl -i {interface} txpwr1 {expect_tx_power}; '
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
        cmd = ''
        for interface in interfaces:
            cmd += f'wl -i {interface} txpwr1 {tx_power}; '
        response = self.run_command(cmd, **kwargs)
        return response

    def get_client_tx_rate(self, ifname, client_mac, **kwargs):
        result = self.run_command(f'wl -i {ifname} sta_info {client_mac}')
        std_out_lines = result[1].splitlines()
        for i, line in enumerate(std_out_lines):
            if 'rx nrate' not in line:
                continue
            # TX Rate entry appears in a next line
            tx_rate_entry = std_out_lines[i + 1]
            result[1] = re.search(r'\d+', tx_rate_entry).group()
            break
        return result

    def get_driver_data_rate(self, ifname, mac_address, **kwargs):  # noqa
        ht_data_rate = [13500, 27000, 40500, 54000, 81000, 108000, 121500, 135000, 27000, 54000, 81000, 108000,
                        162000, 216000, 243000, 270000]
        data_rate_table = []
        result = self.run_command(f'wl -i {ifname} sta_info {mac_address}', **kwargs)
        drate = ''
        dbytes = ''
        rssi = ''
        if result[0]:
            return result

        rx_rate = False
        last_rate = 1000
        for line in result[1].splitlines():
            if 'rate of last rx pkt:' in line:
                last_rate = int(line.split(':')[1].split()[0].strip())
                continue
            if 'rx nrate' in line:
                rx_rate = True
                continue
            if rx_rate:
                rx_rate = False  # noqa
                if 'legacy rate' in line:
                    drate = line[line.index('legacy rate') + len('legacy rate'):line.index('Mbps')].strip() + 'M'
                elif 'vht' in line:
                    mcs = int(line[line.index('mcs') + len('mcs'):line.index('Nss')].strip())
                    mcs = mcs % 8
                    nss = int(line[line.index('Nss') + len('Nss'):line.index('Tx')].strip())
                    bw = line.split()[[i for i, s in enumerate(line.split()) if 'bw' in s][0]].replace('bw', '')
                    if bw == '20':
                        bw = 0
                    elif bw == '40':
                        bw = 1
                    elif bw == '80':
                        bw = 2
                    else:
                        bw = 3
                    drate = f'[{bw} {nss} {mcs}]'
                elif 'mcs index' in line:
                    mcs_raw = int(line[line.index('index') + len('index'): line.index('stf')].strip())
                    mcs = mcs_raw % 8
                    mod = int(line.split()[[i for i, s in enumerate(line.split()) if 'mode' in s][0] + 1])
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
                    drate = f'[{bw} {nss} {mcs}]'
                break
            if 'rx data bytes' in line:
                dbytes = int(line.split(':')[1].strip())
                continue
            if 'per antenna average rssi of rx data frames:' in line:
                rssi = line.split(':')[1].strip().split()
        data_rate_table.append({'data_rate': drate, 'bytes': dbytes, 'rssi': rssi})
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
        ret_1 = self.run_command(f'wl -i {phy_radio_name} radar 1', **kwargs)
        ret_2 = self.run_command(f'wl -i {phy_radio_name} radar 2', **kwargs)
        # any resp with 0 is a success
        for i, ret in zip(range(1, 3), [ret_1, ret_2]):
            log.info(f'Response for radar against {phy_radio_name} radar {i} -> {ret}')
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
        result = self.run_command("sh -c 'sleep 3; echo c > /proc/sysrq-trigger' &", **kwargs)
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
        out_ip = [f"{int(value):03d}" for value in ip.split('.')]
        out_ip = '.'.join(out_ip)

        br_list = self.run_command('cat /proc/fcache/brlist', **kwargs)
        nf_list = self.run_command('cat /proc/fcache/nflist', **kwargs)
        response = self.merge_result(br_list, nf_list)
        dump = self.get_stdout(response, **kwargs)
        if not dump:
            return []
        flows = []
        for line in dump.splitlines():
            # skip title bar
            if line.startswith('Flow'):
                continue
            if out_ip in line:
                flows.append(line.split()[0])
        log.info(f"{self.get_nickname()} flows for {ip}: {flows}")
        return flows

    def set_region(self, region, **kwargs):
        if not self.capabilities.is_regulatory_domain_managed():
            log.error("Model does not support changing region")
            return [1, '', 'Model does not support region modifications']
        if len(self.capabilities.get_phy_radio_ifnames(return_type=list)) == 2:
            return self.set_region_radios_model(region, 2, **kwargs)
        else:
            return self.set_region_radios_model(region, 3, **kwargs)

    def set_region_radios_model(self, region: str, num_of_radios: int, **kwargs):

        match [region, num_of_radios]:
            case ['EU', 2]:
                region = ('E0', 'EU')
                rev_num = (914, 13)
            case ['EU', 3]:
                region = 'E0'
                rev_num = 763
            case ['US', (2 | 3)]:
                rev_num = 0
            case ['UK', 2]:
                region = 'GB'
                rev_num = 0
            case ['UK', 3]:
                region = 'GB'
                rev_num = 36
            case ['CA', 2]:
                rev_num = 860
            case ['CA', 3]:
                rev_num = 886
            case ['JP', 2]:
                rev_num = 879
            case ['JP', 3]:
                rev_num = 914
            case ['KR', (2 | 3)]:
                rev_num = 936
            case ['PH', (2 | 3)]:
                rev_num = 990
            case other:
                raise AssertionError(
                    f"Region {region} is not supported! Supported regions: EU, US, UK, CA, JP, KR, PH.")

        self.enter_factory_mode()
        try:
            log.info(f"Set {region} region for node {self.get_nickname()}")
            res = [0, '', '']
            for radio_id in range(num_of_radios):
                region = region[radio_id] if isinstance(region, tuple) else region
                res = self.merge_result(res, self.run_command(f"pmf -ccode{radio_id} -fw  {region}"))

            for reg_revision in range(num_of_radios):
                rev_num = rev_num[radio_id] if isinstance(rev_num, tuple) else rev_num
                self.run_command(f"pmf -regrv{reg_revision} -fw  {rev_num}")
            self.run_command("pmf --commit")
        finally:
            self.exit_factory_mode()
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

    def get_connection_flows_dump(self, ip_address='', **kwargs):
        """
        Get connection flow dump from device
        Args:
            ip_address: (str) optional, get entries only for target IP address
            **kwargs:

        Returns: list() list of connection flows

        """
        connection_flows = self.run_command('archer flows && dmesg -c', **kwargs)
        connection_flows = self.get_stdout(connection_flows, skip_exception=True)
        if not connection_flows:
            return []
        connection_flows = connection_flows.split('***** FLOW *****')
        if ip_address:
            ip_address = self.parse_ip_address_for_accelerator(ip_address)
        connection_flow_list = list()
        for connection_flow in connection_flows:
            client_flow = re.search(ip_address, connection_flow)
            if ip_address and not client_flow:
                continue
            connection_flow_list.append(connection_flow)
        return connection_flow_list

    def get_cached_flows(self, ip_address='', wds=False, multicast=False, **kwargs):
        if multicast:
            cmd = "cat /proc/fcache/misc/mcastlist"
        elif wds and self.device.config.get('role', '') == 'leaf':
            cmd = "cat /proc/fcache/brlist"
        else:
            cmd = "cat /proc/fcache/nflist"
        cached_flows = self.run_command(cmd)
        cached_flows = self.get_stdout(cached_flows, skip_exception=True)
        if not cached_flows:
            return []
        if ip_address:
            ip_address = self.parse_ip_address_for_accelerator(ip_address)
        cached_flow_list = list()
        for cached_flow in cached_flows.splitlines():
            client_flow = re.search(ip_address, cached_flow)
            if ip_address and not client_flow:
                continue
            cached_flow_list.append(cached_flow)
        return cached_flow_list

    def get_connection_flow_marks(self, ip_address, **kwargs):
        """
        Get connection flow marks for provided IP address
        Args:
            ip_address: (str) IP address
            **kwargs:

        Returns: list()

        """
        ip_connection_flows = self.get_connection_flows_dump(ip_address=ip_address, **kwargs)
        flow_marks = list()
        for ip_connection_flow in ip_connection_flows:
            connection_mark = re.search(r'(?<=ip_tos ).\d+', ip_connection_flow)
            if not connection_mark:
                continue
            flow_marks.append(connection_mark.group())
        return flow_marks

    def check_traffic_acceleration_flex(self, ip_address, wds=False, skip_addresses='', **kwargs):
        """
        Check if traffic was accelerated for flex connection
        Args:
            ip_address: (list) IP addresses to check
            wds: (bool) wds mode
            skip_addresses: (list) Don't consider a flow with provided ip addresses
            **kwargs:

        Returns: bool()

        """
        # Get archer flows
        all_cached_flows = list()
        for i in range(0, 5):
            for ip in ip_address:
                all_cached_flows.extend(self.get_cached_flows(ip, wds=wds, **kwargs))
            time.sleep(4)

        assert all_cached_flows, f'Not found any cached flow for {ip_address} ip addresses for {self.get_nickname()}' \
                                 f' device'
        status = True
        # Verify cached flows
        grouped_cached_flows = self.group_flows_by_id(id_name='@', connection_flows=all_cached_flows)
        all_accelerated_flows = 0
        for flow_id, cached_flows in grouped_cached_flows.items():
            not_accelerated_flows = list()
            accelerated_flows = 0
            cached_flow_tot_hits = []
            for cached_flow in cached_flows:
                parsed_cached_flow = self.parse_cached_flows(cached_flow)
                if not parsed_cached_flow or parsed_cached_flow['idle'] != 0:
                    continue
                tot_hits = parsed_cached_flow.get('packets_sw', 0) + parsed_cached_flow.get('packets_hw', 0)
                # exclude flows if they have less than 20 SW_TotHits + HW_TotHits
                if tot_hits < 20:
                    continue
                cached_flow_tot_hits.append(tot_hits)
            if cached_flow_tot_hits:
                # check if values are increasing
                tmp = []
                tmp.extend(cached_flow_tot_hits)
                cached_flow_tot_hits.sort()
                if tmp != cached_flow_tot_hits:
                    not_accelerated_flows.extend(cached_flows)
                else:
                    accelerated_flows += 1
            if len(not_accelerated_flows) > 1:
                not_accelerated_flows_to_print = '\n'.join(not_accelerated_flows)
                log.error(f'The traffic was not accelerated for following flows:\n{not_accelerated_flows_to_print}')
                status = False
            all_accelerated_flows += accelerated_flows
        if not all_accelerated_flows:
            log.error('There were no flows, which were accelerated')
            status = False
        return status

    def check_traffic_acceleration(self, ip_address, expected_protocol=6, multicast=False, flow_count=1, **kwargs):  # noqa C901
        """
        Check traffic was accelerated
        Args:
            ip_address: (list) IP addresses to check
            expected_protocol: (int) expected protocol id. 6 for TCP, 17 for UDP
            multicast: (bool) True to check for acceleration of multicast traffic
            flow_count: (int) minimum number of expected accelerated flows (connections)
            **kwargs:

        Returns: bool()

        """
        # Get archer flows
        all_archer_flows = list()
        all_cached_flows = list()
        for i in range(0, 5):
            for ip in ip_address:
                if not multicast:
                    all_archer_flows.extend(self.get_connection_flows_dump(ip, **kwargs))
                all_cached_flows.extend(self.get_cached_flows(ip, multicast=multicast, **kwargs))
            time.sleep(4)

        status = True
        if not all_cached_flows:
            log.error(f'Not found any cached flow for {ip_address} ip addresses for {self.get_nickname()} device')
            status = False
        if not all_archer_flows and not multicast:
            log.error(f'Not found any archer flow for {ip_address} ip addresses for {self.get_nickname()} device')
            status = False
        # Verify archer-flows
        grouped_archer_flows = self.group_flows_by_id(id_name='table_index ', connection_flows=all_archer_flows)
        for flow_id, archer_flows in grouped_archer_flows.items():
            pre_flow_packets, pre_flow_bytes = 0, 0
            for archer_flow in archer_flows:
                if ip_protocol := common_util.get_digits_value_from_text(value_to_take='ip_protocol',
                                                                         text_response=archer_flow):
                    if expected_protocol != ip_protocol:
                        # Ignore flows for protocol we don't care about, e.g. for iperf control connection
                        # (which is always TCP) when testing UDP.
                        continue
                flow_packets = common_util.get_digits_value_from_text(value_to_take='packets ',
                                                                      text_response=archer_flow)
                flow_bytes = common_util.get_digits_value_from_text(value_to_take='bytes ',
                                                                    text_response=archer_flow)
                if pre_flow_packets > flow_packets:
                    log.warning(f'Number of packets did not increase according to previous flow: '
                                f'{pre_flow_packets} > {flow_packets} for {self.get_nickname()} device')
                if pre_flow_bytes > flow_bytes:
                    log.warning(f'Number of bytes did not increase according to previous flow: '
                                f'{pre_flow_packets} > {flow_packets} for {self.get_nickname()} device')
                pre_flow_packets, pre_flow_bytes = flow_packets, flow_bytes

        # Verify cached flows
        grouped_cached_flows = self.group_flows_by_id(id_name='@', connection_flows=all_cached_flows)
        for flow_id, cached_flows in grouped_cached_flows.items():
            pre_hw_packets = 0
            pre_sw_packets = 0
            for cached_flow in cached_flows:
                cached_flow = self.parse_cached_flows(cached_flow)
                if not cached_flow or cached_flow['idle'] != 0:
                    continue
                if str(expected_protocol) not in cached_flow['protocol']:
                    # Ignore flows for protocol we don't care about, e.g. for iperf control connection
                    # (which is always TCP) when testing UDP.
                    continue
                hw_packets = cached_flow['packets_hw']
                sw_packets = cached_flow['packets_sw']
                if pre_hw_packets > hw_packets:
                    log.warning(f'Number of hw_packets did not increase according to previous flow: '
                                f'{pre_hw_packets} > {hw_packets} for {self.get_nickname()} device')
                if pre_sw_packets > sw_packets:
                    log.warning(f'Number of sw_packets did not increase according to previous flow: '
                                f'{pre_sw_packets} > {sw_packets} for {self.get_nickname()} device')
                pre_hw_packets = hw_packets
                pre_sw_packets = sw_packets
        return status

    @staticmethod
    def parse_cached_flows(cached_flow):
        cached_flow = cached_flow.split()
        parsed_flow = dict()
        # Incorrect flow. Proper cached flows should have at least 21 items
        if 21 > len(cached_flow):
            return parsed_flow
        idle = re.search(r'\d+', cached_flow[1])
        if not idle:
            return parsed_flow
        parsed_flow.update({'idle': int(idle.group()), 'swhit': int(cached_flow[2]), 'packets_sw': int(cached_flow[4]),
                            'packets_hw': int(cached_flow[7]), 'protocol': cached_flow[12]})
        return parsed_flow

    @staticmethod
    def group_flows_by_id(id_name, connection_flows):
        grouped_connection_flows = dict()
        for connection_flow in connection_flows:
            connection_flow_id = common_util.get_digits_value_from_text(value_to_take=id_name,
                                                                        text_response=connection_flow)
            if not connection_flow_id:
                continue
            if not grouped_connection_flows.get(connection_flow_id):
                grouped_connection_flows.update({connection_flow_id: list()})

            grouped_connection_flows[connection_flow_id].append(connection_flow)
        return grouped_connection_flows

    @staticmethod
    def group_archer_flows_by_id(archer_flows):
        grouped_archer_flows = dict()
        for archer_flow in archer_flows:
            archer_flow_id = re.search(r'(?<=table_index ).\d+', archer_flow)
            if not archer_flow_id:
                continue
            archer_flow_id = archer_flow_id.group()
            if not grouped_archer_flows.get(archer_flow_id):
                grouped_archer_flows.update({archer_flow_id: list()})
            grouped_archer_flows[archer_flow_id].append(archer_flow)
        return grouped_archer_flows

    @staticmethod
    def parse_ip_address_for_accelerator(ip_address):
        if ':' in ip_address:
            parsed_address = common_util.get_full_ipv6_address(abbreviated_ipv6_addr=ip_address)
        else:
            # bcm always uses 3 digits for IP, ex 192.168.200.24 is 192.168.200.024
            parsed_address = [value.zfill(3) for value in ip_address.split('.')]
            parsed_address = '.'.join(parsed_address)
        return parsed_address

    def is_fw_fuse_burned(self, **kwargs):
        """Returns True when device firmware fuse is burned (is locked) and False otherwise."""
        response = self.run_command("pmf -fuse verify", **kwargs)
        match = re.search(
            r"(Secure boot)(\ *)(: UNSECURE; JTAG:UNLOCKED)",
            self.get_stdout(response, **kwargs)
        )
        return match is None
