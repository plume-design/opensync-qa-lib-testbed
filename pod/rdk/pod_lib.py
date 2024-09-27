import re
import time
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.pod.generic.pod_lib import PodLib as PodLibGeneric


class PodLib(PodLibGeneric):
    def version(self, **kwargs):
        """Display firmware version of node(s)"""
        return self.strip_stdout_result(
            self.run_command("cat /version.txt | awk -F 'imagename:' '{print $2}' | head -n 1")
        )

    # mandatory for statistic test cases: tests/stats
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
        response = self.run_command(f"iwpriv {phy_radio_name} set RDDReport=0", **kwargs)
        return response

    # optional
    def get_radio_temperature(self, radio_index, **kwargs):
        ret = self.run_command(f"wl -i wl{radio_index} phy_tempsense", **kwargs)
        # example output: "70 (0x46)"
        ret[1] = ret[1].split(" ")
        ret[1] = ret[1][0] if len(ret[1]) == 2 else "-1"
        return ret

    # optional
    def get_boot_partition(self, **kwargs):
        """
        Get boot partition name
        Args:
            **kwargs:
        Returns: list(retval, stdout, stderr)
        """
        self.last_cmd["command"] = "unknown"
        self.last_cmd["name"] = "unknown"
        return [1, "", "Need to be implemented"]

    # mandatory for tests/device/test_07_fcach_flush.py
    def get_connection_flows(self, ip, **kwargs):
        """
        Get connection flow id for specific IP address
        Args:
            ip: (str) IP address
            **kwargs:
        Returns: (list) flow list
        """
        response = self.run_command("hwnat -g", **kwargs)
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
        # ends immediately with crash and reboot, so sleep here otherwise command ends with timeout exception
        result = self.run_command("sh -c 'sleep 3; echo c > /proc/sysrq-trigger' > /dev/null 2>&1 &", **kwargs)
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
        cmd = "wl -i %s txpwr | awk '{print $1}'" % interface
        response = self.strip_stdout_result(self.run_command(cmd, **kwargs))
        return response

    # optional
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

    # optional
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

    # optional
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
