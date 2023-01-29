import re
import time
from typing import Union
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.pod.generic.pod_lib import PodLib as PodLibGeneric

MANAGER_RESTART_TIMEOUT = 80             # default for DM Manager, and other non-SM Managers


class PodLib(PodLibGeneric):

    # In whole framework to get temperature we use radio index since prefix of phy radio is the same on qca/brcm
    # MTK platform has different prefix for every phy radio.
    # Therefore, we need to update all calls to temperatures in framework
    # optional
    def get_radio_temperature(self, radio_index, **kwargs):
        self.last_cmd['command'] = 'unknown'
        self.last_cmd['name'] = 'unknown'
        return [0, '', '']

    # optional
    def get_driver_data_rate(self, ifname, mac_address, **kwargs):
        """
        Get current data rate from driver
        Args:
            ifname: (str) Name of interface
            mac_address: (str) MAC address of connected client interface
        Returns: list (ret, stdout, stderr) stdout as (dict) {'data_rate': (str), 'bytes': (int), 'rssi': (list)}

        """
        driver_data_rate = self.run_command(f'iwpriv {ifname} get McsStatsRx={mac_address};dmesg -c', **kwargs)
        if driver_data_rate[0]:
            return driver_data_rate
        data_rate_table = list()
        for line in driver_data_rate[1].splitlines():
            if 'bw' not in line:
                continue
            # [ 8105.552000] idx=22   bw=0 nss=1 mcs=7 : avg_snr=0 bytes=0 msdu=0 mpdu=0 ppdu=0 retry=0
            _, _, bw, nss, mcs, _, dbytes, *_ = re.findall(r'(\d+(?:\.\d+)?)', line)
            drate = f'[{bw} {nss} {mcs}]'
            data_rate_table.append({'data_rate': drate, 'bytes': dbytes, 'rssi': 'unknown'})
        driver_data_rate[1] = data_rate_table
        return driver_data_rate

    # mandatory for DFS testing: tests/dfs
    def trigger_single_radar_detected_event(self, phy_radio_name, **kwargs):
        """
        Trigger radar detected event
        Args:
            phy_radio_name: (str): Phy radio name
            **kwargs:

        Returns: list(retval, stdout, stderr)

        """
        response = self.run_command(f'iwpriv {phy_radio_name} set RDDReport=0', **kwargs)
        return response

    # optional
    def get_boot_partition(self, **kwargs):
        """
        Get boot partition name
        Args:
            **kwargs:

        Returns: list(retval, stdout, stderr)
        """
        self.last_cmd['command'] = 'unknown'
        self.last_cmd['name'] = 'unknown'
        return [1, '', 'Need to be implemented']

    # optional
    def get_connection_flows_dump(self, ip_address='', **kwargs):
        """
        Get connection flow dump from device
        Args:
            ip_address: (str) optional, get entries only for target IP address
            **kwargs:

        Returns: list() list of connection flows

        """
        connection_flows = self.run_command('hwnat -g', **kwargs)
        if connection_flows[0]:
            return []
        parse_sfe_dump = [line.strip() for line in connection_flows[1].splitlines() if ip_address in line]
        parse_sfe_dump = '\n'.join(parse_sfe_dump)
        connection_flows[1] = parse_sfe_dump
        return connection_flows

    # mandatory for tests/device/test_07_fcach_flush.py
    def get_connection_flows(self, ip, **kwargs):
        """
        Get connection flow id for specific IP address
        Args:
            ip: (str) IP address
            **kwargs:

        Returns: (list) flow list

        """
        response = self.run_command('hwnat -g', **kwargs)
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
        res = [0, '', '']
        phy_radios = self.capabilities.get_phy_radio_ifnames(return_type=list)
        for phy_radio in phy_radios:
            res = self.merge_result(res, self.run_command(f"iwpriv {phy_radio} set CountryCode={region}"))
        return res

    # mandatory if device supports switching regulatory domains and device has 3 wifi radios
    def set_region_three_radios_model(self, region, **kwargs):
        res = [0, '', '']
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
        result = self.run_command("sh -c 'sleep 3; echo c > /proc/sysrq-trigger' &", **kwargs)
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
        self.last_cmd['command'] = 'unknown'
        self.last_cmd['name'] = 'unknown'
        # Tx power doesn't appear in iwconfig
        return [0, '', '']

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
        self.last_cmd['command'] = 'unknown'
        self.last_cmd['name'] = 'unknown'
        return [0, '', '']

    # optional
    def increase_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Increase value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns:

        """
        self.last_cmd['command'] = 'unknown'
        self.last_cmd['name'] = 'unknown'
        return [0, '', '']

    # optional
    def set_tx_power(self, tx_power, interfaces=None, **kwargs):
        """
        Set current Tx power in dBm
        Args:
            interfaces: (str) or (list) Name of wireless interfaces
            tx_power: (int) Tx power in dBm.

        Returns:

        """
        self.last_cmd['command'] = 'unknown'
        self.last_cmd['name'] = 'unknown'
        return [0, '', '']

    def kill_manager(self, wait_for_restart=False, **kwargs):
        """
        Kill and restart service managers - Override for MTK, requires 'ps ux', 'kill -11'
        Args:
            wait_for_restart: (bool) wait till manager is started again
            **kwargs:
        Returns: list [retval, stdout, stderr]
        """
        active_managers = self.get_managers_list(**kwargs)
        assert active_managers, 'No managers appear to be running'
        for manager in active_managers:
            initial_pid = active_managers[manager]
            log.info(f'Killing process for {manager} manger: kill -11 {initial_pid}')
            self.run_command(f'kill -11 {initial_pid}')

            if wait_for_restart:
                time_to_restart = MANAGER_RESTART_TIMEOUT
                if manager == 'sm':
                    time_to_restart = self.device.config['capabilities']['kpi']['sm_restart']
                log.info(f'Wait up to {time_to_restart} sec for OpenSync manager restart...')
                time.sleep(time_to_restart)

                log.info(f'Check if {manager} manger has been restarted')
                active_managers = self.get_managers_list(**kwargs)
                new_pid = active_managers.get(manager)
                assert new_pid, f'No managers restarted within timeout period. Active managers:\n{active_managers}'
                assert new_pid != initial_pid, f'{manager} manager has not restarted, PID unchanged: {new_pid}'
                log.info(f'{manager} manager: restart verified')
        return [0, active_managers, '']

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
            managers_name = self.run_command(f"ls {osp}/bin | awk '/^.*m$/'", **kwargs)[1].split('\n')
        else:
            managers_name = managers_name if isinstance(managers_name, list) else [managers_name]

        manager_paths = [f'{osp}/bin/{manager_name}' for manager_name in managers_name]
        for manager_path in manager_paths:
            matched_processes = self.get_stdout(
                self.run_command(f'ps ux | grep {manager_path}', **kwargs)).split('\n')[:-1]
            manager_processes = [process_name for process_name in matched_processes if 'grep' not in process_name]
            for process in manager_processes:
                manager_pid = [int(pid) for pid in process.split() if pid.isdigit()][0]
                manager_name = manager_path.split('/')[-1]
                manager_list[manager_name] = manager_pid
        return manager_list
