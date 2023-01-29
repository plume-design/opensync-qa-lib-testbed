import os
import re
import json
import time
import random
import allure
from datetime import datetime, timedelta
from uuid import uuid1
from typing import Union, Tuple, List

from lib_testbed.generic.client.models.generic.client_api import ClientApi
from lib_testbed.generic.pod.pod import PodApi
from lib_testbed.generic.util.iperf_lib.iperf_lib import IperfClientLib, IperfServerLib, IperfParser
from lib_testbed.generic.util.config import REMOTE_HOST_CLIENT_NAME
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.common import get_iperf_ipv4_host_address


class IperfLinuxCommon(IperfParser):

    @property
    def iperf_ip_address(self) -> Union[str, None]:
        return get_iperf_ipv4_host_address(client_obj=self.client)

    def _get_iperf_id(self, device: Union[ClientApi, PodApi], cmd: str) -> Union[Tuple[str, List[int]], None]:
        mode = 'server' if ' -s ' in cmd else 'client'
        sep = ' -s ' if ' -s ' in cmd else ' -c '
        ps_cmd = 'ps aux' if 'Clients' == device.lib.device_type else 'ps'
        pid_col_index = 1 if 'Clients' == device.lib.device_type else 0
        # Preserve identifying part of command line for later, so that we don't kill a reused pid.
        cmd_id = cmd.split(sep)[0]
        ps_res = device.lib.run_command(f'{ps_cmd} | grep -F "{cmd_id}"', timeout=10)
        # sometime SSH gets stuck here, so retry in such case
        if ps_res[0] == 137:
            time.sleep(3)
            ps_res = device.lib.run_command(f'{ps_cmd} | grep -F "{cmd_id}"', timeout=10)
        ps_res = ps_res[1]
        # There are multiple processes associated with single iperf when we start it in a network namespace.
        iperf_pids = [line.split()[pid_col_index] for line in ps_res.splitlines() if 'grep' not in line]
        iperf_pids = [int(pid) for pid in iperf_pids if pid.isdigit()]
        if not iperf_pids:
            # in case of small traffic the iperf process is quickly closed:
            if mode == 'client' and self.bytes_to_send:
                return cmd_id, [0]
            return None
        log.info(f'Iperf {mode} started successfully on {device.nickname} with PIDs {iperf_pids}')
        return cmd_id, iperf_pids

    def reinit_iperf_client(self):
        """
        Re init iperf client configuration in order to start another iperf process on the same client
        Returns:
        """
        self.json_result = None
        self.csv_result = None
        self.iperf_id = None
        self.measurement_start_time = datetime.now()

        self.iperf_output_file = f'/tmp/iperf-{self.client.get_nickname()}-{self.unique_id}.out'
        self.plot_file = f'/tmp/iperf-plot-{self.client.get_nickname()}-{self.unique_id}.png'
        self.csv_file = f'/tmp/iperf-output-{self.client.get_nickname()}-{self.unique_id}.csv'

    def dispose(self):

        try:
            os.remove(self.csv_file)
        except FileNotFoundError:
            pass
        try:
            os.remove(self.plot_file)
        except FileNotFoundError:
            pass
        self.kill_iperf()
        self.client.lib.run_command(f'rm {self.iperf_output_file}', skip_exception=True)

    def kill_iperf(self):
        if self.iperf_id is not None:
            cmd_id, iperf_pids = self.iperf_id
            self.iperf_id = None
            ps = 'ps aux' if 'Clients' == self.client.lib.device_type else 'ps'
            for iperf_pid in iperf_pids:
                if cmd_id in self.client.lib.run_command(f'{ps} | grep {iperf_pid}')[1]:
                    self.client.lib.run_command(f'{self.sudo} kill -9 {iperf_pid}')

    @property
    def sudo(self):
        # pods and remote iperf-server do not have sudo
        if self.client.lib.device_type != 'Clients' or self.client.nickname == REMOTE_HOST_CLIENT_NAME:
            return ''
        return 'sudo'

    def parse_iperf_results(self, iperf_results: str, force_parse: bool = False) -> dict:
        if self.iperf_ver == 2:
            return self.get_iperf2_results(iperf_results)
        return self.get_iperf3_results(iperf_results, force_parse)


class IperfServerLinux(IperfLinuxCommon, IperfServerLib):

    def __init__(self, client: Union[ClientApi, PodApi], port: int = None, interval: int = 1, iperf_ver: int = 3,
                 protocol: str = 'tcp'):
        self.iperf_cmd = "iperf3 -J" if iperf_ver == 3 else "iperf -f b"
        self.client = client
        self.port = self.find_unused_port() if port is None else port
        self.interval = interval
        self.protocol = protocol
        self.server_ip = self.iperf_ip_address
        self.unique_id = uuid1()
        self.iperf_ver = iperf_ver
        assert iperf_ver in (2, 3)
        assert self.protocol in ("tcp", "udp")

        self.reinit_iperf_client()

    def start_server(self, bind_host: str = '', retries: int = 3, extra_param: str = '') -> None:
        log.info('Starting iperf server...')
        bind_host = f'-B {bind_host} ' if bind_host else ''
        udp = '-u ' if self.protocol == 'udp' and self.iperf_ver == 2 else ''
        cmd = f'{self.iperf_cmd} ' \
              f'-p {self.port} ' \
              f'-s ' \
              f'-i {self.interval} ' \
              f'{udp} ' \
              f'{extra_param} ' \
              f'{bind_host} ' \
              f'&> {self.iperf_output_file} ' \
              f'&'
        # Sometimes can not init iperf server for first attempt
        for retry in range(retries):
            self.client.lib.run_command(cmd)
            time.sleep(0.2)
            self.iperf_id = self._get_iperf_id(self.client, cmd)
            if self.iperf_id:
                server_log = self.client.lib.run_command(f'cat {self.iperf_output_file}')[1].strip()
                if "bind failed" in server_log:
                    log.warn(f'Iperf server could not bind: other process might be listening on port {self.port}')
                    self.kill_iperf()
                else:
                    break
            log.warn('Iperf server started unsuccessfully!. Try again in a few seconds')
            time.sleep(2)
        else:
            assert False, 'Iperf server started unsuccessfully!'

    def get_result_from_server(self) -> dict:
        """
        Read and parse results from iperf server. You need to wait for results from client first.
        """
        iperf_results = self.client.lib.run_command(f'cat {self.iperf_output_file}')[1].strip()
        assert iperf_results, 'No iperf results found on server'
        log.info('Successfully read iperf server results')
        return self.parse_iperf_results(iperf_results)

    def find_unused_port(self, min_port: int = 5000, max_port: int = 6000) -> int:
        netstat_out = self.client.lib.run_command('/bin/netstat -taun')[1]
        used_ports = set()
        for item in netstat_out.split('\n'):
            port = re.match(r'^(?:tcp|udp)[6]?\s+\d+\s+\d+\s\S+:(\d{1,5})\s+.+$', item)
            if port is not None:
                used_ports.add(port.groups()[0])

        while True:
            rnd_port = random.randint(min_port, max_port)
            if rnd_port not in used_ports:
                return rnd_port


class IperfClientLinux(IperfLinuxCommon, IperfClientLib):

    def __init__(self, client: Union[ClientApi, PodApi], server_ip: str = None, port: int = None, interval: int = 1,
                 duration: int = 300, bitrate: str = None, parallel: int = 5, omit: int = 2, mss: int = None,
                 connect_timeout_ms: int = 30000, bytes_to_send: int = None, iperf_ver: int = 3,
                 protocol: str = 'tcp'):

        self.iperf_cmd = "iperf3 -J" if iperf_ver == 3 else "iperf -f b"
        self.client = client
        self.port = port
        self.interval = interval
        self.duration = duration
        self.bitrate = bitrate
        self.parallel = parallel
        self.omit = omit
        self.mss = mss
        self.connect_timeout_ms = connect_timeout_ms
        self.bytes_to_send = bytes_to_send
        self.iperf_ver = iperf_ver
        self.protocol = protocol
        self.server_ip = server_ip
        self.unique_id = uuid1()
        assert iperf_ver in (2, 3)
        assert self.protocol in ("tcp", "udp")

        self.reinit_iperf_client()

    def start_client(self, server_ip: str = None, duration: int = None, reverse: bool = False, extra_param: str = '',
                     port: int = None, bind_host: str = '') -> None:

        if duration:
            self.duration = duration
        log.info('Starting iperf client...')
        duration_arg = f'-n {self.bytes_to_send}' if self.bytes_to_send else f'-t {self.duration} '
        if server_ip is None:
            server_ip = self.server_ip
        mss = f'-M {self.mss} ' if self.mss is not None else ''
        con_tt_supported = 'Clients' == self.client.lib.device_type and self.iperf_ver == 3
        con_tt = f"--connect-timeout {self.connect_timeout_ms} " if con_tt_supported else ''
        rev = '-R ' if reverse else ''
        bitrate_arg = f'-b {self.bitrate} ' if self.bitrate else ''
        omit_arg = f'-O {self.omit} ' if self.omit and self.iperf_ver == 3 else ''
        port = port if port else self.port
        udp = '-u ' if self.protocol == 'udp' else ''
        bind_host = f'-B {bind_host} ' if bind_host else ''
        cmd = f'{self.iperf_cmd} ' \
              f'-p {port} ' \
              f'-c {server_ip} ' \
              f'{bitrate_arg}' \
              f'-P {self.parallel} ' \
              f'{omit_arg}' \
              f'-i {self.interval} ' \
              f'{duration_arg} ' \
              f'{mss}' \
              f'{con_tt}' \
              f'{rev}' \
              f'{udp} ' \
              f'{extra_param} ' \
              f'{bind_host} ' \
              f'&> {self.iperf_output_file} ' \
              f'&'
        res = self.client.lib.run_command(cmd)
        self.measurement_start_time = datetime.now()

        if res[0] == 0:
            self.iperf_id = self._get_iperf_id(self.client, cmd)

        if res[0] != 0 or not self.iperf_id:
            iperf_results = self.client.lib.run_command(f'cat {self.iperf_output_file}')[1]
            log.error(f'Iperf client did not start\n: {iperf_results}')
            assert False, 'Iperf client did not start'

    def get_raw_iperf_result(self, timeout: int = None) -> str:
        log.info(f'Waiting for iperf results(ETA '
                 f'@{self.measurement_start_time + timedelta(seconds=self.duration)})')
        iperf_results = None
        # protection against infinite loop
        timeout = time.time() + timeout if timeout else time.time() + self.duration + 120
        ps_cmd = 'ps aux' if self.client.lib.device_type == 'Clients' else 'ps'
        while timeout > time.time():
            pid_grep = self.client.lib.run_command(f'{ps_cmd} | grep -F "{self.iperf_id[0]}" | grep -v grep')[1]
            if any(str(pid) in pid_grep for pid in self.iperf_id[1]):
                time.sleep(5)
            else:
                break
        iperf_results = self.client.lib.run_command(f'cat {self.iperf_output_file}')[1].strip()
        return iperf_results

    def get_result_from_client(self, timeout: int = None, skip_exception: bool = False) -> dict:
        iperf_results = self.get_raw_iperf_result(timeout=timeout)
        if skip_exception and not iperf_results:
            return {'error': 'No iperf results'}

        assert iperf_results, f'No iperf result after wait {self.duration + 120} seconds'
        log.info('Successfully got results')
        return self.parse_iperf_results(iperf_results)

    def export_result_to_csv(self, filename: str = None, attach_to_allure: bool = True) -> None:
        if self.json_result is None:
            self.json_result = self.get_result_from_client()

        iperf_error = self.json_result.get('error')
        if iperf_error and 'interrupt' not in iperf_error:
            raise Exception(f'Iperf ended with error {iperf_error}')

        filename = filename if filename is not None else self.csv_file
        file = open(filename, 'w')

        csv_header = 'Time elapsed in seconds; Speed in bits per second\n'
        self.csv_result = [csv_header]
        file.write(csv_header)
        for item in self.json_result['intervals']:
            item = item['sum']
            csv_line = f'{int(round(item["end"]))}; {item["bits_per_second"] / 1024 / 1024}'
            self.csv_result.append(csv_line)
            file.write(f'{csv_line}\n')

        file.flush()
        file.close()

        if attach_to_allure:
            allure.attach.file(filename, name=filename.split('/')[-1], attachment_type=allure.attachment_type.CSV)

    def export_json_results_to_allure(self, file_name: str, path_to_file: str) -> None:
        if self.json_result is None:
            self.json_result = self.get_result_from_client()

        with open(path_to_file, 'w+') as json_file:
            json.dump(self.json_result, json_file, indent=2)

        allure.attach.file(path_to_file, name=file_name, attachment_type=allure.attachment_type.JSON)

    def generate_plot(self, filename: str = None, attach_to_allure: bool = True) -> None:
        import matplotlib
        from lib_testbed.generic.util.plotter import Plotter, PlotterSerie
        matplotlib.use('Agg')

        if self.json_result is None:
            self.json_result = self.get_result_from_client()

        iperf_error = self.json_result.get('error')
        if iperf_error and 'interrupt' not in iperf_error:
            raise Exception(f'Iperf ended with error {iperf_error}')

        x_values = list()
        y_values = list()

        max_val = 0
        sum = 0
        for item in self.json_result['intervals']:
            item = item['sum']
            x_values.append(int(round(item['end'])))
            y_values.append(item['bits_per_second'] / 1024 / 1024)
            sum += item['bits_per_second']
            if item['bits_per_second'] / 1024 / 1024 > max_val:
                max_val = item['bits_per_second'] / 1024 / 1024

        avg_speed = sum / len(x_values) / 1024 / 1024

        plt = Plotter('Time [s]', 'Speed [Mb/s]')
        plt.add_series(PlotterSerie(x_values, y_values))
        plt.add_series(PlotterSerie(x_values, [avg_speed] * len(x_values)))

        filename = plt.save_to_file(filename if filename is not None else self.plot_file)

        if attach_to_allure:
            allure.attach.file(filename, name=filename.split('/')[-1], attachment_type=allure.attachment_type.PNG)
