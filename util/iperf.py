import re
from typing import Union

from lib_testbed.generic.client.models.generic.client_api import ClientApi
from lib_testbed.generic.util.iperf_lib.iperf_linux import IperfServerLinux, IperfClientLinux
from lib_testbed.generic.util.iperf_lib.iperf_windows import IperfServerWindows, IperfClientWindows
from lib_testbed.generic.util.iperf_lib.iperf_lib import IperfServerLib, IperfClientLib
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.pod.generic.pod_api import PodApi
from lib_testbed.generic.util.config import REMOTE_HOST_CLIENT_NAME


class Iperf:

    server_lib_map = {'linux': IperfServerLinux,
                      'rpi': IperfServerLinux,
                      'mac': IperfServerLinux,
                      'debian': IperfServerLinux,
                      'windows': IperfServerWindows}

    client_lib_map = {'linux': IperfClientLinux,
                      'rpi': IperfClientLinux,
                      'mac': IperfClientLinux,
                      'debian': IperfClientLinux,
                      'windows': IperfClientWindows}

    def __init__(self, server: Union[ClientApi, PodApi], client: Union[ClientApi, PodApi], port: int = None,
                 interval: int = 1, duration: int = 300, bitrate: str = None, parallel: int = 5, omit: int = 2,
                 mss: int = None, connect_timeout_ms: int = 30000, bytes_to_send: int = None,
                 iperf_ver: int = 3, protocol: str = 'tcp'):

        self.server = server
        self.client = client
        self.port = port
        self.interval = interval
        self.duration = duration
        self.protocol = protocol.lower()
        self.bitrate = self.limit_bitrate(bitrate)
        self.parallel = parallel
        self.omit = omit
        self.mss = mss
        self.connect_timeout_ms = connect_timeout_ms
        self.bytes_to_send = bytes_to_send
        self.iperf_ver = iperf_ver

        self.server = self._load_proper_libray(self.server_lib_map, **self.server_params)
        self.client = self._load_proper_libray(self.client_lib_map, **self.client_params)

    def start_server(self, bind_host: str = '', retries: int = 3, extra_param: str = '') -> None:

        self.server.start_server(bind_host, retries, extra_param)

    def start_client(self, server_ip: str = None, duration: int = None, reverse: bool = False, extra_param: str = '',
                     port: int = None, bind_host: str = '') -> None:

        self.client.start_client(server_ip, duration, reverse, extra_param, port, bind_host)

    def get_result_from_client(self, timeout: int = None, skip_exception: bool = False) -> dict:

        return self.client.get_result_from_client(timeout, skip_exception)

    def get_result_from_server(self) -> dict:

        return self.server.get_result_from_server()

    def export_result_to_csv(self, filename: str = None, attach_to_allure: bool = True) -> None:

        self.client.export_result_to_csv(filename, attach_to_allure)

    def export_json_results_to_allure(self, file_name: str, path_to_file: str) -> None:

        self.client.export_json_results_to_allure(file_name, path_to_file)

    def generate_plot(self, filename: str = None, attach_to_allure: bool = True) -> None:

        self.client.generate_plot(filename, attach_to_allure)

    def dispose(self):

        log.info('Disposing iperf and temporary files...')

        self.client.dispose()
        self.server.dispose()

    def _load_proper_libray(self, lib_map: dict, client: Union[ClientApi, PodApi],
                            **kwargs) -> Union[IperfServerLib, IperfClientLib]:

        if self._check_if_client_is_a_pod(client):
            lib = lib_map['linux']
        else:
            lib = lib_map[client.config_type()]
        return lib(client, **kwargs)

    def _check_if_client_is_a_pod(self, client) -> bool:

        return isinstance(client, PodApi)

    @property
    def client_params(self):

        client_params = {
            'client': self.client,
            'server_ip': self.server.iperf_ip_address,
            'port': self.server.port,
            'interval': self.interval,
            'duration': self.duration,
            'bitrate': self.bitrate,
            'parallel': self.parallel,
            'omit': self.omit,
            'mss': self.mss,
            'connect_timeout_ms': self.connect_timeout_ms,
            'bytes_to_send': self.bytes_to_send,
            'iperf_ver': self.iperf_ver,
            'protocol': self.protocol}

        return client_params

    @property
    def server_params(self):

        server_params = {
            'client': self.server,
            'port': self.port,
            'interval': self.interval,
            'protocol': self.protocol,
            'iperf_ver': self.iperf_ver}

        return server_params

    def limit_bitrate(self, current_bitrate):
        # Limit bitrate on public server to avoid an overload issues
        if (self.server.nickname != REMOTE_HOST_CLIENT_NAME):
            return current_bitrate

        # Consider MBytes to limit if provided
        if current_bitrate and 'M' in current_bitrate:
            current_bitrate_int = int(re.search(r'\d+', current_bitrate).group())
            limited_bitrate = '10M' if current_bitrate_int >= 10 else current_bitrate
        else:
            limited_bitrate = '10M' if self.protocol == 'tcp' else '1M'
        log.info(f'Limiting bitrate for {self.server.nickname} server to {limited_bitrate} value')
        return limited_bitrate
