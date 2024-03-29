import os
import time
import re

from datetime import datetime, timedelta
from uuid import uuid1
from typing import Union
from random import randint

from lib_testbed.generic.client.models.generic.client_api import ClientApi
from lib_testbed.generic.pod.pod import PodApi
from lib_testbed.generic.util.iperf_lib.iperf_lib import IperfClientLib, IperfServerLib, IperfCommon
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.common import get_iperf_ipv4_host_address


class IperfWindowsCommon(IperfCommon):
    @property
    def iperf_ip_address(self) -> Union[str, None]:
        return get_iperf_ipv4_host_address(client_obj=self.client)

    def reinit_iperf_client(self) -> None:
        """
        Re init iperf client configuration in order to start another iperf process on the same client
        Returns:
        """
        self.json_result = None
        self.csv_result = None
        self.iperf_pid = None
        self.measurement_start_time = datetime.now()

        self.iperf_output_file = rf"C:\tmp\iperf-{self.client.get_nickname()}-{self.unique_id}.out"
        self.plot_file = f"/tmp/iperf-plot-{self.client.get_nickname()}-{self.unique_id}.png"
        self.csv_file = f"/tmp/iperf-output-{self.client.get_nickname()}-{self.unique_id}.csv"

    def dispose(self) -> None:
        try:
            os.remove(self.csv_file)
        except FileNotFoundError:
            pass
        try:
            os.remove(self.plot_file)
        except FileNotFoundError:
            pass

        if self.iperf_pid is not None:
            self.client.lib.run_command(f"Stop-Process -Id {self.iperf_pid} -Force")
        self.client.lib.run_command(f"Remove-Item {self.iperf_output_file}", skip_exception=True)

    def flush_iperf_result(self):
        """Flush Iperf results."""
        self.client.lib.run_command(f"Remove-Item {self.iperf_output_file}", skip_exception=True)
        self.client.lib.run_command(f"New-Item {self.iperf_output_file}", skip_exception=True)

    def parse_iperf_results(self, iperf_results: str, force_parse: bool = False) -> dict:
        if self.iperf_ver == 2:
            return self.get_iperf2_results(iperf_results)
        return self.get_iperf3_results(iperf_results, force_parse)

    @property
    def _proper_iperf_cmd(self) -> str:
        iperf_cmd = {2: r"C:\iperf\iperf", 3: r"C:\iperf3\iperf3"}
        return iperf_cmd[self.iperf_ver]

    def create_iperf_startup_cmd(self, arguments: str):
        version_related_ars = {2: "-f b", 3: "-J"}

        client_config = self._get_client_config(self.client.lib.config)

        client_username = client_config["host"]["user"]
        client_password = client_config["host"]["pass"]

        cmd = (
            f"schtasks /create /ST {self.client.lib.current_time} /sc ONCE /tn iperf /tr "
            f'"cmd /c {self._proper_iperf_cmd} {version_related_ars[self.iperf_ver]} {arguments} >> '
            f'{self.iperf_output_file}" /RL HIGHEST /F /ru {client_username} /rp {client_password}'
        )
        return cmd

    def _get_iperf_pid(self, device: ClientApi, cmd: str = "", silent: bool = False) -> Union[int, None]:
        mode = "server" if " -s " in cmd else "client"
        process_name = "iperf3" if self.iperf_ver == 3 else "iperf"

        iperf_pid = device.lib.run_command(f"(Get-Process -Name {process_name} -ErrorAction SilentlyContinue).Id")[
            1
        ].replace("\r\n", "")

        if iperf_pid.isdigit():
            if not silent:
                log.info(f"Iperf {mode} started successfully on {device.get_nickname()} with PID {iperf_pid}")
        else:
            iperf_pid = None

        return iperf_pid

    def _get_client_config(self, tb_config):
        for client_config in tb_config["Clients"]:
            if client_config["name"] == self.client.get_nickname():
                return client_config

    _IPERF_RESULT = re.compile(
        r"""
        \[((?P<sum>SUM)|[ ]+(?P<socket>\d+))\]              # SUM or stream ID / socket in square brackets
        [ ]+(?P<start>\d+(\.\d+)?)-                         # Start of measurement interval, in seconds
        [ ]*(?P<end>\d+(\.\d+)?)[ ]sec                      # End of measurement interval, in seconds
        [ ]+(?P<bytes>\d+(\.\d+)?)[ ]Bytes                  # Transfered bytes
        [ ]+(?P<bandwidth>\d+(\.\d+)?)                      # Bandwidth,
        [ ](?P<unit>(bits|Bytes))/sec                       # in bits or bytes per second
        """,
        re.VERBOSE,
    )


class IperfServerWindows(IperfWindowsCommon, IperfServerLib):
    def __init__(
        self,
        client: Union[ClientApi, PodApi],
        port: int = None,
        interval: int = 1,
        iperf_ver: int = 3,
        protocol: str = "tcp",
    ):
        assert iperf_ver in (2, 3)
        assert self.protocol in ("tcp", "udp")
        self.iperf_ver = iperf_ver
        self.iperf_cmd = self._proper_iperf_cmd
        self.client = client
        self.port = self.find_unused_port() if port is None else port
        self.interval = interval
        self.protocol = protocol
        self.server_ip = self.iperf_ip_address
        self.iperf_pid = None
        self.unique_id = uuid1()

        self.reinit_iperf_client()

    def start_server(self, bind_host: str = "", retries: int = 3, extra_param: str = "") -> None:
        bind_host = f"-B {bind_host} " if bind_host else ""
        udp = "-u " if self.protocol == "udp" and self.iperf_ver == 2 else ""
        cmd = (
            f"{self.iperf_cmd} "
            f"-p {self.port} "
            f"-s "
            f"-i {self.interval} "
            f"{udp} "
            f"{extra_param} "
            f"{bind_host} "
            f"| Set-Content -Path {self.iperf_output_file}"
        )
        log.info(f"Starting iperf server on '{self.client.nickname}' by running '{cmd.split('|')[0].strip()}' ...")
        # Sometimes can not init iperf server for first attempt
        for retry in range(retries):
            self.client.lib.run_command(cmd)
            self.client.lib.run_command("schtasks /run /tn iperf")
            time.sleep(0.2)
            self.iperf_pid = self._get_iperf_pid(self.client, cmd)
            if self.iperf_pid:
                server_log = self.client.lib.run_command(f"type {self.iperf_output_file}")[1].strip()
                if "bind failed" in server_log:
                    log.warning(f"Iperf server could not bind: other process might be listening on port {self.port}")
                    self.client.lib.run_command(f"Stop-Process -Id {self.iperf_pid} -Force")
                else:
                    break
            log.warning("Iperf server started unsuccessfully!. Try again in a few seconds")
            time.sleep(2)
        else:
            assert False, "Iperf server started unsuccessfully!"

    def get_result_from_server(self, skip_exception: bool = False) -> dict:
        """
        Read and parse results from iperf server. You need to wait for results from client first.
        """
        iperf_results = self.client.lib.run_command(f"type {self.iperf_output_file}")[1].strip()
        if skip_exception and not iperf_results:
            return {"error": "No iperf results"}
        assert iperf_results, "No iperf results found on server"
        log.info("Successfully read iperf server results")
        return self.parse_iperf_results(iperf_results)

    def find_unused_port(self, min_port: int = 5000, max_port: int = 6000) -> int:
        while True:
            rnd_port = randint(min_port, max_port)
            cmd = f"Get-NetTCPConnection | where Localport -eq {rnd_port} | select Localport"
            output = self.client.lib.run_command(cmd)[1]
            if str(rnd_port) not in output:
                return rnd_port


class IperfClientWindows(IperfWindowsCommon, IperfClientLib):
    def __init__(
        self,
        client: Union[ClientApi, PodApi],
        server_ip: str = None,
        port: int = None,
        interval: int = 1,
        duration: int = 300,
        bitrate: str = None,
        parallel: int = 5,
        omit: int = 2,
        mss: int = None,
        connect_timeout_ms: int = 30000,
        bytes_to_send: int = None,
        iperf_ver: int = 3,
        protocol: str = "tcp",
    ) -> None:
        self.iperf_ver = iperf_ver
        self.iperf_cmd = self._proper_iperf_cmd
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
        self.protocol = protocol
        self.server_ip = server_ip
        self.unique_id = uuid1()
        assert self.protocol in ("tcp", "udp")
        assert self.iperf_ver in (2, 3)

        self.reinit_iperf_client()

    def start_client(
        self,
        server_ip: str = None,
        duration: int = None,
        reverse: bool = False,
        extra_param: str = "",
        port: int = None,
        bind_host: str = "",
    ) -> None:
        if duration:
            self.duration = duration
        duration_arg = f"-n {self.bytes_to_send}" if self.bytes_to_send else f"-t {self.duration} "
        if server_ip is None:
            server_ip = self.server_ip
        mss = f"-M {self.mss} " if self.mss is not None else ""
        rev = "-R " if reverse else ""
        bitrate_arg = f"-b {self.bitrate} " if self.bitrate else ""
        omit_arg = f"-O {self.omit} " if self.omit and self.iperf_ver == 3 else ""
        port = port if port else self.port
        udp = "-u " if self.protocol == "udp" else ""
        bind_host = f"-B {bind_host} " if bind_host else ""
        arguments = (
            f"-p {port} "
            f"-c {server_ip} "
            f"{bitrate_arg}"
            f"-P {self.parallel} "
            f"{omit_arg}"
            f"-i {self.interval} "
            f"{duration_arg} "
            f"{mss}"
            f"{rev}"
            f"{udp} "
            f"{extra_param} "
            f"{bind_host} "
        )

        cmd = self.create_iperf_startup_cmd(arguments)
        log.info(
            f"Starting iperf client on '{self.client.nickname}' by running "
            f"'{cmd.split('cmd /c')[-1].split('>>')[0].strip()}' ..."
        )

        time.sleep(5)
        self.client.lib.run_command(cmd)
        res = self.client.lib.run_command("schtasks /run /tn iperf")
        time.sleep(5)

        self.measurement_start_time = datetime.now()

        if res[0] == 0:
            self.client_pid = self._get_iperf_pid(self.client, cmd)

        if res[0] != 0 or not self.client_pid:
            iperf_results = self.client.lib.run_command(f"type {self.iperf_output_file}")[1]
            log.error(f"Iperf client did not start\n: {iperf_results}")
            assert False, "Iperf client did not start"
        self.measurement_start_time = datetime.now()

    def get_raw_iperf_result(self, timeout: int = None) -> str:
        log.info(
            f"Waiting for iperf results(ETA " f"@{self.measurement_start_time + timedelta(seconds=self.duration)})"
        )
        iperf_results = None
        # protection against infinite loop
        timeout = time.time() + timeout if timeout else time.time() + self.duration + 120
        while timeout > time.time():
            time.sleep(5)
            if not self._get_iperf_pid(self.client, silent=True):
                break

        iperf_results = self.client.lib.run_command(f"type {self.iperf_output_file}")[1].strip()
        return iperf_results

    def get_result_from_client(self, timeout: int = None, skip_exception: bool = False) -> dict:
        iperf_results = self.get_raw_iperf_result(timeout=timeout)
        if skip_exception and not iperf_results:
            return {"error": "No iperf results"}

        assert iperf_results, f"No iperf result after wait {self.duration + 120} seconds"
        log.info("Successfully got results")
        return self.parse_iperf_results(iperf_results)
