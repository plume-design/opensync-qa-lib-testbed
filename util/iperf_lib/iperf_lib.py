import json
import re

from abc import ABC, abstractmethod

from lib_testbed.generic.util.logger import log


class IperfServerLib(ABC):

    @abstractmethod
    def start_server(self, bind_host: str = '', retries: int = 3, extra_param: str = '') -> None:
        pass

    @abstractmethod
    def get_result_from_server(self) -> dict:
        pass

    @abstractmethod
    def find_unused_port(self, min_port: int = 5000, max_port: int = 6000) -> int:
        pass

    @abstractmethod
    def iperf_ip_address(self) -> str:
        pass

    @abstractmethod
    def reinit_iperf_client(self) -> None:
        pass

    @abstractmethod
    def dispose(self) -> None:
        pass

    @abstractmethod
    def parse_iperf_results(self, iperf_results: str) -> dict:
        pass


class IperfClientLib(ABC):

    @abstractmethod
    def start_client(self, server_ip: str = None, duration: int = None, reverse: bool = False, extra_param: str = '',
                     port: int = None, bind_host: str = '') -> None:
        pass

    def get_raw_iperf_result(self, timeout: int = None) -> str:
        pass

    @abstractmethod
    def get_result_from_client(self, timeout: int = None, skip_exception: bool = False) -> dict:
        pass

    @abstractmethod
    def export_result_to_csv(self, filename: str = None, attach_to_allure: bool = True) -> None:
        pass

    @abstractmethod
    def export_json_results_to_allure(self, file_name: str, path_to_file: str) -> None:
        pass

    @abstractmethod
    def generate_plot(self, filename: str = None, attach_to_allure: bool = True) -> None:
        pass

    @abstractmethod
    def get_iperf2_results(self, iperf_results) -> dict:
        pass

    @abstractmethod
    def iperf_ip_address(self) -> str:
        pass

    @abstractmethod
    def reinit_iperf_client(self) -> None:
        pass

    @abstractmethod
    def dispose(self) -> None:
        pass

    @abstractmethod
    def parse_iperf_results(self, iperf_results: str) -> dict:
        pass


# Interval (-i) granularity must be an integer, so we ignore everything after the dot in start/stop field.
# Some iperf2 versions report some small offset for those fields, and do that inconsistently (e.g. report
# that offset only in SUM line, but not in individual stream lines).
_IPERF_2_RESULT = re.compile(r"""
    \[((?P<sum>SUM)|[ ]+\*?(?P<socket>\d+))\]           # SUM or stream ID / socket in square brackets
    [ ]+(?P<start>\d+)(\.\d+)?-                         # Start of measurement interval, in seconds
    [ ]*(?P<end>\d+)(\.\d+)?[ ]sec                      # End of measurement interval, in seconds
    [ ]+(?P<bytes>\d+(\.\d+)?)[ ]Bytes                  # Transfered bytes
    [ ]+(?P<bandwidth>\d+(\.\d+)?)                      # Bandwidth,
    [ ](?P<unit>(bits|Bytes))/sec                       # in bits or bytes per second
    """, re.VERBOSE)


class IperfParser:

    def get_iperf3_results(self, iperf_results: str, force_parse: bool = False) -> dict:
        # fix nan values
        iperf_res = ''
        for line in iperf_results.splitlines():
            if 'nan' in line:
                line = line.replace('nan', '0')
            iperf_res += f'{line}\n'
        # Make sure we want to load only iperf output without std err
        iperf_res = iperf_res[iperf_res.find('{'):]
        try:
            res = json.loads(iperf_res)
            # some iperf3 version return sum some sum_received
            if "end" in res and "sum_received" not in res['end'] and res['end'].get('sum'):
                res['end']['sum_received'] = res['end']['sum']
        except json.decoder.JSONDecodeError as err:
            # Sometimes when connection error appears Iperf3 merge two json configs with missed comma separator
            # Try load only first json object.
            broken_index_number = re.search(r'(?<=char).\d+', err.args[0])
            if broken_index_number and not force_parse:
                broken_index_number = int(broken_index_number.group())
                return self.get_iperf3_results(iperf_results[:broken_index_number], force_parse=True)
            log.error(f"Cannot parse iperf_res: {err}\n{iperf_results}")
            assert False, 'Cannot parse iperf results'
        return res

    def get_iperf2_results(self, iperf_results: str) -> dict:
        parsed_result = dict(intervals=[])
        intervals = {}
        for line in iperf_results.splitlines():
            if re.findall(r'local .* port .*', line):
                if 'connected' not in line:
                    log.error('Iperf did not connect to server')
                    parsed_result.update({'error': 'Iperf did not connect to server'})
                    break
                elif intervals:
                    # Sometimes iperf2 server gets confused and thinks that a second client has connected,
                    # and then outputs a bunch of intervals with zeros. Stop parsing at second connect.
                    break
            if "0.0- 0.0 sec" in line:
                continue
            match = _IPERF_2_RESULT.match(line)
            if match is not None:
                limits = float(match["start"]), float(match["end"])
                interval = intervals.setdefault(limits, {"streams": []})
                res = {}
                for datapoint in "start", "end", "bytes":
                    res[datapoint] = float(match[datapoint])
                bandwidth = float(match["bandwidth"])
                if match["unit"] == "Bytes":
                    res["bits_per_second"] = bandwidth * 8
                else:
                    res["bits_per_second"] = bandwidth
                if match["sum"]:
                    interval["sum"] = res
                else:
                    res["socket"] = match["socket"]
                    interval["streams"].append(res)
        # Summary interval "0.0-10.0" needs to come last, after regular interval "9.0-10.0".
        for _, interval in sorted(intervals.items(), key=lambda item: (item[0][1], -item[0][0])):
            # [SUM] line gets omitted when running with only one stream in parallel.
            if "sum" not in interval:
                interval["sum"] = interval["streams"][-1]
            parsed_result["intervals"].append(interval)
        # Last interval report contains summary data for whole run.
        if parsed_result["intervals"]:
            summary = parsed_result["intervals"].pop()
            summary["sum_sent"] = summary["sum_received"] = summary["sum"]
            parsed_result["end"] = summary
        return parsed_result
