import allure
import json
import re

from abc import ABC, abstractmethod

from lib_testbed.generic.util.logger import log


class IperfServerLib(ABC):
    @abstractmethod
    def start_server(self, bind_host: str = "", retries: int = 3, extra_param: str = "") -> None:
        pass

    @abstractmethod
    def get_result_from_server(self, skip_exception: bool = False) -> dict:
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
    def start_client(
        self,
        server_ip: str = None,
        duration: int = None,
        reverse: bool = False,
        extra_param: str = "",
        port: int = None,
        bind_host: str = "",
    ) -> None:
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

    @abstractmethod
    def flush_iperf_result(self):
        pass


# Interval (-i) granularity must be an integer, so we ignore everything after the dot in start/stop field.
# Some iperf2 versions report some small offset for those fields, and do that inconsistently (e.g. report
# that offset only in SUM line, but not in individual stream lines).
_IPERF_2_RESULT = re.compile(
    r"""
    \[((?P<sum>SUM)|[ ]+\*?(?P<socket>\d+))\]           # SUM or stream ID / socket in square brackets
    [ ]+(?P<start>\d+)(\.\d+)?-                         # Start of measurement interval, in seconds
    [ ]*(?P<end>\d+)(\.\d+)?[ ]sec                      # End of measurement interval, in seconds
    [ ]+(?P<bytes>\d+(\.\d+)?)[ ]Bytes                  # Transfered bytes
    [ ]+(?P<bandwidth>\d+(\.\d+)?)                      # Bandwidth,
    [ ](?P<unit>(bits|Bytes))/sec                       # in bits or bytes per second
    """,
    re.VERBOSE,
)


class IperfCommon:
    def get_iperf3_results(self, iperf_results: str, force_parse: bool = False) -> dict:
        # fix nan values
        iperf_res = ""
        for line in iperf_results.splitlines():
            if "nan" in line:
                line = line.replace("nan", "0")
            iperf_res += f"{line}\n"
        # Make sure we want to load only iperf output without std err
        iperf_res = iperf_res[iperf_res.find("{") :]
        try:
            res = json.loads(iperf_res)
            # some iperf3 version return sum some sum_received
            if "end" in res and "sum_received" not in res["end"] and res["end"].get("sum"):
                res["end"]["sum_received"] = res["end"]["sum"]
        except json.decoder.JSONDecodeError as err:
            # Sometimes when connection error appears Iperf3 merge two json configs with missed comma separator
            # Try load only first json object.
            broken_index_number = re.search(r"(?<=char).\d+", err.args[0])
            if broken_index_number and not force_parse:
                broken_index_number = int(broken_index_number.group())
                return self.get_iperf3_results(iperf_results[:broken_index_number], force_parse=True)
            log.error(f"Cannot parse iperf_res: {err}\n{iperf_results}")
            assert False, "Cannot parse iperf results"
        if (
            hasattr(self, "iperf_terminated")
            and self.iperf_terminated
            and res.get("error", "") == "interrupt - the client has terminated"
        ):
            res.pop("error")
            # if iperf is terminated sum_sent or received depends on the traffic direction is always 0,
            # so make both values the same
            if res["end"].get("sum_sent", {}).get("bytes", -1) == 0:
                res["end"]["sum_sent"] = res["end"].get("sum_received", res["end"].get("sum", {}))
            elif res["end"].get("sum_received", {}).get("bytes", -1) == 0:
                res["end"]["sum_received"] = res["end"].get("sum_sent", res["end"].get("sum", {}))
        return res

    def get_iperf2_results(self, iperf_results: str) -> dict:
        parsed_result = dict(intervals=[])
        intervals = {}
        flows_ids = []
        for line in iperf_results.splitlines():
            if re.findall(r"local .* port .*", line):
                if "connected" not in line:
                    log.error("Iperf did not connect to server")
                    parsed_result.update({"error": "Iperf did not connect to server"})
                    break
                elif "connected" in line and not intervals:
                    # Collect all iperf2 flow IDs which should be considered during parsing results.
                    # Sometimes in the middle of the traffic run, iperf2 server creates additional
                    # flow with unexpected results. Skip this results.
                    if flow_id := re.search(r"\[.*\]", line):
                        flows_ids.append(flow_id.group())
                    continue
            if "0.0- 0.0 sec" in line:
                continue

            match = _IPERF_2_RESULT.match(line)
            if not match:
                continue

            flow_id = re.search(r"\[.*\]", line).group()
            if not match["sum"] and flow_id not in flows_ids:
                continue

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

    def export_result_to_csv(self, filename: str = None, attach_to_allure: bool = True) -> None:
        if self.json_result is None:
            self.json_result = self.get_result_from_client()

        iperf_error = self.json_result.get("error")
        if iperf_error and "interrupt" not in iperf_error:
            raise Exception(f"Iperf ended with error {iperf_error}")

        filename = filename if filename is not None else self.csv_file
        file = open(filename, "w")

        csv_header = "Time elapsed in seconds; Speed in megabits per second\n"
        self.csv_result = [csv_header]
        file.write(csv_header)
        for item in self.json_result["intervals"]:
            item = item["sum"]
            csv_line = f'{int(round(item["end"]))}; {item["bits_per_second"] / 10 ** 6}'
            self.csv_result.append(csv_line)
            file.write(f"{csv_line}\n")

        file.flush()
        file.close()

        if attach_to_allure:
            allure.attach.file(filename, name=filename.split("/")[-1], attachment_type=allure.attachment_type.CSV)

    def export_json_results_to_allure(self, file_name: str, path_to_file: str) -> None:
        if self.json_result is None:
            self.json_result = self.get_result_from_client()

        with open(path_to_file, "w+") as json_file:
            json.dump(self.json_result, json_file, indent=2)

        allure.attach.file(path_to_file, name=file_name, attachment_type=allure.attachment_type.JSON)

    def generate_plot(self, filename: str = None, attach_to_allure: bool = True) -> None:
        import matplotlib
        from lib_testbed.generic.util.plotter import Plotter, PlotterSerie

        matplotlib.use("Agg")

        if self.json_result is None:
            self.json_result = self.get_result_from_client()

        iperf_error = self.json_result.get("error")
        if iperf_error and "interrupt" not in iperf_error:
            raise Exception(f"Iperf ended with error {iperf_error}")

        x_values = list()
        y_values = list()

        max_val = 0
        sum = 0
        for item in self.json_result["intervals"]:
            item = item["sum"]
            x_values.append(int(round(item["end"])))
            y_values.append(item["bits_per_second"] / 10**6)
            sum += item["bits_per_second"]
            if item["bits_per_second"] / 10**6 > max_val:
                max_val = item["bits_per_second"] / 10**6

        avg_speed = sum / len(x_values) / 10**6

        plt = Plotter("Time [s]", "Speed [Mb/s]")
        plt.add_series(PlotterSerie(x_values, y_values))
        plt.add_series(PlotterSerie(x_values, [avg_speed] * len(x_values)))

        filename = plt.save_to_file(filename if filename is not None else self.plot_file)

        if attach_to_allure:
            allure.attach.file(filename, name=filename.split("/")[-1], attachment_type=allure.attachment_type.PNG)
