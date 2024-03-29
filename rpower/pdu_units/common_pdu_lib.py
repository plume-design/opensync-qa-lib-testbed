import functools
import time

from lib_testbed.generic.rpower.util import get_rpower_path


class CommonPduLib:
    def __init__(
        self, server_object, rpower_devices, pod_names, client_names, address, user, password, port, tb_config, **kwargs
    ):
        (
            self.server_object,
            self.rpower_devices,
            self.pod_names,
            self.client_names,
            self.address,
            self.user,
            self.password,
            self.port,
            self.tb_config,
        ) = (server_object, rpower_devices, pod_names, client_names, address, user, password, port, tb_config)
        if "rpower_timestamps" not in self.tb_config:
            self.tb_config["rpower_timestamps"] = dict()

    @functools.cached_property
    def rpower_tool(self):
        return get_rpower_path(self.server_object)

    def get_devices_to_execute(self, device_names):
        if isinstance(device_names, str):
            if device_names == "all":
                return self.rpower_devices.keys()
            elif device_names == "pods":
                return self.pod_names
            elif device_names == "clients":
                return self.client_names
            else:
                return [name for name in device_names.split(",") if name in self.rpower_devices]
        else:
            # Get all requested devices configured in rpower unit
            return [device_name for device_name in device_names if device_name in self.rpower_devices]

    @staticmethod
    def get_name():
        raise NotImplementedError

    def get_request_timestamp(self, device_names):
        ret = dict()
        for device in self.get_devices_to_execute(device_names):
            ret[device] = self.tb_config["rpower_timestamps"].get(device, -1)
        return ret

    def set_request_timestamp(self, device_names):
        for device in self.get_devices_to_execute(device_names):
            self.tb_config["rpower_timestamps"][device] = time.time()


class PduLib(CommonPduLib):
    @staticmethod
    def get_name():
        raise NotImplementedError

    def port_args(self, device_names):
        ports_to_execute = [
            str(self.get_pdu_device_port(device_name)) for device_name in self.get_devices_to_execute(device_names)
        ]
        return ",".join(ports_to_execute)

    def execute_request(self, ports, action_name, args=""):
        if not ports:
            return 0, "", ""
        args += (
            f" --pdu-type {self.get_name()} --user-name {self.user} --password {self.password} "
            f"--ip-address {self.address}:{self.port}"
        )
        return self.strip_stdout(self.server_object.run_raw(f"{self.rpower_tool} -p {ports} -a {action_name} {args}"))

    def execute_requests(self, device_names, action_name):
        device_names = self.get_devices_to_execute(device_names)
        responses = dict()
        for device_name in device_names:
            pdu_device_port = self.get_pdu_device_port(device_name)
            responses[device_name] = self.execute_request(ports=pdu_device_port, action_name=action_name)
        return responses

    @staticmethod
    def strip_stdout(response):
        response[1] = response[1].strip()
        return response

    def get_pdu_device_port(self, device_name):
        device_port = self.rpower_devices.get(device_name, "")
        assert device_port, f"Can not describe PDU port for {device_name} device"
        return device_port

    def parse_response(self, response_output, device_names):
        results = dict()
        device_names = self.get_devices_to_execute(device_names)
        if not device_names:
            return results
        response_stdout = response_output[1].split("\n")
        assert len(response_stdout) == len(device_names), f"Did not get responses from all devices: {device_names}"
        for i, device_name in enumerate(device_names):
            pdu_device_port = self.get_pdu_device_port(device_name)
            for stdout_port in response_stdout:
                if response_output[0] == 0:
                    # keeping this for backwards compatibility when the exit code was zero
                    if str(pdu_device_port) not in stdout_port:
                        continue
                    results[device_name] = (
                        [0, stdout_port, ""] if "failed" not in stdout_port.lower() else [1, "", stdout_port]
                    )
                    break
                else:
                    # get stdout and stderr if the exit code is not zero.
                    results[device_name] = [response_output[0], response_stdout[i], response_output[2].split("\n")[i]]
        return results

    def on(self, device_names):
        ports = self.port_args(device_names)
        response = self.execute_request(ports=ports, action_name="on")
        self.set_request_timestamp(device_names)
        return self.parse_response(response_output=response, device_names=device_names)

    def off(self, device_names):
        ports = self.port_args(device_names)
        response = self.execute_request(ports=ports, action_name="off")
        self.set_request_timestamp(device_names)
        return self.parse_response(response_output=response, device_names=device_names)

    def model(self):
        return self.execute_request(ports="0", action_name="model")

    def version(self):
        return self.execute_request(ports="0", action_name="version")
