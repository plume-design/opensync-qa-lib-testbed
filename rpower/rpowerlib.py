import re
import time
import socket
import importlib
from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.client.client import Client
from lib_testbed.generic.util.config import init_fixed_host_clients
from lib_testbed.generic.rpower.util import get_rpower_path


class PowerControllerLib:
    def __init__(self, conf, **kwargs):
        self.tb_config = conf
        # this speeds up tools help
        skip_init = kwargs.pop("skip_init", False)
        if not skip_init:
            self.rpower_units = self.init_rpower_units()
            self.rpower_devices = self.get_all_rpower_devices()

    def init_rpower_units(self):
        if "rpower" not in self.tb_config:
            raise OpenSyncException(
                "Power control unit not configured for this testbed",
                f"Testbed configuration file {self.tb_config['location_file']} does not include rpower configuration",
            )
        rpower_units = list()
        for rpower_unit in self.tb_config["rpower"]:
            server_address, user, password, port = (
                socket.gethostbyname(rpower_unit["ipaddr"]),
                rpower_unit["user"],
                rpower_unit["pass"],
                rpower_unit["port"],
            )
            device_port = list()
            for device in rpower_unit["alias"]:
                if device.get("port") is None:
                    raise OpenSyncException(
                        "Can not load rpower library without PDU ports.", "Make sure PDU ports are configured"
                    )
                device_port.append(str(device.get("port")))
            server_object = self.init_server_object(address=server_address)
            pdu_ports = ",".join(device_port)
            pdu_type = self.get_pdu_type(
                rpi_server=server_object,
                ipaddr=server_address,
                username=user,
                password=password,
                port=port,
                pdu_ports=pdu_ports,
            )
            rpower_devices = self.init_rpower_devices(rpower_unit)
            pod_names = self.get_pdu_pod_names(rpower_devices)
            client_names = self.get_pdu_client_names(rpower_devices)
            pdu_lib = self.get_pdu_lib(pdu_type=pdu_type)(
                server_object=server_object,
                rpower_devices=rpower_devices,
                pod_names=pod_names,
                client_names=client_names,
                address=server_address,
                user=user,
                password=password,
                port=port,
                tb_config=self.tb_config,
            )
            rpower_units.append(pdu_lib)
        return rpower_units

    @staticmethod
    def get_pdu_lib(pdu_type):
        module_path = ".".join(["lib_testbed", "generic", "rpower", "pdu_units", pdu_type])
        r = re.compile(f".*{pdu_type.replace('_', '')}", re.IGNORECASE)
        module = importlib.import_module(module_path)
        class_name = list(filter(r.match, dir(module)))
        if not class_name:
            raise Exception(f"Can not load rpower library for {pdu_type} PDU type")
        class_name = class_name[0]
        return getattr(module, class_name)

    @staticmethod
    def init_rpower_devices(rpower_unit):
        rpower_devices = dict()
        for device in rpower_unit["alias"]:
            device_name = device.get("name")
            device_port = device.get("port")
            assert device_name, "Rpower alias name not set in location config "
            assert device_port, f"Rpower port number is not set in location config for {device_name} device"
            rpower_devices[device_name] = device_port
        return rpower_devices

    def get_all_devices(self):
        all_devices = list()
        for pdu_unit in self.rpower_units:
            all_devices.extend(pdu_unit.get_devices_to_execute("all"))
        return all_devices

    def get_client_devices(self):
        client_devices = list()
        for pdu_unit in self.rpower_units:
            client_devices.extend(pdu_unit.get_devices_to_execute("clients"))
        return client_devices

    def get_nodes_devices(self):
        nodes_devices = list()
        for pdu_unit in self.rpower_units:
            nodes_devices.extend(pdu_unit.get_devices_to_execute("pods"))
        return nodes_devices

    def get_device_names(self, device_type):
        node_names = [node.get("name") for node in self.tb_config.get(device_type, [])]
        return node_names

    def get_pdu_pod_names(self, rpower_devices):
        return [
            device_name
            for device_name in self.get_device_names(device_type="Nodes")
            if device_name in rpower_devices.keys()
        ]

    def get_pdu_client_names(self, rpower_devices):
        return [
            device_name
            for device_name in self.get_device_names(device_type="Clients")
            if device_name in rpower_devices.keys()
        ]

    def init_server_object(self, address):
        if self.tb_config.get("ssh_gateway") is None:
            return None
        config = {
            "ssh_gateway": {
                "user": self.tb_config.get("ssh_gateway", {}).get("user", "plume"),
                "pass": self.tb_config.get("ssh_gateway", {}).get("pass", "plume"),
                "port": self.tb_config.get("ssh_gateway", {}).get("port", 22),
                "hostname": self.tb_config.get("ssh_gateway", {}).get("hostname", address),
                "opts": self.tb_config.get("ssh_gateway", {}).get("opts", {}),
            }
        }
        init_fixed_host_clients(config)
        kwargs = {"config": config, "multi_obj": True, "nickname": "host", "skip_logging": True}
        client_obj = Client(**kwargs)
        return client_obj.resolve_obj(**kwargs)

    @staticmethod
    def get_pdu_type(rpi_server, ipaddr, username, password, port, pdu_ports):
        if rpi_server is None:
            return "no_rpower_on_rpi_server"
        rpower_tool = get_rpower_path(rpi_server)
        ret = rpi_server.run_raw(
            f"{rpower_tool} -a name --ip-address {ipaddr}:{port} --user-name {username}" f" --password {password}"
        )
        # Min supported RPI server version for a new PDULib is: plume_rpi_server__v2.0-157
        if ret[0]:
            return "no_rpower_on_rpi_server"
        return ret[1].strip()

    def _get_request_timestamp(self, device_names):
        "Get timestamp of the last socket operation"
        response = dict()
        for rpower_unit in self.rpower_units:
            response.update(rpower_unit.get_request_timestamp(device_names))
        return response

    def get_last_request_time(self, device_names):
        "Get time [sec] since last socket operation"
        last_request_time = self._get_request_timestamp(device_names)
        for device in last_request_time:
            timestamp = last_request_time[device]
            last_request_time[device] = int(time.time() - timestamp) if timestamp != -1 else -1
        return last_request_time

    def get_all_rpower_devices(self):
        rpower_devices = list()
        for rpower_unit in self.rpower_units:
            rpower_devices.extend(rpower_unit.rpower_devices.keys())
        return rpower_devices

    def verify_requested_devices(self, device_names):
        if device_names in ["all", "pods", "clients"]:
            return device_names
        device_names = device_names.split(",") if isinstance(device_names, str) else device_names
        for device_name in device_names:
            assert device_name in self.rpower_devices, f"{device_name} is not configured in rpower config."
        return device_names

    def on(self, device_names):
        "Turn devices on"
        device_names = self.verify_requested_devices(device_names=device_names)
        response = dict()
        for rpower_unit in self.rpower_units:
            response.update(rpower_unit.on(device_names))
        return response

    def off(self, device_names):
        "Turn devices off"
        device_names = self.verify_requested_devices(device_names=device_names)
        response = dict()
        for rpower_unit in self.rpower_units:
            response.update(rpower_unit.off(device_names))
        return response

    def status(self, device_names="all"):
        "Get devices power status"
        device_names = self.verify_requested_devices(device_names=device_names)
        response = dict()
        for rpower_unit in self.rpower_units:
            response.update(rpower_unit.status(device_names))
        return response

    def version(self):
        "Get PDU FW version"
        response = dict()
        for rpower_unit in self.rpower_units:
            version = rpower_unit.version()
            # for no_rpower_on_rpi_server we get all PDU at once
            if isinstance(version, dict):
                response = version
                break
            response.update({rpower_unit.address: version})
        return response

    def model(self):
        "Get PDU model"
        response = dict()
        for rpower_unit in self.rpower_units:
            model = rpower_unit.model()
            # for no_rpower_on_rpi_server we get all PDU at once
            if isinstance(model, dict):
                response = model
                break
            response.update({rpower_unit.address: model})
        return response

    def cycle(self, device_names, timeout=5):
        "Power cycle devices"
        device_names = self.verify_requested_devices(device_names=device_names)
        response = dict()
        for rpower_unit in self.rpower_units:
            rpower_unit.off(device_names)
            time.sleep(timeout)
            response.update(rpower_unit.on(device_names))
        return response


class PowerControllerApi(PowerControllerLib):
    @staticmethod
    def get_stdout(responses):
        for device_name, response in responses.items():
            assert not response[0], f"Rpower action failed: {response}"
            responses[device_name] = response[1]
        return responses

    def on(self, device_names):
        responses = super().on(device_names)
        return self.get_stdout(responses)

    def off(self, device_names):
        responses = super().off(device_names)
        return self.get_stdout(responses)

    def status(self, device_names="all"):
        responses = super().status(device_names)
        return self.get_stdout(responses)

    def cycle(self, device_names, timeout=5):
        responses = super().cycle(device_names=device_names, timeout=timeout)
        return self.get_stdout(responses)
