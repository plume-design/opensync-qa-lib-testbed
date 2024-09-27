import collections
import functools
import importlib
import ipaddress
import re
import requests
import socket
import time

from lib_testbed.generic.util.opensyncexception import OpenSyncException

_PDU_PATTERNS = {
    "cyberpower": re.compile(r"cyberpowersystems", re.IGNORECASE),
    "dli": re.compile(r'ACTION="/login.tgi"', re.IGNORECASE),
    "shelly": re.compile(r"Shelly\s+Web\s+Admin", re.IGNORECASE),
}


class _UnsafeSession(requests.Session):
    """Requests session that preserves Authentication across redirects"""

    def should_strip_auth(old_url, new_url):
        return False


class GenericPduLib:
    """
    GenericPduLib determines the type of the PDU, creates concrete PduLib for it and dispatches commands to it
    """

    def __init__(self, pdu_config):
        try:
            address = pdu_config["ipaddr"]
        except KeyError:
            raise OpenSyncException("'ipaddr' setting missing from 'rpower' testbed config section")
        self.address = self.host = address
        self.pdu_config = pdu_config
        self.ipv6 = False
        ipaddr = None
        try:
            ipaddr = ipaddress.ip_address(self.address)
        except ValueError:
            try:
                self.address = socket.gethostbyname(self.address)
            except socket.gaierror:
                pass
            else:
                ipaddr = ipaddress.ip_address(self.address)
        if ipaddr is not None and ipaddr.version == 6:
            self.ipv6 = True
            self.host = f"[{self.address}]"

    @property
    def username(self):
        return self.pdu_config.get("user", "admin")

    @property
    def password(self):
        return self.pdu_config.get("pass", "1234")

    @property
    def port(self):
        return self.pdu_config.get("port", 9000)

    @functools.cached_property
    def session(self):
        session = _UnsafeSession()
        return session

    def type(self):
        if "type" in self.pdu_config:
            return self.pdu_config["type"]
        response = self.session.get(f"http://{self.host}:{self.port}/")
        if not response.ok:
            response.raise_for_status()
        response = response.text
        for typ, pattern in _PDU_PATTERNS.items():
            if pattern.search(response) is not None:
                self.pdu_config["type"] = typ
                return typ
        raise OpenSyncException(f"Unrecognized power controller unit. Supported PDU types: {list(_PDU_PATTERNS)}")

    @functools.cached_property
    def concrete_pdu(self):
        module_path = f"lib_testbed.generic.rpower.pdu_units.{self.type()}"
        module = importlib.import_module(module_path)
        return module.PduLib(self.address, self.port, self.username, self.password, self.ipv6, self.session)

    def __getattr__(self, name):
        return getattr(self.concrete_pdu, name)


class PowerControllerLib:
    """
    PowerControllerLib represents one or more power distribution units (PDUs) listed in testbed config

    It is responsible for setting up individual GenericPduLib classes for each of the testbed PDUs, translating from
    PDU port aliases to actual PDU ports, translating from convenience aliases (all, pods, clients) to actual PDU ports,
    outlet state change timestamp tracking and request batching.
    """

    #: mapping PDU port aliases to their port number (as string) and PDU
    pdu_ports: dict[str, tuple[str, GenericPduLib]]
    #: mapping PDU port groups (all, clients, pods) to their port aliases
    pdu_groups: dict[str, list[str]]
    #: mapping PDU port aliases to the last time (since epoch) that port was turned on or off
    pdu_timestamps: dict[str, float]

    def __init__(self, conf: dict, skip_init: bool = False, **kwargs):
        self.tb_config = conf
        # used only by legacy rpower tool to speed up help display
        if skip_init:
            return
        if "rpower" not in self.tb_config:
            raise OpenSyncException(
                "Power control unit not configured for this testbed",
                f"Testbed configuration file {self.tb_config['location_file']} is missing rpower section",
            )
        pods = {node["name"] for node in self.tb_config.get("Nodes", []) if "name" in node}
        clients = {client["name"] for client in self.tb_config.get("Clients", []) if "name" in client}
        pdu_ports = {}
        pdu_groups = {"clients": [], "pods": []}
        for pdu_config in self.tb_config["rpower"]:
            pdu = GenericPduLib(pdu_config)
            for alias in pdu_config["alias"]:
                if "name" not in alias:
                    raise OpenSyncException(f"PDU alias config is missing 'name' setting: {alias}")
                if "port" not in alias:
                    raise OpenSyncException(f"PDU alias config is missing 'port' setting: {alias}")
                port_name = alias["name"]
                if port_name in pdu_ports:
                    raise OpenSyncException(f"'{port_name}' device config states it is connected to two PDUs")
                if port_name in pods:
                    pdu_groups["pods"].append(port_name)
                if port_name in clients:
                    pdu_groups["clients"].append(port_name)
                pdu_ports[port_name] = str(alias["port"]), pdu
        pdu_groups["all"] = list(pdu_ports)
        self.pdu_ports = pdu_ports
        self.pdu_groups = pdu_groups
        self.pdu_timestamps = self.tb_config.setdefault("rpower_timestamps", {})

    def get_all_devices(self) -> list[str]:
        """Return list of all PDU powered devices"""
        return list(self.pdu_groups["all"])

    def get_client_devices(self) -> list[str]:
        """Return list of PDU powered client devices"""
        return list(self.pdu_groups["clients"])

    def get_nodes_devices(self) -> list[str]:
        """Return list of PDU powered pod devices"""
        return list(self.pdu_groups["pods"])

    def get_last_request_time(self, device_names: str | list[str]) -> dict[str, int]:
        "Return time, in seconds, since each of 'device_names' was last turned on or off"
        last_request_time = {}
        now = time.time()
        for device_name in self.verify_requested_devices(device_names):
            if device_name in self.pdu_timestamps:
                last_request_time[device_name] = int(now - self.pdu_timestamps[device_name])
            else:
                last_request_time[device_name] = -1
        return last_request_time

    def verify_requested_devices(self, device_names: str | list[str]) -> list[str]:
        """Convert device names (testbed config rpower port names, 'all', 'clients' or 'pods') to port names"""
        port_names = []
        if isinstance(device_names, str):
            device_names = device_names.split(",")
        for device_name in device_names:
            if device_name in self.pdu_groups:
                port_names.extend(self.pdu_groups[device_name])
            elif device_name in self.pdu_ports:
                port_names.append(device_name)
            else:
                raise OpenSyncException(f"Unknown PDU powered device: '{device_name}' not in {list(self.pdu_ports)}")
        return port_names

    def on(self, device_names: str | list[str]) -> dict[str, list[int, str, str]]:
        """Turn devices on"""
        return self._ports_action("on", device_names, reset_timestamps=True)

    def off(self, device_names: str | list[str]) -> dict[str, list[int, str, str]]:
        """Turn devices off"""
        return self._ports_action("off", device_names, reset_timestamps=True)

    def status(self, device_names: str | list[str] = "all") -> dict[str, list[int, str, str]]:
        """Get power status of devices"""
        return self._ports_action("status", device_names)

    def consumption(self, device_names: str | list[str] = "all") -> dict[str, list[int, str, str]]:
        """Get power consumption of devices. Supported only on Shelly PDUs."""
        return self._ports_action("consumption", device_names)

    def cycle(self, device_names: str | list[str], timeout: int = 5) -> dict[str, list[int, str, str]]:
        """Power cycle devices"""
        # PowerControllerApi overrides our methods and changes their
        # signatures, so we can't simply call self.off(); self.on()
        PowerControllerLib.off(self, device_names)
        time.sleep(timeout)
        return PowerControllerLib.on(self, device_names)

    def version(self) -> dict[str, list[int, str, str]]:
        """Get PDU firmware version(s)"""
        return self._pdus_action("version")

    def model(self) -> dict[str, list[int, str, str]]:
        """Get PDU model(s)"""
        return self._pdus_action("model")

    def type(self) -> dict[str, list[int, str, str]]:
        """Get PDU type(s)"""
        return {addr: [0, typ, ""] for addr, typ in self._pdus_action("type").items()}

    def _pdus_action(self, action_name: str) -> dict[str, str | tuple[int, str, str]]:
        """Run some method that applies to PDU itself on all PDUs in testbed"""
        response = {}
        for rpower_unit in set(pdu for port, pdu in self.pdu_ports.values()):
            response[rpower_unit.address] = getattr(rpower_unit, action_name)()
        return response

    def _ports_action(
        self, action_name: str, device_names: str | list[str], reset_timestamps: bool = False
    ) -> dict[str, tuple[int, str, str]]:
        """Run some method that applies to PDU outlets on specified device_names outlet aliases"""
        pdus = collections.defaultdict(lambda: collections.defaultdict(list))
        for port_name in self.verify_requested_devices(device_names):
            port, pdu = self.pdu_ports[port_name]
            pdus[pdu][port].append(port_name)
        response = {}
        for pdu, ports in pdus.items():
            for port, result in getattr(pdu, action_name)(sorted(ports)).items():
                for port_name in ports[port]:
                    # We need to copy result for devices on the same port, otherwise they get printed weirdly
                    response[port_name] = list(result)
        if reset_timestamps:
            timestamp = time.time()
            for device_name, result in response.items():
                if result[0] == 0:
                    self.pdu_timestamps[device_name] = timestamp
        return response


class PowerControllerApi(PowerControllerLib):
    @staticmethod
    def get_stdout(responses):
        for device_name, response in responses.items():
            assert not response[0], f"Rpower action failed: {response}"
            responses[device_name] = response[1]
        return responses

    def on(self, device_names):
        """Turn devices on"""
        responses = super().on(device_names)
        return self.get_stdout(responses)

    def off(self, device_names):
        """Turn devices off"""
        responses = super().off(device_names)
        return self.get_stdout(responses)

    def status(self, device_names="all"):
        """Get power status of devices"""
        responses = super().status(device_names)
        return self.get_stdout(responses)

    def consumption(self, device_names="all"):
        """Get power consumption of devices. Supported only on Shelly PDUs."""
        responses = super().consumption(device_names)
        responses = self.get_stdout(responses)
        for device_name, consumption in responses.items():
            responses[device_name] = float(consumption.rstrip("W"))
        return responses

    def cycle(self, device_names, timeout=5):
        """Power cycle devices"""
        responses = super().cycle(device_names=device_names, timeout=timeout)
        return self.get_stdout(responses)
