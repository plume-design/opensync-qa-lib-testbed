import collections
import functools
import importlib
import ipaddress
import random
import re
import requests
import socket
import time
import traceback

from urllib3.util.retry import Retry

from lib_testbed.generic.util.opensyncexception import OpenSyncException

_PDU_PATTERNS = {
    "cyberpower": re.compile(r"cyberpowersystems", re.IGNORECASE),
    "dli": re.compile(r'ACTION="/login.tgi"', re.IGNORECASE),
    "shelly": re.compile(r"Shelly\s+Web\s+Admin", re.IGNORECASE),
}


class _UnsafeSession(requests.Session):
    """Requests session that preserves Authentication across redirects and increases timeout"""

    DEFAULT_TIMEOUT = 10

    def send(self, request, **kwargs):
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self.DEFAULT_TIMEOUT
        return super().send(request, **kwargs)

    def should_strip_auth(old_url, new_url):
        return False


class RetryWithDelayJitter(Retry):
    """
    We want to start using a delay on the first retry, and add some randomness to it.

    E.g., if you specify backoff_factor of one second, then the first retry will be
    made 1 to 2 seconds after first failure, second 2 to 4 seconds after second
    failure, third 3 to 6 seconds after third failure, etc.
    """

    def get_backoff_time(self):
        # Consider only actual failures, not redirects
        retry_factor = 0
        for request in reversed(self.history):
            if request.redirect_location is None:
                retry_factor += 1
            else:
                break
        jitter_factor = 1 + random.random()
        backoff_value = self.backoff_factor * jitter_factor * retry_factor
        return min(self.BACKOFF_MAX, backoff_value)


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
        self._concrete_pdu = None
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
        # Combination of DEFAULT_TIMEOUT and 7 retries with jitter results in
        # waiting up to approximately 2 minutes for PDU to become reachable.
        session = _UnsafeSession()
        retries = RetryWithDelayJitter(
            total=7,
            status_forcelist=(500, 502, 503, 504),
            backoff_factor=1.0,
            method_whitelist={"PATCH"} | Retry.DEFAULT_METHOD_WHITELIST,
            raise_on_redirect=False,
            raise_on_status=False,
        )
        session.mount("http://", requests.adapters.HTTPAdapter(max_retries=retries))
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

    def _concrete_pdu_or_error(self):
        if self._concrete_pdu is not None:
            return self._concrete_pdu
        try:
            pdu_type = self.type()
        except Exception:
            return traceback.format_exc(limit=15)
        module_path = f"lib_testbed.generic.rpower.pdu_units.{pdu_type}"
        module = importlib.import_module(module_path)
        pdu = module.PduLib(self.address, self.port, self.username, self.password, self.ipv6, self.session)
        self._concrete_pdu = pdu
        return pdu

    def _pdu_command(self, command_name: str) -> list[int, str, str]:
        pdu_or_error = self._concrete_pdu_or_error()
        if isinstance(pdu_or_error, str):
            return [1, "", pdu_or_error]
        return getattr(pdu_or_error, command_name)()

    def _ports_command(self, command_name: str, ports: list[str]) -> dict[str : list[int, str, str]]:
        pdu_or_error = self._concrete_pdu_or_error()
        if isinstance(pdu_or_error, str):
            return {port: [1, "", pdu_or_error] for port in ports}
        return getattr(pdu_or_error, command_name)(ports)

    def model(self):
        """Get PDU model"""
        return self._pdu_command("model")

    def version(self):
        """Get PDU firmware version"""
        return self._pdu_command("version")

    def status(self, ports: list[str]):
        """Get on/off status of PDU outlets"""
        return self._ports_command("status", ports)

    def consumption(self, ports: list[str]):
        """Get power consumption of PDU outlets"""
        return self._ports_command("consumption", ports)

    def on(self, ports: list[str]):
        """Turn PDU outlets on"""
        return self._ports_command("on", ports)

    def off(self, ports: list[str]):
        """Turn PDU outlets off"""
        return self._ports_command("off", ports)


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
        return self._ports_set("on", device_names)

    def off(self, device_names: str | list[str]) -> dict[str, list[int, str, str]]:
        """Turn devices off"""
        return self._ports_set("off", device_names)

    def status(self, device_names: str | list[str] = "all") -> dict[str, list[int, str, str]]:
        """Get power status of devices"""
        return self._ports_get("status", device_names)

    def consumption(self, device_names: str | list[str] = "all") -> dict[str, list[int, str, str]]:
        """Get power consumption of devices. Supported only on Shelly PDUs."""
        return self._ports_get("consumption", device_names)

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

    def _group_port_names_by_pdu_and_port(self, port_names: list[str]) -> dict[GenericPduLib : dict[str : list[str]]]:
        """Group port_names as returned by verify_requested_devices into mapping per pdu and port"""
        pdus = collections.defaultdict(lambda: collections.defaultdict(list))
        for port_name in port_names:
            port, pdu = self.pdu_ports[port_name]
            pdus[pdu][port].append(port_name)
        return pdus

    def _ports_get(self, action_name: str, device_names: str | list[str]) -> dict[str, tuple[int, str, str]]:
        """Get PDU outlet on/off state or power consumption on specified device_names outlet aliases"""
        pdus = self._group_port_names_by_pdu_and_port(self.verify_requested_devices(device_names))
        response = {}
        for pdu, ports in pdus.items():
            for port, result in getattr(pdu, action_name)(sorted(ports)).items():
                for port_name in ports[port]:
                    # We need to copy result for devices on the same port, otherwise they get printed weirdly
                    response[port_name] = list(result)
        return response

    def _ports_set(self, action_name: str, device_names: str | list[str]) -> dict[str, tuple[int, str, str]]:
        """Turn PDU outlets on or off on specified device_names outlet aliases"""
        port_names = self.verify_requested_devices(device_names)
        pdus = self._group_port_names_by_pdu_and_port(port_names)
        timeout = time.time() + 60
        done = {}
        todo = {}
        for pdu, ports in pdus.items():
            on_off_results = getattr(pdu, action_name)(sorted(ports))
            timestamp = time.time()
            for port, result in on_off_results.items():
                if result[0] != 0 or action_name.upper() in result[1]:
                    status = done
                    if result[0] == 0:
                        for port_name in ports[port]:
                            self.pdu_timestamps[port_name] = timestamp
                else:
                    status = todo
                for port_name in ports[port]:
                    # We need to copy result for devices on the same port, otherwise they get printed weirdly
                    status[port_name] = list(result)

        # Some PDU models add a delay between turning on outlets, to prevent power spikes. Wait for those
        while time.time() < timeout:
            remaining = set(port_names) - set(done)
            if not remaining:
                break
            time.sleep(2)
            # PowerControllerApi overrides self.status() and changes its signature, so don't call it directly
            remaining_results = PowerControllerLib.status(self, list(remaining))
            timestamp = time.time()
            for port_name, result in remaining_results.items():
                if result[0] != 0 or action_name.upper() in result[1]:
                    done[port_name] = result
                    if result[0] == 0:
                        self.pdu_timestamps[port_name] = timestamp

        # If any of the ports still hasn't changed its state, report the initial result, but mark it failed
        for port_name in set(port_names) - set(done):
            err = todo[port_name[2]] if todo[port_name[2]] else todo[port_name][1]
            done[port_name] = [42, todo[port_name][1], err]
        return done


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
