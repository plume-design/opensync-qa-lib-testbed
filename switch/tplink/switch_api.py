import re
import time
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.common import DeviceCommon
from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.switch.generic.switch_api_generic import SwitchApiGeneric
from lib_testbed.generic.switch.util import get_switch_config_path

PORT_15_NAME = "rpi_dongle"
PORT_15_CONF = {"name": PORT_15_NAME, "port": 15, "backhaul": 309}
FIXED_VLANS = [PORT_15_CONF]


class SwitchApi(SwitchApiGeneric):
    def __init__(self, config, switch_unit_cfg):
        super().__init__(config=config, switch_unit_cfg=switch_unit_cfg)

    def init_fixed_vlans(self):
        for switch in self.config.get("Switch", []):
            switch["alias"] += FIXED_VLANS

    def change_untagged_vlan(self, port_name, target_vlan, enable_port=True):
        """
        Method for change untagged vlan on switch
        Args:
            port_name: (str) port_name from tb config
            target_vlan:   (int) vlan number which will set
            enable_port: (bool)

        Returns: (bool)

        """
        self.switch_ctrl.interface_down(port_name)
        self.switch_ctrl.vlan_set(port_name, target_vlan, "untagged")
        time.sleep(10)
        if enable_port:
            log.info(f"Enabling {port_name}")
            self.switch_ctrl.interface_up(port_name)
        port_info = self.switch_info(port_name)

        if str(target_vlan) not in port_info:
            log.error(f"Current port info: {port_name}, target vlan: {target_vlan}")
            log.error("Wan port action finished unsuccessfully, trying again")
            self.switch_ctrl.interface_down(port_name)
            self.switch_ctrl.vlan_set(port_name, target_vlan, "untagged")
            time.sleep(10)
            if enable_port:
                log.info(f"Enabling {port_name}")
                self.switch_ctrl.interface_up(port_name)
            port_info = self.switch_info(port_name)
            if str(target_vlan) not in port_info:
                log.error(f"Current port info: {port_name}, target vlan: {target_vlan}")
                raise Exception("Wan port action finished unsuccessfully")

        log.info(f"Change backhaul action finished successfully on {port_name} to {target_vlan}")
        return True

    def add_tagged_vlan(self, port_name, target_vlan, enable_port=True):
        """
        Add tagged vlan to switch port
        Args:
            port_name: (str) port_name from tb config
            target_vlan:   (int) vlan number which will be added
            enable_port: (bool)

        Returns: (bool)
        """
        assert str(int(target_vlan)) == str(target_vlan)
        retries = 2
        target_vlan = str(target_vlan)
        port_info = None
        for i in range(retries):
            self.switch_ctrl.interface_down(port_name)
            self.get_stdout_port_requests(self.switch_ctrl.vlan_set(port_name, target_vlan, "tagged"))
            time.sleep(10)
            if enable_port:
                log.info(f"Enabling {port_name}")
                self.switch_ctrl.interface_up(port_name)
            port_info = self.switch_ctrl.switch_info_parsed(port_name)[port_name]
            if target_vlan in port_info["tagged"]:
                break
            log.error(f"Current {port_name} port info: {port_info}, target vlan: {target_vlan}")
            if retries:
                retries -= 1
                log.error(f"Adding tagged vlan to {port_name} failed, trying again")
            else:
                raise Exception(f"Adding tagged vlan to {port_name} failed")
        log.info(f"Adding tagged vlan {target_vlan} to port {port_name} finished successfully")
        log.debug(f"port info: {port_info}")
        return True

    def remove_tagged_vlan(self, port_name, target_vlan, enable_port=True):
        """
        Remove tagged vlan from switch port
        Args:
            port_name: (str) port_name from tb config
            target_vlan:   (int) vlan number which will be removed
            enable_port: (bool)

        Returns: (bool)
        """
        assert str(int(target_vlan)) == str(target_vlan)
        retries = 1
        target_vlan = str(target_vlan)
        while True:
            self.switch_ctrl.interface_down(port_name)
            res = self.switch_ctrl.vlan_remove(port_name, target_vlan)[port_name]
            time.sleep(10)
            if enable_port:
                log.info(f"Enabling {port_name}")
                self.switch_ctrl.interface_up(port_name)
            port_info = self.switch_ctrl.switch_info_parsed(port_name)[port_name]
            if target_vlan not in port_info["tagged"]:
                break
            if res[0]:
                log.error(res[2])
            log.error(f"Current {port_name} port info: {port_info}, unremoved vlan: {target_vlan}")
            if retries:
                retries -= 1
                log.error(f"Removing tagged vlan from {port_name} failed, trying again")
            else:
                raise Exception(f"Removing tagged vlan from {port_name} failed")
        log.info(f"Removing tagged vlan {target_vlan} from port {port_name} finished successfully")
        log.debug(f"port info: {port_info}")
        return True

    def connect_eth_client(self, pod_name, client_name, connect_port="", **kwargs):
        """
        Connect dynamic ethernet client by changing vlan settings
        Args:
            pod_name: (str) Pod name where we want to connect eth client
            client_name: (str) Client name which we want to connect to pod
            connect_port: (str) Connection target port eth0 or eth1. If empty get random port.
        Returns: (str) Target portconnect_eth_client where is connected eth client

        """
        target_port = super().connect_eth_client(
            pod_name=pod_name, client_name=client_name, connect_port=connect_port, **kwargs
        )
        target_client = next(filter(lambda client: client["name"] == client_name, self.config.get("Clients")))
        self.set_client_vlan_to_rpi_dongle(target_port, target_client["vlan"], pod_name=pod_name)
        return target_port

    def disconnect_eth_client(self, pod_name, client_name, disable_no_used_ports=True):
        """
        Disconnect dynamic ethernet client by changing vlan settings
        Args:
            pod_name: (str) Pod name where we want to connect eth client
            client_name: (str) Client name which we want to connect to pod
            disable_no_used_ports: (bool) Disable non-used port on pod if True

        Returns: (str) Target port where was connected eth client

        """
        client_port = super().disconnect_eth_client(
            pod_name=pod_name, client_name=client_name, disable_no_used_ports=disable_no_used_ports
        )
        self.restore_rpi_dongle_vlan(client_port, pod_name)
        return client_port

    # TODO: Create specific function for multiple port and one port arg to get consistent function output
    def get_forward_ports_isolation(self, vlan_port_names):
        """
        Methods for get forward ports isolation from interface
        Args:
            vlan_port_names: For one port: (str) vlan port name
                             For multiple port (list) [(str)]

        Returns:

        """
        if isinstance(vlan_port_names, str):
            return self.switch_ctrl.get_forward_port_isolation(vlan_port_names)[vlan_port_names][1]
        return self.switch_ctrl.get_forward_port_isolation(vlan_port_names)

    def set_forward_ports_isolation(self, vlan_port_names: str | list, ports_isolation: str | list) -> dict[str:str]:
        """
        Set forward ports isolation on target port
        Args:
            vlan_port_names: For one port: (str) vlan port name
                             For multiple port (list) [(str)]
            ports_isolation: (list) list of ports isolation for example (int(),int()) or (str)
            for example '1/0/1-2,1/0/4'

        Returns:

        """
        if isinstance(ports_isolation, list):
            ports_isolation = [f"1/0/{port_isolation}" for port_isolation in ports_isolation]
            ports_isolation = ",".join(ports_isolation)
        response = self.switch_ctrl.set_forward_port_isolation(vlan_port_names, ports_isolation)
        return self.get_stdout_port_requests(response)

    def disable_ports_isolation(self, vlan_port_names, **kwargs) -> dict[str:str]:
        """
        Disable ports isolation on target port
        Args:
            vlan_port_names: For one port: (str) vlan port name
                             For multiple port (list) [(str)]
        Returns: dict() {port_name: switch_stdout}

        """
        response = self.switch_ctrl.disable_port_isolation(vlan_port_names)
        return self.get_stdout_port_requests(response)

    def dump_ports_isolation(self, port_names):
        port_names = port_names if isinstance(port_names, list) else [port_names]
        for port_name in port_names:
            port_isolation_cfg = self.get_forward_ports_isolation(port_name)
            self.ports_isolation_cfg[port_name] = port_isolation_cfg

    def get_port_isolation_cfg(self) -> dict:
        """Get port isolation config based on switch cfg from rpi-server."""
        # Determine switch type
        # TODO: Update testbed cfgs to use one common key to specify IP address of the switch
        switch_ip = (
            self.config["Switch"][0]["ipaddr"]
            if self.config["Switch"][0].get("ipaddr")
            else self.config["Switch"][0].get("hostname")
        )
        if not switch_ip:
            raise OpenSyncException("IP address to the USTB switch not found.", "Check USTB config switch section.")

        # init server obj to get switch cfg
        from lib_testbed.generic.client.client import Client

        kwargs = {"config": self.config, "multi_obj": True, "nickname": "host"}
        client_obj = Client(**kwargs)
        server = client_obj.resolve_obj(**kwargs)

        # get switch config
        switch_cfg_path = get_switch_config_path(server, "tplink", self.model(), self.switch_ctrl.name)
        if not switch_cfg_path:
            raise OpenSyncException(
                f'Unable to get switch cfg: "{switch_cfg_path}" from the rpi server.',
                "Make sure you have a latest rpi-server version.",
            )
        switch_cfg = server.run(f"cat {switch_cfg_path}", skip_exception=True)
        port_isolation_config = self.parse_port_isolation_from_switch_cfg(switch_cfg)
        return port_isolation_config

    def recovery_port_isolation_from_static_cfg(self):
        if not self.switch_isolation:
            log.warning(
                f"Can not find switch config for {self.model()} switch model. Skip recovering port isolation..."
            )
            return False

        # start recovery port isolation
        for port_name in self.get_list_of_all_port_names():
            port_alias = self.switch_ctrl.get_port_alias(port_name)
            if not port_alias:
                log.warning(f"Can not get port alias for {port_name}")
                continue
            port_number = str(port_alias["port"])
            default_port_isolation = self.switch_isolation.get(port_number)
            if not default_port_isolation:
                log.warning(f"Can not describe isolation config for {port_name} and port number: {port_number}")
                continue
            self.switch_ctrl.issue_port_action(port_name, port_action=default_port_isolation)

    @staticmethod
    def parse_port_isolation_from_switch_cfg(switch_cfg):
        isolation_config = dict()
        for i, line in enumerate(switch_cfg.splitlines()):
            if not line.startswith("interface") or "gigabitEthernet" not in line:
                continue
            # Interface cfg
            for interface_cfg_line in switch_cfg.splitlines()[i + 1 :]:
                # End of interface config
                if interface_cfg_line.startswith("#"):
                    break
                if "isolation" not in interface_cfg_line:
                    continue
                # parse "interface gigabitEthernet x/x/x" line to get port number only
                port_number = re.search(r"([^\/]+$)", line).group()
                isolation_config[port_number] = interface_cfg_line.lstrip()
                break
        return isolation_config

    def is_rpi_dongle_used(self, device_port, pod_name):
        # Consider residential-gw only
        if DeviceCommon.get_gw_dev_type(config=self.config) != "residential_gateway":
            return False
        # Skip if port is not used for mgmt access
        if "mn" not in self.get_role_of_port(device_port):
            return False
        # Consider gateway devices only:
        if "gw" not in pod_name:
            return False
        # Skip if link is down for port number 15
        if "down" in self.get_port_link_status(PORT_15_NAME):
            return False
        return True

    # Set client vlan to port number 15 to don't lose mgmt access for specific devices
    def set_client_vlan_to_rpi_dongle(self, device_port, client_vlan, pod_name):
        if not self.is_rpi_dongle_used(device_port=device_port, pod_name=pod_name):
            return
        self.change_untagged_vlan(PORT_15_NAME, client_vlan)

    def restore_rpi_dongle_vlan(self, device_port, pod_name):
        if not self.is_rpi_dongle_used(device_port=device_port, pod_name=pod_name):
            return
        self.change_untagged_vlan(PORT_15_NAME, PORT_15_CONF["backhaul"])

    def set_port_duplex(self, ports: str | list[str], mode: str) -> dict:
        """Sets duplex mode for port(s). Possible modes are "half", "full",
        and "auto"."""
        return self.switch_ctrl.set_port_duplex(port_names=ports, mode=mode)

    def set_port_forwarding_between_gws(self):
        """Set port forwarding between gateway devices."""
        gateways = [
            device_name
            for device_name, connection_type in self.get_devices_connection_type().items()
            if "fake_internet" in connection_type
        ]
        for device_name in gateways:
            wan_port = self.get_wan_port(device_name)
            for device_name_to_forward in gateways:
                if device_name == device_name_to_forward:
                    continue
                port_isolation_to_update = self.get_forward_ports_isolation(wan_port)
                wan_port_to_forward = self.get_wan_port(device_name_to_forward)
                port_to_forward = self.switch_aliases[wan_port_to_forward]["port"]
                port_isolation_to_update += f",1/0/{port_to_forward}"
                self.switch_ctrl.set_forward_port_isolation(wan_port, forward_ports=port_isolation_to_update)
