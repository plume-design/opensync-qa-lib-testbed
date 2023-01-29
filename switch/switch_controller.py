import re
import importlib
from typing import Union

SWITCH_REQUIRED_KEYS = {
    'name': 'name',
    'user': 'user',
    'pass': 'password',
    'hostname': 'hostname',
    'port': 'port',
    'alias': 'alias',
    'type': 'switch_type'
}


class SwitchController:
    def __init__(self, tb_config, switch_unit_cfg=None, switch_api=False):
        self.switch_api = switch_api
        self.tb_config = tb_config
        self.switch_units = self.init_switch_units(switch_unit_cfg)

    def init_switch_cfg(self, switch_unit_cfg):
        for switch_key in SWITCH_REQUIRED_KEYS.keys():
            switch_value = switch_unit_cfg.get(switch_key)
            # TODO: Update testbed cfgs to use one common key to specify IP address of the switch
            if not switch_value and switch_key == 'hostname':
                switch_value = switch_unit_cfg.get('ipaddr')
            assert switch_value, f'{switch_key} not defined in switch config. Please update switch configuration.'
            # Map var name to allowed names
            setattr(self, SWITCH_REQUIRED_KEYS[switch_key], switch_value)

    def init_switch_units(self, switch_unit_cfg):
        switches_to_load = self.tb_config['Switch'] if not switch_unit_cfg else [switch_unit_cfg]
        switch_units = list()
        for switch_unit in switches_to_load:
            self.init_switch_cfg(switch_unit)
            switch_lib = self.get_switch_lib(pdu_type=self.switch_type)(switch_name=self.name, user=self.user,
                                                                        password=self.password, ip=self.hostname,
                                                                        port=self.port, aliases=self.alias,
                                                                        tb_config=self.tb_config)
            switch_units.append(switch_lib)
        return switch_units

    @staticmethod
    def get_switch_lib(pdu_type):
        module_path = ".".join(["lib_testbed", "generic", "switch", pdu_type, 'switch_lib'])
        r = re.compile(".*SwitchLib", re.IGNORECASE)
        module = importlib.import_module(module_path)
        class_name = list(filter(r.match, dir(module)))
        if not class_name:
            raise Exception(f'Not found library for {pdu_type} switch type')
        class_name = class_name[0]
        return getattr(module, class_name)

    @staticmethod
    def parse_port_name_to_list_type(port_names):
        if isinstance(port_names, list):
            return port_names
        return [port_names]

    @staticmethod
    def generate_port_request_output(switch_response: list, port_names: list) -> dict:
        assert len(switch_response) == len(port_names), f'Did not get responses from all ports: {port_names}'
        switch_parsed_response = dict()
        for port_name, switch_response in zip(port_names, switch_response):
            switch_parsed_response[port_name] = switch_response
        return switch_parsed_response

    def execute_port_request(self, request: str, port_names: Union[str, list], **kwargs):
        switch_responses = dict()
        for switch_unit in self.switch_units:
            port_names = self.parse_port_name_to_list_type(port_names=port_names)
            # Get all ports which are defined under switch unit
            switch_unit_ports = switch_unit.map_port_names_to_port_numbers(port_names)
            if not switch_unit_ports:
                continue
            func_request = getattr(switch_unit, request, None)
            assert func_request, f'Not found defined function for {request} request'
            switch_response = func_request(ports=list(switch_unit_ports.values()), **kwargs)
            switch_response = self.generate_port_request_output(switch_response=switch_response,
                                                                port_names=list(switch_unit_ports.keys()))
            switch_responses.update(switch_response)
        return switch_responses

    def execute_switch_request(self, request: str, **kwargs):
        switch_responses = dict()
        for switch_unit in self.switch_units:
            func_request = getattr(switch_unit, request, None)
            assert func_request, f'Not found defined function for {request} request'
            switch_response = func_request(**kwargs)
            switch_responses[switch_unit.ip] = switch_response
        return self.get_output_switch_request(switch_responses)

    def get_output_switch_request(self, switch_response):
        # for API switch requests return only [ret_val, stdout, stderr] without switch_prefix_name
        if self.switch_api:
            return list(switch_response.values())[0]
        return switch_response

    # PORT ACTIONS
    def switch_info(self, port_names: Union[str, list]) -> dict:
        """
        Get current port configuration data
        Args:
            port_names: (str) for one port name or (list) for more than one port

        Returns: dict() {port_name: [ret_val, std_out, std_err]

        """
        return self.execute_port_request(request='interface_info', port_names=port_names)

    def vlan_set(self, port_names: Union[str, list], vlan: Union[str, int], vlan_type: str) -> dict:
        """
        Set vlan on the port
        Args:
            port_names: (str) for one port name or (list) for more than one port
            vlan: (int) or (str) vlan number
            vlan_type: (str) tagged/untagged

        Returns: dict() {port_name: [ret_val, std_out, std_err]

        """
        return self.execute_port_request(request='set_vlan', port_names=port_names, vlan=vlan, vlan_type=vlan_type)

    def vlan_remove(self, port_names: Union[str, list], vlan: Union[int, str]) -> dict:
        """
        Delete VLAN for specific interface
        Args:
            port_names: (str) for one port name or (list) for more than one port
            vlan: (int) or (str) vlan number

        Returns: dict() {port_name: [ret_val, std_out, std_err]

        """
        return self.execute_port_request(request='delete_vlan', port_names=port_names, vlan=vlan)

    def interface_up(self, port_names: Union[str, list]) -> dict:
        """
        Turn interface up
        Args:
            port_names: (str) for one port name or (list) for more than one port

        Returns: dict() {port_name: [ret_val, std_out, std_err]

        """
        return self.execute_port_request(request='no_shutdown_interface', port_names=port_names)

    def interface_down(self, port_names: Union[str, list]) -> dict:
        """
        Turn interface down
        Args:
            port_names: (str) for one port name or (list) for more than one port

        Returns: dict() {port_name: [ret_val, std_out, std_err]

        """
        return self.execute_port_request(request='shutdown_interface', port_names=port_names)

    def interface_status(self, port_names: Union[str, list]) -> dict:
        """
        Get interface status (enable/disable)
        Args:
            port_names: (str) for one port name or (list) for more than one port

        Returns: dict() {port_name: [ret_val, std_out, std_err]

        """
        return self.execute_port_request(request='interface_status', port_names=port_names)

    def get_forward_port_isolation(self, port_names: Union[str, list]) -> dict:
        """
        Get forward ports isolation of interface
        Args:
            port_names: (str) for one port name or (list) for more than one port

        Returns: dict() {port_name: [ret_val, std_out, std_err]

        """
        return self.execute_port_request(request='show_ports_isolation_interface', port_names=port_names)

    def set_forward_port_isolation(self, port_names: Union[str, list], forward_ports: str) -> dict:
        """
        Set port isolation
        Args:
            port_names: (str) for one port name or (list) for more than one port
            forward_ports: (str) forward ports

        Returns: dict() {port_name: [ret_val, std_out, std_err]

        """
        return self.execute_port_request(request='set_forward_port_isolation', port_names=port_names,
                                         forward_ports=forward_ports)

    def disable_port_isolation(self, port_names: Union[str, list]) -> dict:
        """
        Disable port isolation
        Args:
            port_names: (str) for one port name or (list) for more than one port

        Returns: dict() {port_name: [ret_val, std_out, std_err]


        """
        return self.execute_port_request(request='disable_port_isolation', port_names=port_names)

    def set_link_speed(self, port_names: Union[str, list], speed: Union[str, int]) -> dict:
        """
        Set link speed
        Args:
            port_names: (str) for one port name or (list) for more than one port
            speed: (int) link speed (10, 100, 1000) or (str) 'auto'

        Returns: dict() {port_name: [ret_val, std_out, std_err]

        """
        return self.execute_port_request(request='set_link_speed', port_names=port_names, speed=speed)

    def get_link_status(self, port_names: Union[str, list]) -> dict:
        """
        Get port link status info
        Args:
            port_names: (str) for one port name or (list) for more than one port

        Returns: dict() {port_name: [ret_val, std_out, std_err]

        """
        return self.execute_port_request(request='get_link_status', port_names=port_names)

    def issue_port_action(self, port_names: Union[str, list], port_action: str) -> dict:
        """
        Issue port action
        Args:
            port_names: (str) for one port name or (list) for more than one port
            port_action: (str) action name. Example: "port isolation gi-forward-list 1/0/2"

        Returns:

        """
        return self.execute_port_request(request='action_interface', port_names=port_names, action=port_action)

    def switch_info_parsed(self, port_names: Union[str, list]) -> dict:
        """
        Switch info parser
        Args:
            port_names: (str) for one port name or (list) for more than one port

        Returns: (dict) {port_name: dict(parsed_info)}

        """
        return self.execute_port_request(request='interface_info_parsed', port_names=port_names)

    def switch_info_parser(self, raw_info: dict) -> dict:
        """
        Switch info parser
        Args:
            raw_info: (dict) raw info from switch_info() function

        Returns: (dict) {port_name: dict(parser_info)}

        """
        parsed_data = dict()
        for switch_unit in self.switch_units:
            for port_name in raw_info:
                port_names = self.parse_port_name_to_list_type(port_names=port_name)
                switch_unit_ports = switch_unit.map_port_names_to_port_numbers(port_names)
                if not switch_unit_ports:
                    continue
                parsed_data[port_name] = switch_unit.interface_info_parser(raw_info[port_name])
        return parsed_data

    # SWITCH ACTIONS
    def get_version(self) -> Union[dict, tuple]:
        """
        Get switch version
        Returns: dict() {switch_hostname: [ret_val, std_out, std_err]

        """
        return self.execute_switch_request(request='version')

    def get_model(self) -> Union[dict, tuple]:
        """
        Get model name
        Returns: dict() {switch_hostname: [ret_val, std_out, std_err]

        """
        return self.execute_switch_request(request='get_model')

    def get_system_info(self) -> Union[dict, tuple]:
        """
        Get switch information
        Returns: dict() {switch_hostname: [ret_val, std_out, std_err]

        """
        return self.execute_switch_request(request='system_info')

    def restore_config(self) -> Union[dict, tuple]:
        """
        Restore configuration file from the rpi-server
        Returns: dict() {switch_hostname: [ret_val, std_out, std_err]

        """
        return self.execute_switch_request(request='restore_config')

    def pvid_list(self) -> Union[dict, tuple]:
        """
        List of all PVIDs on the switch(es)
        Returns: {switch_hostname: [ret_val, std_out, std_err]

        """
        return self.execute_switch_request(request='list_pvid')

    def vlan_list(self) -> Union[dict, tuple]:
        """
        'List of all VLANs on the switch(es)'
        Returns: {switch_hostname: [ret_val, std_out, std_err]

        """
        return self.execute_switch_request(request='list_vlan')

    def switch_interface_list(self) -> list:
        """
        Switch interface list configured in tb-config
        Returns: list() [ret_val, std_out, std_err]

        """
        switch_list = list()
        for switch_unit in self.switch_units:
            switch_list += switch_unit.aliases.keys()
        return [0, switch_list, '']

    def get_device_port_aliases(self, device_name: str) -> list:
        """
        Get device port aliases
        Args:
            device_name: (str)

        Returns: (list) all aliases assigned to device

        """
        device_port_aliases = list()
        for switch_unit in self.switch_units:
            device_port_aliases += switch_unit.get_device_switch_aliases(device_name=device_name)
        return device_port_aliases

    def get_port_alias(self, port_name: str) -> dict:
        """
        Get port alias
        Args:
            port_name: (str)

        Returns: (dict) {backhaul=backhaul, port=port_number}

        """
        port_alias = dict()
        for switch_unit in self.switch_units:
            port_alias = switch_unit.aliases.get(port_name)
            if port_alias:
                break
        return port_alias

    def set_port_duplex(self, port_names: str | list[str], mode=str) -> dict:
        """Sets duplex mode on given port(s) to selected mode.
        The mode must be a string "half", "full" or "auto". Raises
        :py:exc:`ValueError` when the mode is not correct"""
        if mode not in ["half", "full", "auto"]:
            raise ValueError(f"Mode {mode} must be half, full or auto")
        return self.issue_port_action(port_names, f"duplex {mode}")
