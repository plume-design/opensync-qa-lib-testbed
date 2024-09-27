import sys

from lib_testbed.generic.switch.switch_controller import SwitchController
from lib_testbed.generic.switch.switch_api_resolver import SwitchApiResolver


def parse_bool_parameter(param_name, param_value):
    if isinstance(param_value, bool):
        return param_value
    if not isinstance(param_value, str):
        raise TypeError(f"Invalid type for {param_name}: {type(param_value)}")
    if param_value.startswith(param_name):
        param_value = param_value.split("=", 1)[-1]
    if param_value.lower() in {"1", "yes", "true", "on"}:
        return True
    elif param_value.lower() in {"", "0", "no", "false", "off"}:
        return False
    else:
        # We get called with string paramter values only when called by the
        # switch tool, in which case we can afford to exit the whole process.
        sys.exit(f"Invalid value: {param_value} for argument: {param_name}. Expecting bool value")


class SwitchToolGeneric:
    def __init__(self, config):
        self.switch_api = SwitchApiResolver(config=config)
        self.tool = SwitchController(tb_config=config)

    def version(self):
        """Get config version"""
        return self.tool.get_version()

    def model(self):
        """Get switch model"""
        return self.tool.get_model()

    def system_info(self):
        """Get switch information"""
        return self.tool.get_system_info()

    def restore_config(self):
        """Restore switch config"""
        return self.tool.restore_config()

    def switch_interface_list(self):
        """List all ports configured"""
        return self.tool.switch_interface_list()

    def pvid_list(self):
        """List of all PVIDs on the switch(es)"""
        return self.tool.pvid_list()

    def vlan_list(self):
        """List of all VLANs on the switch(es)"""
        return self.tool.vlan_list()

    def switch_status(self, port_names):
        """Get interface status (enable/disable)"""
        return self.tool.interface_status(port_names)

    def info(self, port_names):
        """Get info about VLANs"""
        return self.tool.switch_info(port_names)

    def interface_up(self, port_names):
        """Turn interface up"""
        return self.tool.interface_up(port_names)

    def interface_down(self, port_names):
        """Turn interface down"""
        return self.tool.interface_down(port_names)

    def vlan_set(self, port_names, vlan, vlan_type):
        """Set vlan untagged/tagged"""
        return self.tool.vlan_set(port_names, vlan, vlan_type)

    def vlan_remove(self, port_names, vlan):
        """Delete VLAN for specific interface"""
        return self.tool.vlan_remove(port_names, vlan)

    def set_connection_ip_type(self, pod_name, ip_type):
        """Set connection IP type. Supported IP types <ipv4, ipv6_stateful, ipv6_stateless, ipv6_slaac, ...>
        For a complete list of supported WAN VLANs see lib_testbed.__init__ or provide numeric vlan id directly."""
        self.switch_api.set_connection_ip_type(pod_name, ip_type)
        return self.info(self.switch_api.get_device_port_names()[pod_name])

    def connect_eth_client_tool(self, pod_name, client_name, connect_port=""):
        """Connect ethernet client <pod_name>=str, <client_name>=str, <connect_port>=str if empty get random port"""
        target_port = self.switch_api.connect_eth_client(pod_name, client_name, connect_port)
        return self.info(target_port)

    def disconnect_eth_client(self, pod_name, client_name, disable_no_used_ports=True):
        """Disconnect ethernet client <pod_name>=str, <client_name>=str"""
        disable_no_used_ports = parse_bool_parameter("disable_no_used_ports", disable_no_used_ports)
        target_port = self.switch_api.disconnect_eth_client(pod_name, client_name, disable_no_used_ports)
        return self.info(target_port)

    def recovery_switch_cfg(self, pod_name, force=False, set_default_wan=False):
        """Set default configuration on switch for the provided <pod_names>=str. <force>=bool <set_default_wan>=bool"""
        force = parse_bool_parameter("force", force)
        set_default_wan = parse_bool_parameter("set_default_wan", set_default_wan)
        target_ports = self.switch_api.recovery_switch_configuration(
            pod_name, force=force, set_default_wan=set_default_wan
        )
        return self.info(target_ports)

    def disable_port_isolations(self):
        """Disable port isolation on all ports from tb-config"""
        port_names = self.switch_api.get_list_of_all_port_names()
        self.switch_api.disable_ports_isolation(vlan_port_names=port_names)
        return self.tool.get_forward_port_isolation(port_names)

    def enable_port_isolations(self):
        """Enable port isolations on all ports from tb-config"""
        port_names = self.switch_api.get_list_of_all_port_names()
        self.switch_api.recovery_port_isolation_from_static_cfg()
        return self.tool.get_forward_port_isolation(port_names)

    def get_port_isolations(self, port_names):
        """Get port isolations"""
        return self.tool.get_forward_port_isolation(port_names)

    def get_link_status(self, port_names):
        """Get port link status"""
        return self.tool.get_link_status(port_names)

    def set_link_speed(self, port_name, link_speed):
        """Set link speed on expected port"""
        results = self.tool.set_link_speed(port_name, link_speed)
        return results

    def set_port_duplex(self, ports: str | list[str], mode: str) -> dict:
        """Sets duplex mode for port(s). Possible modes are "half", "full", and "auto"."""
        return self.tool.set_port_duplex(port_names=ports, mode=mode)

    def set_daisy_chain_connection(self, target_device, connect_to_device):
        """Set daisy chain connection between two pods connect_to_device <--eth--> target_device"""
        self.switch_api.set_daisy_chain_connection(target_device, connect_to_device)
        return self.info(self.switch_api.get_device_port_names()[target_device])

    def get_list_of_all_port_names(self):
        response = self.switch_api.get_list_of_all_port_names()
        # Merge all port names into one list for multiple switch units
        if len(self.tool.switch_units) > 1:
            all_port_names = list()
            for port_names in response:
                all_port_names.extend(port_names)
            response = all_port_names
        return response
