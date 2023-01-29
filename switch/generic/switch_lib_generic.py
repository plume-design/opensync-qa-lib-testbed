
class SwitchLibGeneric:
    def __init__(self, switch_name, user, password, ip, port, aliases, tb_config, **kwargs):
        self.switch_name = switch_name
        self.user = user
        self.password = password
        self.ip = ip
        self.port = port
        self.aliases = self.init_switch_alias(aliases=aliases)
        self.tb_config = tb_config

    def get_device_switch_aliases(self, device_name: str) -> list:
        return [self.aliases[port_name] for port_name in self.aliases.keys() if device_name in port_name]

    @staticmethod
    def init_switch_alias(aliases: str) -> dict:
        switch_aliases = dict()
        for alias in aliases:
            backhaul, name, port = alias['backhaul'], alias['name'], alias['port']
            switch_aliases[name] = dict(name=name, port=port, backhaul=backhaul)
        return switch_aliases

    def map_port_names_to_port_numbers(self, port_names: list) -> dict:
        return {port_name: self.aliases[port_name]['port'] for port_name in port_names if self.aliases.get(port_name)}

    def get_all_config_ports(self):
        config_ports = list()
        for switch_alias in self.aliases.values():
            config_ports.append(switch_alias['port'])
        return config_ports

# Common function definitions. Must be implemented for all switch units
    def login(self):
        raise NotImplementedError()

    def shutdown_interface(self, ports):
        raise NotImplementedError()

    def no_shutdown_interface(self, ports):
        raise NotImplementedError()

    def interface_status(self, ports):
        raise NotImplementedError()

    def interface_status_parser(self, status):
        raise NotImplementedError()

    def interface_info(self, ports):
        raise NotImplementedError()

    def interface_info_parser(self, info):
        raise NotImplementedError()

    def delete_vlan(self, ports, vlan):
        raise NotImplementedError()

    def set_vlan(self, ports, vlan, type):
        raise NotImplementedError()

    def list_vlan(self):
        raise NotImplementedError()

    def list_vlan_parser(self, list_vlan):
        raise NotImplementedError()

    def list_pvid(self):
        raise NotImplementedError()

    def list_pvid_parser(self, list_pvid):
        raise NotImplementedError()

    def logout(self):
        raise NotImplementedError()

    def version(self):
        raise NotImplementedError

    def get_model(self):
        raise NotImplementedError

    def system_info(self):
        raise NotImplementedError

    def restore_config(self):
        raise NotImplementedError

    def set_forward_port_isolation(self, ports, forward_ports=''):
        raise NotImplementedError

    def show_ports_isolation_interface(self, ports):
        raise NotImplementedError

    def disable_port_isolation(self, ports):
        raise NotImplementedError

    def set_link_speed(self, ports, speed):
        raise NotImplementedError

    def get_link_status(self, ports):
        raise NotImplementedError

    def action_interface(self, ports, action):
        raise NotImplementedError
