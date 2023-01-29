import re
import time
import pytest
import random
from typing import Union
from lib_testbed.generic import WAN_VLAN
from distutils.version import StrictVersion
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.allure_util import AllureUtil
from lib_testbed.generic.switch.switch_controller import SwitchController


class SwitchApiGeneric:
    def __init__(self, config, switch_unit_cfg):
        self.config = config
        self.init_ports_info_to_cfg()
        self.init_fixed_vlans()
        self.switch_ctrl = SwitchController(tb_config=self.config, switch_unit_cfg=switch_unit_cfg,
                                            switch_api=True)
        self.switch_unit = self.switch_ctrl.switch_units[0]
        self.min_required_version = '1.0.0'
        self.ports_isolation_cfg = dict()

    def setup_class_handler(self):
        if not hasattr(self, "session_config"):
            return

        if self.session_config.option.skip_init:
            return

        # save switches config versions
        if self.config.get('switch_version'):
            return

        version = self.version(skip_exception=True)
        self.config['switch_version'] = version
        AllureUtil(self.session_config).add_environment(f'switch_{self.switch_unit.ip}_version', version, '_error')
        assert StrictVersion(version) >= StrictVersion(self.min_required_version), \
            f"Config on the {self.switch_unit.ip} switch is older than {self.min_required_version}, " \
            f"please upgrade to the latest"

    def init_fixed_vlans(self):
        ...

    def init_ports_info_to_cfg(self):
        if self.config.get('ports_info'):
            return
        self.config['ports_info'] = dict()

    def dump_ports_info(self, ports_info: dict):
        # Dump ports info to reduce number of calls to switch
        self.config['ports_info'].update({port_name: port_info[1] for port_name, port_info in ports_info.items()})

    # TODO Update all functions to return stdout. Consider update all calls to functions.
    @staticmethod
    def get_stdout_port_requests(responses: dict, skip_exception=False) -> dict:
        stdout = dict()
        for port_name, response in responses.items():
            if not skip_exception:
                assert not response[0], f'Switch call failed {response}'
            stdout[port_name] = response[1]
        return stdout

    @staticmethod
    def get_stdout_switch_requests(response: Union[list, tuple], skip_exception=False):
        if not skip_exception:
            assert not response[0], f'Switch call failed {response}'
        return response[1]

    # TODO: Change return output to dict type then update all calls to function
    def get_switch_alias(self, pod_name: str) -> tuple:
        """
        Get switch alias
        Args:
            pod_name: (str)

        Returns: (port_name, port_number, port_backhaul)

        """
        device_port_aliases = self.switch_ctrl.get_device_port_aliases(device_name=pod_name)
        if not device_port_aliases:
            return None, None, None
        return tuple(random.choice(device_port_aliases).values())

    # TODO: Change alias to dict type then update all calls to function
    def get_all_switch_aliases(self, pod_name: str) -> list:
        """
        Get switch aliases
        Args:
            pod_name: (str)

        Returns: (list) [(port_name, port_number, port_backhaul), ...]

        """
        device_port_aliases = self.switch_ctrl.get_device_port_aliases(device_name=pod_name)
        if not device_port_aliases:
            return [(None, None, None)]
        port_aliases = list()
        for device_port_alias in device_port_aliases:
            port_aliases.append(tuple(device_port_alias.values()))
        return port_aliases

    def get_device_port_names(self):
        device_port_names = {}
        for device in self.config['Nodes']:
            port_names = [port_name for port_name, port_number, vlan_number
                          in self.get_all_switch_aliases(device['name']) if port_name]
            device_port_names[device['name']] = port_names
        return device_port_names

    def get_list_of_all_port_names(self):
        device_port_names = self.get_device_port_names()
        list_of_all_ports = list()
        for device_name in device_port_names.keys():
            list_of_all_ports.extend(device_port_names[device_name])
        return list_of_all_ports

    # TODO: Create specific function for multiple port and one port arg to get consistent function output
    # Deprecated. Please use get_port_info() or get_ports_info()
    def switch_info(self, vlan_port_names):
        """
        Methods for get actual configuration on Switch
        Args:
            vlan_port_names: For one port: (str) vlan port name
                             For multiple port (list) [(str)]

        Returns:

        """
        if isinstance(vlan_port_names, str):
            return self.switch_ctrl.switch_info(vlan_port_names)[vlan_port_names][1]
        ports_info = self.switch_ctrl.switch_info(vlan_port_names)
        self.dump_ports_info(ports_info=ports_info)
        return ports_info

    def get_port_info(self, vlan_port_name: str) -> str:
        """
        Get switch info from port
        Args:
            vlan_port_name: (str)

        Returns: (str) stdout

        """
        response = self.switch_ctrl.switch_info(vlan_port_name)
        self.dump_ports_info(ports_info=response)
        return self.get_stdout_port_requests(response)[vlan_port_name]

    def get_ports_info(self, vlan_port_names: list) -> dict:
        """
        Get switch info from multiple ports
        Args:
            vlan_port_names: (list)

        Returns: (dict) {port_name: [ret_val, stdout, stderr], ...}

        """
        response = self.switch_ctrl.switch_info(vlan_port_names)
        self.dump_ports_info(ports_info=response)
        return response

    def version(self, **kwargs):
        """
        Get switch config version
        Returns: {switch_hostname: [ret_val, std_out, std_err]

        """
        response = self.switch_ctrl.get_version()
        version = self.get_stdout_switch_requests(response, **kwargs)
        if version_num := re.search(r"(\d+\.\d+.\d+)", version):
            version = version_num.group()
        elif version_num := re.search(r"(\d+\.\d+)", version):
            version = version_num.group()
        else:
            log.warning("Cannot get version from switch'")
            version = "100.0.0"
        return version

    def model(self, **kwargs):
        """
        Get switch model
        Returns: {switch_hostname: [ret_val, std_out, std_err]

        """
        response = self.switch_ctrl.get_model()
        return self.get_stdout_switch_requests(response, **kwargs)

    def restore_config(self):
        """
        Restore switch config
        Returns: (str) version

        """
        return self.switch_ctrl.restore_config()

    def disable_port(self, port_name):
        """
        Disable port on switch
        Args:
            port_name: (str) port name from tb config

        Returns:

        """
        return self.switch_ctrl.interface_down(port_name)

    def enable_port(self, port_name):
        """
        Enable port on switch
        Args:
            port_name: (str) port name from tb config

        Returns:

        """
        return self.switch_ctrl.interface_up(port_name)

    def get_interface_state(self, port_name):
        """
        Get interface status (enable/disable)
        Args:
            port_name: (str) port name from tb config

        Returns: (bool) If enable return True else False

        """
        state = self.switch_ctrl.interface_status(port_name)[port_name]
        state = True if 'Enable' in state[1] else False
        return state

    def set_link_speed(self, port_name, link_speed):
        """
        Set link speed on port
        Args:
            port_name: (str) port name from tb config
            link_speed: (int) link speed (10, 100, 1000) or (str) 'auto'

        Returns:  dict() {port_name: [ret_val, std_out, std_err]

        """
        results = self.switch_ctrl.set_link_speed(port_name, link_speed)
        return results

    def get_daisy_chain_devices(self):
        connection_info = self.config.get('connection_info', [])
        if not connection_info:
            return connection_info
        return [key for key, value in connection_info.items() if value == 'daisy_chain']

    def get_port_link_status(self, port_name):
        port_link_status = self.switch_ctrl.get_link_status(port_name)
        return port_link_status[port_name][1]

    def get_uplink_port(self, ports_info):
        port_uplink = None
        port_names = self.get_port_names_from_aliases(ports_info)
        for port_name in port_names:
            port_role = self.get_role_of_port(port_name)
            if 'uplink' in port_role:
                port_uplink = port_name
                break
        return port_uplink

    @staticmethod
    def get_port_names_from_aliases(ports_aliases):
        port_names = []
        for pod_port_info in ports_aliases:
            for port_alias in pod_port_info:
                port_names.append(port_alias[0])
        return port_names

    def get_role_of_port(self, vlan_port_name):
        """
        Get role of vlan port which is described in switch configuration (mn, lan)
        Args:
            vlan_port_name: (str) Name of vlan port

        Returns: (list)

        """
        vlan_roles = [vlan_role['switch'][vlan_port_name] for vlan_role in self.config['Nodes']
                      if vlan_port_name in vlan_role.get('switch', [])]
        vlan_roles = vlan_roles[0] if vlan_roles else vlan_roles
        vlan_roles = [vlan_role.lower() for vlan_role in vlan_roles] if vlan_roles else vlan_roles
        return vlan_roles

    def disable_no_used_ports(self, dev_name=None, device_aliases=None, vlan_type='untagged'):
        use_port = None
        switch_aliases = self.get_all_switch_aliases(dev_name) if dev_name else device_aliases
        if None not in switch_aliases and len(switch_aliases) >= 1:
            port_names = [switch_alias[0] for switch_alias in switch_aliases]
            use_port = [port_name for port_name in port_names if not use_port
                        and self.get_wan_vlan_number(self.switch_info(port_name), vlan_type=vlan_type)]
            if use_port:
                use_port = use_port[0]
                # Make sure that use port is enable
                if not self.get_interface_state(use_port):
                    self.enable_port(use_port)
                log.info(f'Used port: {use_port}')
                port_names.remove(use_port)
            for port_name in port_names:
                port_role = self.get_role_of_port(port_name)
                port_state = self.get_interface_state(port_name)
                # Make sure all ports are enabled in case daisy chain connection
                if 'mn' in port_role or [device for device in self.get_daisy_chain_devices() if device in port_name]:
                    log.info(f'Management used port: {port_name}')
                    if not port_state:
                        self.enable_port(port_name)
                    continue
                log.info(f'No used port: {port_name}')
                if port_state:
                    log.info(f'Disabling no used port {port_name}')
                    self.disable_port(port_name)

    def switch_wan_port(self, pod_name, target_port='', disable_no_used_ports=True, enable_port=True,
                        vlan_type='untagged'):
        """
        Switch wan port between two eth ports
        Args:
            pod_name: (str) pod name where we want to change port
            target_port: (str) Optional target port name eth0 or eth1
            disable_no_used_ports: (bool) Disable no used ports if True
            enable_port: (bool) Enable new wan port if True
            vlan_type: (str) Type of vlan tagged or untagged

        Returns: (str) current wan port information

        """
        port_aliases = self.get_all_switch_aliases(pod_name)
        assert port_aliases, f'Not found port information for {pod_name} device'
        ports_name = [port_name[0] for port_name in port_aliases]
        assert len(ports_name) == 2, 'This method is valid only for devices with two eth ports'
        ports_info = self.switch_info(ports_name)
        old_wan_port_name = ''
        wan_vlan = ''
        for port_name in ports_info:
            port_current_information = ports_info[port_name][1]
            wan_vlan = self.get_wan_vlan_number(port_current_information, vlan_type=vlan_type)
            if wan_vlan:
                old_wan_port_name = port_name
                break

        assert old_wan_port_name and wan_vlan, f'Not found wan vlan\n{ports_info}'
        ports_name.remove(old_wan_port_name)
        new_wan_port_name = ports_name[0]

        if target_port not in new_wan_port_name:
            if disable_no_used_ports:
                self.disable_no_used_ports(device_aliases=port_aliases)
            log.info(f'Changing switch port is not needed. Current wan port: {old_wan_port_name} '
                     f'target wan port {target_port}')
            return False

        # Get default blackhole from test bed config for old wan port
        default_old_wan_blackhole = [port_alias[2] for port_alias in port_aliases
                                     if old_wan_port_name == port_alias[0]][0]

        # disabling gateway port
        self.disable_port(old_wan_port_name)

        if vlan_type == 'untagged':
            # set target port to vlan 200
            self.change_untagged_vlan(new_wan_port_name, int(wan_vlan), enable_port=enable_port)
            # set blackhole to old target blackhole on old gateway port
            self.change_untagged_vlan(old_wan_port_name, default_old_wan_blackhole)
        else:
            self.remove_tagged_vlan(port_name=old_wan_port_name, target_vlan=int(wan_vlan))
            self.add_tagged_vlan(port_name=new_wan_port_name, target_vlan=int(wan_vlan))

        if disable_no_used_ports:
            # disable no used ports
            self.disable_no_used_ports(device_aliases=port_aliases, vlan_type=vlan_type)
        return self.switch_info(new_wan_port_name)

    def connect_eth_client(self, pod_name, client_name, connect_port='', **kwargs):
        """
        Connect dynamic ethernet client by changing vlan settings
        Args:
            pod_name: (str) Pod name where we want to connect eth client
            client_name: (str) Client name which we want to connect to pod
            connect_port: (str) Connection target port eth0 or eth1. If empty get random port.
        Returns: (str) Target portconnect_eth_client where is connected eth client

        """
        port_info = self.get_all_switch_aliases(pod_name)
        assert port_info, f'Not found port information for {pod_name} device'

        # get eth client vlan
        client_blackhole = [client.get('vlan') for client in self.config.get('Clients')
                            if client_name == client.get('name')][0]
        assert client_blackhole, f'Client vlan has not been found for {client_name}'

        # get non wan port
        target_port = None
        for port in port_info:
            # port: (name, port_id, def_vlan)
            # skip port if is not this, which was requested
            if connect_port and connect_port not in port[0]:
                continue
            port_status = self.switch_info(port[0])
            log.debug(port_status)
            # skip internet port
            if self.get_wan_vlan_number(port_status, **kwargs):
                continue
            # we want only port which has default vlan set currently
            if str(port[2]) not in port_status:
                continue
            target_port = port[0]
            break
        assert target_port, 'Target port has not been found. Probably you want to connect eth client to wan port or ' \
            'client is already connected to another pod'

        # connect client to target port
        self.change_untagged_vlan(target_port, client_blackhole)
        log.info("Sleep for cloud to put iface to the bridge")
        time.sleep(20)
        return target_port

    def disconnect_eth_client(self, pod_name, client_name, disable_no_used_ports=True):
        """
        Disconnect dynamic ethernet client by changing vlan settings
        Args:
            pod_name: (str) Pod name where we want to connect eth client
            client_name: (str) Client name which we want to connect to pod
            disable_no_used_ports: (bool) Disable non used port on pod if True

        Returns: (str) Target port where was connected eth client

        """
        # get port information
        port_info = self.get_all_switch_aliases(pod_name)
        assert port_info, f'Not found port information for {pod_name} device'
        ports_name = [port_name[0] for port_name in port_info]

        # get eth client blackhole
        client_blackhole = [client.get('vlan') for client in self.config.get('Clients')
                            if client_name == client.get('name')][0]
        assert client_blackhole, f'Client blackhole has not been found for {client_name}'

        # get port where is connected eth client
        client_port = [port_name for port_name in ports_name if str(client_blackhole) in self.switch_info(port_name)]
        if not client_port:
            log.info('Ethernet client is disconnected')
            return
        client_port = client_port[0]
        assert client_port, 'Port where is connected eth client has not been found'

        # get default port blackhole from test bed config
        default_old_wan_blackhole = [port_alias[2] for port_alias in port_info if client_port == port_alias[0]][0]

        # disconnect eth client from port
        self.change_untagged_vlan(client_port, default_old_wan_blackhole)

        # disable no used ports
        if disable_no_used_ports:
            self.disable_no_used_ports(device_aliases=port_info)
        return client_port

    def disconnect_all_pods_from_client_vlan(self, client_blackhole_vlan):
        """
        Restore pvid and untagged of all pod ports currently connected to client's vlan to their default vlan.

        Args:
            client_blackhole_vlan: (int) Dynamic ehternet client vlan from which pods should be disconnected.

        Returns: None.
        """
        client_blackhole_vlan = str(client_blackhole_vlan)
        all_alias_infos = self.get_all_switch_aliases('')
        port_names = [info[0] for info in all_alias_infos]
        port_infos = self.switch_ctrl.switch_info_parsed(port_names)
        for port_name, _, port_blackhole_vlan in all_alias_infos:
            port_info = port_infos[port_name]
            if client_blackhole_vlan == port_info['pvid'] or client_blackhole_vlan in port_info['untagged']:
                self.change_untagged_vlan(port_name, port_blackhole_vlan)

    def get_unused_pod_ports(self, pod_name):
        """
        Return a list of pod port names which are currently not used for upstream or client connection.

        Args:
            pod_name: (str) Name of the pod.

        Returns: (list) Possibly empty list of unused pod port names.
        """
        pod_alias_infos = self.get_all_switch_aliases(pod_name)
        port_names = [info[0] for info in pod_alias_infos]
        raw_infos = self.get_ports_info(port_names)
        port_infos = self.switch_ctrl.switch_info_parsed(port_names)
        unused = []
        for port_name, _, port_blackhole_vlan in pod_alias_infos:
            # Uplink might be arriving via tagged or untagged VLAN, so check for 2xx WAN VLAN IDs first.
            raw_info = raw_infos[port_name][1]
            if self.get_wan_vlan_number(raw_info, 'untagged') or self.get_wan_vlan_number(raw_info, 'tagged'):
                continue
            port_info = port_infos[port_name]
            port_blackhole_vlan = str(port_blackhole_vlan)
            if port_info['pvid'] == port_blackhole_vlan and port_info['untagged'] == [port_blackhole_vlan]:
                unused.append(port_name)
        return unused

    def recovery_switch_configuration(self, pod_names=None, force=False, set_default_wan=False, default_wan_vlan=200):
        """
        Set default configuration on switch from test bed config.
        Args:
            pod_names: (list) [(str)] or (str) for single device
            force: (bool) By default False, if True recover also fake internet backhauls
            set_default_wan: (bool) Set default wan to port which is marked as uplink form cfg - applies only for
            devices with more than one port
            default_wan_vlan: (int) Set wan in case when wan port is not found

        Returns: (list) recovered switch vlans

        """
        if isinstance(pod_names, str):
            pod_names = [pod_names]

        ports_info = [self.get_all_switch_aliases(pod_name) for pod_name in pod_names]
        # get ports without None values
        ports_info = [port for port in ports_info if None not in port[0]]
        # Applies only when any port from cfg is marked as uplink
        if set_default_wan:
            self.set_default_wan_port(ports_info, default_wan_vlan)
        vlan_name_list = list()
        wan_port = 0
        for port_info in ports_info:
            for port_alias in port_info:
                vlan_name = port_alias[0]
                vlan_name_list.append(vlan_name)
                default_blackhole = port_alias[2]
                if self.ports_isolation_cfg.get(vlan_name):
                    self.set_forward_ports_isolation(vlan_name, self.ports_isolation_cfg.get(vlan_name))
                switch_info = self.switch_info(vlan_name)
                if not force and self.get_wan_vlan_number(switch_info) and wan_port == 0:
                    wan_port += 1
                    continue
                if str(default_blackhole) not in switch_info:
                    log.info(f'Setting default configuration on {vlan_name}')
                    self.change_untagged_vlan(vlan_name, default_blackhole)
                # Specific case for residential gw with mgmt over the eth-dongle
                if 'gw' in vlan_name:
                    self.restore_rpi_dongle_vlan(device_port=vlan_name, pod_name='gw')
            self.disable_no_used_ports(device_aliases=port_info)
        # If force is set to True skip recover wan port
        # Force arg should set only default switch configuration from cfg not more
        if not wan_port and not force:
            self.recover_wan_port(ports_info, default_wan_vlan=default_wan_vlan)
        return vlan_name_list

    def recover_wan_port(self, ports_info, default_wan_vlan):
        port_uplink = self.get_uplink_port(ports_info)
        if not port_uplink:
            return False
        log.info(f'Setting default wan vlan: {default_wan_vlan} on {port_uplink}')
        self.change_untagged_vlan(port_uplink, default_wan_vlan)

    def set_default_wan_port(self, ports_info: list, default_wan_vlan: int):
        # Clear all WAN vlans
        for pod_name, connection_type in self.get_devices_connection_type().items():
            if 'fake_internet' not in connection_type:
                continue
            # Use force flag to clear WAN vlans
            self.recovery_switch_configuration(pod_names=[pod_name], force=True, set_default_wan=False)
        self.recover_wan_port(ports_info=ports_info, default_wan_vlan=default_wan_vlan)

    def set_connection_ip_type(self, pod_name, ip_type, disable_ports_isolation=False, enable_port=True, **kwargs):
        """
        Set connection IP type
        Args:
            pod_name: (str) Name of device
            ip_type: (str) One of the WAN_VLAN names from [ipv4, ipv6_stateful, ipv6_stateless, ipv6_slaac, ...]
            disable_ports_isolation: (bool) Disable port isolation before set connection type -
             For leaf multi-gw mandatory
            enable_port: (bool)

        Returns: (bool)

        """
        ports_aliases = self.get_all_switch_aliases(pod_name)
        ports_name = [port_alias[0] for port_alias in ports_aliases]
        target_port = [port_name for port_name in ports_name if self.get_wan_vlan_number(self.switch_info(port_name))]
        target_port = target_port[0] if target_port else ports_name[0]
        if disable_ports_isolation:
            self.disable_ports_isolation(target_port, **kwargs)
        vlan_map = {vlan_name.lower(): vlan for vlan_name, vlan in WAN_VLAN.__members__.items()}
        target_vlan = ip_type if isinstance(ip_type, int) else vlan_map.get(ip_type.lower())
        return self.change_untagged_vlan(port_name=target_port, target_vlan=int(target_vlan), enable_port=enable_port)

    def get_connection_ip_type(self, pod_name):
        """
        Get connection IP type
        Args:
            pod_name: (str) Name of device

        Returns: (str, int) Used WAN_VLAN name from [ipv4, ipv6_stateful, ipv6_stateless, ipv6_slaac, ...] and VLAN ID.
         Two empty strings when pod isn't connected to any WAN VLAN.
        """
        ports_aliases = self.get_all_switch_aliases(pod_name)
        ports_name = [port_alias[0] for port_alias in ports_aliases]
        vlan = ''
        for port_name in ports_name:
            vlan = self.get_wan_vlan_number(self.switch_info(port_name))
            if vlan:
                break
        vlan_id = int(vlan) if vlan else vlan
        try:
            vlan_name = WAN_VLAN(vlan_id).name
        except ValueError:
            vlan_name = ''
        return vlan_name.lower(), vlan_id

    def get_wan_port(self, pod_name):
        """
        Get wan port from target device
        Args:
            pod_name: (str) name of device

        Returns:

        """
        ports_aliases = self.get_all_switch_aliases(pod_name)
        ports_name = [port_alias[0] for port_alias in ports_aliases]
        ports_info = self.switch_info(ports_name)
        wan_port = ''
        for port_name in ports_name:
            port_info = ports_info[port_name][1]
            if self.get_wan_vlan_number(port_info):
                wan_port = port_name
                break
        if not wan_port and 'CMTS' in self.config.get('capabilities', []):
            pytest.skip('The test is not suitable for gateways connected over CMTS. Skipping the test...')
        assert wan_port, f'Wan port not found for the following device: {pod_name}.\n{ports_info}'
        log.info(f'Wan port for {pod_name}: {wan_port}')
        return wan_port

    def remove_custom_tagged_vlans(self, pod_name, default_tagged_vlans=('4', '24', '35')):
        port_aliases = self.get_all_switch_aliases(pod_name)
        assert port_aliases, f'Not found port information for {pod_name} device'
        ports_name = [port_name[0] for port_name in port_aliases]
        ports_info = self.switch_info(ports_name)
        for port_name, port_info in ports_info.items():
            tagged_vlans = self.get_tagged_vlans(port_info[1])
            for tagged_vlan in tagged_vlans:
                if tagged_vlan in default_tagged_vlans:
                    continue
                self.remove_tagged_vlan(port_name=port_name, target_vlan=tagged_vlan)

    def get_no_wan_port(self, switch_aliases):
        port_name, default_blackhaul = '', ''
        for switch_alias in switch_aliases:
            vlan_port_name, number_port, blackhaul = switch_alias
            assert vlan_port_name, f'Can not describe vlan port name for {switch_aliases}. ' \
                                   f'Make sure switch cfg is set for all nodes from tb-config'
            wan_pvid = self.get_wan_vlan_number(self.switch_info(vlan_port_name))
            if not wan_pvid:
                port_name, default_blackhaul = vlan_port_name, blackhaul
                break
        assert port_name and default_blackhaul, f'Not found no-wan-port for: {switch_aliases}'
        return port_name, default_blackhaul

    def set_daisy_chain_connection(self, target_device, connect_to_device):
        """
        Set daisy chain connection between two pods connect_to_device <--eth--> target_device
        Args:
            target_device: (str) Name of target device which can be connected to another pod
            connect_to_device: (str) Name of device where target device can be connected

        Returns:

        """
        devices_connection_type = self.get_devices_connection_type()
        if devices_connection_type[connect_to_device] == 'daisy_chain':
            all_ports_info = {port_name: port_data[1] for port_name, port_data in
                              self.switch_info(self.get_list_of_all_port_names()).items()}
            for port_name, port_number, default_backhaul in self.get_all_switch_aliases(connect_to_device):
                if not self.is_daisy_chain_connection(all_ports_info, port_name):
                    target_port, target_backhaul = port_name, default_backhaul
                    break
            else:
                assert False, 'Can not find any unused port to set daisy chain connection between' \
                              f' {target_device} <--> {connect_to_device} devices'
        else:
            target_port, target_backhaul = self.get_no_wan_port(self.get_all_switch_aliases(connect_to_device))
        self.enable_port(target_port)
        device_port_name, *_ = self.get_switch_alias(target_device)
        return self.change_untagged_vlan(device_port_name, target_vlan=target_backhaul)

    def get_devices_connection_type(self):
        devices_name = [node['name'] for node in self.config['Nodes'] if node.get('switch')]
        # Get only stdout
        all_ports_info = {port_name: port_data[1] for port_name, port_data in
                          self.switch_info(self.get_list_of_all_port_names()).items()}
        device_connection_type = dict()
        for device_name in devices_name:
            connection_type = None
            for switch_alias in self.get_all_switch_aliases(device_name):
                port_name, port_number, blackhaul_number = switch_alias
                if wan_number := self.get_wan_vlan_number(all_ports_info[port_name]):
                    # fake_internet means only ipv4, another ip_type fake_internet_wan_number
                    connection_type = 'fake_internet' if wan_number == '200' else f'fake_internet_{wan_number}'
                    break
                if self.is_daisy_chain_connection(all_ports_info, port_name):
                    connection_type = 'daisy_chain'
                    continue
            device_connection_type[device_name] = connection_type
            # If eth backhaul is not recognized assume pod is connected via wifi
            if device_connection_type[device_name] is None:
                device_connection_type[device_name] = 'wifi'
        return device_connection_type

    def swap_gw_and_leaf_pod(self, gw_name, leaf_name, ip_type='ipv4', enable_port=True):
        """
        Swaps roles of current gateway `gw_name` with leaf pod `leaf_name`
        i.e. - gateway becomes leaf & leaf becomes gateway

        Args:
            gw_name: (str) - Canonical name of current GW device
            leaf_name: (str) - Canonical name of leaf pod, to be reconfigured as GW device
            ip_type: (str) - may be one of ['ipv4', 'ipv6_stateful', 'ipv6_stateless', 'ipv6_slaac']

        Returns:
            (None) - Asserts that previous leaf has been reconfigured as a gateway
        """
        log.info(f'Swapping current gateway -> "{gw_name}" with leaf "{leaf_name}"')
        self.recovery_switch_configuration(gw_name, force=True)
        self.set_connection_ip_type(pod_name=leaf_name, ip_type=ip_type,
                                    enable_port=enable_port, disable_ports_isolation=True)
        leaf_new_con_type, leaf_new_vlan_num = self.get_connection_ip_type(leaf_name)
        assert 200 <= leaf_new_vlan_num < 300, f'Pod {leaf_name} has been switched to gateway'

    @staticmethod
    def is_daisy_chain_connection(all_ports_info, target_port_name):
        daisy_chain_connection = False
        target_port_info = all_ports_info.get(target_port_name)
        assert target_port_info, f'"all_ports_info" variable does not contain any data about: {target_port_name}'
        target_port_pvid = re.search('3[0-9][0-9]', target_port_info)
        # port pvid is out of 300-399 scope
        if not target_port_pvid:
            return daisy_chain_connection
        target_port_pvid = target_port_pvid.group()
        for port_name, port_info in all_ports_info.items():
            if target_port_name == port_name or target_port_pvid not in port_info:
                continue
            log.info(f'Found daisy chain connection: {target_port_name} is connected to {port_name}')
            daisy_chain_connection = True
            break
        return daisy_chain_connection

    @staticmethod
    def get_wan_vlan_number(port_info, vlan_type='untagged'):
        match_expression = f'(?<={vlan_type}).\s+2[0-9][0-9]' # noqa W605
        result = re.findall(match_expression, port_info, re.IGNORECASE)
        return result[0].strip() if result else ''

    @staticmethod
    def get_tagged_vlans(port_info):
        tagged_vlans = re.findall(r'Tagged.\s+\d+', port_info)
        vlan_numbers = []
        for target_vlan in tagged_vlans:
            vlan_number = re.search(r'\d+', target_vlan)
            if vlan_number:
                vlan_numbers.append(vlan_number.group())
        return vlan_numbers

    def change_untagged_vlan(self, port_name, target_vlan, enable_port=True):
        """
        Method for change untagged vlan on switch
        Args:
            port_name: (str) port_name from tb config
            target_vlan:   (int) vlan number which will set
            enable_port: (bool)

        Returns: (bool)

        """
        raise NotImplementedError

    def add_tagged_vlan(self, port_name, target_vlan, enable_port=True):
        """
        Add tagged vlan to switch port
        Args:
            port_name: (str) port_name from tb config
            target_vlan:   (int) vlan number which will be added
            enable_port: (bool)

        Returns: (bool)
        """
        raise NotImplementedError

    def remove_tagged_vlan(self, port_name, target_vlan, enable_port=True):
        """
        Remove tagged vlan from switch port
        Args:
            port_name: (str) port_name from tb config
            target_vlan:   (int) vlan number which will be removed
            enable_port: (bool)

        Returns: (bool)
        """
        raise NotImplementedError

    # TODO: Create specific function for multiple port and one port arg to get consistent function output
    def get_forward_ports_isolation(self, vlan_port_names):
        """
        Methods for get forward ports isolation from interface
        Args:
            vlan_port_names: For one port: (str) vlan port name
                             For multiple port (list) [(str)]

        Returns:

        """
        raise NotImplementedError

    # TODO: Create specific function for multiple port and one port arg to get consistent function output
    def set_forward_ports_isolation(self, vlan_port_names, ports_isolation):
        """
        Set forward ports isolation on target port
        Args:
            vlan_port_names: For one port: (str) vlan port name
                             For multiple port (list) [(str)]
            ports_isolation: (list) list of ports isolation for example (int(),int()) or (str)
            for example '1/0/1-2,1/0/4'

        Returns:

        """
        raise NotImplementedError

    # TODO: Create specific function for multiple port and one port arg to get consistent function output
    def disable_ports_isolation(self, vlan_port_names, dump_ports_isolation=False, **kwargs):
        """
        Disable ports isolation on target port
        Args:
            vlan_port_names: For one port: (str) vlan port name
                             For multiple port (list) [(str)]
            dump_ports_isolation: (bool) If True dump ports isolation config to switchlib obj
        Returns: None

        """
        raise NotImplementedError

    def restore_rpi_dongle_vlan(self, device_port, pod_name):
        raise NotImplementedError

    def set_port_duplex(self, ports: str | list[str], mode: str) -> dict:
        """Sets duplex mode for port(s). Possible modes are "half", "full",
        and "auto"."""
        raise NotImplementedError
