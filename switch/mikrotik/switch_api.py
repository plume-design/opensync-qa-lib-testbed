import time
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.switch.generic.switch_api_generic import SwitchApiGeneric


class SwitchApi(SwitchApiGeneric):
    def __init__(self, config, switch_unit_cfg):
        super().__init__(config=config, switch_unit_cfg=switch_unit_cfg)
        self.min_required_version = "7.1.2"  # required for REST API

    # Not needed for mikrotik switches
    def restore_rpi_dongle_vlan(self, device_port, pod_name):
        ...

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
        assert str(target_vlan) in port_info, f"Current port info: {port_name}, target vlan: {target_vlan}"
        log.info(f"Untagged vlan: {target_vlan} successfully added to {port_name}")
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
        target_vlan = str(target_vlan)
        self.switch_ctrl.interface_down(port_name)
        self.switch_ctrl.vlan_set(port_name, target_vlan, "tagged")
        time.sleep(10)
        if enable_port:
            log.info(f"Enabling {port_name}")
            self.switch_ctrl.interface_up(port_name)
        port_info = self.switch_ctrl.switch_info_parsed(port_name)[port_name]
        assert target_vlan in port_info["tagged"], f"Adding tagged vlan to {port_name} failed"
        log.info(f"Adding tagged vlan {target_vlan} to port {port_name} finished successfully")
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
        target_vlan = str(target_vlan)
        self.switch_ctrl.interface_down(port_name)
        self.switch_ctrl.vlan_remove(port_name, target_vlan)
        time.sleep(10)
        if enable_port:
            log.info(f"Enabling {port_name}")
            self.switch_ctrl.interface_up(port_name)
        port_info = self.switch_ctrl.switch_info_parsed(port_name)[port_name]
        assert target_vlan not in port_info["tagged"], f"Removing tagged vlan: {target_vlan} from {port_name} failed"
        log.info(f"Removing tagged vlan {target_vlan} from port {port_name} finished successfully")
        return True
