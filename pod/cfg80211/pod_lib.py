from lib_testbed.generic.pod.generic.pod_lib import PodLib as PodLibGeneric


class PodLib(PodLibGeneric):
    def get_tx_power(self, interface, **kwargs):
        """
        Get current Tx power in dBm. Make sure interface is up, otherwise returned value is incorrect.
        Args:
            interface: (str) Wireless interface

        Returns: raw output [(int) ret, (str) std_out, (str) str_err]

        """
        cmd = "iw %s info | grep txpower | awk '{print $2}'" % interface
        return self.strip_stdout_result(self.run_command(cmd, **kwargs))

    def decrease_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Decrease value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns:

        """
        percent_ratio = percent_ratio / 100
        all_interfaces = self.iface.get_all_home_bhaul_ifaces()
        cmd = ""
        for interface in all_interfaces:
            current_tx_power = float(self.get_stdout(self.get_tx_power(interface)))
            expect_tx_power = int(current_tx_power - (current_tx_power * percent_ratio))
            if expect_tx_power < 1:
                expect_tx_power = 1
            # iw sets txpower in mBm, so we need to multiply returned dBm by 100
            cmd += f"iw {interface} set txpower {expect_tx_power * 100}; "
        return self.run_command(cmd, **kwargs)

    def increase_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Increase value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns:

        """
        percent_ratio = percent_ratio / 100
        all_interfaces = self.iface.get_all_home_bhaul_ifaces()
        cmd = ""
        for interface in all_interfaces:
            current_tx_power = float(self.get_stdout(self.get_tx_power(interface)))
            expect_tx_power = int(current_tx_power + (current_tx_power * percent_ratio))
            # iw sets txpower in mBm, so we need to multiply returned dBm by 100
            cmd += f"iw {interface} set txpower {expect_tx_power * 100}; "
        return self.run_command(cmd, **kwargs)

    def set_tx_power(self, tx_power, interfaces=None, **kwargs):
        """
        Set current Tx power in dBm
        Args:
            interfaces: (str) or (list) Name of wireless interfaces
            tx_power: (int) Tx power in dBm.

        Returns:

        """
        if not interfaces:
            interfaces = self.iface.get_all_home_bhaul_ifaces()
        if isinstance(interfaces, str):
            interfaces = [interfaces]
        cmd = ""
        for interface in interfaces:
            # iw sets txpower in mBm, so we need to multiply dBm by 100
            cmd += f"iw {interface} set txpower {tx_power * 100}; "
        return self.run_command(cmd, **kwargs)
