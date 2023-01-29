import os
import time
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.client.models.mac.client_tool import ClientTool
from lib_testbed.generic.client.models.generic.client_lib import ClientLib as ClientLibGeneric


class ClientLib(ClientLibGeneric):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ext_path = '/usr/local/bin:/opt/homebrew/bin'
        self.tools_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources"
        self.tool = ClientTool(lib=self)

    def ping(self, host='', **kwargs):
        """
        Check ping on client(s)
        Args:
            host: (str) IP
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        if host:
            cmds = f"ping -c1 {host}"
        else:
            cmds = f"ping -c1 {self.device.get_ip()}"
        result = self.run_command(cmds, **kwargs)
        return self.strip_stdout_result(result)

    def reboot(self, **kwargs):
        """
        Reboot client(s)
        Args:
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        result = self.run_command("sudo reboot", **kwargs)
        # Change ret val from 255 to 0 due to lost connection after reboot.
        if result[0] == 255:
            result[0] = 0
        return result

    def check_chariot(self, **kwargs):
        """
        Check chariot status on client(s)
        Args:
            **kwargs:

        Returns: (bool) status

        """
        result = self.strip_stdout_result(self.run_command('ps -ax | grep endpoin', **kwargs))
        status = self.get_stdout(result, skip_exception=True)
        chariot = dict()
        chariot['chariot'] = True if 'endpoint' in status else False
        return [0, chariot.copy(), '']

    def version(self, **kwargs):
        """
        Get client image version
        Args:
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]
        """
        result = self.run_command("uname -r", **kwargs)
        return self.strip_stdout_result(result)

    def get_hostname(self, **kwargs):
        """
        Display hostname of client(s)
        Args:
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        result = self.run_command("hostname", **kwargs)
        return self.strip_stdout_result(result)

    def wifi_connection_info(self, **kwargs):
        """
        Display wifi connection information of client(s): agrCtlRSSI, agrExtRSSI, agrCtlNoise, agrExtNoise, state,
        op mode, lastTxRate, maxRate, lastAssocStatus, 802.11 auth, link auth, BSSID, SSID, MCS, channel

        Args:
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        result = self.run_command(f"{self.tools_path}/airport -I", **kwargs)
        return self.strip_stdout_result(result)

    def get_iface_info(self, **kwargs):
        """
        Display interface information of client(s): {ifname: mac_address}
        Args:
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        output = [1, '', 'No Wi-Fi interfaces']
        response = self.get_stdout(self.run_command('networksetup -listallhardwareports', **kwargs))
        ifaces = response.split('Hardware Port')
        for iface in ifaces:
            if 'Wi-Fi' in iface:
                out = dict()
                ifname = None
                mac = None
                for line in iface.split('\n'):
                    if 'Device' in line:
                        ifname = line[line.find('en'):]
                    if 'Ethernet Address' in line:
                        mac = line[line.find('Address:') + 9:].lower()
                        out[ifname] = {'mac': mac}
                if mac and ifname:
                    output = [0, out, '']
                    break
        return output

    def get_mac(self, ifname="", **kwargs):
        """Get wifi MAC address"""
        ifname = ifname if ifname else self.join_ifaces()
        command = f"ifconfig {ifname} | awk '/ether/{{print $2}}'"

        client_mac = self.strip_stdout_result(self.run_command(command, **kwargs))

        if not client_mac[0] and not getattr(self, f'{ifname}_mac', False):
            setattr(self, f'{ifname}_mac', self.get_stdout(client_mac, skip_exception=True))
        return client_mac

    def get_client_info(self, **kwargs):
        """
        Display client(s) information:
        {"arch": (str), "os": (str), "chariot": (bool), "wifi": (bool), "wlan": (dict), hostname: (str)}
        Args:
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        chariot_status = self.check_chariot(**kwargs)
        wifi_info = self.get_iface_info(**kwargs)
        hostname = self.get_hostname(**kwargs)
        output = [0, {
            "arch": 'x86',
            "os": 'osx',
            "chariot": chariot_status[1],
            "wifi": True,
            "wlan": wifi_info[1],
            "hostname": hostname}, '']
        return output

    def turn_on_wifi(self, ifname='', **kwargs):
        """
        Turn on wifi interface on of client(s)
        Args:
            ifname: (str)
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)
        command = f'networksetup -setairportpower {ifname} on'
        result = self.run_command(command, **kwargs)
        return self.strip_stdout_result(result)

    def turn_off_wifi(self, ifname='', **kwargs):
        """
        Turn on wifi interface on of client(s)
        Args:
            ifname: (str)
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)
        command = f'networksetup -setairportpower {ifname} off'
        result = self.run_command(command, **kwargs)
        return self.strip_stdout_result(result)

    def wifi_scan(self, ifname='', **kwargs):
        """
        Trigger flush scan on the client
        Args:
            ifname: (str)
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)
        command = f"{self.tools_path}/airport {ifname} scan"
        result = self.run_command(command, **kwargs)
        return self.strip_stdout_result(result)

    def wifi_disconnect(self, ifname='', **kwargs):
        """
        Disconnect client(s) from network
        Args:
            ifname: (str)
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)
        command = f"sudo {self.tools_path}/airport {ifname} -z"
        result = self.run_command(command, **kwargs)
        return self.strip_stdout_result(result)

    def connect_to_network(self, ssid, psk, ifname='',
                           ping_ip=None, skip_exception=False, retry=5, **kwargs):
        """
        Connect client(s) to network
        Args:
            ssid: (str)
            psk: (str)
            ifname: (str)
            ping_ip: (str) IP for checking connection
            skip_exception: (bool)
            retry: (int)
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        name = self.device.name

        log.info(f'Connect clients {name} iface:{ifname} to ssid:{ssid}')

        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)

        command = f"sudo networksetup -setairportnetwork {ifname} {ssid} {psk}"

        start_time = time.time()
        response = []
        success = False
        for i in range(retry):
            success = True
            self.wifi_disconnect()
            self.turn_on_wifi()
            response = self.run_command(command, **kwargs)
            ssid_response = self.run_command(f"{self.tools_path}/airport -I | sed -n 's/^ *SSID: //'p")
            connected_ssid = self.get_stdout(self.strip_stdout_result(ssid_response))
            if connected_ssid != ssid:
                success = False
            if success and ping_ip:
                # verify connection by ping
                cmd = f'ping {ping_ip} -c1'
                response = self.run_command(cmd, **kwargs)
                if response[0]:
                    log.info(f"Failed to execute <{name}> {cmd}")
                    log.debug(f"Result: {response[1]}, {response[2]}")
                    success = False
                    break
            if success:
                break
            time.sleep(2)
        if not success:
            if skip_exception:
                return response
            if response[0]:
                log.warning(f'[{name}] Last stderr: \n{response[2]}')
            raise RuntimeError(f'Client {name} unable to associate with {ssid}, '
                               f'on iface {ifname} after {retry} retries')
        log.info(f'Client: {name} connected after {int(time.time() - start_time)}s')
        return response

    def _old_get_file(self, remote_file, location, **kwargs):
        """
        Get file from client(s)
        Args:
            remote_file: (str) path on client
            location: (str) path on local computer
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        file_name = os.path.basename(remote_file)
        command = self.device.get_remote_cmd(f"sudo cat {remote_file} > {location}/{file_name}__{self.device.name}")
        return self.run_command(command, skip_remote=True, **kwargs)

    def put_dir(self, directory, location, **kwargs):
        """
        Put for on client(s)
        Args:
            directory: (str) local path on computer
            location: (str) remote path on client
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        command = f"cd {directory}; tar -cf - *  |" + \
                  self.device.get_remote_cmd(f"sudo mkdir -p {location}; cd {location}; sudo tar -xof -") + \
                  ' 2>/dev/null'
        return self.run_command(command, **kwargs, timeout=5 * 60, skip_remote=True)

    def wifi_monitor(self, channel, ifname='', **kwargs):
        """
        Change client(s) to monitor mode
        Args:
            channel: (int)
            ifname: (str)
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)
        command = f'sudo {self.tools_path}/airport {ifname} -z'
        self.run_command(command, **kwargs)
        command = f'{self.tools_path}/airport --channel {channel}'
        self.run_command(command, **kwargs)
        command = f"{self.tools_path}/airport {ifname} -I | sed -n 's/^ *op mode: //'p"
        return self.strip_stdout_result(self.run_command(command, **kwargs))

    def wifi_station(self, ifname='', **kwargs):
        """
        Change client(s) to station mode
        Args:
            ifname: (str)
            **kwargs:

        Returns: (list) [[(int) ret, (str) stdout, (str) stderr]]

        """
        ifname = ifname if ifname else self.get_wlan_iface(**kwargs)
        self.turn_off_wifi(**kwargs)
        self.turn_on_wifi(**kwargs)
        command = f"{self.tools_path}/airport {ifname} -I | sed -n 's/^ *op mode: //'p"
        return self.strip_stdout_result(self.run_command(command, **kwargs))

    def get_wlan_iface(self, **kwargs):
        """
        Get interfaces from client(s)
        Args:
            **kwargs:

         Returns: (str) iface
        """
        return self.get_iface('Wi-Fi', **kwargs)

    def get_iface(self, hw_port, **kwargs):
        """
        Get interfaces from client(s)
        Args:
            hw_port: (str) Wi-Fi, Ethernet, etc.
            **kwargs:

        Returns: (str) iface

        """
        response = self.get_stdout(self.run_command('networksetup -listallhardwareports', **kwargs))
        ifaces = response.split('Hardware Port')
        for iface in ifaces:
            if hw_port in iface:
                for line in iface.split('\n'):
                    if line.startswith('Device'):
                        ifname = line.replace('Device: ', '')
                        return ifname
        return None

    def get_network_info(self, **kwargs):
        """
        Get network info from client
        Args:
            **kwargs

        Returns: (dict) { (str) : {'iface': (str),
                                   'ipv4':  (str),
                                   'ipv6':  (str),
                                   'mac':   (str)}}

        """
        network_info = {}
        services = self.get_stdout(self.run_command('networksetup -listallnetworkservices | tail -n +2', **kwargs))
        services = services.strip('\n').split('\n')
        for service in services:
            iface = self.get_iface(service)
            service_info = self.get_stdout(self.run_command(f'networksetup -getinfo "{service}"', **kwargs))
            ipv4 = ipv6 = mac = None
            for line in service_info.strip('\n').split('\n'):
                if line.startswith('IP address'):
                    ipv4 = line.replace('IP address: ', '')
                if line.startswith('IPv6 IP address'):
                    ipv6 = line.replace('IPv6 IP address: ', '')
                    if ':' not in ipv6:
                        ipv6 = None
                if line.startswith('Ethernet Address'):
                    mac = line.replace('Ethernet Address: ', '').lower()
                    if ':' not in mac:
                        mac = None
            network_info[service] = {'iface': iface,
                                     'ipv4': ipv4,
                                     'ipv6': ipv6,
                                     'mac': mac}
        return network_info

    def get_network_service_by_ip(self, ip):
        """
        Get hw_port from client(s) by ip
        Args:
            ip: (str)
        Returns: (str) service_name(Hardware Port)

        """
        network_info = self.get_network_info()
        for service, info in network_info.items():
            if ip == info['ipv4']:
                return service
        return False

    def get_wifi_power_management(self, **kwargs):
        """Get wifi client power save state"""
        # TODO: add support
        return [0, 'off', '']
