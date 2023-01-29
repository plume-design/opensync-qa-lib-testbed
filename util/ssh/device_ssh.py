from lib_testbed.generic.util.ssh.screen.screen import ScreenHostInfo
from lib_testbed.generic.util.ssh import parallelssh
from lib_testbed.generic.util.ssh import expect
from lib_testbed.generic.util.ssh.cc_rev_ssh import CcReverseSshHostInfo
from lib_testbed.generic.util.config import FIXED_HOST_CLIENTS

SSH_GATEWAY = 'ssh_gateway'


class DeviceSsh:
    def __init__(self, dev_type, name, config):
        self.type = dev_type
        self.name = name
        self.config = config

    def _parse_host_info(self, host_info=None):
        chained_ssh = None
        netns = None
        sshpass = None
        user = parallelssh.DEFAULT_SSH_USER
        port = parallelssh.DEFAULT_SSH_PORT
        if not host_info:
            host_info_tmp = {}
        else:
            host_info_tmp = host_info
        if self.config.get(SSH_GATEWAY):
            gateway_host = self.config[SSH_GATEWAY]['hostname']
            gateway_user = self.config[SSH_GATEWAY].get('user', 'plume')
            gateway_pass = self.config[SSH_GATEWAY].get('pass')
            gateway_port = self.config[SSH_GATEWAY].get('port', 22)
            gateway_opts = self.config[SSH_GATEWAY].get('opts', [])
            opts_str = ''
            for option in gateway_opts:
                opts_str += f' -o {option}={gateway_opts[option]}'
                # force to use only this file
                if option == 'IdentityFile':
                    opts_str += f' -o IdentitiesOnly=yes'
            if self.name in FIXED_HOST_CLIENTS:
                return parallelssh.SSHHostInfo(
                    gateway_host, gateway_user, gateway_port, chained_ssh, netns=self.config.get('netns'),
                    sshpass=gateway_pass, name=self.name, opts=opts_str)
            chained_ssh = parallelssh.SSHHostInfo(gateway_host, gateway_user, gateway_port, sshpass=gateway_pass,
                                                  opts=opts_str)
        if "proxy" in self.config:
            proxy_host, proxy_user, proxy_port = self._extract_host_info(self.config['proxy'])
            chained_ssh = parallelssh.SSHHostInfo(proxy_host, proxy_user, proxy_port)

        if not host_info_tmp:
            if self.config.get("host"):
                host_info_tmp["host"] = self.config["host"]
            elif self.config.get("screen"):
                host_info_tmp["screen"] = self.config["screen"]
            # Backward compatibility
            else:
                host_info_tmp["host"] = self.name
        # host_info_tmp has just one element, so we can relay on 0 element
        host_info_key = list(host_info_tmp.keys())[0]
        host_info_value = host_info_tmp[host_info_key]
        if not host_info_value:
            if self.config.get('host'):
                host_info_value = self.config['host'].get(host_info_key)
        if not host_info_value:
            host_info_value = self.config.get(host_info_key)
        if not host_info_value:
            raise Exception(f"No value resolved for host: '{host_info_key}'. "
                            f"Check '{self.type}' configuration in testbed file")
        if "screen" in host_info_key:
            host = host_info_value
            if "screen_proxy" in self.config:
                proxy_host, proxy_user, proxy_port = self._extract_host_info(self.config['screen_proxy'])
                chained_ssh = parallelssh.SSHHostInfo(proxy_host, proxy_user, proxy_port)
        else:
            user = host_info_value.get('user')
            host = host_info_value.get('name')
            port = host_info_value.get('port', 22)

        # % means that it's ipv6 address, so we need to add brackets
        if host and '%' in host:
            host = '[' + host + ']'

        if "screen" in host_info_key:
            return ScreenHostInfo(host, user, port, chained_ssh, netns, sshpass)
        elif "cc_rev_ssh" in host_info_value:
            return CcReverseSshHostInfo(self.config['id'], host_info_value['cc_rev_ssh'], chained_ssh)
        else:
            sshpass = host_info_value.get('pass', None)
            netns = host_info_value.get('netns', None)
            opts = host_info_value.get('opts', [])
            opts_str = ''
            for option in opts:
                opts_str += f' -o {option}={opts[option]}'
            if host_info_value.get('expect'):
                return expect.ExpectHostInfo(
                    host, user, port, chained_ssh, host_info_value.get('expect'), sshpass, opts=opts_str)
            return parallelssh.SSHHostInfo(host, user, port, chained_ssh, netns, sshpass, name=self.name, opts=opts_str)

    def get_remote_cmd(self, command, skip_ns=False):
        # here different wrappers can be added to command, like ssh, chained ssh, uart, expect
        host_info = self._parse_host_info()
        if skip_ns and getattr(host_info, 'netns', None):
            host_info.netns = ''
        return host_info.command_wrapper(command)

    def get_last_hop_cmd(self, command):
        host_info = self._parse_host_info()
        return host_info.command_last_hop(command)

    def is_client_serial(self):
        host_info = self._parse_host_info()
        return isinstance(host_info, parallelssh.SerialHostInfo)

    def get_port(self):
        host_info = self._parse_host_info()
        return host_info.get_port()

    def get_ip(self):
        host_info = self._parse_host_info()
        return host_info.get_address()

    def scp_cmd(self, *args):
        host_info = self._parse_host_info()
        host_addr = host_info.addr
        if "%" in host_addr:
            # Add additional square brackets for ipv6 address. It's required by scp.
            host_addr = r"\[{}\]".format(host_addr)
        mod_args = []
        for arg in args:
            if '{DEST}' in arg:
                arg = arg.replace('{DEST}', '{}@{}').format(host_info.user, host_addr)
            mod_args.append(arg)
        return host_info.command_scp_wrapper(" ".join(mod_args))

    @staticmethod
    def _extract_host_info(host):
        port = parallelssh.DEFAULT_SSH_PORT
        user = parallelssh.DEFAULT_SSH_USER
        if host.find(":") >= 0 and '%' not in host:
            host, port = host.split(':')
        if host.find('@') >= 0:
            user, host = host.split('@')

        # % means that it's ipv6 address, so add brackets
        if '%' in host:
            host = '[' + host + ']'
        return host, user, port

    @staticmethod
    def get_local_cmd(device, command):
        if isinstance(command, list) or isinstance(command, tuple):
            return " ".join(command).format(device)
        return command.format(device)
