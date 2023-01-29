import sys
import logging
import time
from lib_testbed.generic.util.ssh.sshexception import SshException
from lib_testbed.generic.util.ssh import parallelssh
from lib_testbed.generic.util.ssh.device_discovery import DeviceDiscovery
from lib_testbed.generic.util.ssh.device_log_catcher import DeviceLogCatcher
from lib_testbed.generic.util.logger import log


MOCK_RESPONSES_LOGS = True


class SshExecute:
    def __init__(self, device_type, config, **kwargs):
        self.config = config
        self.multi_devices = kwargs.pop('multi_obj', None)
        self.role_prefix = kwargs.pop('role_prefix', '')
        self.device_type = device_type
        self.ext_path = None
        dev = kwargs.get('dev')
        if dev:
            del kwargs['dev']
        self.name = dev.name
        self.device = dev.device
        self.last_cmd = {}
        self.skip_ns = False
        self.log_catcher = DeviceLogCatcher(
            default_name=f"log_{self.get_type_name()}_{self.get_name()}", obj=self)

    def get_nickname(self):
        return self.name

    def get_name(self):
        role = f"{self.role_prefix}_" if self.role_prefix else ''
        prefix = f'multi_{role}' if self.multi_devices else ''
        return prefix + self.name

    def get_type_name(self):
        return 'client' if self.device_type == "Clients" else 'pod'

    def free_device(self):
        for device_config in self.config[self.device_type]:
            if self.get_nickname() != device_config['name']:
                continue
            if device_config.get('busy'):
                device_config['busy'] = False
            if device_config.get('multi_busy'):
                device_config['multi_busy'] = False
            if device_config.get('main_object'):
                device_config['main_object'] = False

    def is_device_busy(self):
        busy = False
        for device_config in self.config[self.device_type]:
            if self.get_nickname() != device_config['name']:
                continue
            if not self.multi_devices and device_config.get('busy'):
                busy = True
                break
            elif device_config.get('multi_busy'):
                busy = True
                break
        return busy

    def run_command(self, command, *args, **kwargs):
        """Run ssh command on device
        :return: list of [ret_value, stdout, stderr]"""
        skip_remote = kwargs.get('skip_remote')
        if self.ext_path and not skip_remote:
            command = f"PATH=$PATH:{self.ext_path}; {command}"
        return self.execute(command, *args, **kwargs)

    @staticmethod
    def merge_result(old_result, new_result):
        merged_result = [0, "", ""]
        # Merge ret value
        merged_result[0] = old_result[0] + new_result[0]
        # Merge stdout
        merged_result[1] = old_result[1]
        if merged_result[1] and new_result[1]:
            merged_result[1] += "\n"
        merged_result[1] += new_result[1]
        # Merge stderr
        merged_result[2] = old_result[2]
        if merged_result[2] and new_result[2]:
            merged_result[2] += "\n"
        merged_result[2] += new_result[2]
        return merged_result

    @staticmethod
    def _get_stdout(result, cmd, name, skip_exception):
        __tracebackhide__ = True
        assert len(result) == 3
        ret = result[0]
        stdout = result[1]
        stderr = result[2]
        try:
            ret_value = int(ret)
        except TypeError:
            ret_value = None
        if not isinstance(stdout, (dict, str, list)):
            stdout = ""
        if not isinstance(stderr, str):
            stderr = ""
        if ret_value != 0 and not skip_exception or 'mux_client_request_session: session request failed' in stderr:
            raise SshException(cmd=cmd,
                               name=name,
                               ret=ret_value,
                               stdout=stdout,
                               stderr=stderr)
        return stdout

    def get_stdout(self, result, skip_exception=False, **kwargs):
        __tracebackhide__ = True
        command = self.last_cmd['command']
        name = self.last_cmd['name']
        return self._get_stdout(result, command, name, skip_exception)

    def strip_stdout_result(self, result):
        stdout = result[1]
        if stdout:
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", 'backslashreplace')
            stdout = stdout.strip('\n').strip()
            result[1] = stdout
        return result

    def ssh(self, params="", **_kwargs):
        """SSH to client"""
        device = self.device
        skip_ns = _kwargs.pop('skip_ns', False)
        cmd = device.get_remote_cmd(params, skip_ns=skip_ns)
        # Add parameter for interactive session
        ssh_prefix = "ssh "
        pos = cmd.find(ssh_prefix)
        if pos != -1:
            cmd = "{}{}-tt {}".format(cmd[0:pos], ssh_prefix, cmd[pos + len(ssh_prefix):])
        if 'netns exec' in cmd:
            # Execute bash command
            netns_name = cmd.split('netns exec')[1].split()[0]
            netns_name_end = cmd.rfind(netns_name) + len(netns_name)
            cmd = "{} bash {}".format(cmd[0:netns_name_end], cmd[netns_name_end:])

        if 'sshpass' in device.config and 'sshpass' not in cmd:
            cmd = f'sshpass -p {device.config["sshpass"]} ' + cmd

        p = parallelssh.Popen(cmd,
                              stdin=sys.stdin,
                              stdout=sys.stdout,
                              stderr=sys.stdout,
                              close_fds=True,
                              shell=True)
        sys.stdout, sys.stderr = p.communicate()
        return {device.name: (p.returncode, "", "")}

    @staticmethod
    def execute_cmd(commands, timeout=30, **kwargs):
        return parallelssh.execute_commands(commands, timeout, **kwargs)

    def execute(self, command, *args, **kwargs):
        """Run different commands on many devices
        :return: list of [ret_value, stdout, stderr]"""
        assert command
        if not isinstance(command, str):
            raise Exception(f"Unexpected command type: {type(command)}, expecting: string")
        if not self.device:
            raise SshException(cmd=command,
                               name='unknown',
                               ret=1,
                               stdout='',
                               stderr='Device not created')
        self.last_cmd = {'command': command, 'name': self.device.name}
        skip_remote = kwargs.pop("skip_remote", False)
        skip_logging = kwargs.get('skip_logging', False)
        if isinstance(kwargs.get('skip_ns'), bool):
            skip_ns = kwargs.pop('skip_ns', False)
        else:
            skip_ns = self.skip_ns
        new_kwargs = kwargs.copy()
        skip_exception = kwargs.get("skip_exception")
        if skip_exception is not None:
            del new_kwargs["skip_exception"]
        remote_command_dict = {}
        if args:
            command = "{} {}".format(command, " ".join(args))
        if skip_remote:
            remote_command = command
        else:
            remote_command = self.device.get_remote_cmd(command=command, skip_ns=skip_ns)
        remote_command_dict.update({self.device.name: remote_command})

        start_time = time.time()
        result_dict = self.execute_cmd(remote_command_dict, **new_kwargs)
        result = result_dict[self.device.name]
        if result[0] == 255 and not result[1] and not result[2]:
            remote_command_dict[self.device.name] = remote_command_dict[self.device.name].replace(' -o LogLevel=quiet',
                                                                                                  '')
            result_dict = self.execute_cmd(remote_command_dict, **new_kwargs)
        if not skip_logging:
            self.log_catcher.add(command, remote_command_dict, result_dict, self.device, start_time)
            if log.isEnabledFor(logging.DEBUG):
                self.log_catcher.add_mock(command, result_dict, self.device.name)
        return result_dict[self.device.name]

    def result_ok(self, result):
        if result[0]:
            return False
        return True

    def set_skip_ns_flag(self, status):
        self.skip_ns = status


class SshCmd(SshExecute):
    """Common ssh commands methods for client and pod"""

    def scp(self, *args, **kwargs):
        """SCP: "{DEST}" replaced with root@device"""
        command = self.device.scp_cmd(*args)
        return self.run_command(command, **kwargs, timeout=5 * 60, skip_remote=True)

    def wait_available(self, timeout=5, **kwargs):
        """Wait for device(s) to become available"""
        kwargs.pop('skip_logging', True)
        _timeout = time.time() + timeout
        result = [1, '', 'Check not started']
        while time.time() < _timeout:
            time_left = _timeout - time.time()
            command = self.device.get_remote_cmd('ls').replace('-o', f'-o ConnectTimeout={int(time_left)} -o', 1)
            result = self.run_command(command, timeout=time_left, skip_remote=True, skip_logging=True, **kwargs)
            if result[0] == 0:
                result[1] = "Ready"
                break
        if result[0]:
            result[2] = f"SSH not available after {timeout} sec"
        return result

    def put_file(self, file_name, location, timeout=10 * 60, **kwargs):
        """Copy a file onto device(s)"""
        command = self.device.scp_cmd(file_name, f"{{DEST}}:{location}")
        return self.run_command(command, **kwargs, timeout=timeout, skip_remote=True)
