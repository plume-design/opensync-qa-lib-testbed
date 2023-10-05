import os
import io
import errno
import shlex
import stat
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired
import threading
import psutil
from subprocess import getoutput as getout
from pipes import quote
import sys
import select

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.ssh.screen.screen import parse_screen_output
from lib_testbed.generic.util.ssh.expect import ExpectHostInfo
from lib_testbed.generic.util.ssh.cc_rev_ssh import CcReverseSshHostInfo
from lib_testbed.generic.util.ssh.common import EXECUTE_CMD_TIMEOUT
from lib_testbed.generic.util.common import BASE_DIR

DEFAULT_SSH_PORT = 22
DEFAULT_SSH_USER = "root"

DISABLE_SSH_MUX = False


class HostInfo:
    def __repr__(self):
        return "Not implemented"

    def command_wrapper(self, command):
        return None


class SSHHostInfo(HostInfo):
    def __init__(
        self,
        address,
        user=DEFAULT_SSH_USER,
        port=DEFAULT_SSH_PORT,
        chained_host_info=None,
        netns=None,
        sshpass=None,
        name=None,
        opts="",
    ):
        assert address
        self.addr = address
        self.user = user
        self.port = port
        self.chained = False
        self.chained_host_info = chained_host_info
        if chained_host_info:
            self.chained_host_info.chained = True
        self.netns = netns
        self.sshpass = sshpass
        self.name = name
        self.opts = opts
        if not self.name:
            self.name = str(threading.current_thread().ident)

    def __repr__(self):
        s = f"{self.user}@{self.addr}:{self.port}"
        if self.chained_host_info:
            s += f" via {str(self.chained_host_info)}"
        return s

    def get_proxy_command(self, stdio_forward):
        proxy = ""
        if self.chained_host_info:
            for ip in _get_self_ips():
                if ip.strip() == self.chained_host_info.addr:
                    return proxy
            proxy_str = self.chained_host_info.command_wrapper("", stdio_forward)
            proxy = (
                " -o StrictHostKeyChecking=no"
                " -o UserKnownHostsFile=/dev/null"
                " -o ForwardAgent=yes"
                " -o HostKeyAlgorithms=ssh-dss,ssh-rsa,ssh-ed25519"
                f" -o ProxyCommand='{proxy_str}'"
            )
        return proxy

    def get_short_addr(self, length=20):
        if length <= 0:
            return ""
        addr = self.addr.replace(":", "").replace("[", "").replace("]", "").split("%")[0]
        if len(addr) > length:
            addr = addr[-length:]
        return addr

    def get_multiplex_command(self):
        """Create dynamic control path"""
        proxy = ""
        if self.chained_host_info:
            proxy = str(self.chained_host_info).split(":")[0]
            if "@" in proxy:
                proxy = proxy.split("@")[1]
        prefix = "/tmp/.mux"
        max_addr_length = 90 - (len(prefix) + 1 + len(self.name) + 1 + 1 + len(proxy))
        multiplex_cmd = f" -o ControlPath={prefix}_{self.name}_{self.get_short_addr(max_addr_length)}_{proxy}"
        if max_addr_length < 0:
            raise Exception(f"Control path too long: {multiplex_cmd}")
        return multiplex_cmd

    def replace_ssh_config(self):
        """Include ssh config file to set up multiplexing
        Options included in config file: ControlMaster, ControlPath and ControlPersist
        """
        ssh_bin_path = f"/tmp/ssh_config/{self.name}_{self.get_short_addr()}"
        if not os.path.exists(ssh_bin_path):
            try:
                os.makedirs(ssh_bin_path)
            except OSError as e:
                # OK if path is already created
                if e.errno != errno.EEXIST:
                    raise
        # TODO: remove bin_ssh_path after command is executed
        config_ssh = os.path.join(BASE_DIR, "lib_testbed", "generic", "util", "ssh", "config", "config")
        ssh_bin = os.path.join(ssh_bin_path, "ssh")
        ssh_bin_body = f'/usr/bin/ssh -F {config_ssh} "$@"'
        # check first if the file has proper content, updating it over and over does not make sense
        update = True
        try:
            with open(ssh_bin, "r") as f:
                update = True if ssh_bin_body not in f.read() else False
        except FileNotFoundError:
            pass

        if update:
            with open(ssh_bin, "w") as f:
                f.write(ssh_bin_body)
            st = os.stat(ssh_bin)
            os.chmod(ssh_bin, st.st_mode | stat.S_IEXEC)
        if sys.platform == "darwin":
            # Darwin has no support for timeout command, add timeout bash script to the path
            timeout_sh = os.path.join(ssh_bin_path, "timeout")
            with open(timeout_sh, "w") as f:
                f.write("perl -e 'alarm shift; exec @ARGV' \"$@\";".format(config_ssh))
            st = os.stat(timeout_sh)
            os.chmod(timeout_sh, st.st_mode | stat.S_IEXEC)
        path = f'PATH="{ssh_bin_path}:$PATH"'
        path = f"({path} && "
        return path

    def get_ssh_options(self, stdio_forward, forward_agent):
        options = {}
        if self.port != DEFAULT_SSH_PORT:
            options["port"] = f" -p{self.port}"
        else:
            options["port"] = ""

        if stdio_forward:
            options["stdio_forward"] = " -W %h:%p"
        else:
            options["stdio_forward"] = ""

        if self.sshpass:
            options["sshpass"] = f"sshpass -p {shlex.quote(self.sshpass)} "
        else:
            options["sshpass"] = ""

        options["multiplex"] = " -o ControlMaster=no"
        if not self.chained:
            if not DISABLE_SSH_MUX and self.name not in ["host"]:
                # TODO: Resolve problem for host with mux (controlpath is used from config/ssh/config)
                options["multiplex"] = self.get_multiplex_command()
            options["path"] = self.replace_ssh_config()
        else:
            options["path"] = ""

        if forward_agent:
            options["forward_agent"] = " -A"
        else:
            options["forward_agent"] = ""

        # Old OpenSsh doesn't support '+' sign
        options["keys"] = (
            " -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
            " -o HostKeyAlgorithms=ssh-dss,ssh-rsa,ssh-ed25519 -o KexAlgorithms=+diffie-hellman-group1-sha1"
            " -o PubkeyAcceptedKeyTypes=+ssh-rsa"
        )

        options["quiet"] = " -o LogLevel=quiet"
        options["extra_opts"] = self.opts

        return options

    def command_wrapper(self, command, stdio_forward=False):
        if command:
            command = quote(command)
        if self.netns:
            command = f"sudo ip netns exec {self.netns} {command}"
        proxy_command = self.get_proxy_command(stdio_forward=True)
        options = self.get_ssh_options(stdio_forward, forward_agent=True)

        new_cmd = (
            f"{options['path']}{options['sshpass']}ssh "
            f"{options['port']}"
            f"{options['keys']}"
            f"{options['multiplex']}"
            f"{proxy_command}"
            f"{options['stdio_forward']}"
            f"{options['quiet']}"
            f"{options['forward_agent']}"
            f"{options['extra_opts']} "
            f"{self.user}@{self.addr} "
            f"{command}{')' if options['path'] else ''}"
        )
        return new_cmd

    def command_scp_wrapper(self, command):
        if len(command.split()) < 2:
            raise Exception(f"Unexpected scp command parameters: {command}")
        proxy_command = self.get_proxy_command(stdio_forward=True)
        # Remove " -o ForwardAgent=yes"
        options = self.get_ssh_options(stdio_forward=False, forward_agent=False)

        new_cmd = (
            f"{options['path']}{options['sshpass']}scp -r "
            f"{options['port'].replace('p', 'P')}"
            f"{options['keys']}"
            f"{options['multiplex']}"
            f"{proxy_command}"
            f"{options['stdio_forward']}"
            f"{options['quiet']}"
            f"{options['extra_opts']} {command}"
            f"{')' if options['path'] else ''}"
        )
        return new_cmd

    def command_last_hop(self, command):
        if self.chained_host_info:
            command = self.chained_host_info.command_wrapper(command)
        return command

    def get_port(self):
        return self.port

    def get_address(self):
        return self.addr


class SerialHostInfo(HostInfo):
    def __init__(self, device):
        self.device = device


def execute_command(dev_name, cmd, stdin, timeout, **kwargs):  # noqa:C901
    def kill(proc_pid):
        process = psutil.Process(proc_pid)
        for proc in process.children(recursive=True):
            try:
                proc.kill()
            except (psutil.NoSuchProcess, AttributeError):
                pass
        try:
            process.kill()
        except (psutil.NoSuchProcess, AttributeError):
            pass

    thread_id = threading.current_thread().ident
    # make sure directory exists
    os.makedirs("/tmp/automation", exist_ok=True)
    file_name = f"/tmp/automation/stderr_{thread_id}"
    stderr = None
    combine_std = skip_logging = False
    if kwargs:
        skip_logging = kwargs.get("skip_logging", False)
        combine_std = kwargs.get("combine_std", False)

    # Ssh with multiplexing enabled doesn't work with PIPE for the first attempt because ssh keeps opened stderr
    # stream. This issue is solved by redirecting stderr to file
    with open(file_name, "w") as stderr_fh:
        std_err_out = stderr_fh if not combine_std else STDOUT
        proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=std_err_out, close_fds=True, shell=True)
        try:
            stdout, _stderr = proc.communicate(input=stdin, timeout=timeout)
        except TimeoutExpired:
            output = error = None
            try:
                kill(proc.pid)
                try:
                    output, error = proc.communicate(input=stdin)
                    output = None if not output else output
                    if output:
                        output = str(output, "UTF-8")
                    error = None if not error else error
                    if error:
                        error = str(error, "UTF-8")
                except Exception:
                    log.exception("Command timed out. Failed to retrieve buffered data")
            except Exception:
                log.exception("Failed to kill process")
            stdout = ""
            stderr = (
                f"[{dev_name}] Command forced to be terminated after {timeout}s.\n"
                f"cmd: `{cmd}`\n"
                f"std_out: `{output}`\n"
                f"std_err: `{error}`"
            )
            if not skip_logging:
                log.error(stderr)
    if not stderr:
        with open(file_name, "r") as stderr_fh:
            stderr = stderr_fh.read()
    try:
        os.remove(file_name)
    except OSError:
        pass
    if "screen" in cmd:
        retval, stdout = parse_screen_output(cmd, stdout.decode())
    elif "expect" in cmd:
        retval, tstdout = ExpectHostInfo.parse_expect_output(cmd, stdout)
        return (retval, tstdout, stderr) if retval else (proc.returncode, stdout, stderr)
    elif "revstbssh" in cmd:
        stdout, stderr = CcReverseSshHostInfo.parse_rev_ssh_output(stdout, stderr, **kwargs)
        retval = proc.returncode
    else:
        retval = proc.returncode
    return retval, stdout, stderr


def merge_results(old_results, new_results):
    for k, v in new_results.items():
        if k in old_results:
            old_results[k][0] = v[0]
            old_results[k][1] += v[1]
            old_results[k][2] += v[2]
        else:
            old_results[k] = v
    return old_results


def select_items(return_values, sel_fcn=lambda y: y[0] == 0):
    return [node for node, value in list(return_values.items()) if sel_fcn(value)]


# TODO: remove
def get_success_names(return_values, names):
    success_names = []
    for i, value in enumerate(return_values):
        if value[0] == 0:
            success_names.append(names[i])
    return success_names


def execute_commands(command_dict, timeout=EXECUTE_CMD_TIMEOUT, **kwargs):
    results = {}
    stdin = None
    assert len(command_dict) == 1
    try:
        stdin_select = select.select([sys.stdin], [], [], 0)[0]
    except io.UnsupportedOperation:
        stdin_select = []
    if sys.stdin in stdin_select and not sys.stdin.isatty():
        stdin = sys.stdin.readlines()
        stdin = "".join(stdin)
    for node, command in command_dict.items():
        retval, stdout, stderr = execute_command(dev_name=node, cmd=command, stdin=stdin, timeout=timeout, **kwargs)
        retval = retval.decode() if type(retval) is bytes else retval
        if type(stdout) is bytes:
            try:
                stdout = stdout.decode()
            except UnicodeDecodeError:
                pass
        stderr = stderr.decode() if type(stderr) is bytes else stderr
        if "sshpass: not found" in stderr:
            log.error(stderr)
        results[node] = [retval, stdout, stderr]
    return results


def check_return_errors(return_dict):
    for node, item in return_dict.items():
        if item[0] != 0:
            return False
    return True


def _get_self_ips():
    out = getout("ip addr list | grep -P 'inet\\b' | awk '{print $2}' | cut -d '/' -f1 | sort | uniq").split("\n")
    ips = [line.strip().strip(" ").strip("\n") for line in out]
    return ips
