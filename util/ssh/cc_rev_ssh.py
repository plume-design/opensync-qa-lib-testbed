#!/usr/bin/env python3


class CcReverseSshHostInfo(object):
    def __init__(self, dev_id, cmd, chained_ssh, **kwargs):
        self.dev_id = dev_id
        self.cmd = cmd
        self.chained_ssh = chained_ssh

    def __repr__(self):
        s = f'sudo {self.cmd} {self.dev_id} <command>'
        if self.chained_ssh is not None:
            s += ' via : ' + str(self.chained_ssh)
        return s

    def command_wrapper(self, command):
        tmpl = ''
        if self.chained_ssh:
            tmpl = f'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=quiet ' \
                   f'{self.chained_ssh.opts} {self.chained_ssh.user}@{self.chained_ssh.addr} ' \
                   f'-p{self.chained_ssh.port} '
        command = command if command else ''
        # "PATH=$PATH...; pwd" -> need to replace ";" with new line for "<<" script
        # cannot replace all ;, otherwise journalctl is broken
        command = command.replace(';', '/n', 1)
        command = command.replace('"', '\\"')
        if command:
            # the rev_ssh script on bastion does double eval, so $ from PATH modifications does not work.
            # "<<" fixes the problem
            tmpl += f'sudo {self.cmd} {self.dev_id} "<<.\n{command}\n."'
        else:
            tmpl += f'sudo {self.cmd} {self.dev_id}'
        return tmpl

    def command_last_hop(self, command):
        if self.chained_ssh:
            command = self.chained_ssh.command_wrapper(command)
        return command

    def get_port(self):
        return self.chained_ssh.port if self.chained_ssh else 22

    def get_address(self):
        return self.chained_ssh.addr if self.chained_ssh else '10.3.1.1'

    @staticmethod
    def parse_rev_ssh_output(stdout, stderr, **kwargs):
        """
        Remove everything which is not part of command answer
        Args:
            stdout: stdout from execute_command
            stderr: stderr from execute_command

        Returns: updated output

        """
        # remove CC template
        err = stderr.split("evidence of any unauthorized use or access to law enforcement.")
        err = ''.join(err[1:]) if len(err) > 1 else ''
        if err.startswith("\n"):
            err = err[1:]
        if err.endswith("\n"):
            err = err[:-1]

        expect_bytes = kwargs.pop('expect_bytes', False)
        if expect_bytes:
            return CcReverseSshHostInfo.parse_mixed_stdout(stdout, **kwargs), err

        # remove info prints
        start_copy = False
        out = ''
        if not isinstance(stdout, str):
            stdout = stdout.decode()
        for line in stdout.splitlines():
            if "Starting ssh connection for" in line:
                start_copy = True
                continue
            if start_copy:
                out += line + "\n"
        out = out.replace('Connection closed', '')
        if out.startswith("\n"):
            out = out[1:]
        return out, err

    @staticmethod
    def parse_mixed_stdout(stdout, **kwargs):
        # remove info prints from the header
        start_copy = False
        out = b''
        for line in stdout.splitlines():
            try:
                if not start_copy:
                    line = line.decode()
                    if "Starting ssh connection for" in line:
                        start_copy = True
                        continue
            except Exception as e:
                print(f'parsing error: {e}')
            if start_copy:
                out += line + b"\n"
        return out[:-1]
