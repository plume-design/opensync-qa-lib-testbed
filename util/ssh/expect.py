#!/usr/bin/env python3
import random
from lib_testbed.generic.util.ssh.common import EXECUTE_CMD_TIMEOUT


class ExpectHostInfo(object):
    def __init__(self, host, user, port, chained_ssh, expect, sshpass="", opts="", **kwargs):
        self.user = user
        self.host = host
        self.port = f"-p {port}" if port else ""
        self.sshpass = sshpass
        self.opts = opts
        if "timeout" not in expect:
            expect["timeout"] = EXECUTE_CMD_TIMEOUT

        # in case password is required to do SSH
        if self.sshpass:
            # login with password to shell required
            if "shell_passwd" in expect:
                self.expect = (
                    "expect -c 'set timeout %d; spawn ssh -o StrictHostKeyChecking=no"
                    ' -o UserKnownHostsFile=/dev/null %s %s@%s %s; expect "?password" {send "%s\\n"; '
                    'expect "%s" {send "%s\\n"; expect "%s"'
                    ' {send "%s\\n"; expect "%s";'
                    ' send {%s; %s; %s}; send "\\n"; expect "%s"; %s; %s}}}; expect timeout {exit 255}\''
                    % (
                        expect["timeout"],
                        self.opts,
                        self.user,
                        self.host,
                        self.port,
                        self.sshpass,
                        expect["user_prompt"],
                        expect["shell_cmd"],
                        expect["shell_passwd_prompt"],
                        expect["shell_passwd"],
                        expect["shell_prompt"],
                        "%s",
                        "%s",
                        "%s",
                        expect["shell_prompt"],
                        expect["shell_exit"],
                        expect["user_quit"],
                    )
                )
            else:
                # short command to jump into ssh, like sh
                self.expect = (
                    "expect -c 'set timeout %d; spawn ssh -o StrictHostKeyChecking=no"
                    ' -o UserKnownHostsFile=/dev/null %s %s@%s %s; expect "?password" {send "%s\\n"; '
                    'expect "%s" {send "%s\\n"; expect "%s";'
                    ' send {%s; %s; %s}; send "\\n"; expect "%s"; %s; %s}}; expect timeout {exit 255}\''
                    % (
                        expect["timeout"],
                        self.opts,
                        self.user,
                        self.host,
                        self.port,
                        self.sshpass,
                        expect["user_prompt"],
                        expect["shell_cmd"],
                        expect["shell_prompt"],
                        "%s",
                        "%s",
                        "%s",
                        expect["shell_prompt"],
                        expect["shell_exit"],
                        expect["user_quit"],
                    )
                )
        else:
            self.expect = (
                "expect -c 'set timeout %d; spawn ssh -o StrictHostKeyChecking=no"
                ' -o UserKnownHostsFile=/dev/null %s %s@%s %s; expect "%s" {send "%s\\n";'
                ' expect "%s"; send {%s; %s; %s}; send "\\n"; expect "%s"; %s; %s};'
                " expect timeout {exit 255}'"
                % (
                    expect["timeout"],
                    self.opts,
                    self.user,
                    self.host,
                    self.port,
                    expect["user_prompt"],
                    expect["shell_cmd"],
                    expect["shell_prompt"],
                    "%s",
                    "%s",
                    "%s",
                    expect["shell_prompt"],
                    expect["shell_exit"],
                    expect["user_quit"],
                )
            )
        self.chained_ssh = chained_ssh

    def __repr__(self):
        s = self.expect % "<command>"
        if self.chained_ssh is not None:
            s += " via : " + str(self.chained_ssh)
        return s

    @staticmethod
    def generate_end_sign():
        return f"end_sign{random.randint(100, 999)}"

    def command_wrapper(self, command):
        if command:
            end_sign = self.generate_end_sign()
            # need to escape $PATH char, otherwise it uses local PATH
            exp_cmd = self.expect % (f"{end_sign}_", command.replace(r"$", r"\$"), end_sign)  # noqa: W605
        else:
            sshpass = f"sshpass -p {self.sshpass}" if self.sshpass else ""
            exp_cmd = (
                f"{sshpass} ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=quiet"
                f" {self.opts} {self.port} {self.user}@{self.host}"
            )

        # add ssh jump if necessary
        if self.chained_ssh and command:
            exp_cmd = (
                f"ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
                f"{self.chained_ssh.user}@{self.chained_ssh.addr} "
                f"-p{self.chained_ssh.port} sh<<-.\n{exp_cmd}\n."
            )
        elif self.chained_ssh and not command:
            # "pod name ssh" cannot be wrapped with sh since interactive shell is gone
            exp_cmd = (
                f"ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
                f"{self.chained_ssh.user}@{self.chained_ssh.addr} "
                f"-p{self.chained_ssh.port} {exp_cmd}"
            )
        return exp_cmd

    def command_last_hop(self, command):
        if self.chained_ssh:
            command = self.chained_ssh.command_wrapper(command)
        return command

    def get_port(self):
        return self.chained_ssh.port if self.chained_ssh else 22

    def get_address(self):
        return self.chained_ssh.addr if self.chained_ssh else "10.3.1.1"

    @staticmethod
    def parse_expect_output(command, stdout):
        """
        Remove everything which is not part of command answer
        Args:
            command: command which was sent
            stdout: stdout from execute_command

        Returns: updated output

        """
        # first find the end_sign (example 'end_sign123')
        end_sign = command[command.find("end_sign") : command.find("end_sign") + 11]
        # if there is no end_sign probably someone uses expect in his command, so return it
        if not end_sign:
            return None, None
        # analyze line after line
        out = ""
        get_it = False
        stdout = stdout.decode()
        for line in stdout.splitlines():
            if f"{end_sign}_:" in line:
                get_it = True
                continue
            if f"{end_sign}:" in line:
                break
            if get_it:
                out += line + "\n"
        if "No such file or directory" in out:
            ret_code = 127
        else:
            ret_code = 0
        return ret_code, out
