#!/usr/bin/env python3

import random


CHAR_DELAY = ".015"  # delay every character by 0.015 sec


class ScreenHostInfo(object):
    def __init__(self, host, user, port, chained_ssh, *args, **kwargs):
        self.screen = host.split("::")[0]
        self.prompt = host.split("::")[1] if "::" in host else None
        self.chained_ssh = chained_ssh

    def __repr__(self):
        s = f"expect -c 'spawn screen -dRR -r {self.screen} ; send <command>; expect #;'"
        if self.chained_ssh is not None:
            s += 'via : ' + str(self.chained_ssh)
        return s

    def command_wrapper(self, command, timeout=20, expect=None, end_sign=True, stuff=False):
        tmpl = ''
        if self.chained_ssh:
            tmpl = 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=quiet ' \
                   f'{self.chained_ssh.user}@{self.chained_ssh.addr} -p{self.chained_ssh.port} -t '
        if command:
            if end_sign:
                command, expect = self.add_end_sign(command)

            cmd = self.prepare_command(command)
            slow = "-s " if "^M" not in cmd else ""
            send_cmd = "send {}\\\"{}\\\";".format(slow, cmd)
        else:
            send_cmd = ""
        if expect:
            expect_cmd = "expect \\\"{}\\\";".format(expect)
        else:
            expect_cmd = ""
        if not stuff and "^M" not in command:
            if 1:
                detach = "-r"
            else:
                detach = "-d"
            screen_cmd = f"sudo expect -c 'spawn screen -x {detach} {self.screen} ; " \
                         f"set timeout {timeout} ; set send_slow {{1 {CHAR_DELAY}}} ; {send_cmd} {expect_cmd}'"
        else:
            # Some terminals e.g. bootloader shell doesn't accept \r
            screen_cmd = f"sudo screen -S {self.screen} -X stuff {command}"

        tmpl += f"\"export TERM=xterm; {screen_cmd}\""
        return tmpl

    def add_end_sign(self, cmd):
        end_cmd = 'end_sign{}'.format(random.randint(100, 999))
        fake_command_begin = f'\r{end_cmd}_\r'
        fake_command_end = f'\r{end_cmd}\r'
        expect = end_cmd + ":"
        cmd = cmd.strip("\r")
        cmd = cmd.strip("\n")
        cmd = f"{fake_command_begin}{cmd}{fake_command_end}"
        return cmd, expect

    def prepare_command(self, command):
        if '/etc/init.d/manager' in command:
            return command.replace('/etc/init.d/manager', '/etc/init.d/managers')
        elif 'ovsdb-client dump' in command:
            return command.replace('ovsdb-client dump', 'LD_LIBRARY_PATH=/usr/plume/lib; ovsdb-client dump unix:/var/run/db.sock')
        elif 'lm_logs_collector' in command:
            return command.replace('bin/lm_logs_collector.sh', 'tools/lm_log_pull.sh')
        else:
            return command

    def command_last_hop(self, command):
        if self.chained_ssh:
            command = self.chained_ssh.command_wrapper(command)
        return command

    def get_port(self):
        return self.chained_ssh.port if self.chained_ssh else 22

    def get_address(self):
        return self.chained_ssh.addr if self.chained_ssh else '10.3.1.1'


def parse_screen_output(cmd, stdout):
    expect = ""
    end_sign = ""
    expect_list = cmd.split('expect')
    if len(expect_list) > 1:
        expect = cmd.split('expect')[-1]
        if "end_sign" in cmd:
            end_sign = expect[3:(expect.rfind('\\"') - 1)]
        expect = expect[3:]
        expect = expect[:expect.find('\\"') - 1]
    if expect not in stdout:
        expect = None
    stdout_new = ''

    # stdout_tmp = "\n".join(stdout.splitlines()[2:])
    # Remove white space at the end
    stdout_tmp = "\n".join([line.rstrip() for line in stdout.splitlines()])

    if end_sign and len(stdout_tmp.split(end_sign)) < 3:
        stdout_lines = []
        stdout_join = "".join(stdout_tmp.splitlines())
        end_sign_start = stdout_join.find(end_sign)
        end_sign_end = end_sign_start + len(end_sign)
        if len(stdout_join.split(end_sign)) == 3:
            i = 0
            line_to_merge = ""
            for line in stdout_tmp.splitlines():
                if line.endswith("end_sign"):
                    pass
                end_pos = i + len(line)
                if end_pos < end_sign_start or end_sign_end <= end_pos:
                    i += len(line)
                else:
                    line_to_merge = line
                    continue
                stdout_lines.append(line_to_merge + line)
                line_to_merge = ""
    else:
        stdout_lines = stdout_tmp.splitlines()

    if stdout_lines and expect and expect not in stdout_lines[-1]:
        # Remove truncated last line
        stdout_lines = stdout_lines[:-1]
    stdout_tmp = "\n".join(stdout_lines)

    if expect and not end_sign:
        stdout_tmp = expect.join(stdout_tmp.split(expect)[-2:])
    elif end_sign:
        stdout_tmp = "\n".join("".join(stdout_tmp.split(end_sign)[-2:-1]).splitlines()[1:-1])
    for line in stdout_tmp.splitlines():
        if 'sc nodebug 0' in line or line.startswith('#'):
            continue
        if expect and expect in line and expect.rstrip()[-1] in [">", "#"]:
            break
        stdout_new += ''.join(s for s in line if 31 < ord(s) < 126)
        stdout_new += '\n'
        if expect and expect in line:
            break
    ret_code = 0
    return ret_code, stdout_new
