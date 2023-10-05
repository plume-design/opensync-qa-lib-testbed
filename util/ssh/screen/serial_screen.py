#!/usr/bin/env python3

import os
import logging
import time
import random
import hashlib
from lib_testbed.generic.util.ssh.parallelssh import execute_commands
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.ssh.screen.screen import ScreenHostInfo
from lib_testbed.generic.util.ssh.device_log_catcher import DeviceLogCatcher

NEXT_COMAND_DELAY = 1.2  # sec
EXCEPT_WAIT_FOR_TIEOUT = "__wait_for_timeout__"  # unexpected string in screen buffer
SCREEN_CMD_DELAY = NEXT_COMAND_DELAY + 2  # sec. Max time needed to handle screen send command.

REBOOT_TIMEOUT = 60 * 2
RUN_TIME = 60 * 6


class SerialScreen(object):
    def __init__(self, pod, screen_name=None, screen_value=None, prompt=None, fake_cmd=False):
        self.pod = pod
        self.screen = {screen_name: screen_value}
        self.fake_cmd = fake_cmd

        self.device_type = "client"
        self.multi_devices = False
        self.log_catcher = DeviceLogCatcher(default_name=f"log_{self.get_name()}", obj=self)
        if not screen_name:
            screen_name = "screen"
        if not screen_value:
            screen_value = self.get_config_screen_value(screen_name)
        if not screen_value:
            raise Exception(f"Missing '{screen_name}' in config file")
        self.screen = {screen_name: screen_value}
        log.info(f"Resolved serial screen: {self.screen}")
        if not prompt:
            self.prompt = self.get_config_prompt(screen_name)
        self.last_time = time.time()
        self.utils = ScreenUtils(self)
        self.reset()

    def get_name(self):
        return list(self.screen.keys())[0] + ("_raw" if not self.fake_cmd else "")

    def _cmd(self, cmd, screen, expect=None, timeout=5, skip_delay=False, **kwargs):
        cmd_orig = cmd
        if expect:
            expect_str = expect
        else:
            if self.fake_cmd:
                end_cmd = "end_sign{}".format(random.randint(100, 999))
                fake_command_begin = f"\r{end_cmd}_\r"
                fake_command_end = f"; {end_cmd}\r"
                expect_str = end_cmd + ":"
                cmd = cmd.strip("\r")
                cmd = cmd.strip("\n")
                cmd = f"{fake_command_begin}{cmd}{fake_command_end}"
            elif self.prompt:
                expect_str = self.prompt
            else:
                expect_str = EXCEPT_WAIT_FOR_TIEOUT
        delay_time = NEXT_COMAND_DELAY - (time.time() - self.last_time)
        if delay_time > 0 and not skip_delay:
            # log.debug("Delay command: {} for {:.2f} sec".format(
            #     cmd.replace("\r", "\\r").replace("\n", "\\n"), delay_time))
            time.sleep(delay_time)
        result = self.node_run(cmd, screen_info=screen, expect=expect_str, timeout=timeout, **kwargs)
        self.last_time = time.time()
        pod_name = self.pod.get_name()
        if log.isEnabledFor(logging.DEBUG):
            self.log_catcher.add_mock(cmd_orig, result, pod_name)
        if result[pod_name][0]:
            raise Exception(
                "Failed to execute command: '{}' for screen: {}\n{}".format(
                    cmd.replace("\r", "\\r").replace("\n", "\\n"), screen, result[pod_name][2]
                )
            )
        out = result[pod_name][1]
        if expect and expect not in out:
            out_str = out.replace("\r", "\\r").replace("\n", "\\n")
            cmd_str = cmd.replace("\r", "\\r").replace("\n", "\\n")
            raise Exception(f"Invalid output for command: '{cmd_str}'\nexpect: '{expect}', out: '{out_str}'")
        return result[pod_name][1]

    def cmd(self, cmd, expect=None, *args, **kwargs):
        cmd = cmd + "\r"
        return self._cmd(cmd, self.screen, expect, *args, **kwargs)

    def reset(self):
        screen_name = list(self.screen.keys())[0]
        screen_info = {screen_name: None}
        info = self.get_screen_info(screen_info)
        # self.host_run(f"screen -S {self.screen[screen_name]} -X reset", info.chained_ssh)
        self.host_run(f"sudo screen -S {self.screen[screen_name]} -X reset", info.chained_ssh)

    def kill_screen(self):
        screen_name = list(self.screen.keys())[0]
        screen_info = {screen_name: None}
        info = self.get_screen_info(screen_info)
        cmd = f"sudo kill -9 $(ps ax | grep \"expect.*{self.screen[screen_name]}\" | fgrep -v grep | awk '{{ print $1 }}')"
        try:
            self.host_run(cmd, info.chained_ssh)
        except Exception:
            pass

    def raw_cmd(self, cmd, expect=None, skip_delay=False, *args, **kwargs):
        screen_name = list(self.screen.keys())[0]
        screen_value = self.screen[screen_name]
        # Remove possible prompt included in screen
        screen_value = "{}::".format(screen_value.split("::")[0])
        screen = {screen_name: screen_value}
        return self._cmd(cmd, screen, expect, skip_delay=skip_delay, *args, **kwargs)

    def get_screen_info(self, screen_info):
        info = self.pod.lib.device._parse_host_info(host_info=screen_info)
        if not isinstance(info, ScreenHostInfo):
            raise Exception(f"Invalid instance: {info.__class__.__name__}, expecting: {ScreenHostInfo.__name__}")
        return info

    def get_config_screen_value(self, screen_name):
        screen_info = {screen_name: None}
        info = self.get_screen_info(screen_info)
        screen_value = info.screen
        # Try to get PID of the screen name
        screens = self.host_run("sudo screen -list", info.chained_ssh)
        if screen_value not in screens:
            raise Exception("Screen pid not found, screen value: {}, screens:\n{}".format(screen_value, screens))
        prefix = screens.split(screen_value)[0].splitlines()[-1]
        if prefix not in screen_value:
            screen_value = f"{prefix}{screen_value}"
        return screen_value

    def get_config_prompt(self, screen_name):
        screen_info = {screen_name: None}
        return self.get_screen_info(screen_info).prompt

    def node_run(self, command, screen_info, expect, *args, **kwargs):
        # log.info("Command: {}".format(command.replace("\r", "\\r").replace("\n", "\\n")))
        # TODO: it does not support OpenSync path replacement on the fly, but ovsh is not used in recovery,
        #  so skipping for now

        commands = {}
        nodes = [self.pod]
        skip_exception_key = "skip_exception"
        skip_exception = False
        if skip_exception_key in kwargs:
            skip_exception = kwargs[skip_exception_key]
            kwargs.pop(skip_exception_key)
        if "stuff" in kwargs:
            stuff = kwargs["stuff"]
            kwargs.pop("stuff")
        else:
            stuff = False
        for node in nodes:
            host = self.pod.lib.device._parse_host_info(host_info=screen_info)
            commands[node.get_name()] = host.command_wrapper(
                command, expect=expect, end_sign=False, stuff=stuff, *args, **kwargs
            )
        if "timeout" in kwargs:
            kwargs["timeout"] += SCREEN_CMD_DELAY
        # log.debug("{}".format(commands[node].replace("\r", "\\r")))

        try:
            return execute_commands(commands, **kwargs)
        except Exception:
            if skip_exception:
                return None
            raise

    def host_run(self, command, host, *args, **kwargs):
        commands = {"host": host.command_wrapper(command, *args, **kwargs)}
        result = execute_commands(commands, **kwargs)
        values = list(result.values())[0]
        if len(values) != 3:
            raise Exception(f"Result not expected: {result}")
        ret = values[0]
        stdout = values[1]
        stderr = values[2]
        try:
            ret_value = int(ret)
        except TypeError:
            ret_value = None
        if log.isEnabledFor(logging.DEBUG):
            self.log_catcher.add_mock(command, result, "host")
        if ret_value == 0 and stderr:
            # log.warning("Command return value is 0 but stderr isn't empty: {}".format(stderr))
            pass
        if ret_value != 0 or ret_value is None:
            raise Exception(
                "Failed to execute command: {}\nReturn value: {}. Stdout: {}\nError:{}".format(
                    command, ret, stdout.replace("\n", "\\n"), stderr.replace("\n", "\\n")
                )
            )
        return stdout


class ScreenUtils(object):
    def __init__(self, screen):
        self.screen = screen

    def get_md5_checksum(self, file_path, expected_md5, retry=10):
        for i in range(retry):
            md5 = self.screen.cmd(f"md5sum {file_path}")
            if not md5:
                time.sleep(2)
                continue
            log.debug(f"Parsing md5 raw line: {md5}")
            if "No such file" in md5:
                log.debug(f"File: {file_path} does not exist")
                return None
            if len(md5.split(file_path)) < 2:
                log.debug(f"Parsing md5 raw line: {md5}")
                time.sleep(2)
                continue
            md5 = md5.split(file_path)[-2].split()[-1]
            if len(md5) != 32:
                log.debug(f"Parsing md5 raw line: {md5}")
                time.sleep(2)
                continue
            try:
                int(md5, 16)
            except Exception:
                time.sleep(2)
                continue
            if md5 != expected_md5:
                log.info(f"md5 mismatch: {md5}, expecting: {expected_md5} for {file_path}")
                return None
            return md5
        return None

    def copy_text_file(self, in_file, out_file, check_md5=True, retry=5):
        file_exists = False
        out_dir = os.path.dirname(out_file)
        if out_dir == out_file.rstrip("/"):
            out_file = os.path.join(out_dir, os.path.basename(in_file))
        if check_md5:
            with open(in_file) as file_to_check:
                data = file_to_check.read()
                expected_md5 = hashlib.md5(data.encode("utf-8")).hexdigest()
                if self.get_md5_checksum(out_file, expected_md5):
                    log.info(f"md5sum matched for file: {out_file}")
                    file_exists = True
        if not file_exists:
            log.info(f"Copy script to {out_file}")
            for i in range(retry):
                cmds = []
                cmd = None
                try:
                    # Create destination directory
                    cmd = f"mkdir -p {out_dir}"
                    # self.screen.cmd(cmd)
                    cmds.append(cmd)

                    # Clear or create output file
                    cmd = f"> {out_file}"
                    # self.screen.cmd(cmd)
                    cmds.append(cmd)

                    # Copy source file content
                    with open(in_file) as input:
                        for line in input.readlines():
                            cmd = line.rstrip("\n")
                            log.info(cmd, indent=2)
                            cmd = (
                                cmd.replace(" ", "\ ")
                                .replace(">", "\\\\>")  # noqa: W605
                                .replace("\\n", "\\\\\\\\\\\\\\n")
                                .replace("$", "\\\\\\\\\\\\\\$")
                                .replace("`", "\\\\\\\\\\\\\\`")
                                .replace(
                                    # "!", "\\\\\\\\!").replace(
                                    "[",
                                    "\\\\[",
                                )
                                .replace("]", "\\\\]")
                                .replace('"', '\\\\\\\\\\\\\\"')
                                .replace("'", "'\\\\''")
                            )
                            cmd = 'echo \\\\\\"{}\\\\\\" >> {}'.format(cmd, out_file)
                            # self.screen.cmd(cmd)
                            cmds.append(cmd)
                    self.screen.cmd("\r".join(cmds), timeout=4 * 60)

                    # if md5 skipped:
                    if not check_md5:
                        log.info(f"{out_file} copied successfully")
                        break
                    # Validate file content by comparing md5 checksum
                    if check_md5 and self.get_md5_checksum(out_file, expected_md5):
                        log.info(f"md5sum matched for file: {out_file}")
                        return out_file
                    else:
                        written_file = self.screen.cmd(f"cat {out_file}")
                        log.info(f"\n{written_file}")
                        log.error("md5sum failed, retry..")
                except Exception as e:
                    log.debug(f"Failed to send command: {cmd}\n{e}")
                self.screen.kill_screen()
                time.sleep(30)
            else:
                raise Exception("Failed to copy")
        # Add execution permission
        for i in range(retry):
            self.screen.cmd(f"chmod a+x {out_file}")
            break
        return out_file
