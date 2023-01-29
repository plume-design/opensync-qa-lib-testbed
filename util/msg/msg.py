import re
import time

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.msg.journal_msg import JournalMsg
from lib_testbed.generic.util.msg.logread_msg import LogreadMsg
from lib_testbed.generic.util.msg.syslog_msg import SyslogMsg


class LogEmpty(Exception):
    pass


class Msg:

    LogEmpty = LogEmpty

    def __init__(self, pod):
        self.pod = pod
        self.logger_name = self.get_logger_name()
        if self.logger_name == "journalctl":
            self.logger = JournalMsg(self.pod)
        elif self.logger_name == "syslog":
            self.logger = SyslogMsg(self.pod)
        else:
            self.logger = LogreadMsg(self.pod)

    def _cmd_wait(self, *, timeout, cursor, regex, **kwargs):
        pattern = re.compile(regex)
        end_time = time.time() + timeout
        while time.time() < end_time:
            # give at least 5 seconds for log reading to complete
            remaining = max(end_time - time.time(), 5)
            try:
                resp = self._cmd(timeout=remaining, cursor=cursor, **kwargs)
            except Exception as e:
                if "Return value: 1" not in str(e):
                    raise
                continue
            matching = [message for message in resp if pattern.search(message['value']) is not None]
            if matching:
                break
            if resp:
                cursor = resp[-1]['cursor']
            time.sleep(0.5)
        else:
            raise LogEmpty(f"Timeout while waiting for log message after {timeout}sec")
        return matching

    def _cmd(self, **kwargs):
        messages = self.logger.cmd(**kwargs)
        for message in messages:
            assert message.get('date_timestamp')
            assert message.get('timestamp')
            assert message.get('value')
            assert message.get('cursor')
        return messages

    def get_cursor(self, last_log=None):
        if not last_log:
            try:
                last_log = self._cmd(last_lines=1)[-1]
            except IndexError:
                return 0
        return last_log['cursor']

    def get_logger_name(self):
        try:
            logread_method = self.pod.capabilities.get_logread_method()
        except KeyError:
            log.warning("frv_logread not defined in device capabilities")
            return 'logread'
        if logread_method == "logread_v1":
            return "journalctl"
        if logread_method == "logread_v2":
            return "logread"
        assert logread_method == "logread_v3"
        return "syslog"

    def is_systemd(self):
        try:
            logread_version = self.pod.run_command('logread -V')
            if logread_version[0] == 0:
                return False
        except Exception:
            pass
        return True

    def get_service_log(self, *, process=None, cursor=None, timeout=30, module=None, regex='.*'):
        return self._cmd_wait(process=process,
                              cursor=cursor,
                              timeout=timeout,
                              module=module,
                              regex=regex)

    def get_logs_to_print(self, *, process=None, cursor=None, timeout=30, module=None, regex='.*'):
        all_logs = self.get_service_log(process=process,
                                        cursor=cursor,
                                        timeout=timeout,
                                        module=module,
                                        regex=regex)
        all_logs = [f'{log_row["date_timestamp"]} <{process}> <{log_row["severity"]}> <{log_row["module"]}> '
                    f'{log_row["value"]}' for log_row in all_logs]
        return '\n'.join(all_logs)

    def get_logs_before_reboot(self):
        logs = ''
        path = self.pod.get_stdout(self.pod.get_opensync_path())
        if self.pod.run_command('ls /sys/fs/pstore')[1]:
            logs = self.pod.run_command('cat /sys/fs/pstore/pmsg-ramoops-0')[1]
        elif self.pod.run_command(f'ls {path}/log_archive/syslog')[1]:
            logs = self.pod.run_command(f'zcat {path}/log_archive/syslog/*')[1]
        else:
            log.info('Cannot find any logs from before reboot')
        return logs

    def get_name(self):
        return f'msg_{self.pod.get_name()}'
