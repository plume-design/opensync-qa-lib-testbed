import datetime
import json
from lib_testbed.generic.util.logger import log


class JournalMsg:
    def __init__(self, pod):
        self.pod = pod

    def cmd(self, process=None, last_lines=1000, cursor=None, timeout=30, module=None):
        service_str = ""
        last_lines_str = ""
        since_str = ""
        from_cursor_str = ""

        if process:
            service_str = f" -t {process}"
        if last_lines:
            last_lines_str = f" -n {last_lines}"
        since = None
        if since:
            since_str = f' --since "{since}"'
        if cursor:
            from_cursor_str = f' --after-cursor "{cursor}"'
        output = "json"
        output_str = f" -o {output}"
        journal_cmd = f"journalctl {last_lines_str}{service_str}{since_str}{from_cursor_str}{output_str}"
        out = self.pod.run_command(journal_cmd, timeout=timeout, retry=False)
        if out[2]:
            log.warning(out[2])
        return self.parse_journal_resp(out[1].splitlines())

    def convert_journal_timestamp(self, realtime_timestamp):
        epoch = int(realtime_timestamp) / 1000 / 1000
        return datetime.datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")

    def parse_journal_resp(self, resp):
        messages = []
        for line in resp:
            line_info = json.loads(line)
            messages.append(line_info)
        messages_new = []
        for message in messages:
            message_info = {
                "date_timestamp": self.convert_journal_timestamp(message["__REALTIME_TIMESTAMP"]),
                "timestamp": int(message["__REALTIME_TIMESTAMP"]),
                "value": message["MESSAGE"],
                "cursor": message["__CURSOR"],
            }
            messages_new.append(message_info)
        return messages_new
