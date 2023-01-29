import datetime
import json

from lib_testbed.generic.util.logger import log


class LogreadMsg:
    def __init__(self, pod):
        self.pod = pod

    def cmd(self, process=None, last_lines=1000, cursor=None, timeout=30, module=None):
        service_str = ""
        if process:
            service_str = f" -p {process}"
        if module:
            if isinstance(module, list):
                for mod in module:
                    service_str += f" -m {mod}"
            else:
                service_str += f" -m {module}"
        output_str = " -j"  # json
        logread_cmd = f"logread {service_str}{output_str}"
        logread_cmd = f"sh --login -c '{logread_cmd}'"
        out = self.pod.run_command(logread_cmd, timeout=timeout)
        return self.parse_logread_resp(out[1].splitlines(), last_lines, cursor)

    def convert_timestamp(self, realtime_timestamp):
        epoch = int(realtime_timestamp) / 1000 / 1000
        return datetime.datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")

    def convert_epoch(self, date_time):
        # Date example 'Nov 16 12:43:31'
        # Add missing year to date_time
        date_time = f"{datetime.datetime.now().year} {date_time}"
        date_time = datetime.datetime.strptime(date_time, '%Y %b %d %H:%M:%S')
        return (date_time - datetime.datetime(1970, 1, 1)).total_seconds()

    def parse_logread_resp(self, resp, last_lines, from_cursor):
        messages = []
        for line in resp:
            try:
                line_info = json.loads(line)
            except ValueError:
                # Logread might return not expected lines at the beginning
                continue
            messages.append(line_info)
        messages_new = []
        last_timestamp = 0
        cursor_id = 0
        for message in messages:
            # "Nov 16 12:41:41 SM[1276]: <DEBUG>     MAIN: "
            try:
                # value = "{} {}[{}]: <{}>{:9}: {}".format(
                #     message['message_tm'], message['process'], message.get('pid', ''),
                #     message.get('severity', ''), message.get('module', ''), message['message'])
                value = message['message']
            except KeyError as e:
                log.error(f"{e} missing in: {message}")
                continue
            timestamp = self.convert_epoch(message['message_tm']) * 1000000  # usec
            if timestamp == last_timestamp:
                cursor_id += 1
            else:
                cursor_id = 0
                last_timestamp = timestamp
            cursor = timestamp + cursor_id / 100.0
            if from_cursor:
                if cursor <= from_cursor:
                    continue
            message_info = {'date_timestamp': message['message_tm'],
                            'timestamp': timestamp,
                            'value': value,
                            'cursor': cursor,
                            'severity': message.get('severity', 'Unknown'),
                            'module': message.get('module', 'Unknown')
                            }
            messages_new.append(message_info)
        if last_lines and last_lines < len(messages_new):
            messages_new = messages_new[-last_lines:]
        return messages_new
