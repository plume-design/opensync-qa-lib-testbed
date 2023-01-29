
import datetime
import hashlib
import re

# strptime uses locale dependent month names, but we need english names
_ENGLISH_MONTH_ABBREVATIONS = [
    "start indexing with one",
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
]

_SYSLOG_MESSAGE = re.compile(r"""
# logread's dialect of syslog, if we can still call it that:
((?P<weekday>[A-Z][a-z]{2})[ ])?                        # Some vendors feel the need to be very special
((?P<month>[A-Z][a-z]{2})[ ])?                          # Three letters specifying the month
((?P<day>[ ]?[1-3]?\d)[ ]|                              # Day of the month, padded with space
((?P<YY>\d\d)(?P<MM>[0-1]\d)(?P<DD>[0-3]\d)[-]))        # Or YYMMDD, followed by - (minus)
(?P<hour>\d{2}):                                        # decimal hour    [00-23]
(?P<minute>\d{2}):                                      # decimal minutes [00-59]
(?P<second>\d{2})?                                      # decimal seconds [00-59], optional because of another vendor
(?P<subseconds>\.\d*)?[ ]                               # optional micro- or nanoseconds
((?P<year>\d{4})[ ])?                                   # some devices add non-standard 4 digit year
((?P<hostname>[0-9A-Za-z_\-\.\(\)]{1,255})[ ])?         # then we have the optional hostname
((?P<priority>[a-zA-Z0-9]{1,8}[\.\:][a-z]{1,8})[ ])?       # and sometimes non-standard facility.severity
((?P<structured_data>\[(.*?)\])[ ]?)*                   # or random structured data in square brackets
((?P<process>[-\w]{1,32})(\[(?P<pid>\d{1,10})\])?:[ ])? # process name, followed by optional pid in brackets
(\[(?P<mesh>[a-zA-Z]{1,8})\][ ])?                       # or even [Mesh]
((\<(?P<severity>[A-Z]{1,8})\>[ ]+)                     # then optional severity tag
((?P<module>\w{1,32}):[ ]))?                            # and coresponding module, usually capitalized
(?P<value>.*)                                           # finally the rest is the value of the message
""", re.VERBOSE)


def parse_syslog_message(line):
    match = _SYSLOG_MESSAGE.match(line)
    if match is not None:
        message = {}
        d = match.groupdict()
        if d["YY"]:
            d["year"] = "20" + d["YY"]
            d["month"] = _ENGLISH_MONTH_ABBREVATIONS[int(d["MM"], 10)]
            d["day"] = d["DD"]
        if not d["month"]:
            d["month"] = d["weekday"]
        dt = _make_datetime(d["year"], d["month"], d["day"], d["hour"], d["minute"], d["second"])
        # TODO date_timestamp format currently differs between logread_msg and journal_msg
        message["date_timestamp"] = dt.isoformat(sep=" ")
        message["timestamp"] = int(dt.replace(tzinfo=datetime.timezone.utc).timestamp()) * 1000000    # in microseconds
        message["severity"] = d["severity"] or "Unknown"
        message["module"] = d["module"] or "Unknown"
        message["process"] = d["process"]
        message["value"] = d["value"]
        return message
    else:
        return {}


def _make_datetime(year, month, day, hour, minute, second):
    today = datetime.date.today()
    args = []
    if year is None:
        args.append(today.year)
    else:
        args.append(int(year, 10))
    if month is None:
        month = _ENGLISH_MONTH_ABBREVATIONS[today.month]
    try:
        args.append(_ENGLISH_MONTH_ABBREVATIONS.index(month))
    except ValueError:
        # Let's assume it happended this month
        args.append(today.month)
    for arg in (day, hour, minute):
        args.append(int(arg, 10))
    if second is not None:
        args.append(int(second, 10))
    return datetime.datetime(*args)


class SyslogMsg:
    """
    Read log by executing `LOGREAD` command found in `pod`'s config and parsing its output in syslog format.
    """

    def __init__(self, pod):
        self.pod = pod
        self._cmd = pod.capabilities.get_logread_command()

    def cmd(self, process=None, last_lines=1000, cursor=None, timeout=30, module=None):
        if not module:
            modules = set()
        elif isinstance(module, str):
            modules = {module}
        else:
            # list or other sequence
            modules = set(module)
        cmd = f'{self._cmd} | grep {process} -i' if process else self._cmd
        result = self.pod.run_command(cmd, timeout=timeout)
        indexed_lines = []
        for line in self.pod.get_stdout(result).splitlines():
            line = line.rstrip()
            if line:
                if isinstance(line, bytes):
                    blob = line
                    line = blob.decode("utf-8", 'backslashreplace')
                else:
                    blob = line.encode("utf-8")
                checksum = hashlib.md5(blob).hexdigest()
                indexed_lines.append((line, checksum))
                if cursor == checksum:
                    indexed_lines.clear()

        messages = []
        for line, checksum in indexed_lines:
            message = parse_syslog_message(line)
            if not message:
                continue
            if process and message["process"] != process:
                continue
            if modules and message["module"] not in modules:
                continue
            message["cursor"] = checksum
            messages.append(message)
        return messages[-last_lines:]
