import shlex
from lib_testbed.generic.util.logger import log

WIFI_HAL_TEST = "/usr/plume/tools/wifi_hal_test"
WIFI_HAL_TEST2 = "/usr/plume/bin/wifihal_test"

CHECK_DELTA_TIME = False

RADIO_BAND = "band"
RADIO_BAND_24_G = "2.4GHz"
RADIO_BAND_5G = "5GHz"

ACTIVE_CHANNEL = "active_channel"
CHANNELS = "channels"

RADIO_INDEX = "radio_index"
AP_INDEX = "ap_index"

ON_CHANNEL_SCAN = "on_chan"
OFF_CHANNEL_SCAN = "off_chan"

INTERFACE_NAME = "ifname"

RADIO_SSID = "ssid"


class WifiHall:
    def __init__(self, pod):
        self.pod = pod
        self.radio_info = {}

    def wifihal_cmd(self, cmd, parse=True, **kwargs):
        cmd = f"{WIFI_HAL_TEST} {cmd}"
        cmd = f"bash --login -c '{cmd}'"
        out = self.pod.run(cmd, **kwargs)
        if parse:
            if not out:
                raise Exception("No output received")
            out = self.parse_wifihal_resp(out)
        return out

    def parse_wifihal_resp(self, resp):
        resp_info = {}
        for line in resp.splitlines():
            if line.startswith("wifi_"):
                if not line.startswith('wifi_context_') and ' size=' in line:
                    resp_info['cmd'] = "{}".format(line[0:line.rfind('size')].strip().replace("(", " "))
                    resp_info['value'] = []
                continue
            elif line.startswith("CBN_Debug"):
                continue
            elif "return:" in line and not resp_info.get('value'):
                resp_info['ret'] = int(line.split("return:")[1].strip().split()[0])
            else:
                val_dict = {}
                val_name = None
                for value in line.split():
                    if not val_name:
                        val_name = value
                        continue
                    # if val_name.endswith(":"):
                    #     continue
                    try:
                        val_dict[val_name] = int(value)
                    except ValueError:
                        val_dict[val_name] = value
                    val_name = None
                val_dict['org'] = line
                if 'value' not in resp_info or resp_info['value'] and len(resp_info['value'][-1]) != len(val_dict):
                    # skip adding this value as not similar to previous one
                    continue
                resp_info['value'].append(val_dict)
        if not resp_info:
            raise Exception(f"Unexpected response: {resp}")
        return resp_info

    def get_active_channel(self, radio_index):
        ifname = f"wl{radio_index}"  # TODO: get from wifi_hal
        out = self.pod.run(f"wl -i {ifname} channel")
        if "target channel" not in out:
            raise Exception(f"Unexpected output: '{out}'")
        channel = out.split("target channel")[1].splitlines()[0].strip()
        return int(channel)

    def get_radio_info(self, refresh=False):
        if not refresh and self.radio_info:
            return self.radio_info
        out = self.wifihal_cmd("-h", parse=False, skip_exception=True)
        if "radio indexes:" not in out:
            raise Exception(f"Output not expected: '{out}'")
        radios = out.split("radio indexes:")[1].splitlines()
        i = 0
        for radio in radios:
            if i > 1:
                break
            if 'RADIO' not in radio:
                continue
            radio_values = radio.split('RADIO')[1].split()
            radio_info = {}
            radio_info[RADIO_INDEX] = int(radio_values[0].strip(":"))
            radio_info[INTERFACE_NAME] = radio_values[1]
            radio_info[ACTIVE_CHANNEL] = int(radio_values[5])

            assert radio_info[ACTIVE_CHANNEL]
            band = radio_values[3]
            if band == "2.4GHz":
                band = RADIO_BAND_24_G
                # TODO: get channel list from wifi_getRadioChannelStats
                radio_info[CHANNELS] = [1, 6, 11]
            elif band == "5GHz":
                band = RADIO_BAND_5G
                radio_info[CHANNELS] = [radio_info[ACTIVE_CHANNEL]]
            else:
                raise Exception(f"Unexpected band: {band}")
            self.radio_info[band] = radio_info
            i += 1
        aps = out.split("ap indexes:")[1].splitlines()[1:]
        for ap in aps:
            if "IFNAME:" not in ap:
                continue
            ap_info = {}
            ap_info[RADIO_INDEX] = self.get_value(ap, 'RADIO', 'int')
            ap_info[AP_INDEX] = self.get_value(ap, 'AP', 'int')
            ap_info[INTERFACE_NAME] = self.get_value(ap, 'IFNAME')
            ap_info[RADIO_SSID] = self.get_value(ap, 'SSID')
            for band, info in self.radio_info.items():
                if info[RADIO_INDEX] == ap_info[RADIO_INDEX] and info[INTERFACE_NAME] == ap_info[INTERFACE_NAME]:
                    self.radio_info[band].update(ap_info)
        return self.radio_info

    def get_value(self, line, key, type='str'):
        value = shlex.split(line.split(f'{key}:')[1])[0]
        if type == 'int':
            value = int(value)
        return value

##########################
# API getRadioChannelStats
##########################
class RadioChannelStats(WifiHall):
    def __init__(self, pod):
        super(RadioChannelStats, self).__init__(pod)

    def get_channel_stats(self, radio_index, channels=None):
        values = self.wifihal_cmd(f"getRadioChannelStats {radio_index}", timeout=5 * 60)['value']
        if channels:
            out = []
            for value in values:
                # if not value.get('ch'):
                #     raise Exception(f"Unexpected getRadioChannelStats values: {values}")
                if value.get('ch') in channels:
                    out.append(value)
            values = out
        else:
            pass
        return values

    @staticmethod
    def validate_channel_stats_values(stat, scan_type):
        error_list = []
        try:
            assert stat['total']
        except AssertionError:
            error_list.append("Unexpected total=0")
            return error_list
        if scan_type == ON_CHANNEL_SCAN:
            assert stat['busy']
        # assert stats['total'] > stats['busy']
        try:
            assert stat['total'] > stat['busy']
        except AssertionError:
            error_list.append(f"Unexpected total < busy. Stats: {stat['org']}")
        try:
            assert stat['busy'] >= stat['rx'] + stat['tx']
        except AssertionError:
            error_list.append(f"Unexpected busy < (rx + tx). Stats: {stat['org']}")
        return error_list

    @staticmethod
    def count_stats_delta(stats, scan_type, expected_total_delta=None):
        error_list = []
        if len(stats) < 2:
            return error_list
        delta_dict = {}
        stat_names = ['busy', 'tx', 'rx', 'total']
        current_stat = stats[-1]
        previous_stat = stats[-2]

        log.info("[prev]  busy:{:<11} rx:{:<11} tx:{:<11} total:{}".format(
            previous_stat['busy'], previous_stat['rx'], previous_stat['tx'], previous_stat['total']))
        log.info("[now]   busy:{:<11} rx:{:<11} tx:{:<11} total:{}".format(
            current_stat['busy'], current_stat['rx'], current_stat['tx'], current_stat['total']))

        if not current_stat['total']:
            return error_list
        for stat_name in stat_names:
            delta_dict[stat_name] = current_stat[stat_name] - previous_stat[stat_name]
        if not delta_dict['total']:
            log.info("Skipping counting delta, delta['total'] is 0", indent=1)
            return error_list
        delta_dict['busy_percent'] = round(delta_dict['busy'] * 100 / delta_dict['total'], 1)
        delta_dict['tx_percent'] = round(delta_dict['tx'] * 100 / delta_dict['total'], 1)

        if delta_dict['total'] > 1000000:
            total_div = 1000000.0
            time_type = "s"
        else:
            total_div = 1000.0
            time_type = "ms"

        log.info("[delta] busy:{:<11} busy_percent:  {:<14} total:{:.2f}{}".format(
            delta_dict['busy'], str(delta_dict['busy_percent']) + '%', delta_dict['total'] / total_div, time_type))

        log.info("[delta] tx:  {:<11} tx_percent:    {:<14} total:{:.2f}{}".format(
            delta_dict['tx'], str(delta_dict['tx_percent']) + '%', delta_dict['total'] / total_div, time_type))

        if delta_dict['total'] > 0 and (delta_dict['busy'] <= 0
                                        or delta_dict['rx'] < 0
                                        or delta_dict['tx'] < 0):
            error_list.append("Unexpected delta busy|rx|tx < 0")
            error_list.append(f"raw [prev] {previous_stat['org']}")
            error_list.append(f"raw [now] {current_stat['org']}")

        if delta_dict['tx_percent'] > 10:
            log.warning(f"tx_percent: {delta_dict['tx_percent']}% too high, expecting < 10%")

        if not error_list:
            try:
                assert delta_dict['total'] >= delta_dict['busy']
            except AssertionError:
                error_list.append(f"Unexpected total < busy. Delta: {delta_dict}")
                error_list.append(f"raw [prev] {previous_stat['org']}")
                error_list.append(f"raw [now] {current_stat['org']}")

        if CHECK_DELTA_TIME and scan_type == ON_CHANNEL_SCAN and expected_total_delta:
            DELTA_TOTAL_TOLERANCE = 1
            delta_total_s = delta_dict['total'] / total_div
            try:
                assert delta_total_s >= expected_total_delta - 1
            except AssertionError:
                error_list.append("Delta total: {}s not within the expected range of [{},{}]sec".format(
                    delta_total_s, expected_total_delta - DELTA_TOTAL_TOLERANCE,
                    expected_total_delta + DELTA_TOTAL_TOLERANCE))
        return error_list


##########################
# API neighbors
##########################
class Neighbors(WifiHall):
    def __init__(self, pod):
        super(Neighbors, self).__init__(pod)

    def channel_scan(self, ap_index, channel, scan_mode, dwell_time=100):
        assert scan_mode in ['full', 'on', 'off']
        log.info(f"Scanning ap:{ap_index} channel:{channel}, dwell:{dwell_time}ms", indent=1)
        return self.wifihal_cmd(f"startNeighborScan {ap_index} {scan_mode} {dwell_time} {channel}")
