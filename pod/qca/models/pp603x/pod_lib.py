import re

from lib_testbed.generic.pod.qca.pod_lib import PodLib as PodLibGeneric


class PodLib(PodLibGeneric):
    DFS_REGION_MAP = {
        "EU": "0x0037",
        "US": "0x003a",
        "JP": "0x8188",
        "CA": "0x0014",
        "UK": "0x833A",
        "GB": "0x833A",
        "NZ": "0x822A",
        "SG": "0x82BE",
        "IL": "0x8178",
        "HK": "0x8158",
        "KR": "0x005f",
        "PH": "0x8260",
    }

    def get_region(self, **kwargs):
        # FW above 5.4.X has region entry in Wifi_Radio_State table, so start from there
        table_check = super().get_region(override_region=True, **kwargs)
        if table_check[0] == 0:
            return table_check
        response = self.run_command(
            "cfg80211tool wifi0 getCountry; cfg80211tool wifi1 getCountry; cfg80211tool wifi2 getCountry", **kwargs
        )
        cc_codes = re.findall(r"(?<=getCountry:).*", response[1])
        if not cc_codes:
            return [1, "", "Cannot get region"]
        if len(set(cc_codes)) > 1:
            return [2, "", f"Different regions for different radios: {cc_codes}"]
        return [0, cc_codes[0], ""]

    def set_region_three_radios_model(self, region, **kwargs):
        return super().set_region_three_radios_model(region, **kwargs)

    def get_radio_temperature(self, radio_index, **kwargs):
        radio_sensor_map = [
            "hwmon218",
            "hwmon214",
            "hwmon221",
        ]
        if self.run_command(f"ls /sys/class/hwmon/{radio_sensor_map[radio_index]}/temp1_input", **kwargs)[0]:
            return super().get_radio_temperature(radio_index, **kwargs)

        ret = self.run_command(
            f"cat /sys/class/hwmon/{radio_sensor_map[radio_index]}/temp1_input | cut -c -2", **kwargs
        )
        return ret
