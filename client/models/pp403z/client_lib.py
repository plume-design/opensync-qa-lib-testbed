import os
import time

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.base_lib import Iface
from lib_testbed.generic.client.models.pp403z.client_tool import ClientTool
from lib_testbed.generic.client.models.generic.client_lib import ClientLib as ClientLibGeneric


class ClientLib(ClientLibGeneric):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.iface = ClientIface(lib=self)
        self.tool = ClientTool(lib=self)
        self.ext_path = self.get_ext_path()

    @staticmethod
    def get_ext_path():
        ext_path = ":".join(
            ["/bin:/sbin:/usr/bin:/usr/sbin:/opt/bin:/opt/sbin:/usr/opensync/tools:/usr/opensync/bin", "/usr/opensync"]
        )
        return ext_path

    # Skip this check since pod-client does not have namespace
    def check_wireless_client(self):
        return True

    def connect(
        self,
        ssid=None,
        psk=None,
        bssid=None,
        band="24g",
        key_mgmt="WPA-PSK",
        timeout=60,
        dhclient=True,
        e_gl_param="",
        e_net_param="",
        country="US",
        proto="RSN",
        pmf_mode="enabled",
        **kwargs,
    ):
        """
        Connect client(s) to network starting own wpa_supplicant
        Args:
            ssid: ssid
            psk: password
            bssid: bssid if needed
            band: Type of band (2G, 5GL, 5GU) to set correct interface
            key_mgmt: SAE, WPA-PSK, FT-PSK or NONE for open network
            timeout: timeout for connecting to network
            dhclient: start dhcp client after association
            e_gl_param: extra wpa_supplicant global parameters separated with ','
            e_net_param: extra wpa_supplicant network parameters separated with ','
            country: force regulatory domain for desired country; default country is US
            proto (str)
            pmf_mode (str): Used only in case connection with SAE, WPA-PSK-SHA256
            bandwidth (str): Specify bandwidth if provided
            **kwargs:

        Returns: (list) merged clients response

        """
        ssid, psk = self.verify_credentials(ssid=ssid, psk=psk)
        ifname = self.iface.get_interface_from_band(band)
        if not ifname:
            return [1, "", "Missing wlan interface"]
        log.info(f"Connect clients {self.device.name} iface: {ifname} to ssid: {ssid}, bssid: {bssid}")
        wpa_supp_conf = self.create_wpa_conf(
            ssid=ssid,
            psk=psk,
            bssid=bssid,
            ifname=ifname,
            proto=proto,
            key_mgmt=key_mgmt,
            pmf_mode=pmf_mode,
            country=country,
            e_gl_param=e_gl_param,
            e_net_param=e_net_param,
        )

        # first check if old supplicant works and remove old wpa_supplicant files
        base_path = self.get_wpa_supplicant_base_path(ifname)
        self.disconnect(**kwargs)
        log.info(f"base_path: {base_path}")

        command = f"rm {base_path}*"
        # Run command only for wifi clients
        self.run_command(command, **kwargs)

        # save wpa_supplicant.conf on client
        command = f"echo '{wpa_supp_conf}' > {base_path}.conf"
        self.run_command(command, **kwargs)

        # Remove wireless interfaces from br0 to fix EAPoL
        self.remove_wireless_interfaces_from_bridge()

        # Set max bandwidth capabilities for all radios
        self.set_max_bw_cap_for_radios()

        # Make sure STA is set
        self.wifi_station(ifname=ifname)

        # disable roaming
        self.disable_roaming(ifname=ifname)

        # start wpa_supplicant in background with logs redirected to /tmp/wpa_supplicant_<ifname>.log
        command = f"wpa_supplicant -i {ifname} -c {base_path}.conf -P {base_path}.pid " f"-f {base_path}.log -t -B -d"
        result = self.run_command(command, **kwargs)
        if result[0]:
            log.error("Unable to start wpa_supplicant")
            return result

        # wait for an association
        assoc_timeout = time.time() + timeout
        result = None
        while assoc_timeout > time.time():
            result = self.run_command(f'iw {ifname} link | grep -i "connected to"', **kwargs)
            if not result[0]:
                break
            time.sleep(5)

        if result[0]:
            return result

        if dhclient:
            udhcpc_result = self.start_dhcp_client(ifname, **kwargs)
            result = self.merge_result(result, udhcpc_result)
        return result

    @staticmethod
    def create_wpa_conf(ssid, psk, bssid, ifname, proto, key_mgmt, pmf_mode, country, e_gl_param, e_net_param):
        if key_mgmt.upper() in ["SAE", "WPA-PSK-SHA256"] and "ieee80211w" not in e_net_param:
            pmf_modes = {"disabled": 0, "enabled": 1, "required": 2}
            pmf_value_mode = pmf_modes.get(pmf_mode)
            assert pmf_value_mode is not None, f"Incorrect PMF mode. Allowed modes: {pmf_modes.keys()}"
            pmf_param = f"ieee80211w={pmf_value_mode}"
            e_net_param = ",".join(e_net_param.split(",") + [pmf_param])

        bssid_info = f"bssid={bssid}\n" if bssid else ""
        extra_param = "\n".join(e_gl_param.split(","))
        extra_net_param = "\n    ".join(e_net_param.split(","))
        ssid_hex = ssid.encode("utf-8").hex()
        wpa_supp_psk = f'"{psk}"'
        if not psk:
            key_mgmt = None
        security = f"psk={wpa_supp_psk}\n    proto={proto}\n    key_mgmt={key_mgmt}" if key_mgmt else "key_mgmt=NONE"

        wpa_supp_conf = f"""ctrl_interface=/var/run/wpa_supplicant-{ifname}
        update_config=1
        country={country}
        {extra_param}

        network={{
            ssid={ssid_hex}
            {security}
            scan_ssid=1
            priority=1
            {bssid_info}
            {extra_net_param}
        }}"""
        return wpa_supp_conf

    def disconnect(self, ifname=None, **kwargs):
        """
        Kills the wpa_supplicant and dhclient (if exists) based on the pid file in name
        Args:
            ifname: (str) wlan iface name

        Returns: (list) merged clients response
        """
        if not ifname:
            # If not provided check all interfaces.
            ifnames = self.iface.get_wireless_ifaces()
            results = [0, "", ""]
            for ifname in ifnames:
                result = self.disconnect(ifname)
                results[0] += result[0]
                results[1] += f"{result[1]}\n"
                results[2] += f"{result[2]}\n"
            return results

        # Disable interfaces
        self.run_command(f"wl -i {ifname} down; ifconfig {ifname} down")

        wpa_path_ifname = f"/tmp/wpa_supplicant_{ifname}.pid"
        wpa_supp_process = self.run_command(
            f"ps | grep wpa_supplicant | grep {ifname} | grep -v grep" f" | awk '{{print $1}}'", **kwargs
        )
        if not wpa_supp_process[1]:
            return [0, f"Wpa supplicant not running for ifname: {ifname}", ""]

        log.info(f"Disconnect client: {self.get_name()}, ifname: {ifname}")

        # Stop dhclient
        self.stop_udhcpc_client(ifname, **kwargs)

        # Stop wpa_supplicant
        wpa_supp_pid = self.get_stdout(wpa_supp_process).strip()
        response = self.run_command(f"kill {wpa_supp_pid}", **kwargs)
        if response[0] and "Usage:" not in response[2]:
            log.warning(f"Unable to kill wpa_supplicant for {self.device.name}, error: {response[2]}")

        # Remove wpa supplicant log file
        if self.result_ok(self.run_command(f"ls {wpa_path_ifname}", **kwargs)):
            command = f"rm {wpa_path_ifname}"
            self.run_command(command, **kwargs)
        return [0, "", ""]

    def verify_credentials(self, ssid, psk):
        name = self.get_network_name()
        default_ssid, default_psk = self.get_network(name)
        ssid = default_ssid if ssid is None else ssid
        psk = default_psk if psk is None else psk
        return ssid, psk

    def start_dhcp_client(self, ifname, timeout=60, **kwargs):
        result = self.run_command(
            f"udhcpc -i {ifname} -p /var/run/udhcpc-{ifname}.pid " f"-s /usr/opensync/bin/udhcpc.sh -A 10",
            **kwargs,
            timeout=timeout,
        )
        # clear std err for successful results
        if not result[0]:
            result[2] = ""
        return result

    def wifi_station(self, ifname, **kwargs):
        return self.run_command(f"wl -i {ifname} down; wl -i {ifname} apsta 1; wl -i {ifname} up", **kwargs)

    def stop_udhcpc_client(self, ifname, clear_cache=False, **kwargs):
        log.info("Stopping old udhcpc instances")
        command = f"ps | grep /var/run/udhcpc-{ifname}.pid | grep -v grep | awk '{{print $1}}' | xargs kill"
        self.run_command(command, **kwargs)
        self.run_command(f" ip -4 addr flush dev {ifname}", **kwargs)
        if clear_cache:
            # clear cached DHCP leases
            self.run_command("""rm -f /var/udhcpd/udhcpd.leases""", **kwargs)
            # and "cached" DNS nameservers
            self.run_command('''sh -c "echo '' > /etc/resolv.conf"''', **kwargs)
        time.sleep(1.2)
        # since we kill all types, we could have false negative responses, so returning 0
        return [0, "", ""]

    def get_region(self, **kwargs):
        out = self.run_command("pmf -r -ccode0; pmf -r -ccode1; pmf -r -ccode2", **kwargs)
        return out

    def pod_to_client(self, **kwargs):
        """
        Change pod to client
        Returns:

        """
        log.info("Entering factory mode")
        self.run_command("pmf -e", **kwargs)
        time.sleep(10)
        log.info("Wait client be ready")
        self.wait_available(timeout=2 * 60, **kwargs)
        self.remove_wireless_interfaces_from_bridge()
        self.run_command('echo "100.1.1 [$(cat /.version)]" > /.version')
        return [0, "Pod device was successfully changed to be a client", ""]

    def client_to_pod(self, **kwargs):
        """
        Change client to pod
        Returns:

        """
        log.info("Exiting factory mode")
        response = self.run_command("pmf -q", **kwargs)
        if response[0]:
            return response
        time.sleep(10)
        log.info("Wait pod be ready")
        self.wait_available(timeout=2 * 60, **kwargs)
        return [0, "Client device was successfully changed to be a pod", ""]

    def set_region_three_radios_model(self, region, **kwargs):
        region = region.upper()
        if region == "EU":
            region = "E0"
            rev_num = 763
        elif region == "US":
            rev_num = 0
        elif region == "UK":
            region = "GB"
            rev_num = 36
        elif region == "CA":
            rev_num = 886
        elif region == "JP":
            rev_num = 914
        elif region == "KR":
            rev_num = 936
        elif region == "PH":
            rev_num = 990
        else:
            raise AssertionError(f"Region {region} is not supported! Supported regions: EU, US, UK, CA, JP, KR, PH.")

        log.info(f"Set {region} region for node {self.get_nickname()}")
        res = [0, "", ""]
        for radio in ["ccode0", "ccode1", "ccode2"]:
            res = self.merge_result(res, self.run_command(f"pmf -{radio} -fw  {region}"))

        for reg_revision in ["regrv0", "regrv1", "regrv2"]:
            self.run_command(f"pmf -{reg_revision} -fw  {rev_num}")
        self.run_command("pmf --commit")

        timeout = time.time() + 120
        while time.time() < timeout:
            if self.run_command("pmf -r -ccode0")[1]:
                break
            time.sleep(2)
        else:
            assert False, "Cannot get country code information after reboot"

        for radio in ["ccode0", "ccode1", "ccode2"]:
            assert region in self.run_command(f"pmf -r -{radio}")[1]
        return res

    def get_radio_temperature(self, radio_index, **kwargs):
        # make sure interface is up
        self.run_command(f"wl -i wl{radio_index} up")
        ret = self.run_command(f"wl -i wl{radio_index} phy_tempsense", **kwargs)
        # example output: "70 (0x46)"
        ret[1] = ret[1].split(" ")
        ret[1] = ret[1][0] if len(ret[1]) == 2 else "-1"
        return ret

    def reboot(self, **kwargs):
        """Reboot client(s)"""
        result = self.run_command("reboot", **kwargs)
        # Change ret val from 255 to 0 due to lost connection after reboot.
        if result[0] == 255:
            result[0] = 0
        return result

    # Specific fqdn_check implementation to avoid checking dig since the dig packet does not exist on pod devices
    def fqdn_check(self, count=1, v6=False, dns_address="www.google.com", **kwargs):
        dns_address = (
            self.config["wifi_check"]["dns_check"]
            if self.config.get("wifi_check", {}).get("dns_check")
            else dns_address
        )
        ping_ver = "ping6" if v6 else "ping"
        result = self.run_command(f"{ping_ver} -c {count} -t 200 -W 5 {dns_address}", **kwargs)
        # Clear stdout in case of error so that it doesn't get confused for success
        if result[0]:
            result[1] = ""
        return result

    def remove_wireless_interfaces_from_bridge(self, **kwargs):
        response = self.run_command("brctl delif br0 wl0; brctl delif br0 wl1; brctl delif br0 wl2", **kwargs)
        return response

    def get_bit_rate(self, ifname, **kwargs):
        response = self.run_command(f"iw dev {ifname} link | grep bitrate | awk '{{print $3}}'", **kwargs)
        return self.strip_stdout_result(response)

    def set_legacy_data_rate(self, ifname, rate, **kwargs):
        """
        Set legacy data rate
        Args:
            ifname: (str) name of interface
            rate: (int) rate in Mbps

        Returns: raw output [ret, stdout, stderr] from run command

        """
        band_name = self.iface.get_band_from_interface(ifname)
        band_name = "5g" if "5g" in band_name else "2g"
        result = self.run_command(f"wl -i {ifname} {band_name}_rate -r {rate}", **kwargs)
        return result

    def set_ht_data_rate(self, ifname, bandwidth, mcs, **kwargs):
        """
        Set HT data rate
        Args:
            ifname: (str) name of interface
            bandwidth: (int) bandwidth Mhz
            mcs: (int) number of mcs

        Returns: raw output [ret, stdout, stderr] from run command

        """
        band_name = self.iface.get_band_from_interface(ifname)
        band_name = "5g" if "5g" in band_name else "2g"
        result = self.run_command(f"wl -i {ifname} {band_name}_rate -b {bandwidth} -h {mcs}", **kwargs)
        return result

    def set_vht_data_rate(self, ifname, bandwidth, nss, mcs, **kwargs):
        """
        Set vht data rate
        Args:
            ifname: (str) name of interface
            bandwidth: (int) bandwidth Mhz
            nss: (int) number of nss
            mcs: (int) number of mcs

        Returns: raw output [ret, stdout, stderr] from run commands

        """
        result = self.run_command(f"wl -i {ifname} 5g_rate -b {bandwidth} -v {mcs} -s {nss}", **kwargs)
        return result

    def restore_data_rates(self, **kwargs):
        # For 24G
        results = self.run_command("wl -i wl1 2g_rate auto", **kwargs)
        # For 5GL
        results = self.merge_result(new_result=self.run_command("wl -i wl0 5g_rate auto", **kwargs), old_result=results)
        # For 5GU
        results = self.merge_result(new_result=self.run_command("wl -i wl2 5g_rate auto", **kwargs), old_result=results)
        return results

    def set_max_bw_cap_for_radios(self):
        # make sure all radios are down
        self.run_command("wl -i wl0 down; wl -i wl1 down; wl -i wl2 down")
        # cap:
        #   0x1 - 20MHz  - set 20MHz for wl1 since 20/40 mode is problematic for BCM driver
        #   0x3 - 20/40MHz
        #   0x7 - 20/40/80MHz
        #   0xf - 20/40/80/160MHz
        #   0xff - Unrestricted
        return self.run_command("wl -i wl0 bw_cap 5g 0x7; wl -i wl1 bw_cap 2g 0x1; wl -i wl2 bw_cap 5g 0x7")

    def disable_roaming(self, ifname):
        return self.run_command(f"wl -i {ifname} roam_off 1")

    def get_tx_power(self, ifname, **kwargs):
        """
        Get current Tx power in dBm
        Args:
            interface: (str) Wireless interface

        Returns: raw output [(int) ret, (std) std_out, (str) str_err]

        """
        cmd = "wl -i %s txpwr | awk '{print $1}'" % ifname
        response = self.strip_stdout_result(self.run_command(cmd, **kwargs))
        return response

    def set_tx_power(self, tx_power, ifname, **kwargs):
        """
        Set current Tx power in dBm
        Args:
            ifname: (str) Name of wireless interfaces
            tx_power: (int) Tx power in dBm.

        Returns:

        """
        return self.run_command(f"wl -i {ifname} txpwr1 {tx_power}", **kwargs)

    def set_default_tx_power(self, ifname, **kwargs):
        """
        Set Tx power to default value
        Args:
            ifname: (str) Name of wireless interfaces
            **kwargs:

        Returns:

        """
        return self.set_tx_power(tx_power=-1, ifname=ifname, **kwargs)

    def get_max_tx_power(self, **kwargs):
        """
        Get max Tx power value
        Args:
            **kwargs:

        Returns: (str) max Tx power [dBm]
        """
        return [0, "31", ""]

    def get_min_tx_power(self, **kwargs):
        """
        Get min Tx power value
        Args:
            **kwargs:

        Returns: (str) min Tx power [dBm]
        """
        return [0, "1", ""]

    def upgrade(self, fw_path=None, restore_cfg=None, force=None, http_address=None, **kwargs):
        if restore_cfg is not None or force is not None or http_address is not None:
            log.info("Parameters [restore_cfg, force, http_adders] are not available on PP403Z client")
        skip_version_check = False
        image_file = os.path.basename(fw_path)
        target_file_name = f"/tmp/pfirmware/{image_file}"
        dec_passwd = None

        if dec_passwd and fw_path[-3:] != "eim":
            raise Exception("Use eim file for encrypted image")
        if not dec_passwd and fw_path[-3:] != "img":
            raise Exception("Use img file for unencrypted image")

        self.run_command("mkdir -p /tmp/pfirmware", **kwargs)
        self.put_file(fw_path, "/tmp/pfirmware")
        remote_md5sum = self.run_command(f'md5sum /tmp/pfirmware/{image_file} | cut -d" " -f1', **kwargs)
        remote_md5sum = self.get_stdout(remote_md5sum)
        local_md5sum = os.popen(f'md5sum {fw_path} | cut -d" " -f1').read().strip()

        md5sum = remote_md5sum.strip()
        if md5sum != local_md5sum:
            return [1, "", f"Failed MD5sum image: {local_md5sum} node: {md5sum} "]

        # determine which command should be used for upgrade
        if dec_passwd:
            upg_comm = f"safeupdate  -u {target_file_name} -P {dec_passwd}"
        else:
            upg_comm = f"safeupdate  -u {target_file_name}"

        result = self.run_command(upg_comm, timeout=5 * 60, **kwargs)

        # wait for nodes to start rebooting
        time.sleep(10)
        self.wait_available(timeout=180)

        # don't rely on update return value
        result = self.merge_result(result, self.wait_available(60, **kwargs))

        if skip_version_check:
            return result

        log.info("Checking version")
        check_version = self.version(**kwargs)
        return self.merge_result([result[0], "", result[2]], check_version)


class ClientIface(Iface):
    ALLOWED_BANDS = ["24g", "5gl", "5gu"]

    @staticmethod
    def define_band_by_channel(channel):
        if channel in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]:
            return "24g"
        elif channel in [36, 40, 44, 48, 52, 56, 60, 64]:
            return "5gl"
        elif channel in [100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]:
            return "5gu"
        assert False, f"Can not define band name for {channel} channel"

    @staticmethod
    def get_interface_24g():
        return "wl1"

    @staticmethod
    def get_interface_5gl():
        return "wl0"

    @staticmethod
    def get_interface_5gu():
        return "wl2"

    @staticmethod
    def get_wireless_ifaces():
        return ["wl1", "wl0", "wl2"]

    @staticmethod
    def radio_index_map():
        return {"24G": 1, "5GL": 0, "5GU": 2}

    @staticmethod
    def get_interface_map():
        return {"wl0": "5gl", "wl1": "24g", "wl2": "5gu"}

    def get_band_from_interface(self, ifname):
        interface_map = self.get_interface_map()
        band_name = interface_map.get(ifname)
        assert band_name, f"Can not find the band type for {ifname} interface"
        return band_name

    def get_interface_from_band(self, band):
        """
        Get client interface name
        Args:
            band: (str) band name 2.4G or 5G

        Returns: (str) name of wireless interface

        """
        band = band.replace(".", "").lower()
        assert band in ClientIface.ALLOWED_BANDS, (
            f"Provided not supported band: {band}. " f"Allowed bands: {ClientIface.ALLOWED_BANDS}"
        )
        return getattr(self, f"get_interface_{band}")()
