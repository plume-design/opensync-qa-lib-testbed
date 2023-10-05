import re
import time
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.allure_util import AllureUtil
from distutils.version import StrictVersion

from lib_testbed.generic.util.request_handler import parse_request
from lib_testbed.generic.util.ssh.device_api import DeviceApi
from lib_testbed.generic.util.object_resolver import ObjectResolver
from lib_testbed.generic.util.common import mark_failed_recovery_attempt


class ClientApi(DeviceApi):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.lib = self.initialize_device_lib(**kwargs)
        self.iface = self.lib.iface
        self.log_catcher = self.lib.log_catcher
        self.min_required_version = "1.0.1"
        self.skip_init = kwargs.pop("skip_init", False)

    @parse_request
    def setup_class_handler(self, request):
        if (
            not request
            or request.config.option.skip_init
            or not self.lib.device
            or not self.lib.main_object
            or self.skip_init
        ):
            return

        name = self.get_nickname()
        uptime_result = self.lib.get_stdout(self.lib.uptime(timeout=20), skip_exception=True)
        if not uptime_result or not self.lib.check_wireless_client():
            if self.recover_namespace_service():
                return True
            assert self.lib.config.get("rpower"), (
                f"{name} has no management access and rpower section " f"is missing in config"
            )
            # import cannot be on the top, since PowerControllerApi have "client host" object
            from lib_testbed.generic.rpower.rpowerlib import PowerControllerApi

            rpower = PowerControllerApi(self.lib.config)
            # get all rpower aliases for getting client which are connected to rpower
            rpower_clients = rpower.get_client_devices()
            assert name in rpower_clients, f"{name} without management access has no configured rpower"
            log.info(f"{name} has no management access")
            log.info(f"Check last operation on rpower for: {name}")
            last_request_time = rpower.get_last_request_time(name)[name]
            rpower_status = rpower.status(name)[name]
            if -1 < last_request_time < 120 and rpower_status == "ON":
                log.warning(
                    f"Skip changing rpower status due to that last operation has been done"
                    f" {last_request_time} seconds ago"
                )
            else:
                log.info(f"Power cycling not accessible client: {name}")
                rpower.off(name)
                time.sleep(5)
                rpower.on(rpower.get_all_devices())
                timeout = time.time() + (60 * 3)
                while time.time() < timeout:
                    uptime_result = self.lib.get_stdout(
                        self.lib.uptime(timeout=3, skip_logging=True), skip_exception=True
                    )
                    if uptime_result:
                        break
                    time.sleep(5)
                else:
                    mark_failed_recovery_attempt(tb_config=self.lib.config)
                    assert False, (
                        f"Client name: {name} has no management access. " f"Can't recover {name} client by power cycle"
                    )
                log.info(f"{name} successfully recovered")

        # save FW versions
        version = self.version()
        allure_util = AllureUtil(request.config)
        allure_util.add_allure_group_envs(f"client_{self.lib.name}", "version", version, f"file://{self.lib.name}")
        # example ver: "plume_rpi_client_image-1.4-66 [Wed Aug  7 17:30:52 UTC 2019]"
        # example ver: "plume_rpi_client__v1.6-86 [Thu Jan  9 13:36:01 UTC 2020]"
        # example ver: "plume_rpi_server__v1.6-85 [Thu Jan  9 12:54:38 UTC 2020]"
        try:
            ver = re.search(r"(\d+\.\d+.\d+)", version).group().replace("-", ".")
        except AttributeError:
            log.warning(f"Cannot get version from: '{version}'")
            ver = "100.0.0"
        assert StrictVersion(ver) >= StrictVersion(self.min_required_version), (
            f"FW on the client {self.lib.name} "
            f"is older than {self.min_required_version}, please upgrade to the latest"
        )

        # save HW info
        hw_info = self.hw_info()
        allure_util.add_allure_group_envs(f"client_{self.lib.name}", "hw_info", hw_info, f"file://{self.lib.name}")

        if self.get_wifi_power_management() == "on":
            self.set_wifi_power_management("off")

    @parse_request
    def teardown_class_handler(self, request):
        if not self.lib.device or not request or request.config.option.skip_init or not self.lib.main_object:
            super().teardown_class_handler(request)
            return

        region = self.get_region(skip_exception=True)
        AllureUtil(request.config).add_allure_group_envs(
            f"client_{self.lib.name}", "region", region, f"file://{self.lib.name}"
        )
        super().teardown_class_handler(request)

    @staticmethod
    def initialize_device_lib(**kwargs):
        model = "no_mgmt_access"
        if kwargs["dev"].device:
            model = kwargs["dev"].device.config["type"]
        file_name = "client_lib.py"
        _class = ObjectResolver.resolve_client_class(file_name=file_name, model=model)
        return _class(**kwargs)

    def get_stdout(self, result, skip_exception=False, **_kwargs):
        return self.lib.get_stdout(result, skip_exception=skip_exception)

    def ping(self, host, v6=False, **kwargs):
        result = self.lib.ping(host, v6, **kwargs)
        return self.get_stdout(result, skip_exception=True)

    def uptime(self, out_format="user", **kwargs):
        result = self.lib.uptime(out_format, **kwargs)
        return self.get_stdout(result, **kwargs)

    def version(self, **kwargs):
        result = self.lib.version(**kwargs)
        ver = self.get_stdout(result, skip_exception=True)
        return ver if ver else "100.0.0 [UNKNOWN]"

    def get_wifi_power_management(self, **kwargs):
        """Get wifi client power save state"""
        result = self.lib.get_wifi_power_management(**kwargs)
        return self.get_stdout(result, skip_exception=True)

    def set_wifi_power_management(self, state, **kwargs):
        """Set wifi client power save state"""
        result = self.lib.set_wifi_power_management(state, **kwargs)
        return self.get_stdout(result, **kwargs)

    def hw_info(self, **kwargs):
        result = self.lib.hw_info(**kwargs)
        ver = self.get_stdout(result, skip_exception=True)
        return ver if ver else "model_name: UNKNOWN"

    def get_file(self, remote_file, location, create_dir=True, **kwargs):
        """Copy a file from client(s)"""
        result = self.lib.get_file(remote_file, location, create_dir, **kwargs)
        return self.get_stdout(result, **kwargs)

    def put_dir(self, directory, location, **kwargs):
        """Copy dir into client(s)"""
        result = self.lib.put_dir(directory, location, **kwargs)
        return self.get_stdout(result, **kwargs)

    def put_file(self, file_name, location, **kwargs):
        """Copy file into client(s)"""
        result = self.lib.put_file(file_name, location, **kwargs)
        return self.get_stdout(result, **kwargs)

    def info(self, **kwargs):
        """Display client(s) information"""
        result = self.lib.info(**kwargs)
        return self.get_stdout(result, **kwargs)

    # TODO: Add support for json output
    def wifi_winfo(self, ifname="", **kwargs):
        """Display client(s) wireless information."""
        result = self.lib.wifi_winfo(ifname, **kwargs)
        return self.get_stdout(result, **kwargs)

    def is_wifi_connected(self, ifname="", **kwargs):
        result = self.lib.wifi_winfo(ifname, **kwargs)
        if not result[0] and "Connected to" in result[1]:
            return True
        return False

    def ping_check(self, ipaddr="", count=5, fqdn_check=True, v6=False, **kwargs):
        """Check client(s) wireless connectivity (ICMP)."""
        result = self.lib.ping_check(count=count, fqdn_check=fqdn_check, v6=v6, ipaddr=ipaddr, **kwargs)
        if not kwargs.get("skip_logging"):
            # Split error/result logging back into separate lines, they were combined for the tool
            if result[0]:
                for line in result[2].splitlines():
                    log.error(line)
            else:
                for line in result[1].splitlines():
                    log.info(line)
        result = self.get_stdout(result, skip_exception=True)
        return True if result else False

    def fqdn_check(self, count=5, v6=False, dns_address="www.google.com", **kwargs):
        """Check FQDN resolving"""
        result = self.lib.fqdn_check(count=count, v6=v6, dns_addres=dns_address, **kwargs)
        result = self.get_stdout(result, skip_exception=True)
        return True if result else False

    def fqdn_type65(self, domain, **kwargs):
        result = self.lib.fqdn_type65(domain)
        return self.get_stdout(result, **kwargs)

    def wifi_monitor(self, channel, ht="HT20", ifname="", **kwargs):
        """Set interface WIFI_MON_IF in tbvars.conf file to monitor mode."""
        result = self.lib.wifi_monitor(channel, ht, ifname, **kwargs)
        return self.get_stdout(result, **kwargs)

    def wifi_station(self, ifname="", **kwargs):
        """Set interface WIFI_MON_IF in tbvars.conf file to station mode."""
        result = self.lib.wifi_station(ifname, **kwargs)
        return self.get_stdout(result, **kwargs)

    def ping_v4_v6_arp(self, destination, version, wlan_test, count="8", **kwargs):
        result = self.lib.ping_v4_v6_arp(destination, version, wlan_test, count, **kwargs)
        return self.get_stdout(result, skip_exception=True)

    def ping_ndisc6(self, destination, ifname=None, **kwargs):
        result = self.lib.ping_ndisc6(destination, ifname, **kwargs)
        return self.get_stdout(result)

    def client_type(self, **kwargs):
        """Display type of client(s)"""
        result = self.lib.client_type(**kwargs)
        return self.get_stdout(result, **kwargs)

    def config_type(self, **kwargs):
        """Return type of client based on config value"""
        return self.lib.config_type(**kwargs)

    def eth_connect(
        self,
        pod,
        port_alias=None,
        ifname=None,
        dhclient=True,
        ipv4=True,
        ipv6=False,
        ipv6_stateless=False,
        timeout=20,
        **kwargs,
    ):
        """Connect Ethernet client to specified pod and optional switch port_alias."""
        result = self.lib.eth_connect(
            pod,
            port_alias=port_alias,
            ifname=ifname,
            dhclient=dhclient,
            ipv4=ipv4,
            ipv6=ipv6,
            ipv6_stateless=ipv6_stateless,
            timeout=timeout,
            **kwargs,
        )
        return self.get_stdout(result, **kwargs)

    def eth_disconnect(self, ifname=None, disable_unused_ports=True, **kwargs):
        """Disconnect client from all Ethernet pod ports."""
        result = self.lib.eth_disconnect(ifname, disable_unused_ports=disable_unused_ports, **kwargs)
        return self.get_stdout(result, **kwargs)

    def connect(
        self,
        ssid=None,
        psk=None,
        ifname=None,
        bssid=None,
        key_mgmt=None,
        timeout=60,
        dhclient=True,
        e_gl_param="",
        e_net_param="",
        country=None,
        ipv4=True,
        ipv6=False,
        ipv6_stateless=False,
        wps=False,
        retry=3,
        eap=None,
        identity=None,
        password=None,
        **kwargs,
    ):
        """Connect client(s) to network with wpa_supplicant"""
        if country is None:
            if self.lib.config.get("loc_region"):
                country = self.lib.config.get("loc_region")
            else:
                log.warning("Country code not provided, using US")
                country = "US"

        # there is no country code like EU, so we need to switch do DE
        country = "DE" if country == "EU" else country
        result = self.lib.connect(
            ssid,
            psk,
            ifname=ifname,
            bssid=bssid,
            key_mgmt=key_mgmt,
            timeout=timeout,
            dhclient=dhclient,
            e_gl_param=e_gl_param,
            e_net_param=e_net_param,
            country=country,
            ipv4=ipv4,
            ipv6=ipv6,
            ipv6_stateless=ipv6_stateless,
            wps=wps,
            retry=retry,
            eap=eap,
            identity=identity,
            password=password,
            **kwargs,
        )
        # some cases expect empty STDOUT for an expected connectivity failure, so clean it here
        if result[0]:
            result[2] += result[1]
            result[1] = ""
        return self.get_stdout(result, **kwargs)

    def disconnect(self, ifname=None, **kwargs):
        """Connect client(s) to network with wpa_supplicant"""
        result = self.lib.disconnect(ifname, **kwargs)
        return self.get_stdout(result, **kwargs)

    def start_dhcp_client(self, ifname="", cf=None, ipv4=True, ipv6=False, ipv6_stateless=False, timeout=20, **kwargs):
        """Starts dhcp client on wifi iface"""
        result = self.lib.start_dhcp_client(
            ifname, cf, ipv4=ipv4, ipv6=ipv6, ipv6_stateless=ipv6_stateless, timeout=timeout, **kwargs
        )
        return self.get_stdout(result, **kwargs)

    def stop_dhcp_client(self, ifname="", **kwargs):
        result = self.lib.stop_dhcp_client(ifname, **kwargs)
        return self.get_stdout(result, **kwargs)

    def scan(self, ifname="", params="", match_string=None, **kwargs):
        """Trigger flush scan on the client"""
        result = self.get_stdout(self.lib.scan(ifname, params, **kwargs))
        if match_string:
            result_list = []
            for line in result.splitlines():
                # if re.compile(match_string).match(line):
                if "SSID: " not in line:
                    continue
                if match_string == line.replace("SSID: ", "").strip():
                    result_list.append(line)
            result = "\n".join(result_list)
        return result

    def join_ifaces(self, **kwargs):
        return self.lib.join_ifaces(**kwargs)

    def get_wlan_iface(self, **kwargs):
        return self.lib.get_wlan_iface(**kwargs)

    def get_eth_iface(self, **kwargs):
        return self.lib.get_eth_iface(**kwargs)

    def get_client_ips(self, interface=None, ipv6_prefix=None):
        return self.lib.get_client_ips(interface, ipv6_prefix=ipv6_prefix)

    def restart_networking(self, **kwargs):
        return self.lib.restart_networking(**kwargs)

    def start_continuous_flood_ping(self, interface, file_path="/tmp/ping.log", target="", **kwargs):
        target = target if target else self.lib.get_ip_address_ping_check(ipv6=False)
        return self.lib.start_continuous_flood_ping(interface, file_path, target, **kwargs)

    def stop_continuous_flood_ping(self, proc_id, file_path="/tmp/ping.log", **kwargs):
        return self.lib.stop_continuous_flood_ping(proc_id, file_path, **kwargs)

    def start_continuous_ping(self, interface, file_path="/tmp/ping.log", wait="1", target="", **kwargs):
        target = target if target else self.lib.get_ip_address_ping_check(ipv6=False)
        return self.lib.start_continuous_ping(interface, file_path, wait, target, **kwargs)

    def stop_continuous_ping(self, file_path="/tmp/ping.log", target="", threshold=2, **kwargs):
        target = target if target else self.lib.get_ip_address_ping_check(ipv6=False)
        return self.lib.stop_continuous_ping(file_path, target, threshold, **kwargs)

    def get_mac(self, ifname="", **kwargs):
        """Get wifi MAC address"""
        response = self.lib.get_mac(ifname, **kwargs)
        # Cloud API requires lowercase only
        return self.get_stdout(response, **kwargs).lower()

    def reboot(self, **kwargs):
        """Reboot client(s)"""
        response = self.lib.reboot(**kwargs)
        return self.get_stdout(response, **kwargs)

    def set_hostname(self, new):
        response = self.lib.set_hostname(new)
        return self.get_stdout(response, skip_exception=True)

    def get_architecture(self, **kwargs):
        response = self.lib.get_architecture(**kwargs)
        return self.get_stdout(response, **kwargs)

    def check_chariot(self, **kwargs):
        response = self.lib.check_chariot(**kwargs)
        return self.get_stdout(response, **kwargs)

    def get_eth_info(self, timeout=10, **kwargs):
        response = self.lib.get_eth_info(timeout=timeout, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_wlan_information(self, **kwargs):
        response = self.lib.get_wlan_information(**kwargs)
        return self.get_stdout(response, **kwargs)

    def get_bt_info(self, **kwargs):
        response = self.lib.get_bt_info(**kwargs)
        return self.get_stdout(response, **kwargs)

    def prepare_bt(self, **kwargs):
        response = self.lib.prepare_bt(**kwargs)
        return self.get_stdout(response, **kwargs)

    def set_tx_power(self, tx_power, ifname="", **kwargs):
        response = self.lib.set_tx_power(tx_power, ifname, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_tx_power(self, ifname="", **kwargs):
        response = self.lib.get_tx_power(ifname, **kwargs)
        return int(self.get_stdout(response, **kwargs))

    def get_max_tx_power(self, ifname="", **kwargs):
        """
        Get max Tx power value wifi iface
        Args:
            ifname: (str) name of wifi interface
            **kwargs:

        Returns: (str) max Tx power [dBm]
        """
        result = self.lib.get_max_tx_power(ifname, **kwargs)
        return int(self.get_stdout(result, **kwargs))

    def get_min_tx_power(self, ifname="", **kwargs):
        """
        Get min Tx power value for wifi iface
        Args:
            ifname: (str) name of wifi interface
            **kwargs:

        Returns: (str) min Tx power [dBm]
        """
        result = self.lib.get_min_tx_power(ifname, **kwargs)
        return int(self.get_stdout(result, **kwargs))

    def get_frequency(self, ifname="", **kwargs):
        response = self.lib.get_frequency(ifname, **kwargs)
        return self.get_stdout(response, **kwargs)

    def create_ap(self, channel, ifname="", ssid="test", extra_param="", country=None, **kwargs):
        if country is None:
            if self.lib.config.get("loc_region"):
                country = self.lib.config.get("loc_region")
            else:
                log.warning("Country code not provided, using US")
                country = "US"

        # there is no country code like EU, so we need to switch do DE
        country = "DE" if country == "EU" else country
        response = self.lib.create_ap(channel, ifname, ssid, extra_param, country=country, **kwargs)
        return self.get_stdout(response, **kwargs)

    def disable_ap(self, ifname="", **kwargs):
        response = self.lib.disable_ap(ifname, **kwargs)
        return self.get_stdout(response, **kwargs)

    def refresh_ip_address(
        self,
        iface=None,
        ipv4=True,
        ipv6=False,
        ipv6_stateless=False,
        timeout=10,
        reuse=False,
        static_ip=None,
        clear_dhcp=True,
        **kwargs,
    ):
        response = self.lib.refresh_ip_address(
            iface, ipv4, ipv6, ipv6_stateless, timeout, reuse, static_ip, clear_dhcp, **kwargs
        )
        self.get_stdout(response, **kwargs)
        return False if response[0] else True

    def set_mac(self, interface, new_mac, **kwargs):
        response = self.lib.set_mac(interface, new_mac, **kwargs)
        setattr(self.lib, f"{interface}_mac", new_mac)
        return self.get_stdout(response, **kwargs)

    def restore_mac_address(self, ifname, **kwargs):
        response = self.lib.restore_mac_address(ifname, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_region(self, **kwargs):
        response = self.lib.get_region(**kwargs)
        return self.get_stdout(response, **kwargs)

    def set_ip_address(self, ip, netmask="255.255.255.0", iface=None, **kwargs):
        response = self.lib.set_ip_address(ip, netmask, iface, **kwargs)
        return self.get_stdout(response, **kwargs)

    def start_mqtt_broker(self, **kwargs):
        response = self.lib.start_mqtt_broker(**kwargs)
        return self.get_stdout(response, **kwargs)

    def stop_mqtt_broker(self, **kwargs):
        response = self.lib.stop_mqtt_broker(**kwargs)
        return self.get_stdout(response, **kwargs)

    def set_tb_nat(self, mode, **kwargs):
        """
        Set NAT mode for the Test Bed on the rpi-server
        mode: (str) NAT64 or NAT66
        """
        response = self.lib.set_tb_nat(mode, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_tb_nat(self, **kwargs):
        """
        Get NAT mode for the Test Bed on the rpi-server
        """
        response = self.lib.get_tb_nat(**kwargs)
        return self.get_stdout(response, **kwargs)

    def start_selenium_server(self, port=4444, **kwargs):
        response = self.lib.start_selenium_server(port, **kwargs)
        return self.get_stdout(response, **kwargs)

    def change_driver_settings(self, ifname, settings, **kwargs):
        response = self.lib.change_driver_settings(ifname, settings, **kwargs)
        return self.get_stdout(response, **kwargs)

    def recover_namespace_service(self, **kwargs):
        res = self.lib.recover_namespace_service(**kwargs)
        return False if res[0] else True

    def get_stored_mac_address(self, iface="", **kwargs):
        """Get stored MAC address to avoid ssh call. If not stored do ssh call"""
        iface = iface if iface else self.get_wlan_iface(skip_exception=True)
        iface = iface if iface else self.get_eth_iface(skip_exception=True)
        assert iface, "No interface found"
        client_mac = (
            getattr(self.lib, f"{iface}_mac", None)
            if getattr(self.lib, f"{iface}_mac", None)
            else self.get_mac(iface, **kwargs)
        )
        return client_mac

    def get_ble_pair_token(self, serial_id, timeout=180, **kwargs):
        response = self.lib.get_ble_pair_token(serial_id, timeout, **kwargs)
        return self.get_stdout(response, **kwargs)

    def send_cfg_via_ble(self, serial_id, ble_pin, cfg_data, timeout=180, **kwargs):
        response = self.lib.send_cfg_via_ble(serial_id, ble_pin, cfg_data, timeout, **kwargs)
        return self.get_stdout(response, **kwargs)

    def set_skip_ns_flag(self, status):
        self.lib.set_skip_ns_flag(status)

    def get_default_mac_address(self, ifname, **kwargs):
        response = self.lib.get_default_mac_address(ifname, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_temperature(self, **kwargs):
        response = self.lib.get_temperature(**kwargs)
        stdout = self.get_stdout(response, **kwargs)
        if stdout:
            stdout = int(int(stdout) / 1000)
        return stdout

    def make_dir(self, path, **kwargs):
        response = self.lib.make_dir(path, **kwargs)
        return self.get_stdout(response, **kwargs)

    def remove_dir(self, path, **kwargs):
        assert " " not in path, "Whitespace is not allowed in path"
        response = self.lib.remove_dir(path, **kwargs)
        return self.get_stdout(response, **kwargs)

    def remove_file(self, path, **kwargs):
        assert " " not in path, "Whitespace is not allowed in path"
        response = self.lib.remove_file(path, **kwargs)
        return self.get_stdout(response, **kwargs)

    def list_files(self, path, **kwargs):
        response = self.lib.list_files(path, **kwargs)
        if response[0]:
            return []
        return self.get_stdout(response, **kwargs).splitlines()

    def get_pid_by_cmd(self, cmd, **kwargs):
        response = self.lib.get_pid_by_cmd(cmd, **kwargs)
        return self.get_stdout(response, **kwargs)

    def clear_adt(self, ifname="", **kwargs):
        response = self.lib.clear_adt(ifname, **kwargs)
        return self.get_stdout(response, **kwargs)

    # PROPERTIES FOR STORED DATA
    @property
    def mac(self):
        # Cloud API requires lowercase only
        return self.get_stored_mac_address().lower()

    @property
    def type(self):
        return self.config_type()

    @property
    def nickname(self):
        return self.get_nickname()

    @property
    def eth_ifname(self):
        return self.get_eth_iface()

    @property
    def wlan_ifname(self):
        return self.get_wlan_iface()

    @property
    def ifname(self):
        if self.lib.device.config.get("eth"):
            return self.get_eth_iface()
        return self.get_wlan_iface()
