import time
import os
import json
import pytest
import urllib.request
from typing import Union, TYPE_CHECKING
from uuid import UUID

from lib_testbed.generic import WAN_VLAN
from lib_testbed.generic.util.request_handler import parse_request
from lib_testbed.generic.util.ssh.device_api import DeviceApi
from lib_testbed.generic.util.allure_util import AllureUtil
from lib_testbed.generic.util.common import (
    get_git_revision,
    mark_failed_recovery_attempt,
    get_target_pytest_mark,
    ALL_MARKERS_NAME,
)
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.ssh.sshexception import SshException
from lib_testbed.generic.switch.switch_api_resolver import SwitchApiResolver
from lib_testbed.generic.util.object_resolver import ObjectResolver
from lib_testbed.generic.rpower.rpowerlib import PowerControllerApi


class PodApi(DeviceApi):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.lib = self.initialize_device_lib(**kwargs)
        self.ovsdb = self.lib.ovsdb
        self.msg = self.lib.msg
        # self.ovsdb_helper = self.lib.ovsdb_helper
        self.iface = self.lib.iface
        self.capabilities = self.lib.capabilities
        self.log_catcher = self.lib.log_catcher

        if TYPE_CHECKING:
            from lib_testbed.generic.pod.generic.pod_lib import PodLib

            self.lib = PodLib()

    @parse_request
    def setup_class_handler(self, request):
        if not self.lib.device or not request or request.config.option.skip_init:
            return
        # Perform actions for device which is marked as main object
        self.setup_class_handler_main_object(request)

    @parse_request
    def setup_method_handler(self, request):
        super().setup_method_handler(request=request)

    @parse_request
    def setup_class_handler_main_object(self, request):
        if not self.lib.main_object:
            return

        if not self.lib.get_stdout(self.lib.uptime(timeout=20), skip_exception=True):
            self.pod_recovery()

        self.auto_limit_tx_power()
        self.set_wano_configuration()
        name = self.get_nickname()
        log.info(f"Pod{'s' if self.lib.multi_devices else ''}: {name} has management access")

        if not request:
            return
        # save FW versions for main object
        version = self.version()
        region = self.get_region(skip_exception=True)
        AllureUtil(request.config).add_allure_group_envs(
            f"node_{self.serial}", "version", version, f"file://{self.serial}", fixed_value=True
        )
        AllureUtil(request.config).add_allure_group_envs(
            f"node_{self.serial}", "model", self.model, f"file://{self.serial}", fixed_value=True
        )
        if region:
            AllureUtil(request.config).add_allure_group_envs(
                f"node_{self.serial}", "region", region, f"file://{self.serial}"
            )
        git_ver = get_git_revision()
        if git_ver:
            AllureUtil(request.config).add_environment("git_sha", git_ver, "_error")

    @parse_request
    def teardown_class_handler(self, request):
        if not self.lib.device or not request or request.config.option.skip_init:
            super().teardown_class_handler(request)
            return
        # Perform actions for device which is marked as main object
        self.teardown_class_handler_main_object(request=request)

    @parse_request
    def teardown_class_handler_main_object(self, request):
        if not self.lib.main_object:
            super().teardown_class_handler(request)
            return

        # check if FW is correct
        timeout = 2 * 60
        start_time = time.time()
        cur_version = None
        first_loop = True
        # it's quite important to check it, so do it in loop in case pod reboots
        while time.time() - start_time < timeout:
            try:
                cur_version = self.version(skip_exception=True)
            except SshException:
                pass
            if cur_version:
                if not first_loop:
                    log.info(f"[{self.get_nickname()}] Management access ready")
                break
            if first_loop:
                log.warning(f"[{self.get_nickname()}] teardown. Waiting for management access {timeout}s..")
                first_loop = False
            time.sleep(5)
        # skip restoring FW for residential GW since we cannot upgrade them anyway
        if self.lib.device.config["capabilities"]["device_type"] == "residential_gateway":
            super().teardown_class_handler(request)
            return
        if request:
            exp_ver = AllureUtil(request.config).get_allure_group_env(f"node_{self.serial}", "version")
        else:
            exp_ver = None
        try:
            if cur_version and exp_ver and cur_version != exp_ver:
                log.warning(
                    f"Test ended with incorrect FW version: {cur_version}, expected version: {exp_ver}.\n"
                    f"Checking if upgrade can be performed"
                )
                self._teardown_restore_fw(exp_ver)
        finally:
            super().teardown_class_handler(request)

    def _teardown_restore_fw(self, exp_ver):
        if cloud_obj := self.lib.get_custbase():
            cloud_obj.clear_target_matrix()
        else:
            log.warning("Can not disable upgrading FW in the Frontline")

        ret = self.lib.upgrade(exp_ver)
        if ret[0]:
            log.error(f"Restoring FW failed:\n{ret}")
            pytest.exit(f"Cannot restore {exp_ver} on the {self.nickname}, stopping test execution")

    @staticmethod
    def initialize_device_lib(**kwargs):
        model = "no_mgmt_access"
        wifi_vendor = "no_mgmt_access"
        if kwargs["dev"].device:
            wifi_vendor = kwargs["dev"].device.config["capabilities"]["wifi_vendor"]
            assert wifi_vendor, "Can not get wifi vendor from the capabilities device config"
            model = kwargs["dev"].device.config["model"]
        file_name = "pod_lib.py"
        _class = ObjectResolver.resolve_pod_class(file_name=file_name, model=model, wifi_vendor=wifi_vendor)
        return _class(**kwargs)

    def pod_recovery(self):
        name = self.get_nickname()
        pod_prefix = "Pod{}".format("s" if self.lib.multi_devices else "")

        resp = self.lib.recover()
        if not resp[0] and self.lib.get_stdout(self.lib.uptime(timeout=10), skip_exception=True):
            log.info(f"Pod recover has been finished successfully on {name}")
            return

        # Before run rpower action check switch configuration
        if self.lib.config.get("Switch"):
            switch = SwitchApiResolver(**{"config": self.lib.config})
            log.info(f"Running switch recovery on {name} node with switch configuration")
            switch.recovery_switch_configuration(name)
            log.info("Check again management access after switch recovery")
            if self.lib.get_stdout(self.lib.uptime(timeout=10), skip_exception=True):
                log.info(f"Recovery has been finished successfully on {name} node")
                return

        if not self.lib.config.get("rpower"):
            assert False, f"{pod_prefix}: {name} has no management access and rpower section is " f"missing in config"

        # get all rpower aliases for getting pods which are connected to rpower
        rpower = PowerControllerApi(self.lib.config)
        rpower_pods = rpower.get_nodes_devices()
        assert name in rpower_pods, f"{pod_prefix}: {name} without management access has no configured rpower"
        log.info(f"{pod_prefix} {name} has no management access")
        log.info(f"Check last operation on rpower for: {name}")
        last_request_time = rpower.get_last_request_time(name)[name]
        rpower_status = rpower.status(name)[name]
        if -1 < last_request_time < 120 and rpower_status == "ON":
            log.warning(
                f"Skip changing rpower status due to that last operation has been done"
                f" {last_request_time} seconds ago"
            )
        else:
            log.info(f"Power cycling not accessible pod: {name}")
            rpower.off(name)
            # Some models need more time to power off
            time.sleep(15)
            rpower.on(rpower.get_all_devices())
            # recover once again
            resp = self.lib.recover()
            if not resp[0]:
                uptime_result = self.lib.get_stdout(self.lib.uptime(timeout=10), skip_exception=True)
                if uptime_result:
                    log.info(f"Pod recover has been finished successfully on {name}")
        log.info("Check again if pod has management access")
        timeout = time.time() + (60 * 3)
        while time.time() < timeout:
            uptime_result = self.lib.get_stdout(self.lib.uptime(timeout=3, skip_logging=True), skip_exception=True)
            if uptime_result:
                break
            time.sleep(5)
        else:
            mark_failed_recovery_attempt(tb_config=self.lib.config)
            assert False, f"Pod name: {name} has no management access. " f"Can't recover {name} pod by power cycle"
        log.info(f"{pod_prefix}: {name} successfully recovered")

    def set_wano_configuration(self):
        if not hasattr(self, ALL_MARKERS_NAME) or self.obj_name.get("name", "") != "gw":
            return
        wan_connection = get_target_pytest_mark(self.all_markers, "wan_connection")
        vlan_id = getattr(wan_connection, "kwargs", {}).get("vlan_id", 200)
        tagged = getattr(wan_connection, "kwargs", {}).get("tagged", False)
        wan_vlan = WAN_VLAN(vlan_id)
        expected_config = wan_vlan.tagged_wano_config if tagged else wan_vlan.wano_config
        current_config = self.get_wano_cfg(skip_exception=True) or expected_config
        if current_config != expected_config:
            prefix = "tagged" if tagged else "untagged"
            log.info(f"Setting wan orchestrator configuration on {self.nickname} pod for {prefix} {wan_vlan} vlan")
            self.set_wano_cfg(expected_config)

    def auto_limit_tx_power(self):
        if "LimitTxPower" not in self.lib.config.get("capabilities", []):
            return
        self.lib.set_tx_power(5, skip_exception=True)

    def get_stdout(self, result, skip_exception=False, **_kwargs):
        """Returns the second element of result which is stdout. Validate return value"""
        return self.lib.get_stdout(result, skip_exception=skip_exception)

    def run(self, cmd, **kwargs):
        return super().run(cmd, **kwargs)

    def get_opensync_path(self, **kwargs):
        """Get path to opensync"""
        response = self.lib.get_opensync_path(**kwargs)
        return self.get_stdout(response, **kwargs)

    def ping(self, host=None, v6=False, **kwargs):
        """Ping"""
        response = self.lib.ping(host, v6=v6, **kwargs)
        skip_exception = kwargs.pop("skip_exception") if "skip_exception" in kwargs else True
        return self.get_stdout(response, skip_exception=skip_exception, **kwargs)

    def reboot(self, **kwargs):
        """Reboot node(s)"""
        response = self.lib.reboot(**kwargs)
        return self.get_stdout(response, **kwargs)

    def version(self, **kwargs):
        """Display firmware version of node(s)"""
        return self.get_stdout(self.lib.version(**kwargs), **kwargs)

    def platform_version(self, **kwargs):
        """Display platform version of node(s)"""
        return self.get_stdout(self.lib.platform_version(**kwargs), **kwargs)

    def opensync_version(self, **kwargs) -> str:
        """Display opensync version of node(s)"""
        return self.get_stdout(self.lib.opensync_version(**kwargs), **kwargs)

    def uptime(self, timeout=20, **kwargs):
        """Display uptime of node(s)"""
        response = self.lib.uptime(timeout, **kwargs)
        if kwargs.get("out_format"):
            del kwargs["out_format"]
        return self.get_stdout(response, **kwargs)

    def get_datetime(self, **kwargs):
        """
        Get current datetime
        :return: date as python datetime object
        """
        return self.lib.get_datetime(**kwargs)

    def set_datetime(self, date_time, **kwargs):
        """
        Set date
        :param date_time: python datetime object
        """
        return self.lib.set_datetime(date_time, **kwargs)

    def get_file(self, remote_file, location, **kwargs):
        """Copy a file from node(s)"""
        response = self.lib.get_file(remote_file, location, **kwargs)
        return self.get_stdout(response, **kwargs)

    def put_file(self, file_name, location, **kwargs):
        """Copy a file onto device(s)"""
        response = self.lib.put_file(file_name, location, **kwargs)
        return self.get_stdout(response, **kwargs)

    def restart(self, **kwargs):
        """Restart managers on node(s)"""
        response = self.lib.restart(**kwargs)
        return self.get_stdout(response, **kwargs)

    def healthcheck_stop(self, **kwargs):
        """Stop healthcheck on pod"""
        response = self.lib.healthcheck_stop(**kwargs)
        return self.get_stdout(response, **kwargs)

    def healthcheck_start(self, **kwargs):
        """Start healthcheck on pod"""
        response = self.lib.healthcheck_start(**kwargs)
        return self.get_stdout(response, **kwargs)

    def deploy(self, **kwargs):
        """Deploy files to node(s)"""
        response = self.lib.deploy(**kwargs)
        return self.get_stdout(response, **kwargs)

    def check(self, **kwargs):
        """Pod health check"""
        response = self.lib.check(**kwargs)
        return self.get_stdout(response, **kwargs)

    def enable(self, **kwargs):
        """Enable agent and wifi radios on node(s)"""
        response = self.lib.enable(**kwargs)
        return self.get_stdout(response, **kwargs)

    def disable(self, **kwargs):
        """Disable agent and wifi radios on node(s)"""
        response = self.lib.disable(**kwargs)
        return self.get_stdout(response, **kwargs)

    def get_model(self, **kwargs):
        """Display type of node(s)"""
        return self.get_stdout(self.lib.get_model(**kwargs), **kwargs)

    def bssid(self, bridge="", **kwargs):
        """Display BSSID of node bridge = <br-wan|br-home>-, default both"""
        return [val for val in self.get_stdout(self.lib.bssid(bridge, **kwargs)).split("\n") if val != ""]

    def get_serial_number(self, **kwargs):
        """Get node(s) serial number"""
        return self.get_stdout(self.lib.get_serial_number(**kwargs))

    def connected(self, **kwargs):
        """returns cloud connection state of each node"""
        return self.get_stdout(self.lib.connected(**kwargs))

    def get_ovsh_table(self, table, **kwargs):
        """get ovsh table from pods locally json format"""
        response = self.lib.get_ovsh_table(table, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_ovsh_table_tool(self, table, **kwargs):
        """get ovsh table from pods locally tool format"""
        resposne = self.lib.get_ovsh_table_tool(table, **kwargs)
        return self.get_stdout(resposne, **kwargs)

    def role(self, **kwargs):
        """Node role: return gw or leaf"""
        return self.get_stdout(self.lib.role(**kwargs))

    def get_ips(self, iface, **kwargs):
        """get ipv4 and ipv6 address for desired interface"""
        response = self.lib.get_ips(iface, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_macs(self, **kwargs):
        """get all macs from pod using Wifi_VIF_State table"""
        return self.lib.get_macs(**kwargs)

    def get_logs(self, directory=None, **kwargs):
        """get logs from pods locally"""
        response = self.lib.get_logs(directory, **kwargs)
        return self.get_stdout(response, **kwargs)

    def upgrade(self, image, *args, **kwargs):
        """Upgrade node firmware, Optional: -p=<encyp_key>, -e-> erase certificates, -n->skip version check"""
        response = self.lib.upgrade(image, *args, **kwargs)
        return self.get_stdout(response, **kwargs)

    def sanity(self, *args):
        """run sanity on selected pods, add arg --nocolor for simple output"""
        if self.lib.config.get("runtime_sanity_check", True) is False:
            log.info("Skipping sanity check based on the runtime configuration")
            return {"ret": True}
        return self.lib.sanity(*args)

    def poll_pod_sanity(self, timeout=500, expect=True, *args):
        """Loops sanity on until pass"""
        if self.lib.config.get("runtime_sanity_check", True) is False:
            log.info("Skipping sanity check based on the runtime configuration")
            return 0
        return self.lib.poll_pod_sanity(timeout, expect, *args)

    def clear_crashes(self, **kwargs):
        response = self.lib.clear_crashes(**kwargs)
        return self.get_stdout(response, **kwargs)

    def get_crash(self, **kwargs):
        """get crash log file from node"""
        return self.lib.get_crash(**kwargs)

    def remove_crash(self, **kwargs):
        """
        Remove crashes from device
        Args:
            **kwargs:

        Returns: stdout

        """
        response = self.lib.remove_crash(**kwargs)
        return self.get_stdout(response, **kwargs)

    def trigger_crash(self, **kwargs):
        """
        Trigger crash on the platform
        Args:
            **kwargs:

        Returns: stdout

        """
        response = self.lib.trigger_crash(**kwargs)
        return self.get_stdout(response, **kwargs)

    def kill_manager(self, wait_for_restart=False, soft_kill=False, **kwargs):
        """Kill and restart service managers"""
        response = self.lib.kill_manager(wait_for_restart, soft_kill=soft_kill, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_log_level(self, manager_name, **kwargs):
        """Get logging level for OpenSync manager"""
        return self.lib.get_log_level(manager_name, **kwargs)

    def set_log_level(self, manager_name, level, **kwargs):
        """Set logging level for OpenSync manager"""
        return self.lib.set_log_level(manager_name, level, **kwargs)

    def get_backhauls(self):
        """
        Get information about all backhaul interfaces
        Returns: (dict) {'dev_if_name': {str), 'ssid': (str), 'mac_list': (list), 'associated_clients': (list)}

        """
        return self.lib.iface.get_backhauls()

    def get_radio_temperatures(self, radio: Union[int, str, list] = None, retries=3, **kwargs):
        """
        Args:
            radio: accepted arguments: radio_id(e.g.: 0, 1, ...), band frequency(e.g.: '2.4G', '5G'),
                      list of radio_ids or band frequencies, or use None for all radios
            retries: (int) number of retries in case failed ssh call
            **kwargs:

        Returns: radio temperature as int or list(temperatures are ordered the same as in radio argument if provided,
                 else they are ordered by radio id)

        """
        return self.lib.get_radio_temperatures(radio, retries=retries, **kwargs)

    def upgrade_fw_through_ssh(self, fw_matrix_obj, force=False, reboot_wait=True, **kwargs):
        """
        Upgrade all supports models through ssh
        Args:
            fw_matrix_obj: (list) Firmware matrix objects from cloud which contains models, url, keys etc...
            force: (bool): Upgrade firmware even though the same firmware is already on device
            reboot_wait: (bool): Wait for reboot after upgarde
            **kwargs:

        Returns: (list) Current firmware version on devices.

        """
        model = self.get_model()
        if self.capabilities.get_device_type() == "residential_gateway":
            return [1, "", f"Upgrade through ssh is not supported for {model}"]
        current_version = self.version(skip_exception=True)
        # Get firmware url and key from fw_matrix_obj
        fw_desc = {}
        for fw_model in fw_matrix_obj["models"]:
            fw_ver = fw_model.get("firmwareVersion")
            fw_url = fw_model.get("encryptedDownloadUrl")
            fw_key = fw_model.get("firmwareEncryptionKey")
            _model = fw_model.get("model")
            if not fw_url:
                fw_url = fw_model.get("downloadUrl")
            fw_desc[_model] = {"url": fw_url, "key": fw_key, "fw": fw_ver}

        fw_data = fw_desc.get(model)
        assert fw_data, f"Not found firmware url for {model} from {fw_matrix_obj}"
        if current_version and current_version == fw_data.get("fw") and not force:
            log.info("Skip upgrading, current version is the same as requested")
            return True
        fw_url = fw_data.get("url")
        fw_key = fw_data.get("key")
        log.info(f"Upgrading {model} device with {fw_url}")
        if model == "Plume Pod v1.0":
            cfw = fw_data["fw"].split(".")
            if cfw[0] == "1":
                if "-" in cfw[1]:
                    cfw[1] = cfw[1][0]
                if cfw[1] < "8":
                    log.info("Downgrade requires erasing certificates...")
                    self.lib.erase_certificates()
        fw_file_name = fw_url.split("/")[-1]
        if not os.path.exists("/tmp/automation/"):
            os.makedirs("/tmp/automation/")
        urllib.request.urlretrieve(fw_url, f"/tmp/automation/{fw_file_name}")
        self.put_file(f"/tmp/automation/{fw_file_name}", "/tmp/")
        update_cmd = f"safeupdate -u /tmp/{fw_file_name}"

        if fw_key:
            update_cmd += f' -P "{fw_key}"'
        self.run(update_cmd, timeout=600)

        # Wait for a reboot
        if reboot_wait:
            time.sleep(60)
            self.lib.wait_available(timeout=120)
            time.sleep(10)
        current_version = self.version(timeout=20, skip_exception=True)
        return current_version == fw_data.get("fw")

    def get_eth_link_speed(self, iface, **kwargs):
        """
        Get ethernet link speed
        Args:
            iface: (str) interface name

        Returns: (str) Pod response

        """
        response = self.lib.get_eth_link_speed(iface, **kwargs)
        return self.get_stdout(response, **kwargs)

    def wait_eth_connection_ready(self, timeout=600, **kwargs):
        """
        Wait for disable loop status so that to be ready for connect eth client to device
        :param timeout: (int) timeout in seconds
        :return: (bool) True if eth connection is ready, False if not ready after timeout and skip_exception is True
        """
        return self.lib.wait_eth_connection_ready(timeout, **kwargs)

    def wait_bs_table_ready(self, timeout=60, **kwargs):
        """
        Wait for ovsdb Band_Steering_Clients table to be populated
        :param timeout: Timeout
        :return: (bool) True if bs table is ready, False if not ready after timeout and skip_exception is True
        """
        return self.lib.wait_bs_table_ready(timeout, **kwargs)

    def decrease_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Decrease value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns:

        """
        response = self.lib.decrease_tx_power_on_all_ifaces(percent_ratio, **kwargs)
        return self.get_stdout(response, **kwargs)

    def increase_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Increase value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns:

        """
        response = self.lib.increase_tx_power_on_all_ifaces(percent_ratio, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_tx_power(self, interface, **kwargs):
        """
        Get current Tx power in dBm
        Args:
            interface: (str) Wireless interface

        Returns: (int) Tx power (dBm)

        """
        response = self.lib.get_tx_power(interface, **kwargs)
        return self.get_stdout(response, **kwargs)

    def set_tx_power(self, tx_power=-1, interfaces=None, **kwargs):
        """
        Set current Tx power in dBm
        Args:
            interfaces: (str) or (list) Name of wireless interfaces
            tx_power: (int) Tx power in dBm. Value -1 resets Tx power to default settings

        Returns:

        """
        response = self.lib.set_tx_power(tx_power, interfaces, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_driver_data_rate(self, ifname, mac_address, **kwargs):
        """
        Get current data rate from driver
        Args:
            ifname: (str) Name of interface
            mac_address: (str) MAC address of connected client interface
        Returns:

        """
        response = self.lib.get_driver_data_rate(ifname, mac_address, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_client_tx_rate(self, ifname, client_mac, **kwargs):
        """
        Get client Tx rate in Mbits
        Args:
            ifname: (str)
            client_mac: (str)
            **kwargs:

        Returns: (int) Tx rate (Mbits)

        """
        response = self.lib.get_client_tx_rate(ifname=ifname, client_mac=client_mac, **kwargs)
        return int(float(self.get_stdout(response, **kwargs)))

    def trigger_radar_detected_event(self, **kwargs):
        """
        Trigger radar detected event
        Returns: stdout

        """
        response = self.lib.trigger_radar_detected_event(**kwargs)
        return self.get_stdout(response, **kwargs)

    def get_boot_partition(self, **kwargs):
        """
        Get boot partition name
        Args:
            **kwargs:

        Returns: stdout

        """
        response = self.lib.get_boot_partition(**kwargs)
        return self.get_stdout(response, **kwargs)

    def get_partition_dump(self, partition, **kwargs):
        """
        Get hex dump of the partition
        Args:
            partition: (str) partition name
            **kwargs:

        Returns: stdout

        """
        response = self.lib.get_partition_dump(partition, **kwargs)
        return self.get_stdout(response, **kwargs)

    def is_fw_fuse_burned(self, **kwargs):
        return self.lib.is_fw_fuse_burned(**kwargs)

    def get_cpu_memory_usage(self, **kwargs):
        return self.lib.get_cpu_memory_usage(**kwargs)

    def set_fan_mode(self, status, **kwargs):
        """
        Enable or disable fan on the device
        Args:
            status: (bool)
            **kwargs:

        Returns: stdout

        """
        response = self.lib.set_fan_mode(status, **kwargs)
        return self.get_stdout(response, **kwargs)

    def set_region(self, region, **kwargs):
        """
        Set DFS region
        Args:
            region: (str) EU/US/JP

        Returns: stdout

        """
        response = self.lib.set_region(region=region, **kwargs)
        return self.get_stdout(response, **kwargs)

    def get_region(self, **kwargs):
        """
        Get DFS region
        Returns: stdout

        """
        response = self.lib.get_region(**kwargs)
        return self.get_stdout(response, **kwargs)

    def get_connection_flows(self, ip, **kwargs):
        """
        Get connection flow id for specific IP address
        Args:
            ip: (str) IP address
            **kwargs:

        Returns: (list) flow list

        """
        return self.lib.get_connection_flows(ip, **kwargs)

    def get_radios_interference(self, **kwargs):
        """
        Get interference from each Wi-Fi interface in the DUT
        Args:
            **kwargs:

        Returns: (dict) interference per interface

        """
        try:
            return self.lib.get_radios_interference(**kwargs)
        except Exception as e:
            if kwargs.get("skip_exception", False):
                return {}
            else:
                raise e

    def redirect_stats_to_local_mqtt_broker(self, skip_storage=False, **kwargs):
        """
        Updates AWLAN_Node table and redirects stats to mqtt broker started on rpi-server
        Returns: stdout

        No parameters, since rpi-server IP 192.168.200.1 has to match rpi-server certificates used for TLS.
        """
        response = self.lib.redirect_stats_to_local_mqtt_broker(skip_storage=skip_storage, **kwargs)
        return self.get_stdout(response, **kwargs)

    def restore_stats_mqtt_settings(self, **kwargs):
        """
        Restores original AWLAN_Node settings for mqtt
        Returns: stdout
        """
        response = self.lib.restore_stats_mqtt_settings(**kwargs)
        return self.get_stdout(response, **kwargs)

    def get_managers_list(self, managers_name: Union[str, list] = None, **kwargs):
        """
        Get managers list
        Args:
            managers_name: (str) or (list) Get PID number from provided managers if None get list of all managers
            **kwargs:

        Returns: (dict) {manager_name: pid}

        """
        response = self.lib.get_managers_list(managers_name, **kwargs)
        return response

    def ping_check(self, ipaddr="", count=5, v6=False, fqdn_check=False, **kwargs):
        """Check internet connectivity (ICMP)."""
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
        result = self.lib.fqdn_check(count=count, v6=v6, dns_address=dns_address, **kwargs)
        result = self.get_stdout(result, skip_exception=True)
        return True if result else False

    def populate_fake_clients(self, **kwargs):
        """populate 90 pseudo/fake client entries to "Band_Steering_Clients" OVSDB table"""
        result = self.lib.populate_fake_clients(**kwargs)
        return self.get_stdout(result, **kwargs)

    def set_wano_cfg(self, wano_cfg, **kwargs):
        """Set WANO configuration on node. wano_cfg needs to be a dict."""
        result = self.lib.set_wano_cfg(wano_cfg=wano_cfg, **kwargs)
        return self.get_stdout(result, **kwargs)

    def get_wano_cfg(self, **kwargs):
        """Get WANO configuration from node, as a dict."""
        result = self.lib.get_wano_cfg(**kwargs)
        wano_cfg = self.get_stdout(result, **kwargs)
        return json.loads(wano_cfg) if wano_cfg else ""

    def get_wano_from_ovsdb_storage(self, **kwargs):
        """Get WANO configuration from ovsdb storage, as a dict."""
        result = self.lib.get_wano_from_ovsdb_storage(**kwargs)
        wano_cfg = self.get_stdout(result, **kwargs)
        return json.loads(wano_cfg) if wano_cfg else ""

    def get_wano_cfg_from_persistent_storage(self, **kwargs):
        """Get WANO configuration from persistent storage, as a dict."""
        result = self.lib.get_wano_cfg_from_persistent_storage(**kwargs)
        wano_cfg = self.get_stdout(result, **kwargs)
        return json.loads(wano_cfg) if wano_cfg else ""

    def set_wano_cfg_to_persistent_storage(self, wano_cfg, **kwargs):
        """Set WANO configuration to persistent storage on node. wano_cfg needs to be a dict."""
        result = self.lib.set_wano_cfg_to_persistent_storage(wano_cfg=wano_cfg, **kwargs)
        return self.get_stdout(result, **kwargs)

    def set_wano_cfg_to_ovsdb_storage(self, wano_cfg, **kwargs):
        """Set WANO configuration to ovsdb storage on node. wano_cfg needs to be a dict."""
        result = self.lib.set_wano_cfg_to_ovsdb_storage(wano_cfg=wano_cfg, **kwargs)
        return self.get_stdout(result, **kwargs)

    def start_wifi_blast(
        self,
        plan_id=None,
        blast_duration=None,
        blast_packet_size=None,
        blast_sample_count=None,
        step_id_and_dest: list = None,
        threshold_cpu=None,
        threshold_mem=None,
        **kwargs,
    ):
        """Start WiFi Blast through ovsdb api"""
        return self.lib.start_wifi_blast(
            plan_id=plan_id,
            blast_duration=blast_duration,
            blast_packet_size=blast_packet_size,
            blast_sample_count=blast_sample_count,
            step_id_and_dest=step_id_and_dest,
            threshold_cpu=threshold_cpu,
            threshold_mem=threshold_mem,
            **kwargs,
        )

    def get_wifi_associated_clients(self, **kwargs):
        """Get all connected WiFi Clients"""
        return self.get_stdout(self.lib.get_wifi_associated_clients(**kwargs), **kwargs)

    def get_node_services(self, **kwargs):
        """Get all configured services from Node_Services table"""
        return self.get_stdout(self.lib.get_node_services(**kwargs), **kwargs)

    def get_sta_wifi_vif_mac(self, **kwargs):
        """Get MAC entry from Wifi_VIF_State where mode=sta"""
        return self.get_stdout(self.lib.get_sta_wifi_vif_mac(**kwargs), **kwargs)

    def get_parent_wifi_vif_mac(self, **kwargs):
        """Get parent entry from Wifi_VIF_State where mode=sta"""
        return self.get_stdout(self.lib.get_parent_wifi_vif_mac(**kwargs), **kwargs)

    def get_memory_information(self, **kwargs):
        """Get Memory Information of POD"""
        return self.get_stdout(self.lib.get_memory_information(**kwargs), **kwargs)

    def check_traffic_acceleration(
        self, ip_address, expected_protocol=6, multicast=False, flow_count=1, flex=False, **kwargs
    ):
        """
        Check traffic acceleration
        Args:
            ip_address: (list) IP addresses to check
            expected_protocol: (int) expected protocol id. 6 for TCP, 17 for UDP
            multicast: (bool) True to check for acceleration of multicast traffic
            flow_count: (int) minimum number of expected accelerated flows (connections)
            flex: (bool) True to check for acceleration of Flex traffic
            **kwargs:

        Returns: bool()

        """
        return self.lib.check_traffic_acceleration(
            ip_address=ip_address,
            expected_protocol=expected_protocol,
            multicast=multicast,
            flow_count=flow_count,
            flex=flex,
            **kwargs,
        )

    def configure_wifi_radio(self, freq_band: str, channel: int, ht_mode: str, **kwargs):
        """
        Configure wifi radio by manipulating Wifi_Radio_Config table
        Args:
            freq_band: (str)
            channel: (int)
            ht_mode: (str)
            **kwargs:

        Returns: std_out

        """
        response = self.lib.configure_wifi_radio(freq_band=freq_band, channel=channel, ht_mode=ht_mode, **kwargs)
        return self.get_stdout(result=response, **kwargs)

    def get_wps_keys(self, if_name: str) -> dict[str, str]:
        """Returns WPS keys."""
        return self.lib.get_wps_keys(if_name=if_name)

    def start_wps_session(self, key_id: str) -> bool:
        """Starts WPS session on pod.

        Args:
            key_id: the WPS key id.

        Returns:
            True when starting of the WPS session was successful."""
        return self.lib.start_wps_session(key_id=key_id)

    def eth_connect(self, pod_name: str):
        """
        Connect Specified pod to Ethernet pod.

        Args:
            pod_name: (pod_api) pod object to connect to
        Returns: None
        """
        return self.lib.eth_connect(pod_name=pod_name)

    def eth_disconnect(self):
        """Disconnect Specified pod from Ethernet."""
        return self.lib.eth_disconnect()

    def get_parsed_conntrack_entries(self, raw_conntrack_entries: str, ipv6: bool = False) -> dict:
        """
        Get parsed conntrack entries and group them by protocol
        Args:
            raw_conntrack_entries: (str) raw conntrack entries: conntrack -L
            ipv6: (bool) ipv6 mode for getting conntrack entries

        Returns: (dict) {used_protocol: list(), ...}

        """
        return self.lib.get_parsed_conntrack_entries(raw_conntrack_entries=raw_conntrack_entries, ipv6=ipv6)

    def get_pid_by_cmd(self, cmd: str, **kwargs) -> str:
        """Get pid by provided cmd string"""
        result = self.lib.get_pid_by_cmd(cmd=cmd, **kwargs)
        cmd_pid = self.get_stdout(result, **kwargs)
        return cmd_pid

    def stop_sending_mqtt(self, **kwargs) -> str:
        """Stop sending mqtt on the pod"""
        response = self.lib.stop_sending_mqtt(**kwargs)
        return self.get_stdout(result=response, **kwargs)

    def get_client_snr(self, ifname: str, client_mac: str, **kwargs) -> str:
        """Get SNR level of the connected client"""
        response = self.lib.get_client_snr(ifname=ifname, client_mac=client_mac, **kwargs)
        return self.get_stdout(result=response, **kwargs)

    def get_beacon_interval(self, ifname: str = None, **kwargs) -> str:
        """Get Beacon Internal from the Wi-Fi driver"""
        if ifname is None:
            ifname = self.capabilities.get_bhaul_ap_ifnames(return_type=list, freq_band="2.4G")[0]
        response = self.lib.get_beacon_interval(ifname=ifname, **kwargs)
        return self.get_stdout(result=response, **kwargs)

    def is_linux_snd(self) -> bool:
        """Check if LinuxSDN is enabled"""
        ovs_version = self.ovsdb.get_str(table="AWLAN_Node", select="ovs_version", skip_exception=True)
        return ovs_version == "N/A"

    # PROPERTIES FOR STORED DATA
    @property
    def model(self):
        return self.get_model()

    @property
    def serial(self):
        return self.get_serial_by_name("Nodes", self.get_nickname())

    @property
    def nickname(self):
        return self.get_nickname()

    class OvsdbApi:
        def __init__(self, pod_api):
            self.pod_api = pod_api

        def get_int(
            self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False
        ) -> Union[int, list]:
            return self.pod_api.lib.ovsdb.get_int(table, select, where, skip_exception, return_list)

        def get_bool(
            self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False
        ) -> Union[bool, list]:
            return self.pod_api.lib.ovsdb.get_bool(table, select, where, skip_exception, return_list)

        def get_str(
            self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False
        ) -> Union[str, list]:
            return self.pod_api.lib.ovsdb.get_str(table, select, where, skip_exception, return_list)

        def get_map(
            self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False
        ) -> Union[dict, list]:
            return self.pod_api.lib.ovsdb.get_map(table, select, where, skip_exception, return_list)

        def get_set(
            self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False
        ) -> list:
            return self.pod_api.lib.ovsdb.get_set(table, select, where, skip_exception, return_list)

        def get_uuid(
            self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False
        ) -> Union[UUID, list]:
            return self.pod_api.lib.ovsdb.get_uuid(table, select, where, skip_exception, return_list)

        def set_value(self, value: dict, table: str, where: Union[str, list] = None, skip_exception=False):
            return self.pod_api.lib.ovsdb.set_value(value, table, where, skip_exception)

        def delete_row(self, table: str, where: Union[str, list] = None, skip_exception=False):
            return self.pod_api.lib.ovsdb.delete_row(table, where, skip_exception)

        def get_name(self):
            return "ovsdb_api"
