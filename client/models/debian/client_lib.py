import random
import os
import re
import uuid
import time
import shutil

from multiprocessing import Lock
from distutils.version import StrictVersion

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.client.models.generic.client_lib import ClientLib as ClientLibGeneric
from lib_testbed.generic.client.models.rpi.client_tool import ClientTool
from lib_testbed.generic.client.models.generic.client_lib import (
    UPGRADE_DIR,
    UPGRADE_LOCAL_CACHE_DIR,
    TESTBED_IMAGES_PUBLIC_URL,
)


NEW_DHCP_RESERVATION_PATH = "/tools/dhcp/dhcp_reservation.py"
OLD_DHCP_RESERVATION_PATH = "/home/plume/dhcp/dhcp_reservation.py"
NEW_SET_TB_NAT_PATH = "/tools/set-tb-nat"
OLD_SET_TB_NAT_PATH = "/home/plume/config-files/switch-NAT6.sh"
NEW_NAT_MODE_PATH = "/etc/ipv6.nat.mode"
OLD_NAT_MODE_PATH = "/home/plume/.nat6_mode"


class ClientLib(ClientLibGeneric):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.tool = ClientTool(lib=self)

    def upgrade(
        self,
        fw_path=None,
        restore_cfg=True,
        force=False,
        http_address="",
        download_locally=True,
        version=None,
        restore_files=None,
        mirror_url=None,
        **kwargs,
    ):
        """
        Upgrade raspberry clients to target firmware if fw_path=None download latest build version from artifactory
        Args:
            fw_path: (str) Path to image
            force: (bool) Flash image even though the same firmware is already on the device
            restore_cfg: (bool) Restore a client configuration (hostname, dhcpd.conf)
            http_address: (str) Start download image directly from provided HTTP server address
            download_locally: (bool) If True download upgrade files to local machine
            version: (str) version to download from the S3 (or get latest or stable version)
            restore_files: (str): Paths of files to restore. e.g. restore_files=/home/plume/file1,/etc/file2
            mirror_url (str): url to mirror with upgrade files
            **kwargs:

        Returns: (ret_val, std_out, str_err)

        """
        self.run_command("rm -R %s" % UPGRADE_DIR)
        # short sleep to spread threads in time
        time.sleep(random.randint(1, 10) / 10)
        debian_upgrade = DebianClientUpgrade(
            lib=self,
            restore_cfg=restore_cfg,
            download_locally=download_locally,
            restore_files=restore_files,
            mirror_url=mirror_url,
        )
        if http_address:
            if debian_upgrade.device_type not in http_address:
                return [
                    20,
                    "",
                    f"Provided upgrade package is not intended for {debian_upgrade.device_type}: {http_address}",
                ]
            fw_path = debian_upgrade.download_image_from_url(http_address)
        if fw_path and not os.path.isabs(fw_path):
            fw_path = os.path.abspath(fw_path)
        return debian_upgrade.start_upgrade(fw_path, force, version, **kwargs)

    def start_mqtt_broker(self, **kwargs):
        log.info("Starting mosquito (mqtt broker) on the %s" % self.get_nickname())
        self.run_command("sudo systemctl restart mosquitto.service", **kwargs)
        out = self.is_mqtt_broker_started(**kwargs)
        if out[0] == 0:
            return [0, "Mosquito started successfully", ""]
        else:
            out = self.run_command("tail -30 /var/log/mosquitto/mosquitto.log", **kwargs)
            return [1, "", out[1]]

    def stop_mqtt_broker(self, **kwargs):
        # Do nothing, local mqtt broker shouldn't be disabled
        return [0, "", ""]

    def is_mqtt_broker_started(self, **kwargs):
        out = self.run_command("sudo systemctl status mosquitto.service", **kwargs)
        return out

    def set_tb_nat(self, mode, **kwargs):
        """
        Set testbed's IPv6 NAT mode on testbed's server
        mode: (str) NAT64 or NAT66
        """
        assert mode in ["NAT64", "NAT66"]
        assert self.name == "host", "NAT mode for the testbed can be set only on testbed server (host)"
        if self.run_command(f"test -x {NEW_SET_TB_NAT_PATH}", **kwargs)[0] == 0:
            set_tb_nat = NEW_SET_TB_NAT_PATH
        else:
            set_tb_nat = OLD_SET_TB_NAT_PATH
        out = self.run_command(f"sudo {set_tb_nat} {mode}", **kwargs)
        # there is a reboot at the end, which kills SSH, so 255 is positive
        if out[0] not in [0, 255]:
            return out
        # override 255 to 0
        out[0] = 0
        # self.wait_available(2 * 60) -> is not working for the rpi server
        time.sleep(2 * 60)
        tayga = self.run_command("sudo service tayga status")
        if mode == "NAT64":
            tayga_state = "Active: active (running)"
        else:
            tayga_state = "Active: inactive (dead)"
        tayga[0] = 0 if tayga_state in tayga[1] else 3
        return self.merge_result(out, tayga)

    def get_tb_nat(self, **kwargs):
        """
        Get testbed's IPv6 NAT mode from testbed's server
        """
        if self.run_command(f"test -r {NEW_NAT_MODE_PATH}", **kwargs)[0] == 0:
            mode_file = NEW_NAT_MODE_PATH
        else:
            mode_file = OLD_NAT_MODE_PATH
        ret = self.run_command(f"cat {mode_file}", **kwargs)
        ret[1] = ret[1].strip()
        return ret

    def testbed_dhcp_reservation(self, **kwargs):
        """
        Create dhcp reservation for testbed devices
        """
        if self.run_command(f"test -x {NEW_DHCP_RESERVATION_PATH}")[0] == 0:
            dhcp_reservation = NEW_DHCP_RESERVATION_PATH
        else:
            dhcp_reservation = OLD_DHCP_RESERVATION_PATH
        return self.run_command(f"sudo {dhcp_reservation}", timeout=300, **kwargs)

    def limit_tx_power(self, state=True, value=None, **kwargs):
        """
        Limit Wi-Fi TX power on the devices in the testbed
        state: (bool) Enable/disable Tx power modification
        """
        if state:
            cmd = f"echo {value} | sudo tee /.tx_power_enable.flag" if value else "sudo touch /.tx_power_enable.flag"
            out = self.run_command(cmd, **kwargs)
            if out[0]:
                return out
            out[1] = "Please reboot your nodes to make it happen"
        else:
            out = self.run_command("sudo rm /.tx_power_enable.flag", **kwargs)
            if "No such file or directory" in out[2]:
                return [0, "Limiting TX power was not enabled", ""]
        return out

    def get_tx_power_limit(self, **kwags):
        """Get Wi-Fi TX power setting."""
        ret = self.run_command("sudo cat /.tx_power_enable.flag")
        if ret[0]:
            return [0, "Limiting is disabled", ""]
        # if file exists, but it's empty older version of limiting is used and it has fixed value 1
        tx_limit = ret[1].strip() if ret[1] else 1
        return [0, f"Limit set to {tx_limit}", ""]

    def set_bandwidth_limit(
        self,
        *values: int,
        duration: int = 30,
        repeats: int = 10,
        interface: str | None = None,
        queue_size: int | None = None,
        **kwargs,
    ) -> list[int, str, str]:
        """
        Limit bandwidth on testbed server's `interface` to each of the `values` for ˙duration` seconds, `repeats` times.

        Numbers in `values` specify bandwidth limit in megabits per second.

        `duration` is in seconds, each of the limits in `values` will be active for that many seconds.

        The whole cycle of limits in `values` will be repeated `repeats` times.

        `interface` must be one of server's eth0.2xy WAN VLAN uplink interfaces, unless None. If None, WAN VLAN
        interface to which gateway pod is connected will be used, or eth0.200, if gateway's uplink is unknown.

        If `queue_size` is specified, it will be set to that value, in bytes.
        """
        version = self.version()[1]
        short = self.version(short=True)[1]
        if "server" not in version:
            return [2, "", "Bandwidth limiting is supported only on testbed server"]
        if version.startswith(("debian-server", "perf-server")):
            if StrictVersion(short) <= StrictVersion("3.0.48"):
                return [3, "", f"Bandwidth limiting requires testbed server newer than 3.0.48, not {short}"]
        elif version.startswith("rpi_server"):
            if StrictVersion(short.replace("-", ".")) <= StrictVersion("2.0.208"):
                return [3, "", f"Bandwidth limiting requires testbed server newer than 2.0-208, not {short}"]
        else:
            return [5, "", f"Unsupported testbed server: {version}"]
        if interface is None:
            nodes_config = self.config.get("Nodes", [])
            if nodes_config:
                gw_name = nodes_config[0].get("name", "gw")
            else:
                gw_name = "gw"
            vlan_name, vlan_id = self.switch.get_connection_ip_type(gw_name)
            if not vlan_name:
                interface = "eth0.200"
            else:
                interface = f"eth0.{vlan_id}"
        assert all(val > 0 for val in values)
        values = list(values) * repeats
        ifb_name = interface.replace("eth0.", "ifb.")
        limit_bandwidth_cmd = (
            f"sudo tc class {{action}} dev {interface} parent 1: classid 1:10 htb rate {{value}}mbit ceil {{value}}mbit"
            " && sleep 0.5 && "
            f"sudo tc class {{action}} dev {ifb_name}  parent 1: classid 1:10 htb rate {{value}}mbit ceil {{value}}mbit"
        )
        # Add two seconds for each bandwidth limit change
        total = len(values) * (duration + 2)
        enable_bandwidth_limiting_cmd = f"sudo enable-bandwidth-limiting {interface} {total}"
        result = [0, "bandwidth limiting restored to defaults", ""]
        action = "add"
        try:
            with BackgroundTask(self, enable_bandwidth_limiting_cmd):
                log.info(f"Bandwidth limiting enabled on '{interface}' testbed server interface for {total} seconds")
                for value in values:
                    res = self.run_command(limit_bandwidth_cmd.format(action=action, value=value))
                    if res[0] != 0:
                        result = res
                        break
                    log.info(f"Bandwidth limit on '{interface}' interface set to {value} Mbps for {duration} seconds")
                    if queue_size and action == "add":
                        queue_size_cmd = (
                            f"sudo tc qdisc replace dev {interface} handle 10: parent 1:10 bfifo limit {queue_size}"
                            " && sleep 0.5 && "
                            f"sudo tc qdisc replace dev {ifb_name}  handle 10: parent 1:10 bfifo limit {queue_size}"
                        )
                        res = self.run_command(queue_size_cmd)
                        if res[0] != 0:
                            result = res
                            break
                        log.info(f"Queue size on '{interface}' interface set to {queue_size} bytes")
                    action = "change"
                    time.sleep(duration)
            log.info(f"Bandwidth limiting disabled on '{interface}' testbed server interface")
        except BackgroundTaskError as err:
            return err.result
        return result


class BackgroundTaskError(Exception):
    def __init__(self, result):
        self.result = result


class BackgroundTask:
    def __init__(self, lib, command):
        self.lib = lib
        self.command = command
        guid = uuid.uuid4()
        self.stdout = f"/tmp/osrt-background-task-{guid}.stdout"
        self.stderr = f"/tmp/osrt-background-task-{guid}.stderr"
        self.pid = None

    @property
    def sudo(self):
        return "sudo " if self.command.startswith("sudo ") else ""

    def start(self):
        result = self.lib.run_command(f"{self.command} > {self.stdout} 2> {self.stderr} & echo $!")
        if result[0] != 0:
            raise BackgroundTaskError(
                [result[0], result[1], f"'{self.command}' background task did not start:\n{result[2]}"]
            )
        self.pid = result[1].strip()
        # Wait a bit, for task setup to finish
        time.sleep(1)
        if not self.running():
            stdout = self.lib.run_command(f"{self.sudo}cat {self.stdout} || true")[1]
            stderr = self.lib.run_command(f"{self.sudo}cat {self.stderr} || true")[1]
            raise BackgroundTaskError([2, stdout, f"'{self.command}' background task ended immediately:\n{stderr}"])

    def running(self):
        if not self.pid:
            return False
        if self.command in self.lib.run_command(f"{self.sudo}ps auxq {self.pid}")[1]:
            return True
        return False

    def stop(self):
        for signal in "SIGTERM", "SIGKILL":
            if self.running():
                self.lib.run_command(f"{self.sudo}kill -{signal} {self.pid}")
        self.pid = None
        stdout = self.lib.run_command(f"{self.sudo}cat {self.stdout} || true")[1]
        stderr = self.lib.run_command(f"{self.sudo}cat {self.stderr} || true")[1]
        log.debug("'%s' background task ended with:\nstdout:\n%s\nstderr:\n%s", self.command, stdout, stderr)
        self.lib.run_command(f"{self.sudo}rm -f {self.stdout}")
        self.lib.run_command(f"{self.sudo}rm -f {self.stderr}")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()


class DebianClientUpgrade:
    lock = Lock()
    upgrade_script = "upgrade-image"
    compression_type = "tar.xz"
    checksum_type = "sha256"
    type_version_separator = "_"
    version_pattern = r"(\d+\.\d+\.\d+)"

    def __init__(self, lib, restore_cfg, download_locally, restore_files, mirror_url=None):
        self.lib = lib
        self.download_locally = download_locally
        if not self.download_locally:
            self.lib.set_skip_ns_flag(status=True)
        self.restore_cfg = restore_cfg
        self.restore_files = restore_files
        self.device_type, self.brix_type = self.get_client_type()
        self.client_name = self.lib.get_nickname()
        self.upgrade_thread = self.get_upgrade_thread()
        self.current_version = ""
        self.store_files = list()
        self.mirror_url = mirror_url

    def get_version(self):
        version = self.lib.version(short=True)
        if version[0]:
            return version
        if StrictVersion("1.2.23") >= StrictVersion(version[1].replace("-", ".")):
            return [2, "", "Upgrade is supported since version >= 1.2.23. Upgrade your device manually"]
        return [0, version[1], ""]

    def get_client_type(self) -> tuple[str, bool]:
        """
        Return tuple of "client-type", is_brix_client.
        """
        version = self.lib.get_stdout(self.lib.version(timeout=10), skip_exception=True)
        if version.startswith("plume_"):
            # We removed 'plume_' prefix from new RPi testbed images. This is a workaround for old versions
            # of upgrade-rpi script, which check that the current client-type is present in the upgrade package.
            self.lib.run_command("sudo sed -i 's/^plume_//' /.version")
            version = self.lib.get_stdout(self.lib.version(timeout=10), skip_exception=True)
        if self.type_version_separator not in version:
            hostname = self.lib.get_stdout(self.lib.run_command("hostname"), skip_exception=True)
            mount_points = self.lib.get_stdout(self.lib.run_command("mount -t ext4"), skip_exception=True)
            if "brix-client" in hostname:
                # brix-client can be upgraded to debian-client if its disk was reflashed after
                # version 1.2.23 (it then uses debian-client compatible partitioning scheme).
                if "/altroot" in mount_points:
                    return "debian-client", True
                else:
                    return "", True
            return "", False
        return version.partition(self.type_version_separator)[0], False

    def get_upgrade_thread(self):
        if not self.device_type:
            return
        upgrade_thread = False
        with self.lock:
            tmp_list_dir = self.lib.get_stdout(self.lib.run_command("ls /tmp"), skip_exception=True)
            if "automation" not in tmp_list_dir:
                timeout = 40 + time.time()
                while timeout > time.time():
                    # Create directory for upgrade
                    result = self.lib.run_command(
                        f"mkdir -m 1777 {UPGRADE_DIR}; " f"sudo chown -R $USER:$USER {UPGRADE_DIR}", timeout=10
                    )
                    if result[0] == 0:
                        upgrade_thread = True
                        break
                    time.sleep(5)
                if not upgrade_thread:
                    print(f"Can not create a upgrade directory for {self.client_name}")
        return upgrade_thread

    def download_image_to_local_machine(self, fw_path, download_urls, expected_files):
        with self.lock:
            files_list = os.listdir(fw_path)
            if expected_files[0] not in files_list or expected_files[1] not in files_list:
                # TODO: delete unfinished files
                for download_url in download_urls:
                    print(f"Starting downloading the {self.device_type} image from {download_url} url")
                    wget_result = os.system(
                        f"wget {download_url} -P {fw_path} --show-progress --progress=bar:force 2>&1"
                    )
                    if wget_result != 0:
                        raise Exception(f"Download {download_url} url finished unsuccessfully")

    def wait_for_finish_upgrade(self, target_version):
        # Wait for finish upgrade for the another thread
        timeout = time.time() + 2000
        client_version = self.lib.get_stdout(self.lib.version(), skip_exception=True)
        while timeout > time.time():
            tmp_list_dir = self.lib.get_stdout(self.lib.run_command("ls /tmp", skip_logging=True), skip_exception=True)
            if "automation" not in tmp_list_dir:
                client_version = self.lib.get_stdout(self.lib.version(), skip_exception=True)
                client_version = re.search(self.version_pattern, client_version).group() if client_version else ""
                if client_version == target_version:
                    return [0, "Upgrade finished successfully by another thread", ""]
            time.sleep(20)
        return [
            6,
            "",
            f"Upgrade finished unsuccessfully. "
            f"Current version: {client_version}. Expected version: {target_version}",
        ]

    def get_file(self, file_path, store_path, file_name, out_path):
        command = self.lib.device.scp_cmd(f"{{DEST}}:{file_path}", store_path)
        self.lib.run_command(command, skip_remote=True)
        self.store_files.append({"fileName": file_name, "outPath": out_path})

    def store_configs(self, store_path):
        if self.restore_cfg and not self.brix_type:
            # Don't restore hostname when upgrading brix-client, we want it to end up named debian-client
            self.get_file(file_path="/etc/hosts", store_path=store_path, file_name="hosts", out_path="/etc/")

        if "server" in self.device_type:
            # Store testbed reservation file
            reservation_files = self.lib.get_stdout(
                self.lib.strip_stdout_result(self.lib.run_command("ls -a /. | grep reserve")), skip_exception=True
            )
            for reservation_file in reservation_files.splitlines():
                self.get_file(
                    file_path=f"/{reservation_file}", store_path=store_path, file_name=reservation_file, out_path="/"
                )
            # store tx_power_flag
            tx_power_flag = ".tx_power_enable.flag"
            if self.lib.run_command(f"test -f /{tx_power_flag}")[0] == 0:
                self.get_file(
                    file_path=f"/{tx_power_flag}", store_path=store_path, file_name=tx_power_flag, out_path="/"
                )
            if self.restore_cfg:
                # below 2.0-104 dhcp reservation was stored in dhcp.conf, which we should not mixed in
                # tell the user to fix DHCP by starting dhcp_reservation.py script
                if StrictVersion(self.current_version.replace("-", ".")) < StrictVersion("2.0.104"):
                    log.info("Current rpi server version is below 2.0.104, extracting dhcp reservation from dhcp.conf")
                    self._extract_dhcp_reservations(store_path)
                else:
                    # Store dhcpd reservations
                    command = self.lib.device.scp_cmd(f"{{DEST}}:{'/etc/dhcp/dhcpd.reservations'}", store_path)
                    self.lib.run_command(command, skip_remote=True)
                self.store_files.append({"fileName": "dhcpd.reservations", "outPath": "/etc/dhcp/"})

    def store_other_files(self, store_path):
        file_paths = self.restore_files.split(",")
        for file_path in file_paths:
            file_path = file_path[:-1] if file_path[-1].endswith("/") else file_path

            file_name = os.path.basename(file_path)
            out_path = os.path.dirname(file_path)

            self.get_file(file_path=file_path, store_path=store_path, file_name=file_name, out_path=out_path)

    def collect_files(self, fw_path):
        client_hostname = self.lib.get_stdout(
            self.lib.strip_stdout_result(self.lib.run_command("hostname")), skip_exception=True
        )

        update_dir = os.path.dirname(fw_path)
        unique_id = uuid.uuid4().hex
        store_path = os.path.join(update_dir, unique_id)

        os.makedirs(store_path)

        if self.restore_cfg:
            self.store_configs(store_path)
        if self.restore_files:
            self.store_other_files(store_path)

        return client_hostname, store_path

    def _extract_dhcp_reservations(self, store_path):
        command = self.lib.device.scp_cmd(f"{{DEST}}:{'/etc/dhcp/dhcpd.conf'}", store_path)
        self.lib.run_command(command, skip_remote=True)
        out = "# DHCP reservations\n"
        with open(os.path.join(store_path, "dhcpd.conf")) as dhcp_conf:
            store = False
            for line in dhcp_conf.readlines():
                if "group {" in line or store:
                    out += line
                    store = True

        with open(os.path.join(store_path, "dhcpd.reservations"), "w") as dhcp_res:
            dhcp_res.write(out)

    def wait_for_reboot(self):
        time_to_wait = time.time() + 120
        while time.time() < time_to_wait:
            uptime = self.lib.get_stdout(
                self.lib.uptime(out_format="timestamp", skip_logging=True), skip_exception=True
            )
            if uptime:
                uptime = float(uptime)
                uptime = int(uptime / 60)
                if uptime < 5:
                    break
            time.sleep(10)

    def upload_files_to_client(self, client_hostname, store_path):
        if not self.restore_cfg and not self.store_files:
            return

        # wait for reboot
        self.wait_for_reboot()

        # wait for device back after reboot
        timeout = 180 + time.time()
        while timeout > time.time():
            if self.lib.get_stdout(self.lib.uptime(skip_logging=True), skip_exception=True):
                break
            time.sleep(10)

        if client_hostname and not self.brix_type:
            # Don't restore hostname when upgrading brix-client, we want it to end up named debian-client
            self.lib.set_hostname(client_hostname)

        for store_file in self.store_files:
            file_name = store_file["fileName"]
            out_path = store_file["outPath"]
            file_path = os.path.join(store_path, file_name)
            self.lib.run_command(f"mkdir -p {out_path}")
            put_result = self.lib.put_file(file_path, "/tmp")
            mv_result = self.lib.run_command(f"sudo mv /tmp/{file_name} {out_path}")
            result = self.lib.merge_result(put_result, mv_result)
            # Restart dhcp reservation in case of restoring dhcpd configuration
            if "dhcpd" in file_name:
                restart_dhcp = self.lib.run_command("sudo service isc-dhcp-server restart")
                result = self.lib.merge_result(result, restart_dhcp)
            elif "reserve" in file_name:
                self.lib.run_command(f"sudo chown -R $USER:$USER {file_name}")

            if result[0] != 0:
                print(f"Can not restore {file_name} on the server: {result}")

        # Remove unique dir for restore configuration
        shutil.rmtree(store_path, ignore_errors=True)

    def download_image_from_url(self, http_address):
        assert self.compression_type in http_address, (
            f"Incorrect file to download. " f"Provide an image archive with " f'"{self.compression_type}" extension'
        )
        image_name = http_address.split("/")[-1]
        download_urls = [http_address, f"{http_address}.{self.checksum_type}.save"]
        expected_files = [file_name.split("/")[-1] for file_name in download_urls]
        if self.download_locally:
            fw_path = UPGRADE_LOCAL_CACHE_DIR / f"upgrade_{self.device_type}"
            self.download_image_locally(download_urls, fw_path, expected_files)
        else:
            fw_path = UPGRADE_DIR
            self.download_image_to_client(download_urls, UPGRADE_DIR, expected_files)
        return os.path.join(fw_path, image_name)

    def run_stdout(self, cmd, **kwargs):
        return self.lib.get_stdout(self.lib.run_command(cmd, **kwargs))

    @staticmethod
    def get_missed_files_to_download(download_urls, expected_files, current_files):
        target_download_urls = list()
        for expected_file in expected_files:
            if expected_file in current_files:
                continue
            for download_url in download_urls:
                if expected_file in download_url:
                    target_download_urls.append(download_url)
                    break
        return target_download_urls

    def download_image_to_client(self, download_urls, fw_path, expected_files):
        self.lib.run_command(
            "sudo ip r add default via 192.168.4.1 dev eth0  proto static  metric 100; "
            'echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf'
        )
        if self.upgrade_thread:
            self.lib.run_command(f"mkdir -p {fw_path}")
            files_list = self.run_stdout(f"ls {fw_path}")
            for download_url in self.get_missed_files_to_download(download_urls, expected_files, files_list):
                print(f"Starting downloading the file from: {download_url} to {self.client_name}...")
                response = self.run_stdout(
                    f"wget {download_url} -P {fw_path} --progress=bar:force:noscroll 2>&1", timeout=30 * 60
                )
                print(response)

    def download_image_locally(self, download_urls, fw_path, expected_files):
        os.makedirs(fw_path, exist_ok=True)
        self.download_image_to_local_machine(fw_path, download_urls, expected_files)

    def start_upgrade(self, fw_path=None, force=False, version=None, **kwargs):
        """
        Upgrade raspberry clients to target firmware if fw_path=None download latest build version from artifactory
        Args:
            fw_path: (str) Path to image
            force: (bool) Flash image even though the same firmware is already on the device
            version: (str) version to download from the artifactory (or get latest or stable version)
            **kwargs:

        Returns: (ret_val, std_out, str_err)

        """
        if not self.device_type:
            if self.brix_type:
                return [
                    15,
                    "",
                    "Upgrade not possible, brix client uses old disk partitioning scheme, "
                    "disk needs to be physically reflashed",
                ]
            return [10, "", "Upgrade tool is intended for RPI\\Debian clients only"]

        if "server" in self.device_type and self.lib.name != "host":
            return [0, "", f"Skipping {self.lib.name} client, use server tool for its upgrade"]

        self.current_version = self.get_version()
        if self.current_version[0]:
            return self.current_version
        self.current_version = self.lib.get_stdout(self.current_version)

        if fw_path is None:
            fw_path = UPGRADE_LOCAL_CACHE_DIR / f"upgrade_{self.device_type}"
            download_urls = self.get_image_urls(version)
            expected_files = [file_name.split("/")[-1] for file_name in download_urls]
            target_version = re.findall(self.version_pattern, " ".join(expected_files))[0]

            if self.current_version == target_version and force is False:
                return [
                    3,
                    "",
                    f"Target firmware version: {target_version} is the same "
                    f"as on the device: {self.current_version}.\n"
                    f"If you still want to upgrade device to the same "
                    f"version, run command with --force.\n",
                ]

            os.makedirs(fw_path, exist_ok=True)
            expected_files = [file_name.split("/")[-1] for file_name in download_urls]
            try:
                self.download_image_to_local_machine(fw_path, download_urls, expected_files)
            except Exception as e:
                return [7, "", f"Failed to download image files: {e}"]
            image_name = [
                file_name
                for file_name in expected_files
                if re.search(self.compression_type, file_name) and self.checksum_type not in file_name
            ]
            fw_path = os.path.join(fw_path, image_name[0])

        if self.compression_type not in fw_path or self.checksum_type in fw_path:
            return [11, "", f"Path should specify path to image, only {self.compression_type} files are supported"]

        image_name = os.path.basename(fw_path)
        target_fw_type, _, rest = image_name.removeprefix("upgrade_").partition(self.type_version_separator)
        target_fw_type = target_fw_type.removeprefix("plume_")
        target_version = re.findall(self.version_pattern, rest)[0]

        if self.download_locally and not os.path.exists(fw_path):
            return [4, "", f"No image file in {fw_path} directory"]

        checksum_file = self.checksum_file_name(fw_path)
        if self.download_locally and not os.path.exists(checksum_file):
            return [4, "", f"No {self.checksum_type} file in {checksum_file} directory"]

        if self.device_type != target_fw_type:
            return [5, "", f"Device image is intended for {target_fw_type} type instead of {self.device_type} type"]

        if self.current_version == target_version and force is False:
            return [
                3,
                "",
                f"Target firmware version: {target_version} is the same "
                f"as on the Device device: {self.current_version}.\n"
                f"If you still want to upgrade device to the same "
                f"version, run command with force=True argument.\n",
            ]

        # Wait for finish upgrade for others namespaces on the same device
        if not self.upgrade_thread:
            return self.wait_for_finish_upgrade(target_version)

        # Prevent of no space left on device exception
        self.lib.run_command("rm /var/log/*", timeout=180)
        put_upgrade_files_result = self.put_upgrade_files_to_client(fw_path, checksum_file)
        if put_upgrade_files_result[0]:
            return put_upgrade_files_result

        client_hostname, store_path = self.collect_files(fw_path)
        nat_mode = self.lib.get_stdout(self.lib.get_tb_nat(), skip_exception=True)

        upgrade_dir = os.path.join(UPGRADE_DIR, image_name)
        print(
            f'[{self.lib.config.get("user_name", "")}] Starting flashing {self.client_name} device to '
            f"{target_version} version"
        )
        upgrade_result = self.lib.run_command(f"sudo {self.upgrade_script} -f {upgrade_dir}", timeout=1800, **kwargs)

        # Parse output due to original generated output has about 200 lines
        upgrade_result = self.parse_upgrade_output(upgrade_result)

        if "Successfully upgraded" not in upgrade_result[1]:
            return upgrade_result

        self.upload_files_to_client(client_hostname, store_path)
        # Even though upgrade is finished successfully return code is 255
        upgrade_result[0] = 0

        # NAT66 is already set on a fresh device server image
        if self.restore_cfg and nat_mode == "NAT64":
            result = self.lib.set_tb_nat(nat_mode)
            if result[0] != 0:
                print(
                    f"Can not restore IPv6 NAT mode on server to {nat_mode}: "
                    f"{result[0]}\nstdout:\n{result[1]}\nstderr:\n{result[2]}"
                )

        self.lib.run_command(f"rm -rf {UPGRADE_DIR}")

        if self.brix_type:
            # Brix clients (often? always?) need an additional reboot to properly load updated Intel Wi-Fi firmware
            reboot_result = self.lib.reboot()
            upgrade_result = self.lib.merge_result(upgrade_result, reboot_result)
            self.wait_for_reboot()

        return upgrade_result

    def get_image_urls(self, version="stable") -> list[str]:
        """
        Get the device image urls for requested version
        Args:
            version: (str) version to download from the S3 (exact version or 'latest' or 'stable')

        Returns: (list) List of urls for upgrade the device: checksum url, and image url
        """
        storage = self.mirror_url if self.mirror_url else TESTBED_IMAGES_PUBLIC_URL
        if storage.endswith("/"):
            storage = storage[:-1]
        version = self.lib.get_target_version(version) if version in ["latest", "stable"] else version
        if "rpi" in self.device_type:
            file_name = f"upgrade_{self.device_type}__v{version}"
        else:
            file_name = f"{self.device_type}_{version}_upgrade"
        return [
            f"{storage}/{file_name}.{self.compression_type}",
            f"{storage}/{file_name}.{self.compression_type}.{self.checksum_type}.save",
        ]

    @staticmethod
    def parse_upgrade_output(upgrade_result):
        parsed_output = ""
        for upgrade_line in upgrade_result[1].splitlines():
            if "extracted" in upgrade_line.lower():
                continue
            parsed_output += f"{upgrade_line}\n"
        upgrade_result[1] = parsed_output
        return upgrade_result

    def put_upgrade_files_to_client(self, fw_path, checksum_file):
        if not self.download_locally:
            return [0, "", ""]
        print(
            f'[{self.lib.config.get("user_name", "")}] Putting image to "{UPGRADE_DIR}" directory on the '
            f"{self.client_name} device"
        )
        put_image = self.lib.put_file(fw_path, UPGRADE_DIR, timeout=30 * 60)
        put_checksum = self.lib.put_file(checksum_file, UPGRADE_DIR, timeout=1 * 60)
        return self.lib.merge_result(put_image, put_checksum)

    @staticmethod
    def get_target_type_version_from_filename(fw_path):
        fw_name = os.path.basename(fw_path)
        target_type, rest = fw_name.split("_")
        target_version = re.findall(r"(\d+\.\d+\.\d+)", str(rest))[0]
        return target_type, target_version

    def checksum_file_name(self, fw_path):
        return fw_path + f".{self.checksum_type}.save"
