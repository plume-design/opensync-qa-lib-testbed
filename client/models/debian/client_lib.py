import random
import os
import re
import json
import uuid
import time
import shutil
from typing import Literal

import requests

from multiprocessing import Lock
from distutils.version import StrictVersion

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.client.models.generic.client_lib import ClientLib as ClientLibGeneric
from lib_testbed.generic.client.models.rpi.client_tool import ClientTool
from lib_testbed.generic.client.models.generic.client_lib import UPGRADE_DIR, UPGRADE_LOCAL_CACHE_DIR


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

    def get_target_version(self, version: Literal["stable", "latest"]) -> str:
        """Retrieves the actual target version for stable/latest from artifactory.
        Returns string with version.
        """
        debian_upgrade = DebianClientUpgrade(lib=self, restore_cfg=True, download_locally=True, restore_files=None)
        return debian_upgrade.get_target_version(version=version)

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
            version: (str) version to download from the artifactory (or get latest or stable version)
            restore_files: (str): Paths of files to restore. eg. restore_files=/home/plume/file1,/etc/file2
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
        self.run_command("sudo /usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf -d -v", **kwargs)
        out = self.run_command("ps aux | grep mosqui", **kwargs)
        if "mosquitto" in out[1]:
            return [0, "Mosquito started successfully", ""]
        else:
            out = self.run_command("tail -30 /var/log/mosquitto/mosquitto.log", **kwargs)
            return [1, "", out[1]]

    def stop_mqtt_broker(self, **kwargs):
        return self.run_command("sudo killall mosquitto", **kwargs)

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
        time.sleep(60)
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


class DebianClientUpgrade:
    lock = Lock()
    upgrade_script = "upgrade-image"
    compression_type = "tar.xz"
    checksum_type = "sha256"
    build_name = "build_debian_testbed_images"
    build_separator = r"\."
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
            tx_power_flag = self.lib.get_stdout(
                self.lib.strip_stdout_result(self.lib.run_command("ls -a /.tx_power_enable.flag")), skip_exception=True
            )
            if tx_power_flag:
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

    def get_target_version(self, version: Literal["stable", "latest"]) -> str:
        """Retrieves the actual target version for stable/latest from artifactory.
        Returns string with version.
        """
        download_urls = self.get_latest_image_urls(self.device_type, version=version)
        expected_files = [file_name.split("/")[-1] for file_name in download_urls]
        target_version = re.findall(self.version_pattern, " ".join(expected_files))[0]
        return target_version

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
            download_urls = self.get_latest_image_urls(self.device_type, version=version)
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
            self.download_image_to_local_machine(fw_path, download_urls, expected_files)
            image_name = [
                file_name
                for file_name in expected_files
                if re.search(self.compression_type, file_name) and self.checksum_type not in file_name
            ]
            fw_path = os.path.join(fw_path, image_name[0])

        if self.compression_type not in fw_path or self.checksum_type in fw_path:
            return [11, "", "Path should specify path to image"]

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

    def get_latest_image_urls(self, device_type, build_name=None, max_retry=10, version=None) -> list[str]:
        """
        Get the latest device image for target device type
        Args:
            device_type: (str) device type, debian-server, perf-client, rpi_server, ...
            build_name: (str) build name, default: self.build_name
            max_retry: (int) max attempts to get an image for the target device type
            version: (str) version to download from the artifactory (or get latest or stable version)

        Returns: (list) List of urls for upgrade device, checksum, and image
        """
        retry = 0
        headers = {"Content-Type": "application/json"}
        build_name = build_name if build_name is not None else self.build_name
        if version is None:
            version = "latest"
        if self.mirror_url is None:
            artifactory_url = self.lib.config["artifactory"]["url"]
            project_url = os.path.join(artifactory_url, "api", "build", build_name)
            build_info_url = os.path.join(artifactory_url, "api", "search", "buildArtifacts")
            if version == "latest":
                all_builds = requests.get(project_url)
                all_builds = json.loads(all_builds.text)
                all_builds = [int(build_number["uri"].strip("/")) for build_number in all_builds["buildsNumbers"]]
                last_build = max(all_builds)
            elif version == "stable":
                last_build = int(
                    re.split(self.build_separator, self.lib.device.config["capabilities"]["fw_version"])[-1]
                )
            else:
                try:
                    last_build = int(re.split(self.build_separator, version)[-1])
                except Exception as e:
                    log.error(f"Cannot get build number from {version}")
                    raise e

            data = '{ "buildName":"' + build_name + '", "buildNumber":"' + str(last_build) + '" }'

            build_info = ""

            if self.lib.config.get("artifactory", {}).get("user") and self.lib.config.get("artifactory", {}).get(
                "password"
            ):
                auth = (self.lib.config["artifactory"]["user"], self.lib.config["artifactory"]["password"])
            else:
                auth = None

            while max_retry > retry:
                retry += 1
                build_info = requests.post(build_info_url, headers=headers, data=data, auth=auth)
                if device_type in build_info.text:
                    break
                last_build = str(int(last_build) - 1)
                data = '{ "buildName":"' + build_name + '", "buildNumber":"' + last_build + '" }'

            if device_type not in build_info.text:
                raise ValueError(
                    f"Can not find suitable upgrade package for {device_type} after checking last {max_retry} builds "
                    f"from {build_name} project"
                )

            build_info = json.loads(build_info.text)
            download_urls = list()
            for build_url in build_info.get("results", []):
                download_url = build_url.get("downloadUri", "")
                if device_type in download_url and self.compression_type in download_url:
                    download_urls.append(download_url)
                if len(download_urls) == 2:
                    break
            return download_urls
        log.debug("Querying mirror %s for builds", self.mirror_url)
        # this comes with the assumption of certain mirror server directory structure:
        all_builds = requests.get(f"{self.mirror_url}/{self.build_name}", headers=headers).json()

        device_builds = [build for build in all_builds if device_type in build.get("name")]

        # keep a list of tuples with (version, resp) - so that we pick the version number and keep the download URL
        all_versions = [
            (re.findall(rf"(\d+[{self.build_separator}]\d+[{self.build_separator}]\d+)", ver.get("name"))[0], ver)
            for ver in device_builds
        ]
        all_versions_on_mirror = [ver[0] for ver in all_versions]
        log.debug("All versions on mirror: %s", all_versions_on_mirror)

        if version == "latest":
            last_build = max(all_versions, key=lambda x: StrictVersion(x[0].replace("-", ".")))[0]
        elif version == "stable":
            build_id = re.split(self.build_separator, self.lib.device.config["capabilities"]["fw_version"])
            last_separator = "-" if "-" in self.build_separator else "."
            last_id = int(build_id[-1])
            while max_retry > retry:
                retry += 1
                last_build = f"{'.'.join(build_id[:-1])}{last_separator}{last_id}".replace("\\", "")
                if last_build in all_versions_on_mirror:
                    break
                last_id -= 1
            else:
                raise ValueError(
                    f"Can not find suitable upgrade package for {device_type} after checking last {max_retry} builds "
                    f"from {build_name} project"
                )

        log.debug("Build to download: %s", last_build)

        if last_build not in all_versions_on_mirror:
            raise ValueError(f"Version {last_build} not available in: {all_versions_on_mirror}")

        last_versions = [ver[1] for ver in all_versions if ver[0] == last_build]
        log.debug("Got releases on mirror: %s", last_versions)
        if len(last_versions) != 2:
            raise ValueError(
                f"Incorrect number of releases matching the expected version {last_build} found: {last_versions}"
            )

        return [f"{self.mirror_url}/{self.build_name}/{ver.get('name')}" for ver in last_versions]

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
