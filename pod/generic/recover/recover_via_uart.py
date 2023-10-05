import copy
import time
import os

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.pod.pod import Pod
from lib_testbed.generic.util.ssh.screen.serial_screen import SerialScreen
from lib_testbed.generic.client.client import Client


class Recover:
    tools_dir = os.path.join(os.path.dirname(__file__), "tools")
    dropbear_binary = "dropbear"
    dropbear_script = "dropbear_start.sh"
    bootloader_delay = 15
    post_boot_delay = 60 * 3
    max_login_wait = 60 * 2

    def __init__(self, pod_lib):
        self.pod_lib = pod_lib
        self.config = self.pod_lib.config
        self.pod_name = self.pod_lib.get_nickname()
        self.pod_config = [pod for pod in self.config["Nodes"] if pod["name"] == self.pod_name][0]
        self.pod = self.get_pod_recover()
        self.client = self.get_client_host()
        self.serial_raw = SerialScreen(self.pod, "screen")
        self.serial = SerialScreen(self.pod, "screen", fake_cmd=True)
        self.recover()

    def get_pod_recover(self):
        config = copy.deepcopy(self.config)
        pod_config = [pod for pod in config["Nodes"] if pod["name"] == self.pod_name][0]
        if not pod_config.get("host_recover"):
            raise KeyError(f'Missing key: "host_recover" for Node: {self.pod_name} in {self.config["location_file"]}')
        log.info("Pod recovery started")
        pod_config["host"] = pod_config["host_recover"]
        pod_config["busy"] = False
        # Replace host with host_restore
        kwargs = {"config": config, "nickname": self.pod_name, "multi_obj": False}
        pods_obj = Pod(**kwargs)
        return pods_obj.resolve_obj(**kwargs)

    def get_client_host(self):
        kwargs = {"config": copy.deepcopy(self.config), "nickname": "host", "multi_obj": False}
        client_obj = Client(**kwargs)
        return client_obj.resolve_obj(**kwargs)

    def refresh_host_ip(self):
        pod_ip = self.pod_config["host"].get("name")
        log.info(f"Getting host IP connected to GW IP: {pod_ip}")
        host_iface = self.client.iface.get_iface_by_mask(pod_ip)
        log.info(f"Refreshing dhcp lease for host's {host_iface} interface")
        self.client.refresh_ip_address(host_iface, timeout=20, reuse=True, skip_exception=True)
        addr = self.client.get_client_ips(host_iface)["ipv4"]
        assert addr, f"Unable to get IP address from GW, check host's {host_iface} connection"
        return addr

    def recover(self):
        self.serial_init()
        if not self.dropbear_present():
            self.copy_dropbearmulti()
            self.replace_dropbears()
        self.start_dropbear()
        self.verify_ssh_conection()

    def dropbear_present(self):
        return self.serial.cmd(f"ls /usr/sbin/ | grep {self.dropbear_binary}")

    def copy_dropbear_to_tftp(self):
        tftp_path = "/srv/tftp"
        if not self.client.run(f"ls -d {tftp_path}", skip_exception=True):
            # Tftp configuration example: http://www.ronnutter.com/raspberry-pi-tftp-server/
            # Note the expected tftp directory: /srv/tftp
            raise Exception(f"Configure tftp server on the host client, missing path: {tftp_path}")

        dropbear_file = os.path.join(self.tools_dir, self.dropbear_binary)
        log.info(f"Copying {dropbear_file} to {tftp_path}")
        self.client.put_file(dropbear_file, os.path.join(tftp_path, self.dropbear_binary))

    def copy_dropbear_to_pod(self):
        pod_ip = self.pod_config["host"].get("name")
        host_ip = self.refresh_host_ip()
        log.info(f"pod: {pod_ip}, host: {host_ip}", indent=1)
        log.info(f"Copying {self.dropbear_binary} to /tmp/{self.dropbear_binary} using tftp")
        self.serial.cmd("iptables -I INPUT -p udp --dport 69 -j ACCEPT")
        self.serial.cmd("iptables -I OUTPUT -p udp --dport 69 -j ACCEPT")
        self.serial.cmd(f"tftp {host_ip} -g -r {self.dropbear_binary} -l /tmp/{self.dropbear_binary}")

    def start_dropbear(self):
        script_path = self.copy_script(self.dropbear_script)
        self.execute_script(script_path)

    def copy_dropbearmulti(self):
        self.copy_dropbear_to_tftp()
        self.copy_dropbear_to_pod()

    def replace_dropbears(self):
        if "No such file or directory" in self.serial.cmd(f"ls /tmp/{self.dropbear_binary}"):
            log.warning(f"Trying to copy {self.dropbear_binary} once again")
            self.copy_dropbearmulti()
        assert "No such file or directory" not in self.serial.cmd(
            f"ls /tmp/{self.dropbear_binary}"
        ), f"Failed to copy {self.dropbear_binary}"
        self.serial.cmd(f"mv /tmp/{self.dropbear_binary} /usr/sbin/{self.dropbear_binary}")
        self.serial.cmd(f"chmod +x /usr/sbin/{self.dropbear_binary}")
        self.serial.cmd("killall dropbear")
        self.serial.cmd("mv /usr/sbin/dropbear /usr/sbin/dropbear_orig")
        self.serial.cmd(f"ln -s /usr/sbin/{self.dropbear_binary} /usr/sbin/dropbear")
        self.serial.cmd("dropbear -p 222")

    def copy_script(self, file_name):
        file_path = os.path.join(self.tools_dir, file_name)
        dest_path = os.path.join("/usr/plume/scripts", file_name)
        return self.serial.utils.copy_text_file(file_path, dest_path)

    def execute_script(self, script_path):
        log.info(f"Execute script {script_path}")
        self.serial.cmd(f". {script_path}", timeout=2 * 60)

    def verify_ssh_conection(self):
        self.refresh_host_ip()
        resp = self.pod_lib.run_command("uptime")
        assert resp[0] == 0
        log.info("Current uptime: {}".format(resp[1].replace("\n", "")))

    def serial_init(self):
        log.info(f"Waiting for {list(self.serial_raw.screen.keys())[0]} terminal access..")
        start_time = time.time()
        init_done = False
        first_login = True
        # First wait a bit, so that we don't accidentaly get stuck in bootloader.
        time.sleep(self.bootloader_delay)
        while True:
            run_time_min = 0
            self.serial_raw.reset()
            response = self.serial_raw.cmd("_test_command", skip_exception=True)
            time.sleep(0.2)
            uptime = self.serial_raw.cmd("uptime", skip_exception=True)
            if uptime:
                response = uptime
            if "Login incorrect" in response:
                pwd = self.pod_config["host_recover"]["pass"]
                if first_login:
                    pwd = self.pod_config["host_recover"].get("def_pass", pwd)
                self.serial_raw.cmd(self.pod_config["host_recover"]["user"], skip_exception=True)
                self.serial_raw.cmd(pwd, skip_exception=True)
                first_login = False
                continue
            elif "Password:" in response:
                self.serial_raw.cmd("fake_password", skip_exception=True)
                continue
            run_time = uptime.split(" up ")
            if len(run_time) < 2:
                log.info("Received data: {}".format(uptime.replace("\r", "\\r").replace("\n", "\\n")))
                time.sleep(5)
                continue
            run_time = run_time[1]
            if "day" not in run_time:
                run_time = run_time.split()[0].split(",")[0]
            else:
                number_of_days = int(run_time.split()[0].split(",")[0])
                run_time = run_time.split(",")[1].strip()
                run_time_min = 24 * 60 * number_of_days
            try:
                if ":" in run_time:
                    run_time_min += 60 * int(run_time.split(":")[0]) + int(run_time.split(":")[1])
                elif "min" in run_time:
                    run_time_min += int(run_time.split("min")[0])
                else:
                    run_time_min += int(run_time)
            except Exception:
                time.sleep(5)
                continue
            if run_time_min < self.post_boot_delay / 60:
                if not init_done:
                    log.info(
                        "Current run time: {} min, wait {} min..".format(
                            run_time_min, self.post_boot_delay / 60 - run_time_min
                        )
                    )
                init_done = True
                time.sleep(5)
                continue
            log.info(f"Run time: {run_time_min} min")
            if time.time() - start_time > self.post_boot_delay + self.max_login_wait:
                raise Exception(f"Failed to initialize serial terminal: {list(self.serial_raw.screen.keys())[0]}")
            break
