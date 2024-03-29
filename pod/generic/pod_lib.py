import functools
import re
import os
import itertools
import json
import time
import random
import shlex
import shutil
import tempfile
import datetime
import distutils
import subprocess
from typing import Union
from uuid import UUID, uuid4

from lib_testbed.generic.pod.generic.pod_tool import PodTool
from lib_testbed.generic.rpower.rpowerlib import PowerControllerApi
from lib_testbed.generic.switch.switch_api_resolver import SwitchApiResolver
from lib_testbed.generic.util.base_lib import Iface
from lib_testbed.generic.util.msg.msg import Msg
from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.common import BASE_DIR, CACHE_DIR
from lib_testbed.generic.util.common import wait_for
from lib_testbed.generic.pod.pod_base import PodBase
from lib_testbed.generic.pod.generic.capabilities import Capabilities
from lib_testbed.generic.pod.generic.artifactory_reader import ArtifactoryReader
from lib_testbed.generic.util.object_resolver import ObjectResolver
from lib_testbed.generic.util.common import compare_fw_versions

# Regex pattern to parse conntrack entries:
# src=192.168.40.237 dst=192.168.201.1 sport=55818 dport=5706 packets=16821 bytes=874737
_RE_PATTERN_CONNTRACK = re.compile(
    r"(.*src=(?P<src_ip>[^\s]+))"
    r"(.*dst=(?P<dst_ip>[^\s]+))"
    r"(.*sport=.*?(?P<src_port>[^\s]+))?"
    r"(.*dport=.*?(?P<dst_port>[^\s]+))?"
    r"(.*packets=(?P<packets>[^\s]+))"
    r"(.*bytes=(?P<bytes>[^\s]+))",
)
MANAGER_RESTART_TIMEOUT = 80  # default for DM Manager, and other non-SM Managers


class PodLib(PodBase):
    DFS_REGION_MAP = {
        "EU": "0x0037",
        "US": "0x003a",
        "JP": "0x8FAF",
        "CA": "0x0014",
        "UK": "0x833A",
        "NZ": "0x822A",
        "SG": "0x82BE",
        "IL": "0x8178",
        "HK": "0x8158",
        "KR": "0x005f",
        "PH": "0x8260",
    }

    def __init__(self, **kwargs):
        pods = kwargs["config"].get("Nodes")
        if pods:
            # Assume that first Node configured in Nodes is a gateway and the rest are leafs
            # Extend config with roles: gw or leaf
            # TODO: consider to fetch this information from cloud
            for i, pod in enumerate(pods):
                if pod.get("role"):
                    continue
                if i == 0:
                    role = "gw"
                else:
                    role = "leaf"
                pod["role"] = role
        super().__init__(**kwargs)
        self.iface = PodIface(lib=self)
        self.tool = PodTool(lib=self)
        self.capabilities = Capabilities(lib=self)
        self.pod_info = []
        self.ovsdb = Ovsdb(self)
        self.msg = Msg(self)
        self.storage = {}
        self.ext_path = self.set_ext_path()
        self.artifactory = ArtifactoryReader(lib=self)

    @functools.cached_property
    def switch(self):
        return SwitchApiResolver(config=self.config)

    @functools.cached_property
    def rpower(self):
        return PowerControllerApi(conf=self.config)

    def set_ext_path(self):
        ext_path = ":".join([self.capabilities.get_shell_path(), self.capabilities.get_opensync_rootdir()])
        return ext_path

    def get_opensync_path(self, **kwargs):
        """Get path to opensync"""
        res = self.get_stdout(
            self.run_command('ps | grep "bin/dm" | grep -v grep | head -n 1', **kwargs), skip_exception=True
        )
        if not res:
            log.warning(f"[{self.device.name}] Cannot get path to OpenSync, using default: '/usr/opensync'")
            return [0, "/usr/opensync", ""]
        return self.strip_stdout_result([0, res.split(" ")[-1].replace("/bin/dm", ""), ""])

    def ping(self, host=None, v6=False, **kwargs):
        """Ping"""
        ping = "ping6" if v6 else "ping"
        if host:
            result = self.run_command(f"{ping} -c1 -w5 {host}")
        else:
            cmd = self.device.get_last_hop_cmd(f"{ping} -c1 -w5 {self.device.get_ip()}")
            result = self.run_command(cmd, skip_remote=True, **kwargs)
        result[1] = result[1] if result[0] == 0 else ""
        return self.strip_stdout_result(result)

    def reboot(self, **kwargs):
        """Reboot node(s)"""
        result = self.run_command("reboot", **kwargs)
        # Change ret val from 255 to 0 due to lost connection after reboot.
        if result[0] == 255:
            result[0] = 0
        return result

    def version(self, **kwargs):
        """Display firmware version of node(s).

        Returns "native-<version>" for native platforms, which happens when ovs version cannot be determined.
        """
        fw_version = self.ovsdb.get_raw(table="AWLAN_Node", select="firmware_version", **kwargs)
        # FW above 6.0.0 are always native
        if not self.device.config["model_org"][0:2].startswith("PP") or compare_fw_versions(
            self.strip_stdout_result(fw_version)[1], "6.0.0", ">"
        ):
            return self.strip_stdout_result(fw_version)
        if fw_version[1] and "N/A" in self.ovs_version()[1]:
            fw_version[1] = "native-" + fw_version[1]
        return self.strip_stdout_result(fw_version)

    def platform_version(self, **kwargs):
        """Display platform version of node(s)"""
        return self.strip_stdout_result(self.ovsdb.get_raw(table="AWLAN_Node", select="platform_version", **kwargs))

    def ovs_version(self, **kwargs) -> str:
        """Display ovs version of node(s)."""
        return self.strip_stdout_result(self.ovsdb.get_raw(table="AWLAN_Node", select="ovs_version", **kwargs))

    def opensync_version(self, **kwargs):
        """Display opensync version of node(s)"""
        version_matrix = self.ovsdb.get_map(table="AWLAN_Node", select="version_matrix", **kwargs)
        if opensync_version := version_matrix.get("OPENSYNC"):
            return [0, opensync_version, ""]
        else:
            return [1, "", "Opensync version not defined in AWLAN_Node"]

    def uptime(self, timeout=20, **kwargs):
        """Display uptime of node(s)"""
        out_format = "user"
        if kwargs.get("out_format"):
            out_format = kwargs.get("out_format")
            del kwargs["out_format"]
        assert out_format in ["user", "timestamp"], f"Unsupported format {out_format}"
        if out_format == "user":
            result = self.run_command("uptime", timeout=timeout, **kwargs)
            return self.strip_stdout_result(result)
        elif out_format == "timestamp":
            result = self.run_command("cat /proc/uptime", timeout=timeout, **kwargs)
            result = self.strip_stdout_result(result)
            if result[0] == 0:
                result[1] = result[1].split()[0].strip()
            return result

    def _manager_path(self):
        if self.run_command("ls /etc/init.d/manager*")[0] == 0:
            path = "/etc/init.d/manager*"
        elif self.run_command("ls /etc/init.d/opensync")[0] == 0:
            path = "/etc/init.d/opensync"
        elif self.run_command(f"ls {self.capabilities.get_opensync_rootdir()}/scripts/managers.init")[0] == 0:
            path = f"{self.capabilities.get_opensync_rootdir()}/scripts/managers.init"
        else:
            path = ""
        return path

    def restart(self, **kwargs):
        """Restart managers on node(s)"""
        path = self._manager_path()
        if not path:
            return [1, "Cannot find path to manager restart", "Cannot find path to restart managers"]
        stop_result = self.run_command(f"{path} stop", **kwargs)
        start_result = self.run_command(f"{path} start", **kwargs)
        # start always returns 1 even if succeeded, so workaround that
        ret_val = self.merge_result(stop_result, [0, start_result[1], start_result[2]])
        return ret_val

    def healthcheck_stop(self, **kwargs):
        """Stop healthcheck on pod"""
        if self.capabilities.get_device_type() == "residential_gateway":
            return [0, "Nothing to stop", ""]
        out = self.run_command("/etc/init.d/healthcheck stop")
        # stopping always returns 1 even if successful, to change it to 0
        if out[0] == 1:
            out[0] = 0
        return out

    def healthcheck_start(self, **kwargs):
        """Start healthcheck on pod"""
        if self.capabilities.get_device_type() == "residential_gateway":
            return [0, "Nothing to start", ""]
        return self.run_command("/etc/init.d/healthcheck start")

    def deploy(self, **kwargs):
        """Deploy files to node(s)"""
        remote_dir = self.get_node_deploy_path()
        resp = self.run_command(f"mkdir -p {remote_dir}", **kwargs)
        if not self.result_ok(resp):
            raise Exception(f"Can't create directory: {remote_dir}\n{resp}")
        # hint: copy first parent class files, then from model
        deploy_dir = (
            ObjectResolver.resolve_model_path_file(
                file_name="deploy",
                model=self.device.config["model"],
                wifi_vendor=self.device.config["capabilities"]["wifi_vendor"],
            )
            + "/*"
        )
        command = self.device.scp_cmd(deploy_dir, f"{{DEST}}:{remote_dir}")
        return self.run_command(command, **kwargs, timeout=10 * 60, skip_remote=True)

    def check(self, **kwargs):
        """Pod health check"""
        # check if file is there, and it's the latest one
        node_check = (
            ObjectResolver.resolve_model_path_file(
                file_name="deploy",
                model=self.device.config["model"],
                wifi_vendor=self.device.config["capabilities"]["wifi_vendor"],
            )
            + "/node-check"
        )
        ret = subprocess.run(["md5sum", node_check], capture_output=True, text=True).stdout
        org_md5 = ret.split()[0]
        result = self.run_command(f"md5sum {self.get_node_deploy_path()}/node-check", **kwargs)
        # file it not there
        if org_md5 not in result[1]:
            log.info("Deploying tools...")
            deploy_status = self.deploy()
            if deploy_status[0] != 0:
                err_msg = f"Deploy to POD has failed! {deploy_status[2]}"
                # 0, since we do not want to fail GW sanity check
                return [0, err_msg, err_msg]
            # make sure file is executable
            self.run_command(f"chmod +x {self.get_node_deploy_path()}/node-check", **kwargs)

        result = self.run_command(f"{self.get_node_deploy_path()}/node-check", **kwargs)
        # some GW blocks the execution, skip them
        if result[0] and "Permission denied" in result[2]:
            result[0] = 0
        return result

    def enable(self, **kwargs):
        """Enable agent and wifi radios on node(s)"""
        path = self._manager_path()
        if not path:
            return [1, "Cannot find path to start managers", "Cannot find path to start managers"]
        return self.run_command(f"pidof dm || {path} start", **kwargs)

    def disable(self, **kwargs):
        """Disable agent and wifi radios on node(s)"""
        path = self._manager_path()
        if not path:
            return [1, "Cannot find path to stop managers", "Cannot find path to stop managers"]
        return self.run_command(f"killall dm wm nm cm; {path} stop", **kwargs)

    def info(self):
        """Node connection information"""
        result = self.device._parse_host_info()
        if not result:
            return [1, "", "Error during getting connection information"]
        return [0, str(result), ""]

    def get_model(self, **kwargs):
        """Display type of node(s)"""
        return self.strip_stdout_result(self.ovsdb.get_raw(table="AWLAN_Node", select="model", **kwargs))

    def add_to_acl(self, bridge, mac):
        self.ovsdb.set_value(
            table="Wifi_VIF_Config", where=[f"if_name=={bridge}"], value={"mac_list_type": "whitelist"}
        )
        self.ovsdb.set_value(table="Wifi_VIF_Config", where=[f"if_name=={bridge}"], value={"mac_list": mac})

    def bssid(self, bridge="", **kwargs):
        """Display BSSID of node bridge = <br-wan|br-home>-, default both"""
        where = ["mode==ap"]
        if bridge == self.capabilities.get_wan_bridge_ifname():
            where.append(f"bridge!={self.iface.get_native_br_home()}")
        elif bridge == self.capabilities.get_lan_bridge_ifname():
            # For home interfaces vif_radio_idx==2
            where.extend([f"bridge=={self.iface.get_native_br_home()}", "vif_radio_idx==2"])
        result = self.ovsdb.get_raw(table="Wifi_VIF_State", select="mac", where=where, **kwargs)
        return self.strip_stdout_result(result)

    def get_serial_number(self, **kwargs):
        """Get node(s) serial number"""
        return self.strip_stdout_result(self.ovsdb.get_raw(table="AWLAN_Node", select="id", **kwargs))

    def connected(self, **kwargs):
        """returns cloud connection state of each node"""
        result = self.strip_stdout_result(self.ovsdb.get_raw(table="Manager", select="status", **kwargs))

        if "ACTIVE" not in result[1]:
            return [0, "", result[2] or "False"]
        return [0, "True", ""]

    def get_ovsh_table(self, table, **kwargs):
        """get ovsh table from pods locally json format"""
        result = self.run_command(f"ovsh -j s {table}", **kwargs)
        return self.strip_stdout_result(result)

    def get_ovsh_table_tool(self, table, **kwargs):
        """get ovsh table from pods locally tool format"""
        result = self.run_command(f"ovsh s {table}", **kwargs)
        return self.strip_stdout_result(result)

    def role(self, **kwargs):
        """Node role: return gw or leaf"""
        if not self.iface.is_ovs():
            # Assume that only residential gateways doesn't support ovs
            return [0, "GW", ""]
        # stations exists only on leafs
        result = self.ovsdb.get_bool(table="Wifi_VIF_State", select="enabled", where=["mode==sta"])

        return [0, "Leaf" if result else "GW", ""]

    def get_ips(self, iface, **kwargs):
        """get ipv4 and ipv6 address for desired interface"""
        ip_adds = {"ipv4": False, "ipv6": False}
        get_int = f"ip addr show {iface}"
        result = self.run_command(get_int, **kwargs)
        for res in result[1].splitlines():
            if "inet " in res:
                ip_adds["ipv4"] = res.strip().split(" ")[1].split("/")[0].strip()
            if "inet6 " in res:
                ip_adds["ipv6"] = res.strip().split(" ")[1].split("/")[0].strip()
        return [0, ip_adds, ""]

    def get_logs(self, directory=None, **kwargs):
        """get logs from pods locally"""
        if directory and not os.path.isdir(directory):
            try:
                os.makedirs(directory)
            except Exception as e:
                return [1, "", f"Could not create dir {directory}: {e}."]

        if kwargs.get("timeout"):
            log_pull_timeout = kwargs["timeout"]
        else:
            log_pull_timeout = 180
        kwargs["timeout"] = 20
        path = self.get_stdout(self.get_opensync_path())
        # TODO: Remove once all devices has support for creating log-pull tarball file
        if self.result_ok(self.run_command(f"ls {path}/scripts/logpull.sh", **kwargs)):
            command = f"{path}/scripts/logpull.sh --stdout"
        elif self.result_ok(self.run_command(f"ls {path}/scripts/logpull/logpull.sh", **kwargs)):
            command = f"{path}/scripts/logpull/logpull.sh --stdout"
        elif self.result_ok(self.run_command(f"ls {path}/bin/lm_logs_collector.sh", **kwargs)):
            command = f"{path}/bin/lm_logs_collector.sh --stdout"
        elif self.result_ok(self.run_command(f"ls {path}/bin/logpull.sh", **kwargs)):
            command = f"{path}/bin/logpull.sh --stdout"
        elif self.result_ok(self.run_command(f"ls {path}/scripts/lm_log_pull.sh", **kwargs)):
            command = (
                f"sh -c 'set -- 1 log-pull.tgz; curl() {{ cp log-pull.tgz /tmp/lm/log-pull-copy.tgz; true; }}; "
                f". {path}/scripts/lm_log_pull.sh' 1>&2 && cat /tmp/lm/log-pull-copy.tgz"
                f" && rm /tmp/lm/log-pull-copy.tgz"
            )
        else:
            return [1, "", "Log-pull script not found in /usr/opensync/"]
        kwargs["timeout"] = log_pull_timeout
        kwargs["expect_bytes"] = True
        result = self.run_command(command, **kwargs)
        if result[0] == 0:
            fn = "logs-%s-%s.tgz" % (
                self.get_name(),
                datetime.datetime.strftime(datetime.datetime.utcnow(), "%Y%m%d_%H%M%S"),
            )
            if directory:
                fn = os.path.join(directory, fn)
            if not result[1]:
                return [1, "", "Log-pull script returned empty response"]
            with open(fn, "wb") as fh:
                fh.write(result[1])
            log_file = [0, fn, ""]
        else:
            log_file = [result[0], "", result[2]]
        return log_file

    def erase_certificates(self):
        """Erase partition and install DEVELOPMENT certificates"""
        # get certs from lab-server
        dev_null = open(os.devnull, "w")
        # 10.100.1.2 -> lab-server.sf.wildfire.exchange
        subprocess.check_call(
            ["scp", "plume@10.100.1.2:/home/plume/piranha_unencrypted_certs/*", "/tmp/"], stdout=dev_null
        )
        # copy them to nodes
        for cert in ["/tmp/ca.pem", "/tmp/client.pem", "/tmp/client_dec.key"]:
            put_output = self.put_file(cert, "/tmp")

        # Check output from def put_file()
        self.get_stdout(put_output)

        # erase partition
        self.get_stdout(self.run_command("mtd erase /dev/mtd14"))

        # install certs
        install_crets = "cd /tmp; certwrite ca.pem; certwrite client.pem; certwrite client_dec.key"

        # Raise exception if failed
        self.get_stdout(self.run_command(install_crets))

    def upgrade(self, image: str, *args, **kwargs):
        """Upgrade node firmware, Optional: -p=<encyp_key>, -e-> erase certificates, -n->skip version check"""
        if os.path.exists(image):
            output = self.upgrade_from_local_file(image, *args, **kwargs)
        else:
            output = self.upgrade_from_artifactory(image, *args, **kwargs)

        return output

    def upgrade_from_artifactory(self, image: str, use_build_map_suffix: bool = False, *args, **kwargs):
        filename = self.artifactory.download_proper_version(image, use_build_map_suffix=use_build_map_suffix)
        filepath = os.path.join(self.artifactory.tmp_dir, filename)

        return self.upgrade_from_local_file(filepath, *args, **kwargs)

    def upgrade_from_local_file(self, image: str, *args, **kwargs):
        if kwargs.get("skip_if_the_same"):
            cur_ver = self.version(**kwargs)[1]
            if cur_ver in image:
                return [0, cur_ver, ""]
        kwargs.pop("skip_if_the_same", "")
        log.info("Upgrading with %s", image)
        skip_version_check = False
        erase_certs = False
        image_file = os.path.basename(image)
        target_file_name = f"/tmp/pfirmware/{image_file}"
        dec_passwd = None
        for arg in args:
            if arg == "-n" or arg == "skip_version_check":
                skip_version_check = True
            if "-p=" in arg:
                dec_passwd = arg[3:]
            if "-e" in args:
                erase_certs = True

        if dec_passwd and image[-3:] != "eim":
            raise Exception("Use eim file for encrypted image")
        if not dec_passwd and image[-3:] != "img":
            raise Exception("Use img file for unencrypted image")

        self.run_command("mkdir -p /tmp/pfirmware", **kwargs)
        self.put_file(image, "/tmp/pfirmware")
        remote_md5sum = self.run_command(f'md5sum /tmp/pfirmware/{image_file} | cut -d" " -f1', **kwargs)
        remote_md5sum = self.get_stdout(remote_md5sum)
        local_md5sum = os.popen(f'md5sum {image} | cut -d" " -f1').read().strip()

        md5sum = remote_md5sum.strip()
        if md5sum != local_md5sum:
            return [1, "", f"Failed MD5sum image: {local_md5sum} node: {md5sum} "]

        # determine which command should be used for upgrade
        if dec_passwd:
            upg_comm = f"safeupdate  -u {target_file_name} -P {dec_passwd}"
        else:
            upg_comm = f"safeupdate  -u {target_file_name}"

        if erase_certs:
            self.erase_certificates()

        result = self.run_command(upg_comm, timeout=5 * 60, **kwargs)

        # wait for nodes to start rebooting
        time.sleep(30)
        self.wait_available(timeout=180)
        # even the first ssh call was successful, connection is still unstable, so pause for a moment
        time.sleep(30)
        result = self.merge_result(result, self.wait_available(60, **kwargs))

        if skip_version_check:
            return result

        log.info("Checking version")
        check_version = self.version(**kwargs)
        return self.merge_result([result[0], "", result[2]], check_version)

    def sanity(self, *args):
        """run sanity on selected pods, add arg --nocolor for simple output"""
        out = "full"
        for arg in args:
            if arg == "--nocolor":
                out = "simple"
            elif arg == "--noout":
                out = "none"
            elif arg == "--lib":
                out = "lib"

        # we used to call sanity often to see when location is onboarded,
        # so it might happen that SSH is not working yet after reboot
        self.wait_available(timeout=120)
        dump = self.run_command(
            "ovsdb-client dump -f json $(cat /proc/$(pidof ovsdb-server)/cmdline | " 'grep -ao unix:.* | cut -d"-" -f1)'
        )
        dump = self.get_stdout(dump, skip_exception=True)
        tmpd = os.path.join(tempfile.gettempdir(), f"podsanity-{str(time.time())}")

        poddir = os.path.join(tmpd, self.get_name())
        os.makedirs(poddir)
        dmpfile = os.path.join(poddir, "ovsdb-client_-f_json_dump")
        with open(dmpfile, "w") as dumpfile:
            print(dump, file=dumpfile)

        ret_status = PodLib._sanity_tool(tmpd, out)

        # cleanup
        shutil.rmtree(tmpd)

        # health check
        health_result = self.check()
        ret_status["health"] = health_result[1]
        if "Failure" in health_result[1]:
            if out in ["full", "simple"]:
                log.error(f"Health check for {self.get_nickname()} failed:")
                log.info(health_result[1], indent=1)
            if "Kernel/managers dumps:    Failure" in health_result[1]:
                self.get_crash()
            if "was restarted" in health_result[1] or "is not running" in health_result[1]:
                self.restart()
        if health_result[0]:
            ret_status["ret"] = False
        return ret_status

    def poll_pod_sanity(self, timeout=300, expect=True, *args):
        """
        Loops sanity on until pass
        Args:
            timeout: (int) time to wait for sanity pass,
            expect: (bool) What we are expecting, True for pass sanity, False for fail sanity.
            *args:

        Returns: 1 if sanity failed 0 otherwise
        """
        status = {"ret": False}
        log.info(f"[{self.get_name()}] Waiting for sanity to {'pass' if expect else 'fail'} {int(timeout / 60)} min")
        timeout = time.time() + timeout
        while time.time() < timeout:
            status = self.sanity("--lib", *args)
            if status["ret"] is expect:
                break
            if "Kernel/managers dumps:    Failure" in status.get("health"):
                log.error(f'Sanity failed due to crash:\n{status.get("health")}')
                break
            time.sleep(5)
        self.print_sanity_output(status)
        return 1 if status["ret"] is False else 0

    def print_sanity_output(self, sanity_out):
        """
        User-friendly sanity output printer
        Args:
            sanity_out: (dict) output from node_sanity

        """
        msg = "[{}:{}] Sanity {}\n".format(
            self.get_name(),
            sanity_out["serial"][0] if sanity_out["serial"] else "unknown",
            "successful" if sanity_out["ret"] else "failed",
        )

        if sanity_out["gw_pod"]:
            msg += f'GW pod: {sanity_out["gw_pod"]}\n'
        for i in range(len(sanity_out["serial"])):
            msg += f'Sanity check for: {sanity_out["serial"][i]}\n'
            for line in sanity_out["out"][i]:
                msg += "{0: >17}- {1: <10}:{2}\n".format(line[0], line[1], line[2])
            msg += "\n"
        if sanity_out.get("health"):
            msg += sanity_out["health"]
        log.info(msg, show_file=False)

    def clear_crashes(self, **kwargs):
        core_crash_files = self.get_stdout(self.run_command("ls /tmp | grep core.gz"), skip_exception=True)
        for item in core_crash_files.split("\n"):
            if not item:
                continue
            self.run_command(f"rm tmp/{item}", **kwargs)
        self.run_command("rm /usr/plume/log_archive/crash/*; rm /sys/fs/pstore/*; rm /var/log/lm/crash/*", **kwargs)
        return [0, "", ""]

    def get_crash(self, **kwargs):
        """get crash log file from node"""
        serial = self.get_serial_number()[1].strip()
        name = self.get_nickname()
        # /usr/plume/log_archive/crash/ < 3.0.0
        # /usr/opensync/log_archive/crash/ links to the /var/log/lm/crash/
        crash_places = ["/usr/plume/log_archive/crash/", "/sys/fs/pstore/", "/var/log/lm/crash/"]
        crash_exist = False
        crash_saved = False
        crash_response = ""
        crash_no_crash = f"Crash not found for {name}"
        lpdir = os.path.join(CACHE_DIR, f"crash_{serial}_{str(int(time.time()))}")

        # core.gz are stored in /tmp
        kwargs.pop("skip_exception", True)
        tmp_file = self.get_stdout(self.run_command("ls /tmp | grep core.gz"), skip_exception=True, **kwargs)
        for item in tmp_file.split("\n"):
            if not item:
                continue
            self.get_file("/tmp/" + item, lpdir)
            self.run_command("rm " + "/tmp/" + item)

        for remote_path in crash_places:
            grep = " | grep -v console-ramoops-0 | grep -v pmsg-ramoops-0" if remote_path == "/sys/fs/pstore/" else ""
            out = self.get_stdout(self.run_command(f"ls {remote_path}{grep}", **kwargs), skip_exception=True)
            if not out:
                continue
            crash_exist = True
            tar_name = f"/tmp/{remote_path.split('/')[-2]}_log.tar"
            tar = self.run_command(f"tar -cvpf {tar_name} {remote_path}*")
            if tar[0]:
                log.error(f"Cannot tar {remote_path}: {tar[2]}")
                continue
            response = self.get_file(tar_name, lpdir)
            if response[0] == 0:
                crash_response += f"{serial} crash saved on {name} to: {lpdir}"
                log.info(f"{serial} crash saved on {name} to: {lpdir}")
            else:
                log.error(f"Cannot download crash file: {response[2]}")
            self.run_command(f"rm {remote_path}*")
            self.run_command(f"rm {tar_name}")
            crash_saved = True
            crash_no_crash = ""
        if crash_exist:
            self.restart()
            time.sleep(30)
        return [int(not crash_saved), crash_response, crash_no_crash]

    def remove_crash(self, **kwargs):
        """
        Remove crashes from device
        Args:
            **kwargs:

        Returns: list [retval, stdout, stderr]

        """
        return self.run_command(
            "rm /usr/plume/log_archive/crash/*; rm /sys/fs/pstore/*; rm /var/log/lm/crash/*", **kwargs
        )

    def get_log_level(self, manager_name, **kwargs):
        """
        Get logging level for OpenSync manager
        Args:
            manager_name: (str) OpenSync manager name: SM, BM, etc

        Returns: level: (str) logging level: trace, debug, info, notice, warning, err, crit, alert, emerg
        """
        # special case for BM
        if manager_name == "BM":
            level = self.ovsdb.get_int(table="Band_Steering_Config", select="debug_level")
            if level == 1:
                level = "debug"
            elif level == 2:
                level = "trace"
            else:
                level = "err"

        else:
            level = self.ovsdb.get_str(table="AW_Debug", select="log_severity", where=[f"name=={manager_name}"])
        return level

    def set_log_level(self, manager_name, level, **kwargs):
        """
        Set logging level for OpenSync manager
        Args:
            manager_name: (str) OpenSync manager name: SM, BM, etc
            level: (str) logging level: trace, debug, info, notice, warning, err, crit, alert, emerg

        Returns: ([[0,0,0],]) nodes output
        """
        if level not in ["trace", "debug", "info", "notice", "warning", "err", "crit", "alert", "emerg"]:
            raise OpenSyncException(
                f"Unknown logging level: {level}",
                "Possible levels: ['trace', 'debug', 'info', 'notice', 'warning', 'err', 'crit'," " 'alert', 'emerg']",
            )
        # special case for BM
        if manager_name == "BM":
            if level == "debug":
                level = 1
            elif level == "trace":
                level = 2
            else:
                level = 0
            self.ovsdb.set_value(table="Band_Steering_Config", value={"debug_level": level})
        else:
            self.ovsdb.set_value(table="AW_Debug", value={"log_severity": f"{level}"}, where=[f"name=={manager_name}"])

    @staticmethod
    def _sanity_tool(tmpd, out):
        try:
            from lib_testbed.generic.util.sanity.sanity import Sanity
        except ModuleNotFoundError:
            log.warning("Sanity module is not available, skipping")
            return {"gw_pod": None, "serial": [], "ret": True, "out": [], "wifi_stats": []}

        with open(os.path.join(tmpd, "sanity.log"), "w") as out_file:
            san_tool = Sanity(outfile=out_file, outstyle=out)
            if out != "lib":
                log.info(f"running sanity on {tmpd}")
            return san_tool.sanity_location(tmpd)

    @staticmethod
    def sanity_message(ret_status):
        """Method to print the output"""
        # TODO: wifi_stats
        # TODO: Add attributes to filter printing
        node_out = ret_status["out"]
        serial = ret_status["serial"]
        health = ret_status["health"]
        log.info(f"{ret_status['gw_pod']} sanity check for: {serial}")
        for row in node_out:
            tname = row[0]
            level = row[1]
            regex = re.compile(r"\033\[[0-9;]+m")
            message = regex.sub("", row[2])

            log_method = log.info
            if "ERROR" in level:
                log_method = log.error
            elif "Warning" in level:
                log_method = log.warning
            log_method("{0: >17}- {1: <25}:{2}".format(level, tname, message))
        log_method = log.info
        if "Failure" in health:
            log_method = log.error
        log_method(f"Health check for {serial}:")
        for line in health.split("\n"):
            log_method("\t" + line)

    def get_userbase(self):
        if not hasattr(self, "cloud"):
            return None
        from lib.cloud.userbase import UserBase

        for _obj_name, obj in self.cloud.__dict__.items():
            if isinstance(obj, UserBase):
                return obj
        return None

    def get_custbase(self):
        if not hasattr(self, "cloud"):
            return None
        from lib.cloud.custbase import CustBase

        for _obj_name, obj in self.cloud.__dict__.items():
            if isinstance(obj, CustBase):
                if not obj.is_initialized():
                    obj.initialize()
                return obj
        return None

    # TODO: Might be broken after refactor
    def cache_pods_info(self):
        ub = self.get_userbase()
        if not ub:
            raise Exception("No userbase object found. Ensure that a test includes opensync_cloud mark")
        log.console("Discovering nodes: ", show_file=False, end="")
        serial = self.get_stdout(self.get_serial_number(), skip_exception=True)
        serial = serial.strip()
        name = self.get_nickname()
        cb_nodes_info = ub.get_pods_info()
        pods_info = []
        for node_nick, nodes in cb_nodes_info.items():
            for node in nodes:
                info_serial = node["serialNumber"]
                info_nickname = node_nick
                info_connection = node["connectionState"]
                info_gw = True if node_nick == "gw" else False
                info_model = node["model"]
                pods_info.append(
                    {
                        "serial": info_serial,
                        "id": info_serial,
                        "name": None,
                        "access": False,
                        "connectionState": info_connection,
                        "gw": info_gw,
                        "model": info_model,
                        "nickname": info_nickname,
                    }
                )
            if not serial:
                log.warning(f"Cannot get serial for node: {name} through management access")
                continue
            found = False
            for node in pods_info:
                if node["serial"] == serial:
                    node["access"] = True
                    node["name"] = name
                    found = True
                    break
            if not found:
                out = self.get_model()
                if not out[0]:
                    model = out[1].strip()
                else:
                    log.warning(f"Unable to get model for pod {name}")
                    model = "unknown"
                pods_info.append(
                    {
                        "serial": serial,
                        "id": serial,
                        "name": name,
                        "access": True,
                        "connectionState": "Disconnected",
                        "gw": False,
                        "model": model,
                        "nickname": name,
                    }
                )
        nodes_log = []
        for node in pods_info:
            if node["gw"]:
                # Add gateway as a first item in the list
                idx = 0
            else:
                idx = len(nodes_log)
            access = ", access:False" if not node["access"] else ""
            disconnected = f", status:'{node['connectionState']}'" if node["connectionState"] != "connected" else ""
            nodes_log.insert(
                idx, f"{node['serial']}: {{name:{node['name']}, model:{node['model']}{access}{disconnected}}}"
            )
        log.console(",  ".join(nodes_log), show_file=False)
        self.pod_info = [pod_info for pod_info in pods_info if pod_info["name"] == name]

    def eth_connect(self, pod_name):
        """
        Connect Specified pod to Ethernet pod.

        Args:
            pod_name: (pod_api) pod object to connect to
        Returns: None
        """

        target_port, target_backhaul = self.switch.get_no_wan_port(self.switch.get_all_switch_aliases(pod_name))
        unused_port = self.switch.get_unused_pod_ports(self.get_nickname())[0]

        if not unused_port:
            return [4, "", f"pod '{self.get_nickname()}' has no free ports left"]

        self.eth_disconnect()
        self.switch.switch_ctrl.vlan_set(unused_port, target_backhaul, "untagged")

        # Disabling isolations
        all_ports = self.switch.get_list_of_all_port_names()
        self.switch.switch_ctrl.disable_port_isolation(all_ports)

        self.rpower.cycle(self.get_nickname())

        return [0, f"'{self.get_nickname()}' connected to '{pod_name}' by backhaul: '{target_backhaul}'", ""]

    def eth_disconnect(self, **kwargs):
        """Disconnect pod from Ethernet ports."""
        pods_connection_type = self.switch.get_devices_connection_type().get(self.get_nickname())

        if pods_connection_type == "daisy_chain":
            self.switch.recovery_switch_configuration(pod_names=self.get_nickname(), force=True)

        return [0, "Disconnected pod from Ethernet ports", ""]

    def get_radio_temperatures(self, radio: Union[int, str, list] = None, retries=2, **kwargs):
        """
        Args:
            radio: accepted arguments: radio_id(e.g.: 0, 1, ...), band frequency(e.g.: '2.4G', '5G'),
                      list of radio_ids or band frequencies, or use None for all radios
            retries: (int) number of retries in case failed ssh call
            **kwargs:

        Returns: radio temperature as int or list(temperatures are ordered the same as in radio argument if provided,
                 else they are ordered by radio id)

        """
        radio_band_mapping = self.capabilities.get_wifi_indexes()
        if radio is None:
            return [
                self.get_radio_temperatures(value, retries=retries, **kwargs) for _, value in radio_band_mapping.items()
            ]
        elif isinstance(radio, list):
            return [self.get_radio_temperatures(item, retries=retries, **kwargs) for item in radio]
        elif isinstance(radio, str):
            return self.get_radio_temperatures(radio_band_mapping[radio], retries=retries, **kwargs)
        elif isinstance(radio, int):
            temp = -1
            for i in range(1 + retries):
                output = self.strip_stdout_result(self.get_radio_temperature(radio_index=radio, **kwargs))
                if not output[0]:
                    temp = int(output[1])
                    break
            return temp
        raise ValueError

    def get_client_tx_rate(self, ifname, client_mac, **kwargs):
        raise NotImplementedError

    def get_radio_temperature(self, radio_index, **kwargs):
        raise NotImplementedError

    def get_tx_power(self, interface, **kwargs):
        """
        Get current Tx power in dBm
        Args:
            interface: (str) Wireless interface

        Returns: raw output [(int) ret, (std) std_out, (str) str_err]

        """
        raise NotImplementedError

    def decrease_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Decrease value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns: raw output [(int) ret, (std) std_out, (str) str_err]

        """
        raise NotImplementedError

    def increase_tx_power_on_all_ifaces(self, percent_ratio, **kwargs):
        """
        Increase value of Tx power on the all home_ap, bhaul interfaces
        Args:
            percent_ratio: (int) Percent ratio from 0 to 100

        Returns: raw output [(int) ret, (std) std_out, (str) str_err]

        """
        raise NotImplementedError

    def set_tx_power(self, tx_power, interfaces=None, **kwargs):
        """
        Set current Tx power in dBm
        Args:
            interfaces: (str) or (list) Name of wireless interfaces
            tx_power: (int) Tx power in dBm.

        Returns: raw output [(int) ret, (std) std_out, (str) str_err]

        """
        raise NotImplementedError

    def get_driver_data_rate(self, ifname, mac_address, **kwargs):
        raise NotImplementedError

    def get_boot_partition(self, **kwargs):
        """
        Get boot partition name
        Args:
            **kwargs:

        Returns: list(retval, stdout, stderr)

        """
        raise NotImplementedError

    def check_traffic_acceleration(
        self, ip_address, expected_protocol=6, multicast=False, flow_count=1, flex=False, map_t=False, **kwargs
    ):
        """
        Check traffic acceleration
        Args:
            ip_address: (list) IP addresses to check
            expected_protocol: (int) expected protocol id. 6 for TCP, 17 for UDP
            multicast: (bool) True to check for acceleration of multicast traffic
            flow_count: (int) minimum number of expected accelerated flows (connections)
            flex: (bool) True to check for acceleration of Flex traffic
            map_t: (bool): True if checking acceleration of MAP-T traffic
            **kwargs:

        Returns: bool()

        """
        raise NotImplementedError

    def run_traffic_acceleration_monitor(self, samples: int = 5, interval: int = 5, delay: int = 20, **kwargs):
        """
        Start making traffic acceleration statistics dumps on the pod in the background
        Args:
            samples: (int) number of statistic dumps
            interval: (int) seconds apart
            delay: (int) seconds after the method is called.
            **kwargs:

        Returns: Return (dict) e.g. dict(sfe_dump=dict(dump_file="", pid="")) Acceleration statistics dumps details.

        """
        raise NotImplementedError

    def check_traffic_acceleration_dump(
        self,
        acceleration_dump: dict,
        ip_address: list,
        expected_protocol=6,
        multicast=False,
        flow_count=1,
        flex=False,
        map_t=False,
        **kwargs,
    ):
        """
        Check traffic was accelerated
        Args:
            acceleration_dump: (dict) Acceleration dump details from run_traffic_acceleration_monitor()
            ip_address: (list) IP addresses to check
            expected_protocol: (int) expected protocol id. 6 for TCP, 17 for UDP
            multicast: (bool) True to check for acceleration of multicast traffic
            flow_count: (int) minimum number of expected accelerated flows (connections)
            flex: (bool) True to check for acceleration of Flex traffic
            map_t: (bool): True if checking acceleration of MAP-T traffic
            **kwargs:

        Returns: bool()

        """
        raise NotImplementedError

    def get_connection_flows(self, ip, **kwargs):
        """
        Get connection flow id for specific IP address
        Args:
            ip: (str) IP address
            **kwargs:

        Returns: (list) flow list

        """
        raise NotImplementedError

    def trigger_crash(self, **kwargs):
        """
        Trigger crash on the platform
        Args:
            **kwargs:
        Returns: list [retval, stdout, stderr]
        """
        raise NotImplementedError

    def kill_manager(self, wait_for_restart=False, time_to_restart=MANAGER_RESTART_TIMEOUT, soft_kill=False, **kwargs):
        """
        Kill and restart service managers
        Args:
            wait_for_restart: (bool)
            time_to_restart: (int) default 80s
            soft_kill: (bool) gently kill the process otherwise use SIGSEGV
            **kwargs:
        Returns: list [retval, stdout, stderr]
        """
        active_managers = self.get_managers_list(**kwargs)
        assert active_managers, "No managers appear to be running"
        for manager in active_managers:
            initial_pid = active_managers[manager]
            kill_cmd = "kill" if soft_kill else "kill -segv"
            log.info(f"Killing process for {manager} manger: {kill_cmd} {initial_pid}")
            self.run_command(f"{kill_cmd} {initial_pid}")

            if wait_for_restart:
                if manager == "sm":
                    time_to_restart = self.device.config["capabilities"]["kpi"]["sm_restart"]
                log.info(f"Wait up to {time_to_restart} sec for OpenSync manager restart...")
                timeout = time.time() + time_to_restart
                new_pid = None
                while timeout > time.time():
                    time.sleep(10)
                    log.info(f"Check if {manager} manger has been restarted")
                    active_managers = self.get_managers_list(**kwargs)
                    new_pid = active_managers.get(manager)
                    if not new_pid or new_pid == initial_pid:
                        continue
                    log.info(f"{manager} manager: restart verified")
                    break
                assert new_pid != initial_pid, f"{manager} manager has not restarted, PID unchanged: {new_pid}"
        return [0, active_managers, ""]

    def get_managers_list(self, managers_name: Union[str, list] = None, **kwargs):
        """
        Get managers list
        Args:
            managers_name: (str) or (list) Get PID number from provided managers if None get list of all managers
            **kwargs:

        Returns: (dict) {manager_name: pid}

        """
        manager_list = dict()
        osp = self.get_stdout(self.get_opensync_path())

        if not managers_name:
            managers_name = self.run_command(f"ls {osp}/bin | awk '/^.*m$/'", **kwargs)[1].split("\n")
        else:
            managers_name = managers_name if isinstance(managers_name, list) else [managers_name]

        manager_paths = [f"{osp}/bin/{manager_name}" for manager_name in managers_name]
        for manager_path in manager_paths:
            matched_processes = self.get_stdout(
                self.run_command(f"ps | grep {manager_path}", **kwargs), skip_exception=True
            ).split("\n")[:-1]
            manager_processes = [process_name for process_name in matched_processes if "grep" not in process_name]
            for process in manager_processes:
                manager_pid = [int(pid) for pid in process.split() if pid.isdigit()][0]
                manager_name = manager_path.split("/")[-1]
                manager_list[manager_name] = manager_pid
        return manager_list

    # TODO: Remove as this method is already implemented in Iface class
    def get_mac(self, ifname="", **kwargs):
        """
        Get MAC address of interface from device
        Args:
            ifname: (str) Device interface name
            **kwargs:

        Returns: (list) [[(int) ret, (dict) stdout, (str) stderr]]

        """
        result = self.run_command(f"cat /sys/class/net/{ifname}/address", **kwargs)
        return self.strip_stdout_result(result)

    def get_macs(self, **kwargs):
        return self.ovsdb.get_str(
            table="Wifi_VIF_State", select="mac", where=["enabled==true", "ssid_broadcast==enabled"]
        )

    def recover(self, **kwargs):
        """
        Recover pod by using dedicated recover class for a pod model.
        This method might use serial access to the pod instead of ssh management access.
        :return: list including ret_value, stdout, stderr
        """
        failed = [255, "", "Failed to recover"]
        success = [0, "Successfully recovered", ""]
        model = self.device.config["model"]
        response = None
        try:
            default_family = self.capabilities.get_wifi_vendor()
            recover_path = ObjectResolver.resolve_model_path_file(
                file_name="recover/recover.py", model=model, wifi_vendor=default_family
            )
            recover_class = ObjectResolver.resolve_model_path_class(file_path=recover_path, file_name="recover.py")
            response = recover_class(self, **kwargs)
        except KeyError as e:
            if "Could not resolve path" in str(e):
                log.info(f"SSH recovery procedure not defined for {model}, moving forward.")
            else:
                log.exception("Failed to recover")
        except Exception:
            log.exception("Failed to recover")
        if not response:
            return failed
        return success

    def get_eth_link_speed(self, iface, **kwargs):
        ret = self.run_command(f"ethtool {iface}", **kwargs)
        if ret[0]:
            return ret
        for line in ret[1].splitlines():
            if "Speed:" in line:
                return [0, line.replace("Speed:", "").strip(), ""]
        return [2, "Unknown", "Unknown"]

    # TODO: to remove
    def wait_eth_connection_ready(self, timeout, **kwargs):
        # TODO: change ovsdb call with wait operation when implemented
        """
        Wait for disable loop status so that to be ready for connect eth client to device
        :param timeout: (int) timeout in seconds
        :return: (bool) True if eth connection is ready, False if not ready after timeout and skip_exception is True
        """
        return True
        skip_exception = kwargs.get("skip_exception", False)
        start_time = time.time()
        while start_time + timeout > time.time():
            loop = self.ovsdb.get_bool(
                table="Connection_Manager_Uplink", select="loop", where=["if_type==eth"], skip_exception=True
            )

            if isinstance(loop, list) and True not in loop:
                break
            elif isinstance(loop, bool) and not loop:
                break
            elif loop is None:
                break

            time.sleep(1)
        else:
            if skip_exception:
                return False
            raise TimeoutError(f"Ethernet connection is not ready after {timeout} seconds.")
        return True

    def get_datetime(self, **kwargs):
        """
        Get current datetime
        :return: date as python datetime object
        """
        epoch = self.get_stdout(self.strip_stdout_result(self.run_command("date +%s")), **kwargs)
        if not epoch:
            return None
        epoch = int(epoch)
        return datetime.datetime.fromtimestamp(epoch)

    def set_datetime(self, date_time, **kwargs):
        """
        Set date
        :param date_time: python datetime object
        """
        return self.run_command(f"date -s @{int(date_time.timestamp())}", **kwargs)

    def wait_bs_table_ready(self, timeout=60, **kwargs):
        # TODO: change ovsdb call with wait operation when implemented
        """
        Wait for ovsdb Band_Steering_Clients table to be populated
        :param timeout: Timeout
        :return: (bool) True if bs table is ready, False if not ready after timeout and skip_exception is True
        """
        skip_exception = kwargs.get("skip_exception", False)
        start_time = time.time()
        while time.time() - start_time < timeout:
            bs_uuid = self.ovsdb.get_uuid(table="Band_Steering_Clients", select="_uuid", skip_exception=skip_exception)

            if bs_uuid is None or (isinstance(bs_uuid, list) and len(bs_uuid) == 0):
                time.sleep(5)
                continue

            return True
        else:
            if skip_exception:
                return False
            raise TimeoutError(f"Band_Steering_Clients table is not available after {timeout} seconds.")

    def trigger_radar_detected_event(self, freqband="", **kwargs):
        """
        Trigger radar detected event
        Args:
            **kwargs:

        Returns: list(retval, stdout, stderr)

        """
        phy_5g_radios = self.capabilities.get_phy_radio_ifnames(return_type=list, freq_band="5g")
        responses = list()
        if freqband:
            radio_ifnames = self.capabilities.get_phy_radio_ifnames()
            log.info(f"Found freqband/interface-mapping for pod -> {radio_ifnames}")
            phy_5g_radios = [radio_ifnames.get(freqband.lower())]
        log.info(f"Generating radar against interfaces -> {phy_5g_radios}")
        for phy_5g_radio in phy_5g_radios:
            responses.append(self.trigger_single_radar_detected_event(phy_5g_radio, **kwargs))
        # Return first response with std ret value == 0
        for response in responses:
            if not response[0]:
                response = response
                break
        else:
            response = responses[-1]
        return response

    def trigger_single_radar_detected_event(self, phy_5g_radio, **kwargs):
        raise NotImplementedError

    def get_partition_dump(self, partition, **kwargs):
        """
        Get partition hex dump
        Args:
            partition: (str) partition name
            **kwargs:

        Returns: list(retval, stdout, stderr)

        """
        log.warning("Method not implemented, as model is not supporting it")
        return [0, "Not implemented", ""]

    def is_fw_fuse_burned(self, **kwargs):
        """Returns True when device firmware fuse is not burned (is unlocked) and False otherwise."""
        raise NotImplementedError

    def get_cpu_memory_usage(self, **kwargs):
        """
        Get CPU and memory usage
        Returns: dict('memory': {'used': int, 'free': int}, 'cpu': {'usr': int, 'sys': int, 'nic': int, 'idle': int',
                                 'io': int, 'irq': int, 'sirq': int}
        """
        top = self.run_command("top -n1", **kwargs)
        if top[0]:
            return top
        out = {}
        top = top[1]
        for line in top.splitlines():
            if "Mem:" in line:
                line = line[line.find("Mem:") + 4 :]
                out["memory"] = {}
                for element in line.split(","):
                    try:
                        if "used" in element:
                            out["memory"]["used"] = int(element[: element.find("K")])
                        if "free" in element:
                            out["memory"]["free"] = int(element[: element.find("K")])
                    except ValueError:
                        log.warning(f"Unable to parse {element}")
            if "CPU:" in line:
                line = line.replace("CPU:", "")
                line = line.replace("%", "")
                out["cpu"] = {}
                keys = ["usr", "sys", "nic", "idle", "io", "irq", "sirq"]
                idx = 0
                for element in line.split():
                    try:
                        out["cpu"][keys[idx]] = int(element)
                        idx += 1
                    except ValueError:
                        continue
        return out

    def get_process_mem_usage(self, process_name: str, **kwargs):
        """Get process VSZ mem in kilobytes and %VSZ usage"""
        response = self.run_command(f"top -n1 | grep -w {process_name} -i" + "| awk '{print $5, $6}'", **kwargs)
        if not response[1]:
            response = [1, "", f"Not found any {process_name} process in process list"]
        return self.strip_stdout_result(response)

    def start_wps_session(self, key_id, **kwargs):
        result = self.ovsdb.set_value(
            value={"wps_pbc_key_id": f'"{key_id}"'}, table="Wifi_VIF_Config", where="ssid_broadcast==enabled", **kwargs
        )
        if result[0]:
            return False

        wait_for(
            lambda: self.ovsdb.get_str("Wifi_VIF_State", "wps_pbc_key_id", where="ssid_broadcast==enabled", **kwargs)
            == key_id,
            timeout=30,
            tick=3,
        )
        result = self.ovsdb.set_value(
            value={"wps": True, "wps_pbc": True}, table="Wifi_VIF_Config", where="ssid_broadcast==enabled", **kwargs
        )
        return result[0] == 0

    def get_wps_keys(self, if_name, **kwargs):
        keys_str = self.run_command(f"cat /var/run/hostapd-{if_name}.pskfile", **kwargs)[1]
        key_passphrase_list = re.findall(r"keyid=(\S*)\s\S*\s(\S*)", keys_str)
        return dict(key_passphrase_list) if key_passphrase_list is not None else None

    # optional needed for checking interference level around testbed in the testbed_validator script
    def get_radios_interference(self, **kwargs):
        raise NotImplementedError

    def set_region(self, region, **kwargs):
        if not self.capabilities.is_regulatory_domain_managed():
            log.error("Model does not support changing region")
            return [1, "", "Model does not support region modifications"]
        if len(self.capabilities.get_phy_radio_ifnames(return_type=list)) == 2:
            return self.set_region_two_radios_model(region, **kwargs)
        else:
            return self.set_region_three_radios_model(region, **kwargs)

    def set_region_two_radios_model(self, region, **kwargs):
        raise NotImplementedError

    def set_region_three_radios_model(self, region, **kwargs):
        raise NotImplementedError

    def get_region(self, **kwargs):
        kwargs.pop("skip_exception", True)
        kwargs.pop("return_list", True)
        override_region = kwargs.pop("override_region", True)
        cc_codes = self.ovsdb.get_str("Wifi_Radio_State", "country", return_list=True, skip_exception=True, **kwargs)
        # remove empty codes if any
        cc_codes = [cc_code for cc_code in cc_codes if cc_code]
        if not cc_codes:
            return [1, "", "Cannot get region"]
        valid_cc = cc_codes[0].strip()
        # workaround for BRCM Country Code for 2.4G radio
        if override_region and valid_cc in ["E0", "UK", "GB", "CH"]:
            valid_cc = "EU"
        for cc_code in cc_codes:
            if not cc_code:
                log.warning("Missing county code for a radio")
                continue
            cc_code = "EU" if cc_code.strip() in ["E0", "UK", "GB", "CH"] else cc_code.strip()
            if cc_code != valid_cc:
                return [2, "", f"Different regions for different radios: {cc_codes}"]
        return [0, valid_cc, ""]

    def _update_pod_ca_file(self, **kwargs):
        ca_cert = os.path.join(BASE_DIR, "lib_testbed", "generic", "mqtt", "certs", "ca-rpi.pem")
        ca_path = self.ovsdb.get_str(table="SSL", select="ca_cert", skip_exception=True)
        ca_path = ca_path if ca_path else "/var/certs/ca.pem"
        with open(ca_cert, "r") as f:
            ca_cert = f.read().strip()
            res = self.run_command(f"cat {ca_path}", **kwargs)
            assert res[0] == 0, res
            certs = res[1].strip()
            if ca_cert not in certs:
                log.info(f"Updating CA cert on the {self.get_nickname()}")
                tmp_cas = f"/tmp/ca_certs_with_rpi_ca_{uuid4()}.pem"
                for cmd in (
                    f"cp {ca_path} {tmp_cas}",
                    f'echo "{ca_cert}" >> {tmp_cas}',
                    f"mount --bind {tmp_cas} {ca_path}",
                ):
                    res = self.run_command(cmd, **kwargs)
                    assert res[0] == 0, res
                certs = self.run_command(f"cat {ca_path}", **kwargs)[1].strip()
                assert ca_cert in certs

    def redirect_stats_to_local_mqtt_broker(self, skip_storage=False, **kwargs):
        pure_redirect = kwargs.pop("pure_redirect", False)
        if not pure_redirect:
            # stop firewall on the res GW devices - not a common code, so ignoring the output
            self.run_command("firewall-cli filter -m nat", **kwargs)
            # redirect mqtt from the test_node to local mqtt broker
            if not skip_storage:
                self.storage["mqtt_settings"] = self.ovsdb.get_map("AWLAN_Node", "mqtt_settings", **kwargs)
                if not self.storage["mqtt_settings"].get("broker"):
                    log.warning("Mqtt setting are gone, restarting managers...")
                    self.restart()
                    time.sleep(120)
                    self.wait_available(timeout=120)
                    timeout = time.time() + 5 * 60
                    while time.time() < timeout:
                        log.info("Waiting till node connect with controller and gets mqtt settings")
                        cur_map = self.ovsdb.get_map("AWLAN_Node", "mqtt_settings")
                        if cur_map.get("topics", ""):
                            break
                        time.sleep(5)
                    else:
                        return [2, "", "Pod does not have any mqtt settings"]
                    self.storage["mqtt_settings"] = self.ovsdb.get_map("AWLAN_Node", "mqtt_settings", **kwargs)
                    if not self.storage["mqtt_settings"].get("broker"):
                        return [1, "", f"Cannot get mqtt setting from the {self.get_nickname()}"]
            # append ca.crt to /var/certs/ca.pem if needed
            self._update_pod_ca_file(**kwargs)

        self.ovsdb.mutate("AWLAN_Node", "mqtt_settings", "del", '["port", "compress", "broker"]', **kwargs)
        self.ovsdb.mutate(
            "AWLAN_Node",
            "mqtt_settings",
            "ins",
            '["broker","192.168.200.1"], ["compress",""],["port","8883"]',
            **kwargs,
        )
        cur_sett = self.ovsdb.get_map("AWLAN_Node", "mqtt_settings", **kwargs)
        if cur_sett.get("broker", "") == "192.168.200.1":
            return [0, "Mqtt settings updated successfully", ""]
        else:
            return [
                1,
                "",
                f"Mqtt settings not updated properly, expected broker:"
                f" 192.168.200.1 but got: {cur_sett.get('broker', '')}",
            ]

    def restore_stats_mqtt_settings(self, **kwargs):
        # restore firewall
        self.run_command("firewall-cli filter -m on")
        if "mqtt_settings" not in self.storage:
            return [10, "", "There is no cached information about mqtt settings"]
        self.ovsdb.mutate("AWLAN_Node", "mqtt_settings", "del", '["port", "compress", "broker"]', **kwargs)
        self.ovsdb.mutate(
            "AWLAN_Node",
            "mqtt_settings",
            "ins",
            f'["broker","{self.storage["mqtt_settings"]["broker"]}"],'
            f'["compress","{self.storage["mqtt_settings"]["compress"]}"],'
            f'["port","{self.storage["mqtt_settings"]["port"]}"]',
            **kwargs,
        )
        cur_sett = self.ovsdb.get_map("AWLAN_Node", "mqtt_settings", **kwargs)
        if cur_sett.get("broker", "") == self.storage["mqtt_settings"]["broker"]:
            return [0, "Mqtt settings restored successfully", ""]
        else:
            return [
                1,
                "",
                f"Mqtt settings not updated properly, expected broker:"
                f" {self.storage['mqtt_settings']['broker']} but got: {cur_sett.get('broker', '')}",
            ]

    def enter_factory_mode(self, **kwargs):
        log.info("Entering factory mode")
        assert self.run_command("pmf -e", **kwargs)[0] == 0
        time.sleep(10)
        self.device.config["host"]["org_pass"] = self.device.config["host"].get("pass", "")
        self.device.config["host"]["pass"] = "plume"
        assert self.wait_available(timeout=2 * 60, **kwargs)[0] == 0

    def exit_factory_mode(self, **kwargs):
        log.info("Exiting factory mode")
        timeout = time.time() + 20
        while time.time() < timeout:
            if self.run_command("pmf -q", **kwargs)[0] == 0:
                break
            time.sleep(3)
        else:
            raise EnvironmentError("Exiting factory mode failed")
        time.sleep(10)
        if org_pass := self.device.config["host"].pop("org_pass", ""):
            self.device.config["host"]["pass"] = org_pass
        self.wait_available(timeout=2 * 60, **kwargs)

    def simulate_clients(self, count=1, **kwargs):
        if len(self.capabilities.get_lan_ifaces()) == 1:
            raise OpenSyncException(
                "Device does not support simulating ethernet clients", "Use device with two Ethernet ports"
            )
        device_types = [
            {
                "id": "lg-smarttv",
                "hostname": "LGSmartTV-558",
                "mac_prefix": "64:bc:0c",
                "fingerprint": "252,3,42,15,6,1,12",
            },
            {
                "id": "google-chromecast-ultra",
                "hostname": "Chromecast-Ultra-73",
                "mac_prefix": "3c:28:6d",
                "fingerprint": "1,33,3,6,15,28,51,58,59",
            },
            {
                "id": "microsoft-xbox",
                "hostname": "Xbox-SystemOS",
                "mac_prefix": "4c:0b:be",
                "vendor_class_id": "MSFT 5.0",
            },
            {"id": "microsoft-xbox", "hostname": "HOMEXBOX", "mac_prefix": "58:82:a8", "vendor_class_id": "MSFT 5.0"},
            {
                "id": "whatever",
                "hostname": "retropie-71",
                "mac_prefix": "b8:27:eb",
                "fingerprint": "1,121,33,3,6,12,15,26,28,42,51,54,58,59,119",
                "vendor_class_id": "dhcpcd-6.11.5:Linux-4.14.98-v7+:armv7l:BCM2835",
            },
        ]

        def generate_random_ip(ips):
            new_ip = ips[0]
            while new_ip in ips:
                new_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 254)}"
            ips.append(new_ip)
            return new_ip

        def generate_random_mac(prefix):
            return (
                f"{prefix}:{random.randint(0, 9)}{random.randint(0, 9)}:"
                f"{random.randint(0, 9)}{random.randint(0, 9)}:{random.randint(0, 9)}{random.randint(0, 9)}"
            )

        # only GW types devices correctly, so make sure we are on GW
        is_gw = False
        free_port = ""
        for eth in self.ovsdb.get_json_table("Connection_Manager_Uplink", where="if_type==eth", **kwargs):
            if eth["has_L2"] is True and eth["has_L3"] is True:
                is_gw = True
            else:
                free_port = eth["if_name"]
        if not is_gw:
            return [2, "", "Can be used only for GW node"]

        # get used IPs so far
        out = [0, "", ""]
        ips = self.ovsdb.get_str("DHCP_leased_IP", "inet_addr", return_list=True, **kwargs)
        for _ in range(count):
            device = device_types[random.randint(0, len(device_types) - 1)]
            new_ip = generate_random_ip(ips)
            new_mac = generate_random_mac(device["mac_prefix"])
            ret = self.ovsdb.set_value(
                table="OVS_MAC_Learning",
                value={"brname": "br-home", "hwaddr": new_mac, "ifname": free_port, "vlan": 0},
                **kwargs,
            )
            out = self.merge_result(out, ret)
            ret = self.ovsdb.set_value(
                table="DHCP_leased_IP",
                value={
                    "hostname": device["hostname"],
                    "hwaddr": new_mac,
                    "inet_addr": new_ip,
                    "lease_time": 720000,
                    "fingerprint": device.get("fingerprint", ""),
                    "vendor_class": device.get("vendor_class_id", ""),
                },
                **kwargs,
            )
            out = self.merge_result(out, ret)
        return out

    def fqdn_check(self, count=5, v6=False, dns_address="www.google.com", **kwargs):
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

    def set_fan_mode(self, status, **kwargs):
        if not self.capabilities.is_fan():
            log.info("There is no fan to set, skipping")
            return [0, "", ""]
        log.info(f'{"Enabling" if status else "Disabling"} fan')
        fan_value = "9000" if status else "0"
        results = None
        for state in range(1, 9):
            response = self.ovsdb.set_value(
                table="Node_Config",
                value={"key": f"SPFAN_state{state}_fanrpm", "value": fan_value, "module": "tm"},
                **kwargs,
            )
            results = self.merge_result(response, response)
        return results

    def populate_fake_clients(self, **kwargs):
        """populate 90 pseudo/fake client entries to "Band_Steering_Clients" OVSDB table"""
        deploy_status = self.deploy(**kwargs)
        if deploy_status[0] != 0:
            err_msg = f"Deploy to POD has failed! {deploy_status[2]}"
            return [1, "", err_msg]
        self.run_command(f"chmod +x {self.get_node_deploy_path()}/generate_fake_clients.sh", **kwargs)
        return self.run_command(f"{self.get_node_deploy_path()}/generate_fake_clients.sh")

    # new_ovsdb_type -> (old_json_key, removed_params, [(new_param_name, old_param_name, old_param_type), ...])
    _ovsdb_to_json_mapping = {
        "pppoe": (
            "PPPoE",
            {},
            [
                ("username", "username", str),
                ("password", "password", str),
            ],
        ),
        "static_ipv4": (
            "staticIPv4",
            {},
            [
                ("ip", "ip", str),
                ("gateway", "gateway", str),
                ("subnet", "subnet", str),
                ("primary_dns", "primaryDns", str),
                ("secondary_dns", "secondaryDns", str),
            ],
        ),
        "vlan": (
            "DataService",
            {"QoS": 0},
            [
                ("vlan_id", "VLAN", int),
            ],
        ),
    }

    def set_wano_cfg_to_persistent_storage(self, wano_cfg, **kwargs):
        """
        Set WANO cfg to persistent storage
        Args:
            wano_cfg: (dict) WANO config
            **kwargs:

        Returns:

        """
        return self.run_command(f"osps -p set local_config wan {shlex.quote(json.dumps(wano_cfg))}", **kwargs)

    def set_wano_cfg_to_ovsdb_storage(self, wano_cfg, **kwargs):
        """
        set WANO cfg to ovsdb storage
        Args:
            wano_cfg: (dict) WANO config
            **kwargs:

        Returns:

        """
        rows = []
        for new_ovsdb_type, (old_json_key, _, param_info) in self._ovsdb_to_json_mapping.items():
            if old_json_key in wano_cfg:
                config = wano_cfg[old_json_key]
                row = {}
                row["type"] = new_ovsdb_type
                row["os_persist"] = True
                row["enable"] = config["enabled"]
                params = row["other_config"] = {}
                for new_name, old_name, _ in param_info:
                    params[new_name] = str(config[old_name])
                rows.append(row)
        result = self.ovsdb.delete_row("WAN_Config", **kwargs)
        if result[0]:
            return result
        for row in rows:
            result = self.ovsdb.set_value(value=row, table="WAN_Config", **kwargs)
            if result[0]:
                return result
        return [0, "", ""]

    def set_wano_cfg(self, wano_cfg, **kwargs):
        """
        Set WANO cfg
        Args:
            wano_cfg: (dict) WANO config
            **kwargs:

        Returns:

        """
        # When WAN_Config table doesn't exist, WANO config is stored directly in persistent storage.
        if self.run_command("ovsdb-client list-tables | grep -q WAN_Config", **kwargs)[0]:
            return self.set_wano_cfg_to_persistent_storage(wano_cfg=wano_cfg, **kwargs)
        return self.set_wano_cfg_to_ovsdb_storage(wano_cfg=wano_cfg, **kwargs)

    def get_wano_cfg_from_persistent_storage(self, **kwargs):
        """
        Get WANO config from persistent storage
        Args:
            **kwargs:

        Returns:

        """
        result = self.run_command("osps -p get local_config wan", **kwargs)
        result[1] = result[1].rstrip("\0")
        return result

    def get_wano_from_ovsdb_storage(self, **kwargs):
        """
        Get WANO from ovsdb storage
        Args:
            **kwargs:

        Returns:

        """
        # We have to skip exception because selecting from empty table exits with 1.
        table = self.ovsdb.get_json_table("WAN_Config", **dict(kwargs, skip_exception=True)) or []
        # When there is only one row it gets returned as a dict, not wrapped in a list.
        if not isinstance(table, list):
            table = [table]
        wano_cfg = {"wanConnectionType": "dynamic"}
        for wan_type, rows in itertools.groupby(table, key=lambda row: row["type"]):
            json_key, removed_params, param_info = self._ovsdb_to_json_mapping[wan_type]
            configs = []
            for row in sorted(rows, key=lambda row: row["priority"], reverse=True):
                config = removed_params.copy()
                config["enabled"] = row["enable"]
                params = dict(row["other_config"][1])
                for new_name, old_name, old_type in param_info:
                    config[old_name] = old_type(params[new_name])
                configs.append(config)
            # Normally there is only one config per WAN type, treat that case as special.
            if len(configs) == 1:
                configs = configs[0]
            wano_cfg[json_key] = configs
        return [0, json.dumps(wano_cfg), ""]

    def get_wano_cfg(self, **kwargs):
        """
        Get WANO config from the node
        Args:
            **kwargs:

        Returns:

        """
        # When WAN_Config table doesn't exist, WANO config is stored directly in persistent storage.
        if self.run_command("ovsdb-client list-tables | grep -q WAN_Config", **kwargs)[0]:
            return self.get_wano_cfg_from_persistent_storage(**kwargs)
        return self.get_wano_from_ovsdb_storage(**kwargs)

    def start_wifi_blast(
        self,
        plan_id=None,
        blast_duration=None,
        blast_packet_size=None,
        blast_sample_count=None,
        mac_list: list = None,
        threshold_cpu=None,
        threshold_mem=None,
        **kwargs,
    ):
        """Start a WiFi blast through OVSDB"""
        step_id_and_mac, blast_config, blast_config_value, plan_steps = [], [], [], []
        # Step ID and Client mac
        for i in range(0, len(mac_list)):
            step_id = str(i + 1)
            step_id_and_mac.append([step_id, mac_list[i]])
        step_id_and_dest = str('["map",' + str(step_id_and_mac) + "]").replace("'", '"')

        # Adding Threshold mem and threshold cpu only if the value is passed
        if threshold_mem or threshold_cpu:
            if threshold_mem:
                blast_config_value.append('["threshold_mem","' + str(threshold_mem) + '"]'.replace("'", '"'))
            if threshold_cpu:
                blast_config_value.append('["threshold_cpu","' + str(threshold_cpu) + '"]'.replace("'", '"'))
            blast_config = str('["map",' + str(blast_config_value) + "]").replace("'", "")
        else:
            blast_config = str('["map",[]]')

        # Inserting values to Wifi_Blaster_Config table
        result = self.ovsdb.set_value_wifi_blast(
            table="Wifi_Blaster_Config",
            value={
                "plan_id": f"{plan_id}",
                "blast_duration": blast_duration,
                "blast_packet_size": blast_packet_size,
                "blast_sample_count": blast_sample_count,
                "step_id_and_dest": f"'{step_id_and_dest}'",
                "blast_config": f"'{blast_config}'",
            },
            **kwargs,
        )
        if result[0]:
            return result
        # Returning the request
        for i in range(0, len(mac_list)):
            temp = {"STEP_ID": i + 1, "CLIENT_MAC": mac_list[i]}
            plan_steps.append(temp)

        request = {
            "planId": plan_id,
            "planSteps": plan_steps,
            "requestId": result,
            "sampleDuration": blast_duration,
            "numberOfSamples": blast_sample_count,
        }
        return [0, request, ""]

    def get_wifi_associated_clients(self, **kwargs):
        """Get all connected WiFi Clients"""
        # TODO: refactor to use ovsdb object
        raw_table = self.get_stdout(self.get_ovsh_table("Wifi_Associated_Clients mac"), **kwargs)
        if not raw_table:
            return [1, "", "No entries in Wifi_Associated_Clients"]
        table = json.loads(raw_table)
        mac_list = []
        for entry in table:
            mac = entry.get("mac")
            mac_format = re.compile(r"(?:[0-9a-fA-F]:?){12}")
            mac_address = re.findall(mac_format, mac)[0]
            mac_list.append(mac_address)
        return [0, mac_list, ""]

    def get_sta_wifi_vif_mac(self, **kwargs):
        """Get MAC entry from Wifi_VIF_State where mode=sta"""
        # TODO: refactor to use ovsdb object
        raw_table = self.get_stdout(self.get_ovsh_table("Wifi_VIF_State -w mode==sta mac"), **kwargs)
        if not raw_table:
            return [1, "", "No entries for Wifi_VIF_State where mode=sta"]
        table = json.loads(raw_table)[0]
        if len(table) > 1:
            return [2, "", "Parent must be a single entry"]
        sta_mac = table["mac"]
        return [0, sta_mac, ""]

    def get_parent_wifi_vif_mac(self, **kwargs):
        """Get parent entry from Wifi_VIF_State where mode=sta"""
        # TODO: refactor to use ovsdb object
        raw_table = self.get_stdout(self.get_ovsh_table("Wifi_VIF_State -w mode==sta parent"), **kwargs)
        if not raw_table:
            return [1, "", "No entries for Wifi_VIF_State where mode=sta"]
        table = json.loads(raw_table)[0]
        if len(table) > 1:
            return [2, "", "Parent must be a single entry"]
        parent_mac = table["parent"]
        return [0, parent_mac, ""]

    def get_memory_information(self, **kwargs):
        """Get Memory Information of POD"""
        raw_table = self.get_stdout(self.run_command("cat /proc/meminfo"), **kwargs)
        # Converting the String to a list
        list_mem_info = raw_table.split("\n")
        # Removing the last empty entry
        list_mem_info.pop()
        # Converting list to dictionary
        mem_info_dict = dict(x.split(":") for x in list_mem_info)
        # Removing the empty spaces in key
        mem_info_dict = {key: value.lower().translate({32: None}) for key, value in mem_info_dict.items()}
        # If "kB" is not present in the value throwing exception to change logic!
        for key, value in mem_info_dict.items():
            if not value.find("kb"):
                return [2, "", 'String "kb" is not present in value. Revisit logic!']
        # Splitting the key based on "kB"
        mem_info_dict = {key: int(value.split("kb")[0]) for key, value in mem_info_dict.items()}
        return mem_info_dict

    def get_node_services(self, **kwargs):
        """Get all configured services from Node_Services table"""
        raw_table = self.strip_stdout_result(self.ovsdb.get_raw(table="Node_Services", select="service", **kwargs))
        table_list = raw_table[1].split("\n")
        return [raw_table[1], table_list, raw_table[2]]

    def configure_wifi_radio(self, freq_band: str, channel: int, ht_mode: str, **kwargs):
        """
        Configure wifi radio by manipulating Wifi_Radio_Config
        Args:
            freq_band: (str)
            channel: (int)
            ht_mode: (str)
            **kwargs:

        Returns: list([ret_val, std_out, std_err])

        """
        channel_request = self.ovsdb.set_value(
            value=dict(channel=channel), table="Wifi_Radio_Config", where=f"freq_band=={freq_band}", **kwargs
        )
        bw_request = self.ovsdb.set_value(
            value=dict(ht_mode=ht_mode), table="Wifi_Radio_Config", where=f"freq_band=={freq_band}", **kwargs
        )
        return self.merge_result(channel_request, bw_request)

    def list_builds(self, requested_version):
        return self.artifactory.build_list(requested_version)

    def run_plume_or_opensync_stats_extra(self, command: str, **kwargs) -> list[int, str, str]:
        parameters_from_cmd = command.split(" ", 1)[1]

        output = self.run_command(f"opensync-stats-extra {parameters_from_cmd}", **kwargs)

        if output[0] == 127:
            output = self.run_command(f"plume {parameters_from_cmd}", **kwargs)

        return output

    def get_parsed_conntrack_entries(self, raw_conntrack_entries: str, ipv6: bool = False) -> dict:
        """
        Get parsed conntrack entries and group them by protocol
        Args:
            raw_conntrack_entries: (str) raw conntrack entries: conntrack -L
            ipv6: (bool) ipv6 mode for getting conntrack entries

        Returns: (dict) {used_protocol: list(), ...}

        """
        if not raw_conntrack_entries:
            ipv6_option = "-f ipv6" if ipv6 else ""
            raw_conntrack_entries = self.get_stdout(
                self.run_command(f"conntrack -L {ipv6_option}"), skip_exception=True
            )

        parsed_conntrack_entries = dict()
        for conntrack_entry in raw_conntrack_entries.splitlines():
            used_protocol = conntrack_entry.split()[0]
            if not parsed_conntrack_entries.get(used_protocol):
                parsed_conntrack_entries[used_protocol] = list()
            # One conntrack entry contain two flows for upload and download direction.
            # Find next connection flow started from src= argument
            next_connection_flow_index = conntrack_entry.find(re.findall(r"src=[^\s]+ ", conntrack_entry)[-1])
            first_connection_flow = conntrack_entry[:next_connection_flow_index]
            second_connection_flow = conntrack_entry[next_connection_flow_index:]
            for connection_flow in [first_connection_flow, second_connection_flow]:
                match = _RE_PATTERN_CONNTRACK.match(connection_flow)
                if not match:
                    continue
                parsed_entry = match.groupdict()
                parsed_entry["bytes"] = int(parsed_entry["bytes"])
                parsed_conntrack_entries[used_protocol].append(parsed_entry)

        return parsed_conntrack_entries

    def get_pid_by_cmd(self, cmd: str, **kwargs) -> list[int, str, str]:
        """Get pid by provided cmd string"""
        grep_cmd = f'sh -c \'ps | grep "{cmd}"\' | grep -v "grep"'
        response = self.run_command(grep_cmd + " | awk '{print $1}'", **kwargs)
        if response[0] or not response[1]:
            return response
        return self.strip_stdout_result(response)

    def stop_sending_mqtt(self, **kwargs) -> list[int, str, str]:
        """Stop sending mqtt on the pod"""
        response = self.ovsdb.delete_row("Wifi_Stats_Config", where="stats_type!=device", **kwargs)
        return response

    def get_client_snr(self, ifname: str, client_mac: str, **kwargs) -> [int, str, str]:
        """
        Get SNR level of the connected client.
        Args:
            ifname: (str) Name of interface where is associated a client
            client_mac: (str) Client mac address
            **kwargs:

        Returns: [int, str, str]

        """
        raise NotImplementedError

    def get_beacon_interval(self, ifname: str, **kwargs) -> [int, str, str]:
        """
        Get Beacon Internal from the Wi-Fi driver.
        Args:
            ifname: (str) Name of interface
            **kwargs:

        Returns: [int, str, str]

        """
        raise NotImplementedError

    def get_rssi(self, ifname: str, mac: str, **kwargs) -> [int, str, str]:
        """
        Get RSSI.
        Args:
            ifname: (str) Name of interface
            mac: (str) mac address
            **kwargs:

        Returns: str

        """
        rssi_index = self.run_command(f"wlanconfig {ifname} list sta", **kwargs)[1].split().index("RSSI")
        response = self.run_command(f"wlanconfig {ifname} list sta | grep -i {mac}", **kwargs)[1].split()[rssi_index]

        if not response:
            return [1, "", f"Can not get RSSI value for interface: {ifname} and mac: {mac}"]
        return [0, str(response), ""]

    def wait_for_close_process(self, pid: str, timeout: int = 300, tick: float = 30) -> bool:
        """
        Wait for close a process
        Args:
            pid: (str) process id
            timeout: (int)
            tick: (float)

        Returns:

        """
        condition, ret = wait_for(lambda: self.run_command(f"ls /proc/ | grep {pid}")[0], timeout=timeout, tick=tick)
        return condition

    def clear_traffic_acceleration_dump(self, acceleration_dump: dict, **kwargs):
        """
        Clear traffic acceleration dump.
        Args:
            acceleration_dump: (dict) The acceleration dump details from run_traffic_acceleration_monitor() method

        Returns:

        """
        for acc_name, acc_monitor_details in acceleration_dump.items():
            pid, dump_file = acc_monitor_details["pid"], acc_monitor_details["dump_file"]
            process_cmd_line = self.get_stdout(
                self.strip_stdout_result(self.run_command(f"cat /proc/{pid}/cmdline", **kwargs)), skip_exception=True
            )
            # Make sure it's the acceleration monitor process
            if dump_file in process_cmd_line:
                self.run_command(f"kill {pid}", **kwargs)
            self.run_command(f"rm {dump_file}", **kwargs)

    def _run_traffic_acceleration_monitor(
        self, acc_name: str, acc_tool: str, samples: int = 5, interval: int = 5, delay: int = 20, **kwargs
    ) -> dict:
        """Helper method for starting traffic acceleration monitor in the background."""
        monitor_cmd_template = (
            "i=1; while  [ $i -le {samples} ]; "
            "do if [[ $i -eq 1 ]]; then sleep {delay}; fi; "
            "i=$(( $i + 1 )); {acc_tool} >> {acc_dump}; sleep {interval}; "
            "done & echo $!"
        )
        acc_dump_file = f"/tmp/{acc_name}_dump_{str(uuid4())[:5]}"
        ecm_monitor_cmd = monitor_cmd_template.format(
            samples=samples, delay=delay, acc_tool=acc_tool, acc_dump=acc_dump_file, interval=interval
        )
        acc_monitor_pid = self.get_stdout(self.strip_stdout_result(self.run_command(ecm_monitor_cmd, **kwargs)))
        return {acc_name: {"dump_file": acc_dump_file, "pid": acc_monitor_pid}}


class PodIface(Iface):
    def get_name(self):
        return f"iface_{self.lib.get_name()}"

    def get_iface_by_mask(self, ip, prefix=24):
        assert prefix == 24  # TODO: handle other prefixes
        pattern = ip[0 : ip.rfind(".")]
        wifi_inet_state = self.lib.ovsdb.get_json_table("Wifi_Inet_State")
        for table in wifi_inet_state:
            if pattern not in table.get("inet_addr", ""):
                continue
            target_ifname = table["if_name"]
            break
        else:
            assert False, f"Can not get ifname from following IP subnet: {pattern}"
        return target_ifname

    def get_vif_mac(self, ovs_bridge):
        """Get MAC of VIF bridge"""
        mac_list = self.lib.ovsdb.get_str(
            table="Wifi_VIF_State", select="mac", where=[f"if_name=={ovs_bridge}"], return_list=True
        )
        return mac_list

    def get_inet_mac(self, ovs_bridge):
        """Get MAC of inet bridge"""
        mac_list = self.lib.ovsdb.get_str(
            table="Wifi_Inet_State", select="hwaddr", where=[f"if_name=={ovs_bridge}"], return_list=True
        )
        return mac_list

    def get_native_ifname(self, ovs_bridge):
        # if not self.lib.run_command('ls /usr/opensync/lib/libaw.so'):
        #     return ovs_bridge
        path = self.lib.get_stdout(self.lib.get_opensync_path())
        response = self.lib.run_command(f"strings {path}/lib/libaw.so | grep -A1 {ovs_bridge}")
        assert not response[0]
        return response[1].splitlines()[1]

    def get_br_wan_mac(self):
        br_wan = self.lib.capabilities.get_wan_bridge_ifname()
        br_wan_mac = self.lib.ovsdb.get_str(table="Wifi_Inet_State", select="hwaddr", where=[f"if_name=={br_wan}"])
        return br_wan_mac

    def get_br_home_ip(self):
        br_home_iface = self.lib.capabilities.get_lan_bridge_ifname()
        br_home_ip = self.lib.ovsdb.get_str(
            table="Wifi_Inet_State", select="inet_addr", where=[f"if_name=={br_home_iface}"]
        )
        return br_home_ip

    def get_br_wan_ip(self):
        br_wan_iface = self.lib.capabilities.get_wan_bridge_ifname()
        br_wan_ip = self.lib.ovsdb.get_str(
            table="Wifi_Inet_State", select="inet_addr", where=[f"if_name=={br_wan_iface}"]
        )
        return br_wan_ip

    def get_native_br_home(self):
        br_home_iface = self.lib.capabilities.get_lan_bridge_ifname()
        br_home_mac = self.lib.ovsdb.get_str(
            table="Wifi_Inet_State", select="hwaddr", where=[f"if_name=={br_home_iface}"]
        )
        try:
            br_home_name = self.get_iface_by_mac(br_home_mac)
        except ValueError:
            br_home_ip = self.get_br_home_ip()
            br_home_name = self.get_iface_by_mask(br_home_ip)
        return br_home_name

    def get_bhal_60_ssid(self, ifname=None):
        if not ifname:
            ifname = self.lib.capabilities.get_bhaul_ap_ifnames(return_type=list, freq_band="6g")[0]
        ssid = self.lib.ovsdb.get_str(table="Wifi_VIF_State", select="ssid", where=[f"if_name=={ifname}"])
        return ssid

    def get_bhal_60_mac_list(self, bhal_60_iface=None):
        if bhal_60_iface is None:
            bhal_60_iface = self.lib.capabilities.get_bhaul_ap_ifnames(return_type=list, freq_band="6g")[-1]
        bhal_60_mac_list = self.lib.ovsdb.get_str(
            table="Wifi_VIF_State", select="mac_list", where=[f"if_name=={bhal_60_iface}"], return_list=True
        )
        return bhal_60_mac_list

    def get_bhal_50_ssid(self, ifname=None):
        if not ifname:
            ifname = self.lib.capabilities.get_bhaul_ap_ifnames(return_type=list, freq_band="5g")[0]
        ssid = self.lib.ovsdb.get_str(table="Wifi_VIF_State", select="ssid", where=[f"if_name=={ifname}"])
        return ssid

    def get_bhal_24_ssid(self):
        bhaul_ap_24 = self.lib.capabilities.get_bhaul_ap_ifname("24g")
        ssid_24 = self.lib.ovsdb.get_str(
            table="Wifi_VIF_State", select="ssid", where=[f"if_name=={bhaul_ap_24}", "ssid_broadcast==disabled"]
        )
        return ssid_24

    def get_bhal_24_mac(self):
        bhaul_ap_24 = self.lib.capabilities.get_bhaul_ap_ifname("24g")
        bssid_24 = self.lib.ovsdb.get_str(
            table="Wifi_VIF_State", select="mac", where=[f"if_name=={bhaul_ap_24}", "ssid_broadcast==disabled"]
        )
        return bssid_24

    def get_home_50_macs(self):
        home_50_ifnames = self.lib.capabilities.get_home_ap_ifnames(return_type=list, freq_band="5g")
        home_50_macs = [
            self.lib.ovsdb.get_str(table="Wifi_VIF_State", select="mac", where=[f"if_name=={home_50_ifname}"])
            for home_50_ifname in home_50_ifnames
        ]
        return home_50_macs

    def get_home_50_mac(self, freq_band=None):
        if not freq_band:
            home_50_ifname = self.lib.capabilities.get_home_ap_ifnames(return_type=list)[-1]
        else:
            home_50_ifname = self.lib.capabilities.get_home_ap_ifname(freq_band)
        home_50_mac = self.lib.ovsdb.get_str(table="Wifi_VIF_State", select="mac", where=[f"if_name=={home_50_ifname}"])
        return home_50_mac

    def get_home_24_mac(self):
        home_24_ifname = self.lib.capabilities.get_home_ap_ifname("24g")
        home_24_mac = self.lib.ovsdb.get_str(table="Wifi_VIF_State", select="mac", where=[f"if_name=={home_24_ifname}"])
        return home_24_mac

    def get_bhal_50_mac(self, freq_band=None):
        if not freq_band:
            ovs_bhal_50 = self.lib.capabilities.get_bhaul_ap_ifnames(return_type=list)[-1]
        else:
            ovs_bhal_50 = self.lib.capabilities.get_bhaul_ap_ifname(freq_band)
        bhal_50_mac = self.lib.ovsdb.get_str(
            table="Wifi_VIF_State", select="mac", where=[f"if_name=={ovs_bhal_50}"], return_list=True
        )[0]
        return bhal_50_mac

    def get_bhal_50_mac_list(self, bhal_50_iface=None):
        if bhal_50_iface is None:
            bhal_50_iface = self.lib.capabilities.get_bhaul_ap_ifnames(return_type=list)[-1]
        bhal_50_mac_list = self.lib.ovsdb.get_str(
            table="Wifi_VIF_State", select="mac_list", where=[f"if_name=={bhal_50_iface}"], return_list=True
        )
        return bhal_50_mac_list

    def get_bhal_50_macs_with_interfaces(self):
        bhal_50_ifaces = self.lib.capabilities.get_bhaul_ap_ifnames(return_type=list)
        bhal_50_mac_list = [
            self.lib.ovsdb.get_str(table="Wifi_VIF_State", select="mac", where=[f"if_name=={bhal_50_iface}"])
            for bhal_50_iface in bhal_50_ifaces
        ]
        return bhal_50_mac_list, bhal_50_ifaces

    def get_bhal_24_mac_list(self, bhal_24_iface=None):
        if bhal_24_iface is None:
            bhal_24_iface = self.lib.capabilities.get_bhaul_ap_ifname("24g")
        bhal_24_mac_list = self.lib.ovsdb.get_str(
            table="Wifi_VIF_State", select="mac_list", where=[f"if_name=={bhal_24_iface}"], return_list=True
        )
        return bhal_24_mac_list

    def get_bhal_24_mac_with_interfaces(self):
        bhal_24_iface = self.lib.capabilities.get_bhaul_ap_ifname("24g")
        bhal_24_mac_list = self.lib.ovsdb.get_str(
            table="Wifi_VIF_State", select="mac", where=[f"if_name=={bhal_24_iface}"]
        )
        return bhal_24_mac_list, bhal_24_iface

    def get_ifname_ssid(self, ifname):
        ssid = self.lib.ovsdb.get_str(table="Wifi_VIF_State", select="ssid", where=[f"if_name=={ifname}"])
        return ssid

    def get_ifname_psk(self, ifname):
        psk_dict = self.lib.ovsdb.get_str(table="Wifi_VIF_State", select="security", where=[f"if_name=={ifname}"])
        return psk_dict["key"]

    def get_bands_types(self):
        bands_types = self.lib.ovsdb.get_str(table="Wifi_Radio_State", select="freq_band")
        return bands_types

    def get_all_allowed_channels_for_regulatory_domain(self, band_type):
        allowed_channels = self.lib.ovsdb.get_set(
            table="Wifi_Radio_State", select="allowed_channels", where=[f"freq_band=={band_type}"], return_list=True
        )
        return allowed_channels

    def get_all_allowed_channels(self, band_type):
        allowed_channels = self.lib.ovsdb.get_set(
            table="Wifi_Radio_State", select="allowed_channels", where=[f"freq_band=={band_type}"], return_list=True
        )
        allowed_channels.sort()
        # remove channels not used by the optimizer
        for channel in [132, 136, 140, 144, 165]:
            if channel in allowed_channels:
                allowed_channels.remove(channel)
        if not self.lib.capabilities.is_dfs():
            # removing dfs channels
            for chan in allowed_channels[:]:
                if 52 <= chan <= 144:
                    allowed_channels.remove(chan)
        # Type conversion to string due to topology lib supports only string channel values
        allowed_channels = [str(allowed_channel) for allowed_channel in allowed_channels]
        return allowed_channels

    def get_allowed_channels(self, band_type):
        allowed_channels = self.lib.ovsdb.get_map(
            table="Wifi_Radio_State", select="channels", where=[f"freq_band=={band_type}"], return_list=True
        )
        allowed_channels = [
            int(allowed_channel) for allowed_channel, state in allowed_channels.items() if "allowed" in state
        ]
        allowed_channels.sort()
        # remove channels not used by the optimizer
        for channel in [132, 136, 140, 144, 165]:
            if channel in allowed_channels:
                allowed_channels.remove(channel)
        # Type conversion to string due to topology lib supports only string channel values
        allowed_channels = [str(allowed_channel) for allowed_channel in allowed_channels]
        return allowed_channels

    def get_dfs_channels(self, band_type):
        allowed_channels = self.lib.ovsdb.get_map(
            table="Wifi_Radio_State", select="channels", where=[f"freq_band=={band_type}"], return_list=False
        )
        dfs_channels = [
            int(allowed_channel)
            for allowed_channel, state in allowed_channels.items()
            if 52 <= int(allowed_channel) <= 144
        ]
        dfs_channels.sort()
        dfs_channels = [str(dfs_channel) for dfs_channel in dfs_channels]
        return dfs_channels

    def get_physical_wifi_mac(self, ifname):
        mac_address = self.lib.ovsdb.get_str(table="Wifi_Radio_State", select="mac", where=[f"if_name=={ifname}"])
        return mac_address

    def get_ip(self, external=True):
        """
        Get pod IP
        Args:
            external: (bool) in case of router mode, indicate, which br-wan or br-home IP return

        Returns: (str) IP address

        """
        if self.is_router_mode():
            br_wan_ip = None
            try:
                br_wan_ip = self.get_iface_ip(self.lib.capabilities.get_wan_bridge_ifname())
            except Exception:
                pass
            if external and br_wan_ip:
                return br_wan_ip
            return self.get_iface_ip(self.get_native_br_home())
        else:
            return self.get_iface_ip(self.lib.capabilities.get_wan_bridge_ifname())

    def is_router_mode(self):
        try:
            self.get_iface_ip(self.get_native_br_home())
            return True
        except ValueError:
            return False

    def is_ovs(self, **kwargs):
        response = self.lib.run_command("ovs-vsctl show", **kwargs)
        if response[0] == 0 and len(response[1].splitlines()) > 10:
            return True
        if response[0] and "not found" not in response[2]:
            # Raise exception
            self.lib.get_stdout(response, **kwargs)
        return False

    def get_backhauls(self):
        """
        Get information about all backhaul interfaces
        Returns: (dict) {'dev_if_name': {str), 'ssid': (str), 'mac_list': (list), 'associated_clients': (list)}

        """
        bhal_dict = {}
        bhal_24_ssid = self.get_bhal_24_ssid()

        # get info about bhal24 interfaces
        for bhal_24_iface in [self.lib.capabilities.get_bhaul_ap_ifname("24g")]:
            mac_list = self.get_bhal_24_mac_list(bhal_24_iface)
            associated_clients = self.lib.ovsdb.get_uuid(
                table="Wifi_VIF_State",
                select="associated_clients",
                where=[f"if_name=={bhal_24_iface}"],
                return_list=True,
            )
            if associated_clients is not None:
                associated_clients = [
                    str(assoc_client) for assoc_client in associated_clients if assoc_client is not None
                ]
            bhal_dict[bhal_24_iface] = {
                "dev_if_name": bhal_24_iface,
                "ssid": bhal_24_ssid,
                "mac_list": mac_list,
                "associated_clients": associated_clients,
            }

        # get info about bhal50 interfaces
        bhal_50_ifaces = self.lib.capabilities.get_bhaul_ap_ifnames(return_type=list, freq_band="5g")
        for bhal_50_iface in bhal_50_ifaces:
            bhal_50_ssid = self.get_bhal_50_ssid(bhal_50_iface)
            mac_list = self.get_bhal_50_mac_list(bhal_50_iface)
            associated_clients = self.lib.ovsdb.get_uuid(
                table="Wifi_VIF_State",
                select="associated_clients",
                where=[f"if_name=={bhal_50_iface}"],
                return_list=True,
            )
            if associated_clients is not None:
                associated_clients = [
                    str(assoc_client) for assoc_client in associated_clients if assoc_client is not None
                ]
            bhal_dict[bhal_50_iface] = {
                "dev_if_name": bhal_50_iface,
                "ssid": bhal_50_ssid,
                "mac_list": mac_list,
                "associated_clients": associated_clients,
            }

        bhal_60_ifaces = self.lib.capabilities.get_bhaul_ap_ifnames(return_type=list, freq_band="6g")
        for bhal_60_iface in bhal_60_ifaces:
            bhal_60_ssid = self.get_bhal_60_ssid(bhal_60_iface)
            mac_list = self.get_bhal_60_mac_list(bhal_60_iface)
            associated_clients = self.lib.ovsdb.get_uuid(
                table="Wifi_VIF_State",
                select="associated_clients",
                where=[f"if_name=={bhal_60_iface}"],
                return_list=True,
            )
            if associated_clients is not None:
                associated_clients = [
                    str(assoc_client) for assoc_client in associated_clients if assoc_client is not None
                ]
            bhal_dict[bhal_60_iface] = {
                "dev_if_name": bhal_60_iface,
                "ssid": bhal_60_ssid,
                "mac_list": mac_list,
                "associated_clients": associated_clients,
            }
        return bhal_dict

    def get_all_home_bhaul_ifaces(self):
        """
        Get all home_ap, bhaul interfaces
        Returns: (list)

        """
        all_interfaces = self.lib.capabilities.get_bhaul_ap_ifnames(
            return_type=list
        ) + self.lib.capabilities.get_home_ap_ifnames(return_type=list)
        return all_interfaces

    def get_all_assoc_clients_mac(self):
        return self.lib.ovsdb.get_str(table="Wifi_Associated_Clients", select="mac", return_list=True)

    def get_all_mac_addresses(self):
        wifi_vif_state = self.lib.ovsdb.get_json_table("Wifi_VIF_State")
        return [row["mac"].upper() for row in wifi_vif_state if row.get("mac")]


class Ovsdb:
    def __init__(self, lib):
        self.lib = lib
        self.re_mac_filter = re.compile("(?:[0-9a-fA-F]:?){12}", re.IGNORECASE)

    def _generate_get_cmd(self, table, select: str, where: Union[str, list] = None, option: str = ""):
        # handle OR operator for where argument
        if where and ("|" in where or "|" in where[0]):
            if isinstance(where, list):
                if len(where) > 1:
                    log.warning('Generating "where" only for the first where statement')
                or_where = where[0]
            else:
                or_where = where
            generated_echo = " ".join([f"'{where}'" for where in or_where.split("|")])
            cmd = f"echo {generated_echo} | xargs -n1 ovsh s {option} {table} {self.generate_select(select)} -w"
        else:
            cmd = f"ovsh s {table} " f"{self.generate_select(select)} " f"{self.generate_where(where)} " f"{option}"
        return cmd

    def get_raw(self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, **kwargs):
        cmd = self._generate_get_cmd(table, select, where, "-r")
        return self.lib.run_command(cmd, skip_exception=skip_exception, **kwargs)

    def get(self, table, select: str, where: Union[str, list] = None, skip_exception=False, **kwargs):
        results = self.lib.get_stdout(
            self.get_raw(table, select, where, **kwargs), skip_exception=skip_exception, **kwargs
        )
        if results or not results and not self.is_mac_address(where):
            return results
        # MAC address values from some devices are lower or upper cases.
        where = self.set_upper_mac_addresses(where)
        return self.lib.get_stdout(
            self.get_raw(table, select, where, **kwargs), skip_exception=skip_exception, **kwargs
        )

    def set_upper_mac_addresses(self, where_patterns):
        where_patterns = [where_patterns] if isinstance(where_patterns, str) else where_patterns
        for i, where_pattern in enumerate(where_patterns):
            if not (mac_address := re.search(self.re_mac_filter, where_pattern)):
                continue
            mac_address = mac_address.group()
            where_patterns[i] = where_pattern.replace(mac_address, mac_address.upper())
        return where_patterns

    def is_mac_address(self, where):
        if not where:
            return False
        return True if list(filter(self.re_mac_filter.search, where)) else False

    def get_json_table(self, table, where: Union[str, list] = None, select: Union[str, list] = None, **kwargs):
        result = self.lib.get_stdout(
            self.lib.run_command(
                f"ovsh -j s {table} {self.generate_where(where)} {self.generate_select(select)}", **kwargs
            ),
            **kwargs,
        )
        if not result:
            return None
        result = json.loads(result)
        return result[0] if len(result) == 1 and isinstance(result, list) else result

    @staticmethod
    def generate_where(value, **kwargs):
        if value is None or not value or value == "update":
            return ""
        elif isinstance(value, list):
            return f'-w {" -w ".join(value)}'
        elif isinstance(value, str):
            return f"-w {value}"
        else:
            raise ValueError

    @staticmethod
    def generate_select(value):
        if value is None or not value:
            return ""
        elif isinstance(value, list):
            return " ".join(value)
        elif isinstance(value, str):
            return value
        else:
            raise ValueError

    def parse_raw(  # noqa: C901
        self, value_type, output, skip_exception=False, return_list=False  # noqa C901
    ) -> Union[int, bool, str, dict, list, UUID]:
        result = list()

        lines = output.splitlines()

        for line in lines:
            line = line.strip()
            if line == '["set",[]]':
                result.append([])
                continue
            elif line == "":
                continue

            try:
                if value_type == str:
                    if re.match(r"^\[\"set\",\[.*?\]\]$", line) is not None:
                        result.append(self.parse_raw(list, line))
                        continue
                    else:
                        value = line
                else:
                    try:
                        value = json.loads(line)
                    except json.decoder.JSONDecodeError:
                        # Workaround for parsing json with missed brackets. Ticket has been already created to fix it.
                        updated, line = self.fix_map_json_end_brackets(raw_data=line)
                        if updated:
                            value = json.loads(line)
                        else:
                            value = json.loads(f'["set",["{line}"]]')

                if value_type is None:
                    result.append(value)
                elif value_type == dict and isinstance(value, list) and len(value) > 1:
                    if value[0] != "map":
                        raise ValueError(f"Type mismatch. Expected map; got {value[0]}")
                    result.append(self.ovsdb_map_to_python_dict(value))
                elif value_type == list and isinstance(value, list) and len(value) > 1:
                    if value[0] != "set":
                        raise ValueError(f"Type mismatch. Expected set; got {value[0]}")
                    result.append(value[1])
                elif value_type == list and (isinstance(value, int) or isinstance(value, str)):
                    result.append(value)
                elif value_type == UUID and isinstance(value, list) and len(value) > 1:
                    if re.match(r"^\[\"set\",\[.*?\]\]$", line) is not None:
                        values = self.parse_raw(list, line, skip_exception=skip_exception, return_list=return_list)
                        result += [UUID(val[1]) for val in values]
                        continue
                    if value[0] != "uuid":
                        raise ValueError(f"Type mismatch. Expected uuid; got {value[0]}")
                    result.append(self.ovsdb_uuid_to_python_uuid(value[1]))
                elif value_type == bool and isinstance(value, str):
                    result.append(bool(distutils.util.strtobool(value)))
                elif value_type == type(value):
                    result.append(value)
                else:
                    raise ValueError(f"Can not convert {type(value).__name__} to {value_type.__name__}")
            except Exception as e:
                result.append(None)
                if not skip_exception:
                    raise e

        if len(result) == 1 and (not return_list or return_list and isinstance(result[0], list)):
            result = result[0]

        # join the rows together as we got multiple lines as a raw_data from ovsh
        if value_type == str and len(result) > 1 and result[0] and isinstance(result[0], list):
            result = [item for row in result for item in row]

        return result

    def get_int(
        self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False, **kwargs
    ) -> Union[int, list]:
        raw_data = self.get(table, select, where, skip_exception=skip_exception, **kwargs)
        return self.parse_raw(int, raw_data, skip_exception=skip_exception, return_list=return_list)

    def get_bool(
        self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False, **kwargs
    ) -> Union[bool, list]:
        raw_data = self.get(table, select, where, skip_exception=skip_exception, **kwargs)
        return self.parse_raw(bool, raw_data, skip_exception=skip_exception, return_list=return_list)

    def get_str(
        self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False, **kwargs
    ) -> Union[str, list]:
        raw_data = self.get(table, select, where, skip_exception=skip_exception, **kwargs)
        return self.parse_raw(str, raw_data, skip_exception=skip_exception, return_list=return_list)

    def get_map(
        self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False, **kwargs
    ) -> Union[dict, list]:
        raw_data = self.get(table, select, where, skip_exception=skip_exception, **kwargs)
        return self.parse_raw(dict, raw_data, skip_exception=skip_exception, return_list=return_list)

    def get_set(
        self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False, **kwargs
    ) -> list:
        raw_data = self.get(table, select, where, skip_exception=skip_exception, **kwargs)
        return self.parse_raw(list, raw_data, skip_exception=skip_exception, return_list=return_list)

    def get_uuid(
        self, table: str, select: str, where: Union[str, list] = None, skip_exception=False, return_list=False, **kwargs
    ) -> Union[UUID, list]:
        raw_data = self.get(table, select, where, skip_exception=skip_exception, **kwargs)
        return self.parse_raw(UUID, raw_data, skip_exception=skip_exception, return_list=return_list)

    def set_value(self, value: dict, table: str, where: Union[str, list] = None, skip_exception=False, **kwargs):
        cmd = (
            f'ovsh {"i" if where is None or len(where) == 0 else "U"} {table} '
            f"{self.generate_values_str(value, skip_exception=skip_exception, **kwargs)} "
            f"{self.generate_where(where, **kwargs)}"
        )
        result = self.lib.run_command(cmd, skip_exception=skip_exception, **kwargs)
        if result[0] == 1 and "ERROR: Upsert: more than one row matched" in result[2]:
            cmd = (
                f"ovsh u {table} "
                f"{self.generate_values_str(value, skip_exception=skip_exception, **kwargs)} "
                f"{self.generate_where(where)}"
            )
            result = self.lib.run_command(cmd, skip_exception=skip_exception, **kwargs)

        return result

    # TOD0: merge with the default set_value method once get possibility to test
    def set_value_wifi_blast(self, value: dict, table: str, where: Union[str, list] = None, skip_exception=False):
        def generate_values(values, skip_exception=False):
            return " ".join(
                [f'{k}{":"}' f"={self.python_value_to_ovsdb_value(v, skip_exception)}" for k, v in values.items()]
            )

        cmd = (
            f'ovsh {"i" if where is None or len(where) == 0 else "U"} {table} '
            f"{generate_values(value, skip_exception=skip_exception)} "
            f"{self.generate_where(where)}"
        )
        result = self.lib.run_command(cmd, skip_exception=skip_exception)
        if result[0] == 1 and "ERROR: Upsert: more than one row matched" in result[2]:
            cmd = (
                f"ovsh u {table} "
                f"{self.generate_values_str(value, skip_exception=skip_exception)} "
                f"{self.generate_where(where)}"
            )
            result = self.lib.run_command(cmd, skip_exception=skip_exception)
        return result

    def delete_row(self, table: str, where: Union[str, list] = None, skip_exception=False, **kwargs):
        cmd = f"ovsh d {table} " f"{self.generate_where(where)}"
        return self.lib.run_command(cmd, skip_exception=skip_exception, **kwargs)

    def mutate(
        self,
        table: str,
        select: str,
        action: str,
        value: str,
        where: Union[str, list] = None,
        row_type: str = "set",
        skip_exception=False,
        **kwargs,
    ):
        assert action in ["ins", "del"]
        if action == "del" and row_type == "set":
            cmd = f"ovsh u {table} {self.generate_where(where)} {select}:{action}:'[\"set\",{value}]'"
        else:
            cmd = f"ovsh u {table} {self.generate_where(where)} {select}:{action}:'[\"map\",[{value}]]'"
        return self.lib.run_command(cmd, skip_exception=skip_exception, **kwargs)

    def generate_values_str(self, values, skip_exception=False, **kwargs):
        operator = kwargs.pop("operator", None)
        return " ".join(
            [
                f'{k}{operator if operator else "~" if isinstance(v, str) else ":"}'
                f"={self.python_value_to_ovsdb_value(v, skip_exception)}"
                for k, v in values.items()
            ]
        )

    @staticmethod
    def python_list_to_ovsdb_set(value):
        if not isinstance(value, list):
            raise ValueError

        return f'\'["set",[{",".join(value)}]]\''

    @staticmethod
    def ovsdb_map_to_python_dict(value):
        if value[0] == "map":
            value = value[1]

        res = dict()
        for item in value:
            res[item[0]] = item[1]

        return res

    @staticmethod
    def python_dict_to_ovsdb_map(value):
        if not isinstance(value, dict):
            raise ValueError

        str_list = list()
        for k, v in value.items():
            if isinstance(v, bool):
                v = str(v).lower()

            str_list.append(f'["{k}","{v}"]')

        return f'\'["map",[{",".join(str_list)}]]\''

    @staticmethod
    def ovsdb_uuid_to_python_uuid(value):
        if isinstance(value, list) and len(value) > 1:
            value = value[1]

        return UUID(value)

    @staticmethod
    def python_uuid_to_ovsdb_uuid(value):
        if not isinstance(value, UUID):
            raise ValueError

        return f'\'["uuid","{value}"]\''

    def python_value_to_ovsdb_value(self, value, skip_exception=False):
        if isinstance(value, dict):
            value = self.python_dict_to_ovsdb_map(value)
        elif isinstance(value, list):
            value = self.python_list_to_ovsdb_set(value)
        elif isinstance(value, UUID):
            value = self.python_uuid_to_ovsdb_uuid(value)
        elif isinstance(value, bool):
            value = str(value).lower()
        elif isinstance(value, int):
            value = str(value)
        elif isinstance(value, str):
            value = f'"{value}"'
        else:
            if skip_exception:
                return None
            raise ValueError
        return value

    def get_name(self):
        return f"ovsdb_{self.lib.get_name()}"

    @staticmethod
    def fix_map_json_end_brackets(raw_data):
        updated = False
        expected_close_map_brackets = 3
        if "map" not in raw_data:
            return updated, raw_data
        brackets = re.findall(r"]", raw_data[-3:])
        if len(brackets) == 3:
            return updated, raw_data
        for _i in range(expected_close_map_brackets):
            raw_data += "]"
            if len(re.findall(r"]", raw_data[-3:])) == 3:
                break
        updated = True
        return updated, raw_data
