import collections
import os
import re
import time
import pexpect
from pexpect import spawn
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.switch.generic.switch_lib_generic import SwitchLibGeneric
from lib_testbed.generic.switch.util import get_switch_config_path

REQUEST_TIMEOUT = 30
MAX_READ = 2000


class SwitchLib(SwitchLibGeneric, spawn):
    def __init__(self, switch_name, user, password, ip, port, set_echo=False, **kwargs):
        # Initialize spawn class with all default parameters
        spawn.__init__(
            self,
            command=None,
            timeout=REQUEST_TIMEOUT,
            maxread=MAX_READ,
            searchwindowsize=None,
            logfile=None,
            cwd=None,
            env=None,
        )
        SwitchLibGeneric.__init__(
            self, switch_name=switch_name, user=user, password=password, ip=ip, port=port, **kwargs
        )
        self.switch_prompt = f"{self.switch_name}[#>(]"
        self.set_echo = set_echo
        self.spawn_cmd = f"telnet {self.ip} {self.port}"
        self._port_to_interface = {}
        self._port_id_to_speed = {}

    def _login(self):
        self._spawn(self.spawn_cmd)
        self.setecho(self.set_echo)
        # self.logfile = sys.stdout
        try:
            self.expect("User:")
        except pexpect.exceptions.EOF as e:
            log.error(f"Probably there is no connection with the switch: {self.ip}:{self.port}. Exiting...")
            raise e
        self.sendline(self.user + "\r")
        self.expect("Password:")
        self.sendline(self.password + "\r")
        for _ in range(10):
            self.send_command("")
            if (
                isinstance(self.after, bytes)
                and (self.after.endswith(b">") or self.after.endswith(b"#"))
                or self.after == pexpect.EOF
            ):
                break
            time.sleep(0.5)
        if self.after == pexpect.TIMEOUT:
            raise pexpect.TIMEOUT("Can not login to switch. Check switch configuration")

    def login(self):
        try:
            self._login()
        except Exception as err:
            # Close telnet session in case of failed login attempt
            self.logout()
            raise err

    def admin_login(self):
        self.login()
        self.enable_admin_mode()
        self._cache_switch_interfaces()

    def admin_logout(self):
        self.logout()

    def _cache_switch_interfaces(self):
        if self._port_to_interface:
            return
        out = self.send_command("show interface configuration")
        short_to_full_type = {
            "Gi": "gigabitEthernet",
            "Tw": "two-gigabitEthernet",
            "Te": "ten-gigabitEthernet",
        }
        interfaces = {}
        port_speeds = {}
        for line in out.splitlines():
            # Port      State       Speed     Duplex    FlowCtrl    Description
            # ----      -----       -----     ------    --------    -----------
            # Tw1/0/1   Enable      Auto      Auto      Disable
            if line.strip():
                port = line.split()[0]
                speed, unit_one, position = port.partition("1/0/")
                if unit_one:
                    port_type = short_to_full_type.get(speed, "fastEthernet")
                    interfaces[position] = f"{port_type} 1/0/{position}"
                    port_speeds[f"1/0/{position}"] = speed.lower()
        self._port_to_interface.update(interfaces)
        self._port_id_to_speed.update(port_speeds)

    def get_interface_id(self, port):
        return self._port_to_interface.get(str(port), f"gigabitEthernet 1/0/{port}")

    def no_shutdown_interface(self, ports):
        return self.action_interface(ports, "no shutdown")

    def shutdown_interface(self, ports):
        return self.action_interface(ports, "shutdown")

    def action_interface(self, ports, action):
        self.admin_login()
        self.send_command("configure")
        retval = []
        for port in ports:
            interface_id = self.get_interface_id(port)
            out = self.send_command(f"interface {interface_id}")

            if "Invalid port number".lower() in out.lower():
                retval.append([1, "", f"Invalid port number {port}"])
                continue

            # (no)shutdown
            self.send_command(action)
            for _ in range(10):
                self.send_command("")
                if (
                    isinstance(self.after, bytes)
                    and (self.after.endswith(b">") or self.after.endswith(b"#"))
                    or self.after == pexpect.EOF
                ):
                    break
                time.sleep(0.5)
            out = self.send_command("show interface configuration")

            port_num = f"1/0/{port}"
            for line in out.splitlines():
                if port_num not in line:
                    continue
                parts = line.split()
                state = parts[1].strip()
                speed = parts[2].strip().replace(".5G", "500M").replace("G", "000M")
                if "shutdown" in action:
                    if (action == "no shutdown" and state == "Enable") or (action == "shutdown" and state == "Disable"):
                        retval.append([0, f"{port_num} {state}", ""])
                    else:
                        retval.append([1, "", f"Could not change status to {action.upper()} on port {port}"])
                elif "speed" in action:
                    exp_speed = action.split()[1].strip()
                    if exp_speed.upper() == "AUTO":
                        exp_speed = "Auto"
                    else:
                        exp_speed = f"{exp_speed}M"
                    if exp_speed == speed:
                        retval.append([0, f"{port_num} {speed}", ""])
                    else:
                        retval.append([1, "", f"Could not change speed to {exp_speed} on port {port}"])
                else:
                    retval.append([0, "", ""])
                break

            self.send_command("exit")
        self.send_command("exit")
        self.send_command("exit")
        self.admin_logout()
        return retval

    def interface_status(self, ports):
        self.admin_login()
        cmd = "show interface configuration"
        out = self.send_command(cmd)

        status = {}
        for line in out.splitlines():
            m = re.search(r"([0-9A-Za-z]{3}/[0-9]{1}/([0-9]+) \s* [A-Za-z]{6,7}).*", line.strip())
            if m:
                port_status = m.group(1)
                port_num = m.group(2)
                status[port_num] = port_status

        retval = []
        for port in ports:
            if str(port) in status:
                retval.append([0, status[str(port)], ""])
            else:
                retval.append([1, "", f"Could not find status for port {port}"])

        self.admin_logout()
        return retval

    def interface_status_parser(self, status):
        """
        Parse return value of interface_status() method.
        @param status: Return value of interface_status() method. Example: [0, 'Gi1/0/12  Enable', '']
        @return: {
            'name': <Interface name (Gi1/0/12)>,
            'id': <Interface id (1/0/12)>,
            'type': <Interface type (gigabitEthernet)>,
            'state': <Interface state (Enable)>
        }
        """
        parsed = {"name": None, "id": None, "type": None, "state": None}
        if status[0] == 0:
            stat = status[1].split()
            parsed["name"] = stat[0]
            speed, unit, position = parsed["name"].partition("1/0/")
            if unit is not None:
                parsed["id"] = f"{unit}{position}"
                if speed == "Gi":
                    parsed["type"] = "gigabitEthernet"
                elif speed == "Tw":
                    parsed["type"] = "two-gigabitEthernet"
                elif speed == "Te":
                    parsed["type"] = "ten-gigabitEthernet"
            parsed["state"] = stat[1]
        return parsed

    def interface_info(self, ports):
        self.admin_login()
        retval = []
        for port in ports:
            interface_id = self.get_interface_id(port)
            cmd = f"show interface switchport {interface_id}"
            out = self.send_command(cmd)

            if "Invalid port number".lower() in out.lower():
                retval.append([1, "", f"Invalid port number {port}"])
                continue

            port_status = ""
            for line in out.splitlines():
                if line.strip().startswith("PVID:"):
                    pvid = line.strip().split(" ")[1]
                    port_status += "{:^8} {:^6}".format("PVID", pvid)

                m = re.search(r"([0-9]{1,4}) \s* ([0-9A-Za-z].*) \s* ([A-Za-z].*)", line.strip())
                if m:
                    vlan = m.group(1)
                    description = m.group(2)
                    type = m.group(3)
                    port_status += "\n{:^8} {:^6} {:^8}".format(type, vlan, description)

            if len(port_status) == 0:
                retval.append([1, "", f"Problems to find info for port {port}"])
            else:
                retval.append([0, port_status, ""])

        self.send_command("exit")
        self.admin_logout()
        return retval

    def show_ports_isolation_interface(self, ports):
        self.admin_login()
        retval = []
        for port in ports:
            interface_id = self.get_interface_id(port)
            cmd = f"show port isolation interface {interface_id}"
            out = self.send_command(cmd)

            if "Invalid port number".lower() in out.lower():
                retval.append([1, "", f"Invalid port number {port}"])
                continue

            ports_isolation = None
            for line in out.splitlines():
                # Port      LAG       Forward-List
                # ----      ---       ------------------------------------------------
                # Tw1/0/2   N/A       Tw1/0/3-5,1/0/7,Te1/0/9
                line = line.strip()
                if line.startswith(("Gi", "Tw", "Te")):
                    _port, _lag, forward_list = line.split()
                    port_groups = [g[2:] if g.startswith(("Gi", "Tw", "Te")) else g for g in forward_list.split(",")]
                    ports_isolation = ",".join(port_groups)
                    break

            if not ports_isolation:
                retval.append([1, "", f"Problems to find port isolation info for port {port}"])
            else:
                retval.append([0, ports_isolation, ""])

        self.admin_logout()
        return retval

    def interface_info_parsed(self, ports):
        interface_info = self.interface_info(ports)
        parsed_ports_info = list()
        for port_info in interface_info:
            parsed_ports_info.append(self.interface_info_parser(port_info))
        return parsed_ports_info

    def interface_info_parser(self, info):
        """
        Parse return value of interface_info() method.
        @param info: Return value of interface_info() method.
                     Example:
                     [0, '  PVID    712  \n Tagged    4    Management        \nUntagged  712   BlackHole_712     ', '']
        @return: {
            'pvid': <PVID (712)>,
            'tagged': [<Tagged VLAN ID (4)>],
            'untagged': [<Untagged VLAN ID (712)>],
            'vlans': {<VLAN ID (4)>: <VLAN name (Management)>}
        }
        """
        parsed = {"pvid": None, "tagged": [], "untagged": [], "vlans": {}}
        if info[0] == 0:
            for line in info[1].splitlines():
                s = line.split()
                if "PVID" in line:
                    parsed["pvid"] = s[1]
                elif "Tagged" in line:
                    parsed["tagged"].append(s[1])
                    parsed["vlans"][s[1]] = s[2]
                elif "Untagged" in line:
                    parsed["untagged"].append(s[1])
                    parsed["vlans"][s[1]] = s[2]
        return parsed

    def system_info(self):
        self.admin_login()
        out = self.send_command("show system-info")
        out = "\n".join(line.strip() for line in out.lstrip("show system-info").strip().splitlines())
        self.admin_logout()
        return 0, out, ""

    def version(self):
        system_info = self.system_info()
        for line in system_info[1].splitlines():
            if "System Location" in line:
                return 0, line.split("-")[-1].strip(), ""
        return 1, "UNKNOWN", "UNKNOWN"

    def restore_config(self):
        def copy_config_to_tftp(config_path):
            log.info(f"Copying {config_path} to {tftp_path}")
            return client.run_raw(f"cp {config_path} {tftp_path}")[0]

        # need to know which config to restore
        model = self.get_model()[1]
        client = self.get_host_client()
        config_path = get_switch_config_path(client, "tplink", model, self.switch_name)
        if not config_path:
            return [2, "", f"Switch model {model} named '{self.switch_name}' is not supported"]
        # Copy required config to the tftp directory on the rpi-server
        tftp_path = "/srv/tftp"
        if copy_config_to_tftp(config_path):
            return [5, "", "Failed to copy switch config file"]
        filename = os.path.basename(config_path)
        self.admin_login()
        out = self.send_command(f"copy tftp startup-config ip-address 192.168.5.1 filename {filename}")
        self.admin_logout()
        if "Failed to load" in out:
            return [25, "", out]
        # get rid of first line with command printed 4 times
        out = "\n".join(out.splitlines()[1:])
        # wait for a switch boot
        timeout = time.time() + 180
        while time.time() < timeout:
            if client.run_raw("pwd", skip_logging=True, retry=False)[0] == 0:
                break
            time.sleep(5)
        else:
            return [255, "", "Cannot restore connection with rpi-server"]
        client.run(f"rm  {tftp_path}/{filename}", skip_exception=True)
        return [0, out, ""]

    def list_vlan(self):
        self.admin_login()
        self.send_command("configure")
        out = self.send_command("show vlan brief")
        # show vlan command output contains a mix of \n, \r\n and \n\r line endings
        table = "\n".join(line.rstrip() for line in out.lstrip("show vlan brief").splitlines() if line.strip())

        self.admin_logout()
        return [0, table, ""]

    def list_vlan_parser(self, list_vlan):
        """
        Parse return value of list_vlan() method.
        @param list_vlan: Return value of list_vlan() method.
                          Example: 'VLAN  Name                 Status    Ports\r\n
                                    ----- -------------------- --------- ----------------------------------------\r\n
                                    1     System-VLAN          active    Gi1/0/46, Gi1/0/47, Gi1/0/48, Gi1/0/49,\r\n'
        @return: {
            <VLAN ID (1)>: {
                'name': <VLAN name (System-VLAN)>,
                'status': <VLAN status (active)>,
                'ports': [<Interface name (Gi1/0/46)>]
            }
        }
        """
        parsed = {}
        vlan = None
        for line in list_vlan.splitlines():
            s = [x.rstrip(",") for x in line.strip().split()]
            if len(s) == 0:
                continue
            if s[0] == "VLAN" or all(x == "-" for x in s[0]):
                continue
            if s[0].isdigit():
                vlan = s[0]
                parsed[vlan] = {}
                parsed[vlan]["name"] = s[1]
                parsed[vlan]["status"] = s[2]
                parsed[vlan]["ports"] = s[3:]
            else:
                parsed[vlan]["ports"].extend(s)
        return parsed

    def list_pvid(self):
        self.admin_login()
        self.send_command("configure")
        out = self.send_command("show interface switchport")
        table = out.lstrip("show interface switchport").strip()
        self.admin_logout()
        return [0, table, ""]

    def list_pvid_parser(self, list_pvid):
        """
        Parse return value of list_pvid() method.
        @param list_pvid: Return value of list_pvid() method.
                          Example: 'Port      LAG       Type          PVID      Acceptable frame type  Ingress Checking
                                    -------   ---       ----          ----      ---------------------  ----------------
                                    Gi1/0/1   N/A       General       200       All                    Enable\r\n '
        @return: {
            <Interface name (Gi1/0/1)>: {
                'lag': <LAG participation (N/A)>,
                'type': <PVID type (General)>,
                'pvid': <PVID ID (200)>,
                'acceptable_frame_type': <Acceptable frame type (All)>,
                'ingress_checking': <Ingress Checking (Enable)>
            }
        }
        """
        parsed = {}
        for line in list_pvid.splitlines():
            s = line.strip().split()
            if len(s) == 0:
                continue
            if s[0] == "Port" or all(x == "-" for x in s[0]):
                continue
            parsed[s[0]] = {
                "lag": s[1],
                "type": s[2],
                "pvid": s[3],
                "acceptable_frame_type": s[4],
                "ingress_checking": s[5],
            }
        return parsed

    def delete_vlan(self, ports, vlan):
        vlan = str(vlan)
        self.admin_login()
        self.send_command("configure")
        retval = []
        for port in ports:
            interface_id = self.get_interface_id(port)
            out = self.send_command(f"show interface switchport {interface_id}")

            if "Invalid port number".lower() in out.lower():
                retval.append([1, "", f"Invalid port number {port}"])
                continue

            vlans = self._get_vlan_status(out)
            if vlan in vlans:
                self.send_command(f"interface {interface_id}")
                out = self.send_command(f"no switchport general allowed vlan {vlan}")

                vlans2 = self._get_vlan_status(out)
                if vlan not in vlans2:
                    retval.append([0, f"1/0/{port}  VLAN {vlan}  Deleted", ""])
                else:
                    retval.append([1, "", f"Could not delete VLAN {vlan} - 1/0/{port}"])

            else:
                retval.append([1, "", f"Could not find vlan {vlan} for interface {interface_id}"])

        self.admin_logout()
        return retval

    def set_vlan(self, ports, vlan, vlan_type):
        vlan = str(vlan)
        if vlan_type not in ["tagged", "untagged"]:
            return [[1, "", f"Vlan type '{vlan_type}' is not allowed. You can use: ['tagged', 'untagged']"]]

        self.admin_login()
        self.send_command("configure")

        if not self._check_vlan_exists(vlan):
            return [[1, "", f"Vlan '{vlan}' does not exist. Please create it manually on the switch ({self.ip})!"]]

        retval = []
        for port in ports:
            interface_id = self.get_interface_id(port)
            out = self.send_command(f"interface {interface_id}")

            if "Invalid port number".lower() in out.lower():
                retval.append([1, "", f"Invalid port number {port}"])
                continue

            if vlan_type == "untagged":
                # set PVID
                self.send_command(f"switchport pvid {vlan}")

            # set VLAN
            self.send_command(f"switchport general allowed vlan {vlan} {vlan_type}")
            out = self.send_command(f"show interface switchport {interface_id}")
            found = False
            for line in out.splitlines():
                m = re.search(r"([0-9]{1,4}) \s* [0-9A-Za-z].* \s* ([A-Za-z].*)", line.strip())
                if m:
                    vl = m.group(1)
                    v_type = m.group(2)

                    if str(vl) == str(vlan) and str(vlan_type) == str(v_type).lower():
                        retval.append([0, f"{interface_id} - VLAN '{vlan}' Type: '{vlan_type}' Set Successfully", ""])
                        found = True
                        if vlan_type == "untagged":
                            # delete old VLAN
                            self._delete_existing_vlan(port, whitelist=[vlan])
                        break

            if not found:
                retval.append([1, "", f"{interface_id} - VLAN '{vlan}' Type: '{vlan_type}' NOT Set"])

        self.admin_logout()
        return retval

    def logout(self):
        self.pid = None
        while self.after and isinstance(self.after, bytes) and not self.after.endswith(b">"):
            self.send_command("exit")
        self.sendline("logout")
        self.close()

    def send_command(self, cmd, prompt=None, timeout=10):
        if not cmd.endswith("\r"):
            cmd += "\r"
        if prompt is None:
            prompt = f"{self.switch_prompt}.*"
        more = r"(Press any key to continue.*|.*\(Y/N\):.*)"
        pattern_list = [more, pexpect.TIMEOUT, pexpect.EOF, prompt]
        self.sendline(cmd)
        out = ""
        stop_time = time.time() + timeout
        while time.time() < stop_time:
            time.sleep(0.2)
            index = self.expect(pattern=pattern_list, timeout=timeout)
            out += str(self.before, "utf-8")
            if index == 0:
                # Not finished yet, send space to continue
                self.sendline("Y")
            else:
                break
        return out

    def get_model(self):
        system_info = self.system_info()
        for line in system_info[1].splitlines():
            if "Hardware Version" not in line:
                continue
            # Hardware Version     - T1500G-8T 2.0
            model = line.split("-", 1)[-1].strip().split()[0]
            return [0, model, ""]
        return [1, "", "Cannot get switch size"]

    def enable_admin_mode(self):
        self.buffer = bytes(0)
        if "EOF" in str(self.after):
            self.logout()
            self.login()
        while self.after and isinstance(self.after, bytes) and not self.after.endswith(b">"):
            self.send_command("exit")

        while self.after and isinstance(self.after, bytes) and not self.after.endswith(b"#"):
            self.send_command("enable", prompt=f"{self.switch_name}[#]")

    def get_link_status(self, ports):
        self.admin_login()
        self.send_command("configure")
        retval = []
        for port in ports:
            interface_id = self.get_interface_id(port)
            out = self.send_command(f"show interface status {interface_id}")
            if "invalid port number" in out.lower():
                retval.append([1, "", f"Invalid port number {port}"])
                continue
            if regex_search := re.search("link *.+", out, re.IGNORECASE):
                out = regex_search.group().lower()
            retval.append([0, out, ""])
        self.send_command("exit")
        self.send_command("exit")
        self.admin_logout()
        return retval

    def _get_vlan_status(self, before):
        vlans = {}
        for line in before.splitlines():
            m = re.search(r"([0-9]{1,4}) \s* [0-9A-Za-z].* \s* ([A-Za-z].*)", line.strip())
            if m:
                vl = m.group(1)
                type = m.group(2)
                vlans[vl] = type
        return vlans

    def _check_vlan_exists(self, vlan):
        out = self.send_command("show vlan brief")
        vlans = []
        for line in out.splitlines():
            m = re.search(r"([0-9]{1,4}) \s* [0-9A-Za-z].* \s* [A-Za-z].*", line.strip())
            if m:
                vlans.append(m.group(1))
        return vlan in vlans

    def _delete_existing_vlan(self, port, whitelist=()):
        interface_id = self.get_interface_id(port)
        out = self.send_command(f"show interface switchport {interface_id}")
        vlans = {}
        for line in out.splitlines():
            m = re.search(r"([0-9]{1,4}) \s* [0-9A-Za-z].* \s* ([A-Za-z].*)", line.strip())
            if m:
                vlan = m.group(1)
                vlan_type = m.group(2)
                vlans[vlan] = vlan_type

        for vl_key in vlans:
            if "untagged" == vlans[vl_key].lower() and vl_key not in whitelist:
                self.send_command(f"no switchport general allowed vlan {vl_key}")

    def set_forward_port_isolation(self, ports, forward_ports=""):
        ports_by_speed = collections.defaultdict(list)
        for port_range in forward_ports.split(","):
            if port_range.startswith("Po"):
                # Skip Link Aggregation Groups (LAGs), we aren't using them.
                # They show up in forward_ports when port isolation is disabled.
                continue
            elif "-" not in port_range:
                port_range = [port_range]
            else:
                prefix, last = port_range.split("-")
                _, first = prefix.rsplit("/", 1)
                port_range = [f"1/0/{n}" for n in range(int(first), int(last) + 1)]
            for port_id in port_range:
                port_speed = self._port_id_to_speed[port_id]
                ports_by_speed[port_speed].append(port_id)
        forward_list = []
        for speed, port_ids in ports_by_speed.items():
            forward_list.append(f"{speed}-forward-list")
            forward_list.append(",".join(port_ids))
        log.info(f"setting port isolation for ports {ports} to {' '.join(forward_list)}")
        action = f"port isolation {' '.join(forward_list)}"
        return self.action_interface(ports, action)

    def disable_port_isolation(self, ports):
        action = "no port isolation"
        return self.action_interface(ports, action)

    def set_link_speed(self, ports, speed):
        action = f"speed {speed}"
        return self.action_interface(ports, action)

    def map_port_names_to_port_numbers(self, port_names: list) -> dict:
        return {port_name: self.aliases[port_name]["port"] for port_name in port_names if self.aliases.get(port_name)}

    @staticmethod
    def init_switch_alias(aliases: str) -> dict:
        switch_aliases = dict()
        for alias in aliases:
            backhaul, name, port = alias["backhaul"], alias["name"], alias["port"]
            switch_aliases[name] = dict(name=name, port=port, backhaul=backhaul)
        return switch_aliases
