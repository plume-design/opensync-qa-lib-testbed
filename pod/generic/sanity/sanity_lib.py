#!/usr/bin/env python3

import os
import time
import json
import re
from termcolor import colored
from subprocess import getoutput as getout
from subprocess import getstatusoutput as getstatusout
from multiprocessing import Lock

from lib_testbed.generic.util.common import is_inside_infrastructure
from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.util import config
from lib_testbed.generic.util.sanity import ovsdb
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.common import DeviceCommon

lock = Lock()

# Function names map for generic validate_tables() method
func_name_map = {
    "AWLAN_Node table": ["_ovsdb_sanity_check_awlan_node_table"],
    "Manager table": ["_ovsdb_sanity_check_manager_table"],
    "Bridge table": ["_ovsdb_sanity_check_bridge_table"],
    "DHCP_leased_IP table": ["_ovsdb_sanity_check_dhcp_leased_ip_table"],
    "Interface table": ["_ovsdb_sanity_check_interface_table"],
    "Wifi_Master_State table": ["_ovsdb_sanity_check_wifi_master_state_table"],
    "Wifi_Inet_Config table": ["_ovsdb_sanity_check_wifi_inet_config_table"],
    "Wifi_Radio_Config table": ["_ovsdb_sanity_check_wifi_radio_config_table"],
    "Wifi_Associated_Clients table": ["_ovsdb_sanity_check_wifi_associate_clients_table"],
    "Wifi_VIF_Config table": ["_ovsdb_sanity_check_wifi_vif_config_table", "_ovsdb_sanity_check_wifi_check_leaf"],
    "Radios country code check": ["check_regulatory_domains"],
    "Syslog sanity check": ["sys_log_sanity_check"],
}


class SanityLib(object):
    def __init__(self, tables, gw_tables, logs_dir=None, outfile=None, outstyle="full", capabilities=None):
        self.func_name_map = func_name_map
        self.tables = tables
        self.gw_tables = gw_tables
        self.output = []
        self.logs_dir = logs_dir
        self._id = None
        self._outfile = outfile
        self.outstyle = outstyle
        self.sanity_logs = ""

        # self arguments for methods
        self.retval = True
        self.gw_node, self.router_mode, self.wifi_vendor, self.sys_log_file_name = None, None, None, None
        self.device_type, self.device_mode = None, None
        self.table_list, self.wan_bridge, self.lan_bridge, self.home_ap, self.home_ap_all = [], [], [], [], []
        self.re_backhaul_ap, self.backhaul_ap, self.backhaul_sta, self.lan_interfaces, self.regulatory_domains = (
            [],
            [],
            [],
            [],
            [],
        )
        self.supported_bands, self.wan_interfaces, self.phy_radio_name = [], [], []
        self.init_capabilities(capabilities)
        self.wano = self.check_wano()
        self.set_home_ap_list()

        if logs_dir:
            if self.logs_dir[-1] != "/":
                self.logs_dir += "/"
            self.sys_log_file = self.logs_dir + self.sys_log_file_name
        else:
            self.sys_log_file = None

    def init_capabilities(self, capabilities):
        interfaces = capabilities.get("interfaces")
        sanity_to_check = capabilities.get("frv_sanity")
        model_string = DeviceCommon.convert_model_name(capabilities.get("model_string", "unknown"))
        assert sanity_to_check and interfaces, f"Missing data in config/duts/{model_string}.yaml"

        # init capabilities
        for capability in capabilities:
            if capability in ["interfaces", "frv_sanity"]:
                continue
            setattr(self, capability, capabilities[capability])

        # init interfaces
        for interface in interfaces:
            if isinstance(interfaces[interface], dict):
                value = [name for iface, name in interfaces[interface].items() if name is not None]
            else:
                value = interfaces[interface]
            setattr(self, interface, value)

        # use regex interface names if exists
        if self.re_backhaul_ap:
            self.backhaul_ap = self.re_backhaul_ap

        # init sanity keys
        for sanity in sanity_to_check:
            if sanity in ["tables"]:
                continue
            setattr(self, sanity, sanity_to_check[sanity])

        # set tables to check
        self.table_list = sanity_to_check["tables"]

    def set_home_ap_list(self):
        self.home_ap_all = self.home_ap
        if not self.tables.get("Interface table", []):
            return
        current_home_ap = []
        for home_ap in self.home_ap_all:
            if ovsdb.ovsdb_find_row(self.tables["Interface table"], "name", home_ap):
                current_home_ap.append(home_ap)
        if len(current_home_ap) == 1:
            self._create_output("Interface table", "ERROR", "No home-ap on 5G interface")
        self.home_ap = current_home_ap

    @staticmethod
    def get_model(awlan_table):
        return awlan_table[0]["model"]

    def validate_tables(self, skip_tables=()):
        for table_name in self.table_list:
            if table_name[0] in skip_tables:
                continue
            func_names = func_name_map.get(table_name[0], None)
            if not func_names:
                continue
            for func_name in func_names:
                self.retval &= getattr(self, func_name)()

    def sanity_message(self):
        """
        Method to print the output
        """
        for row in self.output:
            if self.outstyle == "simple":
                regex = re.compile(r"\033\[[0-9;]+m")  # noqa W605
                self.print_line("{0: >17}- {1: <25}:{2}".format(row[1], row[0], regex.sub("", row[2])))
            elif self.outstyle == "full":
                if row[1] == "INFO":
                    level = colored(row[1], "green")
                elif row[1] == "Warning":
                    level = colored(row[1], "yellow")
                elif row[1] == "ERROR":
                    level = colored(row[1], "red", attrs=["bold", "blink"])
                else:
                    level = colored(row[1], "white")
                tname = colored(row[0], "magenta")
                message = colored(row[2], "white")

                self.print_line("{0: >17}- {1: <25}:{2}".format(level, tname, message))
            elif self.outstyle in ["none", "lib"]:
                log.info(f"outstyle in {self.outstyle}, skipping")
                # we don't want output at all
                pass
            else:
                # ?? unknown output style
                log.warning(f"Unknown output style: {self.outstyle}")
        self.flush_logs()
        log.console("", show_file=False)

    def print_line(self, line):
        self.sanity_logs += line + "\n"
        # log.console(line, show_file=False)
        if self._outfile:
            print(line, file=self._outfile)

    def flush_logs(self):
        with lock:
            print(self.sanity_logs)

    def get_id(self):
        return self._id if self._id else "UNKNOWN_ID"

    def _create_output(self, table, level, msg):
        table = table.replace(" table", "")
        self.output.append([table, level, msg])

    # ##########################################################################
    # ovsdb tables related methods
    # ##########################################################################
    def _ovsdb_sanity_check_awlan_node_table(self):
        tname = "AWLAN_Node table"
        table = self.tables[tname]
        errs = 0

        if len(table) == 0:
            self._create_output(table, "ERROR", "No rows")
            errs = errs + 1
        else:
            if len(table) > 1:
                self._create_output(tname, "Warning", "More than one row")

            if len(table[0]["id"]) == 0:
                self._create_output(tname, "ERROR", "ID length is 0")
                errs = errs + 1
            elif len(table[0]["id"]) < 10:
                self._create_output(tname, "Warning", "ID length is shorter than 10 chars")

            if len(table[0]["serial_number"]) == 0:
                self._create_output(tname, "ERROR", "Serial_number length is 0")
                errs = errs + 1

            if len(table[0]["firmware_version"]) == 0:
                self._create_output(tname, "ERROR", "Firmware version length is 0")
                errs = errs + 1
            else:
                self._create_output(
                    tname,
                    "INFO",
                    colored(table[0]["model"], "white", attrs=["blink"])
                    + ", "
                    + colored(table[0]["id"], "cyan", attrs=["bold", "blink"])
                    + ", "
                    + colored(table[0]["firmware_version"], "green", attrs=["dark"]),
                )
                if self.gw_node:
                    gwstr = "Gateway "
                    if self.router_mode:
                        gwstr += "- Router Mode"
                    else:
                        gwstr += "- Bridge Mode"
                    self._create_output(
                        tname,
                        "INFO",
                        colored(gwstr, "yellow", "on_blue", attrs=["bold", "blink", "underline", "reverse"]),
                    )
                if self.device_mode != "cloud":
                    self._create_output(tname, "INFO", f"Device mode: {self.device_mode}")
            if "mqtt_settings" in table[0]:
                mqtt = table[0]["mqtt_settings"]
                if "broker" in mqtt:
                    if mqtt["broker"].find("amazonaws") >= 0:
                        self._create_output(tname, "Warning", "MQTT broker is pointing at Amazon AWS IOT")
                else:
                    self._create_output(tname, "ERROR", "MQTT broker not configured")
                    errs = errs + 1
            else:
                self._create_output(tname, "ERROR", "No MQTT settings")
                errs = errs + 1

        return True if errs else False

    def _ovsdb_sanity_check_manager_table(self):
        tname = "Manager table"
        table = self.tables[tname]
        errs = 0

        if len(table) == 0:
            self._create_output(tname, "ERROR", "No rows")
            errs = errs + 1
        else:
            if len(table) > 1:
                self._create_output(tname, "Warning", "More than one row")
            if len(table[0]["target"]) == 0:
                self._create_output(tname, "ERROR", "Target length is 0")
            if table[0]["is_connected"] != 1:
                self._create_output(tname, "ERROR", "Not connected to manager: " + str(table[0]["target"]))
                errs = errs + 1
            else:
                self._create_output(
                    tname,
                    "INFO",
                    "Connected to manager: " + colored(str(table[0]["target"]), "white", attrs=["bold", "blink"]),
                )
        return True if errs else False

    def _ovsdb_sanity_check_bridge_table(self):
        tname = "Bridge table"
        table = self.tables[tname]
        errs = 0
        iflist = [self.wan_bridge, self.lan_bridge]
        if len(table) == 0:
            self._create_output(tname, "ERROR", "No rows")
            errs = errs + 1
        else:
            for n in iflist:
                if not n:
                    continue
                row = ovsdb.ovsdb_find_row(table, "name", n)
                if not row:
                    self._create_output(tname, "ERROR", str(n) + " row is missing")
                    errs = errs + 1
                elif len(row["ports"]) == 0:
                    self._create_output(tname, "Warning", str(n) + "has no ports associated with it")

        return True if errs else False

    def _ovsdb_sanity_check_dhcp_leased_ip_table(self):  # noqa C901
        tname = "DHCP_leased_IP table"
        table = self.tables[tname]
        errs = 0

        bhome_cnt = 0
        if len(table) == 0 and self.gw_node:
            self._create_output(tname, "Warning", "No rows")
            return False
        # find out DHCP home subnet (exists only for router mode)
        hsub = None
        try:
            hsub = ovsdb.ovsdb_find_row(self.tables["Wifi_Route_State table"], "if_name", self.lan_bridge)
            hsub = ".".join(hsub["dest_addr"].split(".")[:-1])
        except (KeyError, TypeError):
            ips = ovsdb.ovsdb_get_key_values(table, "inet_addr")
            for ip in ips:
                if ip.startswith("169.254"):
                    continue
                hsub = ".".join(ip.split(".")[:-1])
                break
        if not hsub:
            hsub = "192.168.0"
        for row in table:
            val = ".".join(row["inet_addr"].split(".")[:-1])
            if val == hsub:
                bhome_cnt = bhome_cnt + 1
            elif "169.254" in val:
                is_gre = ovsdb.ovsdb_find_row(
                    self.tables["Wifi_Associated_Clients table"], "mac", row["hwaddr"].lower()
                )
                if not is_gre:
                    # not valid GRE entry
                    continue

                gre = ovsdb.ovsdb_find_row(
                    self.tables["Wifi_Inet_Config table"], "gre_remote_inet_addr", row["inet_addr"]
                )
                if not self.check_wds:
                    if not gre:
                        self._create_output(
                            tname,
                            "ERROR",
                            str(row["inet_addr"]) + " is missing downlink GRE interface" " in Wifi_Inet_Config",
                        )
                        errs = errs + 1
                    else:
                        prt = ovsdb.ovsdb_find_row(self.tables["Port table"], "name", gre["if_name"])
                        if not prt:
                            self._create_output(tname, "ERROR", str(gre["if_name"]) + " is missing from the Port table")
                        else:
                            br = ovsdb.ovsdb_find_row(self.tables["Bridge table"], "ports", prt["_uuid"])
                            if not br:
                                self._create_output(
                                    tname, "ERROR", str(gre["if_name"]) + "port does not belong to a bridge"
                                )
                            elif br["name"] != self.lan_bridge:
                                self._create_output(tname, "ERROR", str(gre["if_name"]) + "port belongs to bridge")

        if self.gw_node and self.router_mode and bhome_cnt == 0:
            self._create_output(tname, "Warning", f"No home {hsub}* addresses found")
        return True if errs else False

    def _ovsdb_sanity_check_interface_table(self):
        tname = "Interface table"
        table = self.tables[tname]
        errs = 0
        iflist = [self.wan_bridge, self.lan_bridge] + self.home_ap
        if self.device_type != "residential_gateway":
            iflist += self.lan_interfaces
        if len(table) == 0:
            self._create_output(tname, "ERROR", "No rows")
            return False
        if_list = iflist + ["patch-w2h", "patch-h2w"] if not self.router_mode and not self.wano else iflist
        for n in if_list:
            if not n:
                continue
            row = ovsdb.ovsdb_find_row(table, "name", n)
            if not row:
                # ignore missing lan interfaces, since only active one are there, where we list all cases
                if n in self.lan_interfaces:
                    continue
                self._create_output(tname, "Warning", str(n) + " row is missing")
                errs = errs + 1
                continue
            if len(row["error"]) > 0:
                self._create_output(tname, "ERROR", str(row["error"]))
                continue
            if row["admin_state"] != "up":
                self._create_output(tname, "Warning", str(n) + " admin_state " + str(row["admin_state"]) + "!=up")
                continue
            if n.startswith("patch-"):
                if not row["options"] or not row["options"]["peer"]:
                    self._create_output(tname, "ERROR", str(n) + " is missing peer option")
                    errs = errs + 1
                else:
                    peer = "patch-h2w" if n == "patch-w2h" else "patch-w2h"
                    if row["options"]["peer"] != peer:
                        self._create_output(
                            tname, "ERROR", str(n) + " peer " + str(row["options"]["peer"]) + " !=" + peer
                        )
                        errs = errs + 1
        for n in self.backhaul_ap:
            if not n:
                continue
            row = ovsdb.ovsdb_find_row(table, "name", n)
            # do not print the same error twice
            if not row:
                continue
            if row["mtu"] != self.mtu["backhaul"]:
                self._create_output(tname, "Warning", f"{n} MTU {row['mtu']} != {self.mtu['backhaul']}")
        return True if errs else False

    def _ovsdb_sanity_check_wifi_master_state_table(self):  # noqa
        """
        Check interface type, network state and port state
        Returns: (bool)

        """
        tname = "Wifi_Master_State table"
        table = self.tables[tname]
        errs = 0

        lan_bridge_ifaces = [
            f"{self.lan_bridge}.{iface}" for iface in ["arp", "dhcp", "dns", "dpi", "http", "l2uf", "ndp", "tx", "upnp"]
        ]
        optional = lan_bridge_ifaces + [self.lan_bridge]
        iflist = [self.lan_bridge, self.wan_bridge] + self.backhaul_ap + self.backhaul_sta
        if self.home_ap_managed:
            iflist += self.home_ap

        if len(table) == 0:
            self._create_output(tname, "ERROR", "No rows")
            errs = errs + 1
        else:
            sta_ok = 0
            for n in iflist:
                if not n:
                    continue
                row = ovsdb.ovsdb_find_row(table, "if_name", n)
                if not row:
                    if n in self.backhaul_sta or n in optional:
                        continue
                    else:
                        self._create_output(tname, "Warning", str(n) + " row is missing")
                        errs = errs + 1
                else:
                    if n in self.backhaul_sta:
                        if row["if_type"] != "vif":
                            self._create_output(tname, "Warning", str(n) + " if_type " + row["if_type"] + "!=vif")
                        if self.gw_node:
                            # GW does not have STA interface up and active
                            if row["network_state"] not in ["down", "inactive"]:
                                self._create_output(
                                    tname,
                                    "ERROR",
                                    str(n) + " network_state " + row["network_state"] + " != down on gateway node",
                                )
                                errs = errs + 1
                        else:
                            if (row["port_state"] == "active" and row["network_state"] == "up") or self.check_wds:
                                sta_ok = sta_ok + 1
                    elif n in [self.wan_bridge, self.lan_bridge] + lan_bridge_ifaces:
                        if row["if_type"] != "bridge":
                            self._create_output(tname, "Warning", str(n) + " if_type" + row["if_type"] + " != bridge")
                        if row["port_state"] != "active" and n != self.lan_bridge:
                            self._create_output(
                                tname, "ERROR", str(n) + " port_state " + row["port_state"] + " != active"
                            )
                            errs = errs + 1
                        if row["network_state"] != "up":
                            self._create_output(
                                tname, "ERROR", str(n) + " network_state " + row["network_state"] + " != up"
                            )
                            errs = errs + 1
                        if n == self.wan_bridge and row["inet_addr"] == "0.0.0.0":
                            self._create_output(tname, "Warning", str(n) + " does not have an IP Address")
                    elif n in self.lan_interfaces:
                        if row["if_type"] != "eth":
                            self._create_output(tname, "Warning", str(n) + " if_type" + row["if_type"] + " != eth")
            if not self.gw_node and sta_ok == 0:
                self._create_output(tname, "ERROR", "No active/up STA connection found")
                errs = errs + 1
        return True if errs else False

    def _ovsdb_sanity_check_wifi_associate_clients_table(self):
        tname = "Wifi_Associated_Clients table"
        table = self.tables[tname]
        errs = 0

        vif_state = self.tables["Wifi_VIF_State table"]
        assoc_cnt = 0
        for row in vif_state:
            if isinstance(row["associated_clients"], list):
                assoc_cnt = assoc_cnt + len(row["associated_clients"])
            elif len(row["associated_clients"]) > 4:
                assoc_cnt = assoc_cnt + 1
        if len(table) != assoc_cnt:
            self._create_output(
                tname, "ERROR", str(len(table)) + " != Wifi_VIF_State associated_clients total " + str(assoc_cnt)
            )
            errs = errs + 1
        return True if errs else False

    def _ovsdb_sanity_check_wifi_inet_config_table(self):  # noqa
        """
        Check Wifi_Inet_State with Wifi_Inet_Config
        Returns: (bool)

        """
        config_tname = "Wifi_Inet_Config table"
        state_tname = "Wifi_Inet_State table"
        config_table = self.tables[config_tname]
        state_table = self.tables[state_tname]
        errs = 0

        lan_bridge_ifaces = [
            f"{self.lan_bridge}.{iface}" for iface in ["arp", "dhcp", "dns", "dpi", "http", "l2uf", "ndp", "tx", "upnp"]
        ]
        iflist = [self.wan_bridge, self.lan_bridge] + lan_bridge_ifaces + self.backhaul_ap + self.backhaul_sta
        optional = lan_bridge_ifaces + [self.lan_bridge]
        if self.home_ap_managed:
            iflist += self.home_ap

        if self.gw_node and self.wan_interfaces:
            wan_interfaces = self.wan_interfaces if isinstance(self.wan_interfaces, list) else [self.wan_interfaces]
            iflist.extend(wan_interfaces)

        for r in iflist:
            if not r:
                continue
            for pair in [[config_tname, config_table], [state_tname, state_table]]:
                tname = pair[0]
                table = pair[1]
                row = ovsdb.ovsdb_find_row(table, "if_name", r)
                if not row:
                    if r in optional:
                        continue
                    self._create_output(tname, "ERROR", f"{r} row is missing")
                    errs = errs + 1
                    continue
                if self.wan_bridge and r == self.wan_bridge:
                    if self.router_mode and not row["NAT"]:
                        self._create_output(tname, "Warning", f"{r} does not have NAT enabled")
                        errs = errs + 1
                elif self.lan_bridge and r in lan_bridge_ifaces:
                    if row["if_type"] not in ["eth", "tap"]:
                        self._create_output(tname, "Warning", f"Unexpected type for {r}")
                    if tname == state_tname:
                        inet_cnt = 0
                        if isinstance(row["inet_addr"], list):
                            inet_cnt = inet_cnt + len(row["inet_addr"])
                        elif len(row["inet_addr"]) > 0 and row["inet_addr"] != "0.0.0.0":
                            inet_cnt = inet_cnt + 1
                        if r == self.wan_bridge and inet_cnt == 0:
                            self._create_output(tname, "ERROR", f"{r} is missing inet_addr")
                            errs = errs + 1
                        elif r == self.lan_bridge and inet_cnt != 0 and not self.router_mode and not self.wano:
                            self._create_output(tname, "ERROR", f"{r} has an inet_addr")
                            errs = errs + 1
                        if r == self.lan_bridge:
                            if self.router_mode and row["ip_assign_scheme"] != "static":
                                self._create_output(tname, "ERROR", f"{r} ip_assign_scheme is not set to static")
                            elif not self.router_mode and row["ip_assign_scheme"] != "none" and not self.wano:
                                self._create_output(tname, "ERROR", f"{r} ip_assign_scheme is not set to dhcp")
                                errs = errs + 1
                elif r == self.wan_interfaces:
                    # special case for tagged eth ifaces eth0/1.835
                    if_type = "vlan" if "835" in r else "eth"
                    if row["if_type"] != if_type:
                        self._create_output(tname, "Warning", f"{r} if_type {row['if_type']} != {if_type}")

        # Make sure required config entries present in state table
        for crow in config_table:
            if crow["if_name"] in iflist:
                continue
            srow = ovsdb.ovsdb_find_row(state_table, "if_name", crow["if_name"])
            if not srow:
                self._create_output(state_tname, "ERROR", f"{crow['if_name']} not found in State but exists in Config")
                errs = errs + 1
        return True if errs else False

    def _ovsdb_sanity_check_wifi_radio_config_table(self):
        config_tname = "Wifi_Radio_Config table"
        state_tname = "Wifi_Radio_State table"
        config_table = self.tables[config_tname]
        state_table = self.tables[state_tname]
        errs = 0

        for r in self.supported_bands:
            for pair in [[config_tname, config_table], [state_tname, state_table]]:
                tname = pair[0]
                table = pair[1]
                row = ovsdb.ovsdb_find_row(table, "freq_band", r)
                if not row:
                    self._create_output(tname, "ERROR", str(r) + " row is missing")
                    errs = errs + 1
                elif tname == "Wifi_Radio_State table":
                    if len(row["mac"]) == 0:
                        self._create_output(tname, "ERROR", str(r) + " does not have a MAC Address")
                        errs = errs + 1  # print out channel mode for Radio State table
        for row in state_table:
            if row["channel_mode"]:
                self._create_output(
                    state_tname, "INFO", "Channel_mode " + row["freq_band"] + ": " + str(row["channel_mode"])
                )

        return True if errs else False

    def check_regulatory_domains(self):
        table_name = "Wifi_Radio_State table"
        wifi_radio_state_table = self.tables[table_name]
        errs = 0
        for table_column in wifi_radio_state_table:
            band_name = table_column.get("freq_band")
            country_code = self.get_country_code(wifi_radio_state_table, band_name)
            if not country_code:
                self._create_output(
                    table_name, "Warning", f"{band_name} Can not check country code - missing info from {table_name}"
                )
                continue
            self.regulatory_domains.append(country_code)
            # Reference value is first checked band
            if self.regulatory_domains and country_code not in self.regulatory_domains[0]:
                self._create_output(
                    table_name,
                    "ERROR",
                    f"Band: {band_name} Different regulatory domain between"
                    f" bands at the device {self.regulatory_domains[0]} != {country_code}",
                )
                errs += 1

        if not errs and self.regulatory_domains:
            self._create_output(table_name, "INFO", f"Regulatory domain: {self.regulatory_domains[0]}")

        if not self.gw_node and self.gw_tables and self.gw_tables.get(table_name):
            gw_bands = [
                band_name["freq_band"] for band_name in self.gw_tables.get(table_name) if band_name.get("freq_band")
            ]
            gw_regulatory_domains = list()
            for gw_band in gw_bands:
                gw_country_code = self.get_country_code(self.gw_tables.get(table_name), gw_band)
                if gw_country_code:
                    # (UK and GB) && (GB and EU) are equal
                    gw_country_code = (
                        "GB"
                        if gw_country_code == "UK" or gw_country_code == "EU" and "GB" in set(self.regulatory_domains)
                        else gw_country_code
                    )
                    gw_regulatory_domains.append(gw_country_code)
            if gw_regulatory_domains and set(gw_regulatory_domains) != set(self.regulatory_domains):
                self._create_output(
                    table_name,
                    "ERROR",
                    f"Different country code between gateway and leaf device"
                    f" {list(set(gw_regulatory_domains))} != {list(set(self.regulatory_domains))}",
                )
                errs += 1
        return True if errs else False

    @staticmethod
    def get_country_code(wifi_radio_state_table, band_name):
        region_map = {
            "0x37": "EU",
            "0x3a": "US",
            "0x16": "US",
            "0x8faf": "JP",
            "0x14": "CA",
            "E0": "EU",
            "US": "US",
        }
        table_column = ovsdb.ovsdb_find_row(wifi_radio_state_table, "freq_band", band_name)
        if not table_column:
            return None
        country_code = (
            table_column.get("country")
            if table_column.get("country")
            else table_column.get("hw_params", {}).get("reg_domain")
        )

        if not country_code:
            return None

        # Parse country code
        if country_code.isdigit():
            country_code = region_map.get(hex(int(country_code)))
        else:
            # Workaround for parsing US country code
            if re.search(r"US/\d+", country_code):
                country_code = "US"
            country_code = region_map.get(country_code) if region_map.get(country_code) else country_code
        return country_code.upper() if country_code else None

    def _ovsdb_sanity_check_wifi_vif_config_table(self):  # noqa
        config_tname = "Wifi_VIF_Config table"
        state_tname = "Wifi_VIF_State table"
        config_table = self.tables[config_tname]
        state_table = self.tables[state_tname]
        errs = 0
        home_ap_cnt = 0
        bhaul_ap_cnt = 0
        bhaul_sta_cnt = 0
        home_ap_list = self.home_ap
        bhaul_ap_list = self.backhaul_ap
        bhaul_sta_list = self.backhaul_sta
        req_list = self.home_ap + self.backhaul_sta
        if self.device_mode == "cloud":
            req_list += self.backhaul_ap

        for r in req_list:
            for pair in [[config_tname, config_table], [state_tname, state_table]]:
                tname = pair[0]
                table = pair[1]
                row = ovsdb.ovsdb_find_row(table, "if_name", r)
                if not row:
                    # bhaul-sta is optional (GW of eth bhaul case)
                    if r not in bhaul_sta_list:
                        self._create_output(tname, "ERROR", str(r) + " row is missing")
                        errs = errs + 1
                    continue
                if tname != config_tname:
                    continue
                if row["encryption_key"]:
                    enc_str = " Key=" + str(row["encryption_key"])
                else:
                    enc_str = "Enc="
                    if row["security"] and row["security"]["encryption"]:
                        enc_str = " " + row["security"]["encryption"]
                        if row["security"]["encryption"] == "WPA-PSK":
                            if "key" in row["security"]:
                                enc_str = enc_str + " Key=" + str(row["security"]["key"])
                            else:
                                enc_str = enc_str + " NO KEY"
                                self._create_output(tname, "ERROR", "NO PASSWORD FOR WPA!")
                    elif row.get("wpa_key_mgmt"):
                        enc_str = f"Enc={row['wpa_key_mgmt']}, Keys={list(row.get('wpa_psks', {}).values())}"
                    else:
                        enc_str = enc_str + "UNKNOWN"
                if r in bhaul_sta_list:
                    if bhaul_sta_cnt == 0 and bhaul_ap_cnt == 0:
                        self._create_output(
                            tname, "INFO", "{0: >16}{1: <20} {2}".format("Backhaul SSID=", str(row["ssid"]), enc_str)
                        )
                    bhaul_sta_cnt = bhaul_sta_cnt + 1
                    if row["mode"] != "sta":
                        self._create_output(tname, "ERROR", r + " mode" + str(row["mode"]) + " !=sta")
                        errs = errs + 1
                    if tname == state_tname and isinstance(row["parent"], list) or len(row["parent"]) == 0:
                        self._create_output(tname, "Warning", r + " parent not set")
                elif r in bhaul_ap_list:
                    if bhaul_sta_cnt == 0 and bhaul_ap_cnt == 0:
                        self._create_output(
                            tname, "INFO", "{0: >16}{1: <20} {2}".format("Backhaul SSID=", str(row["ssid"]), enc_str)
                        )
                    bhaul_ap_cnt = bhaul_ap_cnt + 1
                    if row["mode"] != "ap":
                        self._create_output(tname, "ERROR", r + " mode" + str(row["mode"]) + "!=ap")
                        errs = errs + 1
                elif r in home_ap_list:
                    if home_ap_cnt == 0:
                        ssid = row["ssid"].encode("ascii", "replace")
                        self._create_output(
                            tname, "INFO", "{0: >16}{1: <20} {2}".format("Home SSID=", str(ssid), enc_str)
                        )
                    home_ap_cnt = home_ap_cnt + 1
                    if row["mode"] != "ap":
                        self._create_output(tname, "ERROR", r + "mode " + str(row["mode"]) + "!=ap")
                        errs = errs + 1
                    if row["bridge"] != self.lan_bridge:
                        self._create_output(tname, "ERROR", r + "bridge " + str(row["bridge"]) + f"!={self.lan_bridge}")
                        errs = errs + 1
                else:
                    break

        home_ap_list_cnt = len(home_ap_list)
        if home_ap_cnt != home_ap_list_cnt:
            self._create_output(state_tname, "ERROR", f"Number of home-ap {home_ap_cnt} != {home_ap_list_cnt}")
            errs = errs + 1

        bhaul_ap_list_cnt = len(bhaul_ap_list)
        if "bhaul-ap-24" in req_list and bhaul_ap_cnt != bhaul_ap_list_cnt:
            self._create_output(state_tname, "ERROR", f"Number of bhaul-ap {bhaul_ap_cnt} != {bhaul_ap_list_cnt}")
            errs = errs + 1
        if self.gw_node:
            if bhaul_sta_cnt != 0:
                self._create_output(state_tname, "ERROR", f"Number of bhaul-ap {bhaul_ap_cnt} != 0 on gateway")
                errs = errs + 1
        elif bhaul_sta_cnt > 1:
            self._create_output(state_tname, "Warning", "More than one bhaul-sta VIFs found " + str(bhaul_ap_cnt))
        # Make sure non-required config entries are present in state table
        for crow in config_table:
            if crow["if_name"] in req_list:
                continue
            srow = ovsdb.ovsdb_find_row(state_table, "if_name", crow["if_name"])
            if not srow:
                self._create_output(state_tname, "ERROR", str(crow["if_name"]) + " not found but exists in VIF config")
                errs = errs + 1
        # Check for every vlan found in Vif_config confirm that for every pgd
        # interface there exists ifname with that vlan
        for crow in config_table:
            if not crow["vlan_id"]:
                continue
            srow = ovsdb.ovsdb_find_row(self.tables["Wifi_Inet_Config table"], "vlan_id", crow["vlan_id"])
            if not srow:
                self._create_output(
                    state_tname,
                    "ERROR",
                    "Pdg interface for vlan id:" + str(crow["vlan_id"]) + " not found in Wifi_Inet_State table",
                )
                errs = errs + 1

        # Check svc-d, security, ssid_broadcast is same in config and state table
        for crow in config_table:
            if crow["if_name"][0:5] != "svc-d":
                continue
            srow = ovsdb.ovsdb_find_row(self.tables["Wifi_VIF_State table"], "if_name", crow["if_name"])
            if not srow:
                self._create_output(
                    state_tname, "ERROR", "If_name:" + str(crow["if_name"]) + " not found in Wifi_VIF_State table"
                )
                errs = errs + 1
            secrow = ovsdb.ovsdb_find_row(self.tables["Wifi_VIF_State table"], "security", crow["security"])
            if not secrow:
                self._create_output(
                    state_tname, "ERROR", "Security" + str(crow["security"]) + " not found in Wifi_VIF_State table"
                )
                errs = errs + 1
            ssidrow = ovsdb.ovsdb_find_row(
                self.tables["Wifi_VIF_State table"], "ssid_broadcast", crow["ssid_broadcast"]
            )
            if not ssidrow:
                self._create_output(
                    state_tname,
                    "ERROR",
                    "SSID Broadcast:" + str(crow["ssid_broadcast"]) + " not found in Wifi_VIF_State table",
                )
                errs = errs + 1

        # compare channel column of VIF state and Radio state
        for crow in state_table:
            if not crow["channel"]:
                continue
            srow = ovsdb.ovsdb_find_row(self.tables["Wifi_Radio_State table"], "channel", crow["channel"])
            if not srow:
                self._create_output(
                    state_tname, "ERROR", f"Channel: {crow['channel']} not found in Wifi_Radio_State table"
                )
                errs = errs + 1

        return True if errs else False

    def _ovsdb_sanity_check_wifi_vif_config_table_bcm(self):  # noqa: C901
        config_tname = "Wifi_VIF_Config table"
        state_tname = "Wifi_VIF_State table"
        config_table = self.tables[config_tname]
        state_table = self.tables[state_tname]
        errs = 0
        home_ap_cnt = 0
        bhaul_ap_cnt = 0
        bhaul_sta_cnt = 0
        req_list = self.home_ap + self.backhaul_sta
        if self.device_mode == "cloud":
            req_list += self.backhaul_ap

        # Check active sta interface and add it to the req_list if not there already
        if not self.gw_node:
            tname = "Connection_Manager_Uplink table"
            row = "is_used"
            uplink_row = ovsdb.ovsdb_find_row(self.tables[tname], row, True)
            if uplink_row:
                if_name = uplink_row.get("if_name").lstrip("g-")
                if if_name not in req_list:
                    req_list.append(if_name)
            else:
                self._create_output(tname, "ERROR", f"{row} row is missing")
                errs = errs + 1

        home_ap_list = [ap for ap in req_list if ap in self.home_ap]
        bhaul_ap_list = [ap for ap in req_list if ap in self.backhaul_ap]

        for r in req_list:
            for pair in [[config_tname, config_table], [state_tname, state_table]]:
                tname = pair[0]
                table = pair[1]
                row = ovsdb.ovsdb_find_row(table, "if_name", r)
                if not row:
                    if not r and r not in self.backhaul_sta:
                        self._create_output(tname, "ERROR", str(r) + " row is missing")
                        errs = errs + 1
                    continue
                if tname != config_tname:
                    continue
                if row["encryption_key"]:
                    enc_str = " Key=" + str(row["encryption_key"])
                else:
                    enc_str = "Enc="
                    if row["security"] and row["security"]["encryption"]:
                        enc_str = " " + row["security"]["encryption"]
                        if row["security"]["encryption"] == "WPA-PSK":
                            if "key" in row["security"]:
                                enc_str = enc_str + " Key=" + str(row["security"]["key"])
                            else:
                                enc_str = enc_str + " NO KEY"
                                self._create_output(tname, "ERROR", "NO PASSWORD FOR WPA!")
                    elif row.get("wpa_key_mgmt"):
                        enc_str = f"Enc={row['wpa_key_mgmt']}, Keys={list(row.get('wpa_psks', {}).values())}"
                    else:
                        enc_str = enc_str + "UNKNOWN"
                if r in self.backhaul_ap:
                    if bhaul_sta_cnt == 0 and bhaul_ap_cnt == 0:
                        self._create_output(
                            tname, "INFO", "{0: >16}{1: <20} {2}".format("Backhaul SSID=", str(row["ssid"]), enc_str)
                        )
                    bhaul_ap_cnt = bhaul_ap_cnt + 1
                    if row["mode"] != "ap":
                        self._create_output(tname, "ERROR", r + " mode" + str(row["mode"]) + "!=ap")
                        errs = errs + 1
                elif r in self.home_ap:
                    if home_ap_cnt == 0:
                        ssid = row["ssid"].encode("ascii", "replace")
                        self._create_output(
                            tname, "INFO", "{0: >16}{1: <20} {2}".format("Home SSID=", str(ssid), enc_str)
                        )
                    home_ap_cnt = home_ap_cnt + 1
                    if row["mode"] != "ap":
                        self._create_output(tname, "ERROR", r + "mode " + str(row["mode"]) + "!=ap")
                        errs = errs + 1
                    if row["bridge"] != self.lan_bridge:
                        self._create_output(tname, "ERROR", f"Bridge for {r} {row['bridge']} != {self.lan_bridge}")
                        errs = errs + 1
                elif r in self.backhaul_sta:
                    if bhaul_sta_cnt == 0 and bhaul_ap_cnt == 0:
                        self._create_output(
                            tname, "INFO", "{0: >16}{1: <20} {2}".format("Backhaul SSID=", str(row["ssid"]), enc_str)
                        )
                    if row["enabled"] is True:
                        bhaul_sta_cnt = bhaul_sta_cnt + 1
                    if row["mode"] != "sta":
                        self._create_output(tname, "ERROR", r + " mode" + str(row["mode"]) + " !=sta")
                        errs = errs + 1
                    if tname == state_tname and isinstance(row["parent"], list) or len(row["parent"]) == 0:
                        self._create_output(tname, "Warning", r + " parent not set")

        home_ap_list_cnt = len(home_ap_list)
        if home_ap_cnt != home_ap_list_cnt:
            self._create_output(state_tname, "ERROR", f"Number of home-ap {home_ap_cnt} != {home_ap_list_cnt}")
            errs = errs + 1

        bhaul_ap_list_cnt = len(bhaul_ap_list)
        if bhaul_ap_cnt != bhaul_ap_list_cnt:
            self._create_output(state_tname, "ERROR", f"Number of bhaul-ap {bhaul_ap_cnt} != {bhaul_ap_list_cnt}")
            errs = errs + 1
        if self.gw_node:
            if bhaul_sta_cnt != 0:
                self._create_output(state_tname, "ERROR", f"Number of bhaul-stap {bhaul_sta_cnt} != 0 on gateway")
                errs = errs + 1
        elif bhaul_sta_cnt > 1:
            self._create_output(state_tname, "Warning", "More than one bhaul-sta VIFs found: " + str(bhaul_sta_cnt))
        # Make sure non-required config entries are present in state table
        for crow in config_table:
            if crow["if_name"] in req_list:
                continue
            srow = ovsdb.ovsdb_find_row(state_table, "if_name", crow["if_name"])
            if not srow:
                self._create_output(state_tname, "ERROR", str(crow["if_name"]) + " not found but exists in VIF config")
                errs = errs + 1
        # Check for every vlan found in Vif_config confirm that for every pgd
        # interface there exists ifname with that vlan
        for crow in config_table:
            if crow["vlan_id"]:
                srow = ovsdb.ovsdb_find_row(self.tables["Wifi_Inet_Config table"], "vlan_id", crow["vlan_id"])
                if not srow:
                    self._create_output(
                        state_tname,
                        "ERROR",
                        "Pdg interface for vlan id:" + str(crow["vlan_id"]) + " not found in Wifi_Inet_State table",
                    )
                    errs = errs + 1

        # Check svc-d, security, ssid_broadcast is same in config and state table
        for crow in config_table:
            if crow["if_name"][0:5] == "svc-d":
                srow = ovsdb.ovsdb_find_row(self.tables["Wifi_VIF_State table"], "if_name", crow["if_name"])
                if not srow:
                    self._create_output(
                        state_tname, "ERROR", "If_name:" + str(crow["if_name"]) + " not found in Wifi_VIF_State table"
                    )
                    errs = errs + 1
                secrow = ovsdb.ovsdb_find_row(self.tables["Wifi_VIF_State table"], "security", crow["security"])
                if not secrow:
                    self._create_output(
                        state_tname, "ERROR", "Security" + str(crow["security"]) + " not found in Wifi_VIF_State table"
                    )
                    errs = errs + 1
                ssidrow = ovsdb.ovsdb_find_row(
                    self.tables["Wifi_VIF_State table"], "ssid_broadcast", crow["ssid_broadcast"]
                )
                if not ssidrow:
                    self._create_output(
                        state_tname,
                        "ERROR",
                        "SSID Broadcast:" + str(crow["ssid_broadcast"]) + " not found in Wifi_VIF_State table",
                    )
                    errs = errs + 1

        # compare channel column of VIF state and Radio state
        for crow in state_table:
            if crow["channel"]:
                srow = ovsdb.ovsdb_find_row(self.tables["Wifi_Radio_State table"], "channel", crow["channel"])
                if not srow:
                    self._create_output(
                        state_tname, "ERROR", "Channel:" + str(crow["channel"]) + " not found in Wifi_Radio_State table"
                    )
                    errs = errs + 1

        return True if errs else False

    def ovsdb_sanity_check(self, **kwargs):
        self._id = self.tables["AWLAN_Node table"][0]["serial_number"]
        model = self.get_model(self.tables["AWLAN_Node table"])
        if self.outstyle not in ["none", "lib"]:
            self.print_line(f"{model} sanity check for: {self._id}")

        # check if all tables exist
        for table in self.table_list:
            # skip checks withouts tables
            if "table" not in table:
                continue
            for i in range(len(table)):
                if self.tables.get(table[i]) is None:
                    self.print_line(f"Table {table[i]} does not exist")
                    return False

        if kwargs:
            if kwargs.get("createOutput"):
                self._create_output(
                    kwargs["createOutput"]["tableName"],
                    kwargs["createOutput"]["logLevel"],
                    kwargs["createOutput"]["msg"],
                )
                del kwargs["createOutput"]

        # check if gateway
        self.check_is_gateway()

        # check network mode
        if not self.router_mode:
            self.router_mode = self.check_network_mode()

        if self.router_mode and not self.gw_node:
            self.print_line("Non-Gateway node is not in bridge mode")

        self.device_mode = self.tables["AWLAN_Node table"][0]["device_mode"]
        # if key is empty use "cloud"
        self.device_mode = self.device_mode if self.device_mode else "cloud"
        reduced_mode_skip = [
            "_ovsdb_sanity_check_dhcp_leased_ip_table",
            "_ovsdb_sanity_check_wifi_associate_clients_table",
            "_ovsdb_sanity_check_wifi_inet_config_table",
        ]
        if self.device_mode != "cloud":
            kwargs.update(
                {
                    "createOutput": {
                        "tableName": "AWLAN_Node table",
                        "logLevel": "INFO",
                        "msg": f"Device mode: {self.device_mode}",
                    }
                }
            )

        # Update method name  based on the Wi-Fi vendor and verify tables
        postfix = "_bcm" if self.wifi_vendor == "bcm" else ""
        for table_name in self.table_list:
            func_names = self.func_name_map.get(table_name[0], None)
            if not func_names:
                continue
            for func_name in func_names:
                if func_name == "_ovsdb_sanity_check_wifi_vif_config_table":
                    func_name = func_name + postfix
                if self.device_mode != "cloud" and func_name in reduced_mode_skip:
                    continue
                ret = getattr(self, func_name)()
                self.retval &= ret

        self.retval &= self.inventory_data_sanity_check()
        return self.retval

    def _ovsdb_sanity_check_wifi_check_leaf(self):
        """
        Check SSID, security, ssid_broadcast, mac_list_type, mode
        Returns: (bool)

        """
        if not self.gw_tables:
            return False
        config_tname = "Wifi_VIF_Config table"
        state_tname = "Wifi_VIF_State table"
        config_table = self.tables[config_tname]
        state_table = self.tables[state_tname]
        errs = 0
        req_list = self.home_ap + self.backhaul_ap

        # Check SSID, security, ssid_broadcast, mac_list_type, mode
        for r in req_list:
            crow = ovsdb.ovsdb_find_row(config_table, "if_name", r)
            srow = ovsdb.ovsdb_find_row(state_table, "if_name", r)

            if not srow:
                self._create_output(state_tname, "ERROR", "if name:" + str(r) + " not found in Wifi_VIF_State table")
                errs = errs + 1
                continue
            if not crow:
                self._create_output(state_tname, "ERROR", "if name:" + str(r) + " not found in Wifi_VIF_Config table")
                errs = errs + 1
                continue
            # check ssid
            if crow["ssid"] != srow["ssid"]:
                self._create_output(
                    config_tname, "ERROR", f"ssid does not match: Config {crow['ssid']} State [{srow['ssid']}]"
                )
                errs = errs + 1
            # check security
            if crow["security"] != srow["security"]:
                self._create_output(
                    config_tname,
                    "ERROR",
                    f"security does not match: Config {crow['security']} State [{srow['security']}]",
                )
                errs = errs + 1
            # check ssid_broadcast
            if "ssid_broadcast" in crow and crow["ssid_broadcast"] is None or crow["ssid_broadcast"] == "":
                crow["ssid_broadcast"] = "enabled"
            elif str(crow["ssid_broadcast"]) != str(srow["ssid_broadcast"]):
                self._create_output(
                    config_tname,
                    "ERROR",
                    f"ssid_broadcast does not match: Config {crow['ssid_broadcast']} State [{srow['ssid_broadcast']}]",
                )
                errs = errs + 1
            # check mac_list_type
            if crow["mac_list_type"] is None or crow["mac_list_type"] == "":
                crow["mac_list_type"] = "none"

            elif str(crow["mac_list_type"]) != str(srow["mac_list_type"]):
                self._create_output(
                    config_tname,
                    "ERROR",
                    f"mac_list_type does not match: {crow['mac_list_type']} " f"!= {srow['mac_list_type']}",
                )
                errs = errs + 1
            # check mode
            if crow["mode"] != srow["mode"]:
                self._create_output(config_tname, "ERROR", f"mode does not match: {crow['mode']} != {srow['mode']}")
                errs = errs + 1

        return True if errs else False

    def check_is_gateway(self):
        if self.gw_node:
            return
        if self.device_type == "residential_gateway":
            self.gw_node = True
            self.router_mode = True
            return
        for wan in self.wan_interfaces:
            # Implementation for devices without WANO
            if not self.wano:
                prt = ovsdb.ovsdb_find_row(self.tables["Port table"], "name", wan)
                if prt:
                    br = ovsdb.ovsdb_find_row(self.tables["Bridge table"], "ports", prt["_uuid"])
                    if br["name"] == self.wan_bridge:
                        self.gw_node = True
                        self.wan_interfaces = wan
                        break
            # Implementation for devices with WANO
            else:
                prt = ovsdb.ovsdb_find_row(self.tables["Connection_Manager_Uplink table"], "if_name", wan)
                # The interface that has has_L2 and has_L3 both on true is WAN
                if prt and prt.get("has_L2") and prt.get("has_L3"):
                    self.gw_node = True
                    self.wan_interfaces = wan
                    break

    def check_network_mode(self):
        router_mode = True
        if not self.wano:
            prt_w2h = ovsdb.ovsdb_find_row(self.tables["Port table"], "name", "patch-w2h")
            prt_h2w = ovsdb.ovsdb_find_row(self.tables["Port table"], "name", "patch-h2w")

            if prt_w2h and prt_h2w:
                br_w2h = ovsdb.ovsdb_find_row(self.tables["Bridge table"], "ports", prt_w2h["_uuid"])
                br_h2w = ovsdb.ovsdb_find_row(self.tables["Bridge table"], "ports", prt_h2w["_uuid"])
                if br_w2h and br_w2h["name"] == self.wan_bridge and br_h2w and br_h2w["name"] == self.lan_bridge:
                    router_mode = False
                else:
                    self.retval = False
        else:
            # get default route
            default_route = ovsdb.ovsdb_find_row(self.tables["Wifi_Route_State table"], "dest_addr", "0.0.0.0")
            if default_route and default_route.get("if_name", "") != self.wan_interfaces:
                router_mode = False
        return router_mode

    def check_wano(self):
        if not self.tables.get("Node_Services table"):
            return False
        wano_service = ovsdb.ovsdb_find_row(self.tables["Node_Services table"], "service", "wano")
        if not wano_service:
            return False
        elif wano_service.get("status", "") == "enabled":
            # Do not check WAN bridge interface in case of WANO
            self.wan_bridge = None
            return True
        else:
            return False

    def check_wds(self):
        wds = ovsdb.ovsdb_find_row(self.tables["Wifi_VIF_Config table"], "multi_ap", "backhaul_bss")
        if not wds:
            return False
        else:
            return True

    # ##########################################################################
    # sys log related methods
    # ##########################################################################
    def _check_kernel_crash(self):
        """
        Check for kernel crash
        """
        boot_cnt = getout(f"grep 'Calibrating delay loop' {self.sys_log_file}* | wc -l")
        lvl = "Warning" if int(boot_cnt) > 3 else "INFO"
        crash_status, crash_log = getstatusout(f"ls {self.logs_dir}/*crash-ramoops* > /dev/null 2>&1")
        if not crash_status:
            lvl = "ERROR"
            extra = "   #### Contains kernel crash log ####"
        else:
            extra = ""
        up_time, up_time_str = self._get_up_time()
        if up_time < 600:
            lvl = "Warning"
        self._create_output("KERNEL", lvl, f"Uptime {up_time} sec [{up_time_str}], Boot Count={boot_cnt}{extra}")

    def _get_up_time(self):
        """
        :brief: get uptime
        :return: uptime in sec and in str format
        """
        if os.path.isfile(self.logs_dir + "uptime"):
            up_time = getout(f"cat {self.logs_dir}uptime").strip()
            try:
                if "day" in up_time:
                    up_days = int(up_time.split()[2])
                    up_hours = int(up_time.split()[4].split(":")[0])
                    up_min = int(up_time.split()[4].split(":")[1][:-1])
                elif "min" in up_time:
                    up_days, up_hours = 0, 0
                    up_min = int(up_time.split()[2])
                else:
                    up_days = 0
                    up_hours = int(up_time.split()[2].split(":")[0])
                    up_min = int(up_time.split()[2].split(":")[1][:-1])
                uptime_sec = (up_min + up_hours * 60 + up_days * 60 * 24) * 60
            except ValueError:
                uptime_sec = -1
            except IndexError:
                uptime_sec = -1
        else:
            uptime_sec = getout(f"grep '.' {self.logs_dir}dmesg | tail -1")
            try:
                uptime_sec = int(uptime_sec.split(".")[0][1:])
            except (TypeError, KeyError, ValueError):
                log.warning(f"Cannot get uptime from: {uptime_sec}")
                uptime_sec = -1
        if uptime_sec > 0:
            up_time_str = time.strftime("%H hrs, %M min, %S sec", time.gmtime(uptime_sec))
            days = int(uptime_sec / 60 / 60 / 24)
            up_time_str = str(days) + " days, " + up_time_str
        else:
            up_time_str = "UNKNOWN"
        return uptime_sec, up_time_str

    def _check_app_crash(self):
        app_crashes = int(getout(f"ls {self.logs_dir}crashed_* 2>&- | wc -l"))
        tar_app_crashes = int(getout(f"ls {self.logs_dir}crash_* 2>&- | wc -l"))
        core_dumps = int(getout(f"ls {self.logs_dir}*.core.gz 2>&- | wc -l"))
        if app_crashes or core_dumps or tar_app_crashes:
            self._create_output(
                "USERSPACE",
                "Warning",
                f"#### There are {app_crashes} app crashes, "
                f"{tar_app_crashes} tar app crashes "
                f"and {core_dumps} core dumps ####",
            )

    def _check_vap(self):
        vaps = self.backhaul_ap + self.home_ap
        # Make sure AP VAPs are beaconing
        for x in vaps:
            state, msg = getstatusout(
                f"cat {self.logs_dir}iwconfig | grep -A 1 '^{x}[^0-9]' | egrep 'Not-Associated' > /dev/null 2>&1"
            )
            if not state:
                self._create_output("VAP Check", "ERROR", x + " is not beaconing!")

    def _check_eth(self):
        up_cnt = int(getout(f"cat {self.sys_log_file}* | egrep -i '{self.wan_interfaces}: link up' | wc -l"))
        down_cnt = int(getout(f"cat {self.sys_log_file}* | egrep -i '{self.wan_interfaces}: link down' | wc -l"))
        lvl = "Warning" if down_cnt >= 2 else "INFO"
        if up_cnt or down_cnt:
            up_1000 = int(
                getout(
                    f"cat {self.sys_log_file}* | egrep -i '{self.wan_interfaces}: link up' | egrep '1000Mbps' | wc -l"
                )
            )
            up_100 = int(
                getout(
                    f"cat {self.sys_log_file}* | egrep -i '{self.wan_interfaces}: link up' | egrep '100Mbps' | wc -l"
                )
            )
            up_10 = int(
                getout(f"cat {self.sys_log_file}* | egrep -i '{self.wan_interfaces}: link up' | egrep '10Mbps' | wc -l")
            )
            self._create_output(
                f"{self.wan_interfaces} STATS",
                lvl,
                f"DOWN={down_cnt} times, UP={up_cnt} times ({up_1000}=1000Mbps, {up_100}=100Mbps, {up_10}=10Mbps)",
            )

    def _check_cm(self):
        disconn_cnt = int(getout(f"egrep 'OVS connection changed from TRUE to FALSE' {self.sys_log_file}* | wc -l"))
        conn_cnt = int(getout(f"egrep 'OVS connection changed from FALSE to TRUE' {self.sys_log_file}* | wc -l"))
        link_errs = int(getout(f"egrep 'erroring out due to previous state' {self.sys_log_file}* | wc -l"))
        reinit_cnt = int(getout(f"egrep 'State RE-INIT starting' {self.sys_log_file}* | wc -l"))
        fatal_cnt = int(getout(f"egrep 'FATAL condition triggered' {self.sys_log_file}* | wc -l"))
        lvl = "Warning" if fatal_cnt >= 5 or conn_cnt >= 10 else "INFO"
        self._create_output(
            "CM STATS",
            lvl,
            f"Connect={conn_cnt}, Disconnect={disconn_cnt}, "
            f"LinkErrs={link_errs}, ReInit={reinit_cnt}, Recoveries={fatal_cnt}",
        )

    def _check_wm(self):
        csa = {}
        for iface in self.phy_radio_name:
            csa[iface] = int(getout(f"egrep 'using CSA' {self.sys_log_file}* | egrep '{iface}' | wc -l"))

        pchange = {}
        configuring = {}
        assoc = {}
        disassoc = {}
        for sta in self.backhaul_sta:
            pchange[sta] = int(getout(f"egrep '{sta}: Parent change' {self.sys_log_file}* | wc -l"))
            configuring[sta] = int(getout(f"egrep '{sta}: Configuring' {self.sys_log_file}* | wc -l"))
            assoc[sta] = int(getout(f"egrep '{sta}: STA now associated' {self.sys_log_file}* | wc -l"))
            disassoc[sta] = int(getout(f"egrep '{sta}: STA still disassociated' {self.sys_log_file}* | wc -l"))

        cassoc = {}
        cdisassoc = {}
        for ap in self.home_ap_all:
            cassoc[ap] = int(getout(f"egrep '{ap}: Client associated' {self.sys_log_file}* | wc -l"))
            cdisassoc[ap] = int(getout(f"egrep '{ap}: Client disassociated' {self.sys_log_file}* | wc -l"))

        total_csa = sum(csa.values())
        total_pchange = sum(pchange.values())
        total_conf = sum(configuring.values())
        total_disc = sum(disassoc.values())
        total_assoc = sum(assoc.values())
        total_ap_assoc = sum(cassoc.values())
        total_ap_disassoc = sum(cdisassoc.values())
        total_lvl = "Warning" if total_disc > 5 or total_assoc - total_conf > 5 else "INFO"

        # sfmt = 'CSA={} P.Change={} Conf={} Assoc={} Disc={} C.Conn={} C.Disc={}'
        sfmt = "{0: >8} {1: <7} {2:<11} {3:<8} {4:<9} {5:<8} {6:<10} {7:<9}"
        self._create_output(
            "WM STATS",
            total_lvl,
            sfmt.format(
                "Totals:",
                f"CSA={total_csa}",
                f"P.Change={total_pchange}",
                f"Conf={total_conf}",
                f"Assoc={total_assoc}",
                f"Disc={total_disc}",
                f"C.Conn={total_ap_assoc}",
                f"C.Disc={total_ap_disassoc}",
            ),
        )
        radio = {0: "2.4G", 1: "5G", 2: "5GU"}
        for i in range(len(self.backhaul_sta)):
            lvl = (
                "Warning"
                if disassoc[self.backhaul_sta[i]] > 5
                or assoc[self.backhaul_sta[i]] - configuring[self.backhaul_sta[i]] > 5
                else "INFO"
            )
            self._create_output(
                "",
                lvl,
                sfmt.format(
                    f"{radio[i]}:",
                    f"CSA={csa[self.phy_radio_name[i]]}",
                    f"P.Change={pchange[self.backhaul_sta[i]]}",
                    f"Conf={configuring[self.backhaul_sta[i]]}",
                    f"Assoc={assoc[self.backhaul_sta[i]]}",
                    f"Disc={disassoc[self.backhaul_sta[i]]}",
                    f"C.Conn={cassoc[self.home_ap_all[i]]}",
                    f"C.Disc={cdisassoc[self.home_ap_all[i]]}",
                ),
            )

    def _check_time(self):
        """
        :brief: Check if Date and Time is set properly after boot
        """
        state, msg = getstatusout(
            f"tail -1 $(ls -1t {self.sys_log_file}* | head -1) | egrep '^Jan  1 ' > /dev/null 2>&1"
        )

        if not state:
            self._create_output("DateTime", "Warning", "Detected date and time was not set")

    def _check_dhcp_idx(self):
        link = self.logs_dir.split("/")
        link = "/".join(link[:-2])
        ids = []
        try:
            [ids.append(node["backhaulDhcpPoolIdx"]) for node in json.load(open(link + "/log-pull.json", "r"))["nodes"]]
        except IOError:
            self._create_output("DHCP Idx", "Warning", "log-pull.json file not found!")
            return
        dups = []
        [dups.append(str(i)) for i in ids if ids.count(i) > 1]
        dup_ids = ",".join(set(dups))
        if dup_ids:
            self._create_output("DHCP Idx", "ERROR", f"DHCP pool index collision in {link}, duplicate Id(s): {dup_ids}")

    def _check_single_dhcp_server(self):
        """
        :brief: Find gateway from log messages
                if there is
        """
        tname = "Wifi_Inet_State table"
        table = self.tables[tname]
        errs = 0

        try:
            row = ovsdb.ovsdb_find_row(table, "if_name", self.wan_bridge)
            dhcpc = row["dhcpc"]["gateway"]
        except (KeyError, TypeError):
            # use first found in sys log
            dhcpc = getout(f"cat {self.sys_log_file}* | egrep -i 'udhcpc.user: gateway=' | tail -n +3 | head -1")
            try:
                dhcpc = dhcpc.split("gateway=")[1]
            except IndexError:
                # nothing to do here...
                return

        dhcpc_gw = getout(f"cat {self.sys_log_file}* | egrep -i 'udhcpc.user: gateway='")

        # Check for multiple dhcp servers
        for line in dhcpc_gw.split("\n"):
            # if log time is <Jan  1> reboot was detected
            if "Jan  1" in line:
                errs = 0
                continue
            if "gateway=" in line and dhcpc not in line:
                errs += 1

        if errs:
            self._create_output("DHCP", "ERROR", "Multiple dhcp servers")

    def sys_log_sanity_check(self):
        """
        :brief: system log sanity check
        """
        if self.sys_log_file is None:
            return False
        if any(x.startswith(self.sys_log_file_name) for x in os.listdir(self.logs_dir)):
            self._check_dhcp_idx()
            self._check_time()
            self._check_kernel_crash()
            self._check_app_crash()
            self._check_vap()
            self._check_eth()
            self._check_wm()
            self._check_cm()
            self._check_single_dhcp_server()
        return False

    def inventory_data_sanity_check(self):
        def _report_not_possible():
            self._create_output("INVENTORY", "INFO", "Cannot compare data with inventory")

        def _get_mac_from_pmf_report(interface):
            for line in pmf_report.splitlines():
                if interface in line:
                    return line.split()[-1]

        # _usr_opensync_tools_pmf_--report-quick:
        # # QCA
        # Ethernet MAC address 0         xx:yy:zz:11:22:31
        # Ethernet MAC address 1         xx:yy:zz:11:22:32
        # Bluetooth MAC address          xx:yy:zz:11:22:36
        # Wifi MAC address 0             xx:yy:zz:11:22:33
        # Wifi MAC address 1             xx:yy:zz:11:22:34
        # Wifi MAC address 2             xx:yy:zz:11:22:35

        # # BRCM
        # MAC eth0                       xx:yy:zz:11:22:31
        # MAC eth1                       xx:yy:zz:11:22:32
        # Wifi MAC address 0             xx:yy:zz:11:22:33
        # Wifi MAC address 1             xx:yy:zz:11:22:34
        # Wifi MAC address 2             xx:yy:zz:11:22:35
        # Bluetooth MAC address          xx:yy:zz:11:22:36

        pmf_report = getout(f"cat {self.logs_dir}/_usr_opensync_tools_pmf_--report-quick")
        if "No such file or directory" in pmf_report:
            _report_not_possible()
            return False

        if not is_inside_infrastructure():
            _report_not_possible()
            return False

        try:
            from lib.cloud.api.inventory import Inventory
        except (ModuleNotFoundError, OpenSyncException):
            _report_not_possible()
            return False

        try:
            deployment_file = config.find_deployment_file("dogfood")
        except (KeyError, OpenSyncException):
            _report_not_possible()
            return False

        _config = config.load_file(deployment_file)
        if not _config.get("inv_user") or not _config.get("inv_pwd"):
            _report_not_possible()
            return False

        inv = Inventory.fromurl(_config.get("inventory_url"), _config.get("inv_user"), _config.get("inv_pwd"))
        # inventory keys
        #         "ethernetMac"
        #         "ethernet1Mac"
        #         "radioMac24"
        #         "radioMac50L"
        #         "radioMac50U"
        #         "radioMac50"
        #         "radioMac60"
        #         "bluetoothMac"
        inv_node_info = inv.get_api_node(self._id, skip_exception=True)
        if not inv_node_info:
            _report_not_possible()
            return False

        errs = 0
        # check eth interfaces
        for i in range(len(self.lan_interfaces)):
            if self.wifi_vendor == "bcm":
                iface_string = f"MAC eth{i}"
            else:
                iface_string = f"Ethernet MAC address {i}"
            inv_key = f"ethernet{i}Mac".replace("0", "")
            if _get_mac_from_pmf_report(iface_string) != inv_node_info.get(inv_key, "NONE"):
                err_type = "Warning" if i > 0 else "ERROR"
                self._create_output("INVENTORY", err_type, f"eth{i} MAC address does not match with inventory")
                if err_type == "ERROR":
                    errs += 1

        # check Wi-Fi interfaces
        for band, radio, i in zip(self.supported_bands, self.phy_radio_name, range(len(self.phy_radio_name))):
            inv_key = f"radioMac{band}".replace("G", "0").replace(".", "").replace("240", "24")
            if _get_mac_from_pmf_report(f"Wifi MAC address {radio[-1]}") != inv_node_info.get(inv_key, "NONE"):
                self._create_output("INVENTORY", "ERROR", f"Wi-Fi{i} MAC address does not match with inventory")
                errs += 1

        # check Bluetooth interface
        if "bluetoothMac" in inv_node_info and _get_mac_from_pmf_report("Bluetooth MAC address") != inv_node_info.get(
            "bluetoothMac", "NONE"
        ):
            self._create_output("INVENTORY", "ERROR", "Bluetooth MAC address does not match with inventory")
            errs += 1

        return True if errs else False
