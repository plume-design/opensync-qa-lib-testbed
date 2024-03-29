#!/usr/bin/env python3
import fnmatch
import os
import re
import json
from lib_testbed.generic.util.sanity import ovsdb
from lib_testbed.generic.util.common import DeviceCommon
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.config import get_model_capabilities
from lib_testbed.generic.util.common import BASE_DIR
from lib_testbed.generic.util.object_resolver import ObjectResolver


class Sanity(object):
    def __init__(self, outfile=None, outstyle="full"):
        self.location = None
        self.outfile = outfile
        self.outstyle = outstyle

    def print_line(self, line):
        print(line)
        if self.outfile:
            print(line, file=self.outfile)

    def run_sanity_on_file(self, filename, gw=None, logs_dir=None):
        sanity = SanityFactory(outfile=self.outfile, outstyle=self.outstyle)
        sanity.load_tables(filename)
        if "AWLAN_Node table" not in sanity.tables:
            self.print_line("AWLAN_Node table not found in ovsdb dump, skipping")
            return None
        model = sanity.tables["AWLAN_Node table"][0]["model"]
        if not model:
            self.print_line(f'Cannot get model from: "{model}"')
            return None
        model = DeviceCommon.convert_model_name(model)
        obj = sanity.get_sanity_model(model, gw, logs_dir)
        if not obj:
            self.print_line(f"Unknown device: {model}")
            return None
        obj.ovsdb_sanity_check()
        return obj

    def sanity_single(self, filename):
        """
        Run sanity given an input file containing dump of OVSDB Tables
        """
        try:
            obj = self.run_sanity_on_file(filename)
            if not obj:
                return 1
            if self.outstyle == "lib":
                stripped = list()
                for line in obj.output:
                    regex = re.compile("\033\\[[0-9;]+m")
                    line[2] = regex.sub("", line[2])
                    stripped.append(line)
                return stripped
            else:
                obj.sanity_message()
                if "ERROR" in [line[1] for line in obj.output]:
                    return 1
                return 0
        except Exception as e:
            log.warning(e)
            return 1

    def sanity_location(self, logs_dir):  # noqa C901
        """
        Run sanity in the logs_dir directory
        """
        ret_status = {"gw_pod": None, "serial": [], "ret": True, "out": []}
        # collect all directory
        listdir = os.listdir(logs_dir)
        logs_list = []
        for item in listdir:
            if os.path.isdir(os.path.join(logs_dir, item)):
                logs_list.append(os.path.join(logs_dir, item))
        if not logs_list:
            # Single directory from one pod
            logs_list = [logs_dir]
        # find out what location is tested and sort logs to start from GW
        logs_list = self.reorder_files(listdir, logs_list, logs_dir)
        root_pod = ""
        stop = False
        for path in logs_list:
            if stop:
                break
            for filename in fnmatch.filter(os.listdir(path), "ovsdb-client_-f_json_dump*"):
                with open(os.path.join(path, filename)) as json_dump:
                    tables = ovsdb.ovsdb_decode(json_dump)
                    if "AWLAN_Node table" not in tables:
                        self.print_line("AWLAN_Node table not found in ovsdb dump, skipping")
                        continue
                    gw_node = True
                    eth_uuid = []
                    for iface in tables["Port table"]:
                        if iface["name"] in ["eth0", "eth1", "eth0.835", "eth1.835"]:
                            eth_uuid.append(iface["_uuid"])
                    if eth_uuid:
                        for bridge in tables["Bridge table"]:
                            if bridge["name"] != "br-wan":
                                continue
                            if not isinstance(bridge["ports"], list):
                                bridge["ports"] = [bridge["ports"]]
                            gw_node = any((x in eth_uuid for x in bridge["ports"]))
                    if gw_node:
                        root_pod = tables["AWLAN_Node table"][0]["model"]
                        logs_list.insert(0, logs_list.pop(logs_list.index(path)))
                        stop = True
                        break
        if root_pod:
            ret_status["gw_pod"] = root_pod
            if self.outstyle not in ["lib", "none"]:
                self.print_line(f"GW pod: {root_pod}")
            gw = {"model": root_pod, "gw_tables": None}
        else:
            gw = None
        for path in logs_list:
            for filename in fnmatch.filter(os.listdir(path), "ovsdb-client_-f_json_dump*"):
                file_path = os.path.join(path, filename)
                with open(file_path) as json_dump:
                    obj = self.run_sanity_on_file(json_dump, gw=gw, logs_dir=path)
                    if not obj:
                        continue
                    if gw and not gw["gw_tables"]:
                        # print 'Storing GW pod tables for leafs'
                        gw["gw_tables"] = obj.tables
                    if self.outstyle not in ["lib", "none"]:
                        obj.sanity_message()
                    ret_status["out"].append(obj.output)
                    ret_status["serial"].append(obj._id)
                    if "ERROR" in [line[1] for line in obj.output]:
                        ret_status["ret"] = False
        return ret_status

    @staticmethod
    def reorder_files(list_dir, logs_list, logs_dir):
        # First check sanity on the gateway
        if "topology.json" in list_dir:
            with open(os.path.join(logs_dir, "topology.json")) as topo_file:
                topology = json.load(topo_file)
                for node in topology:
                    if not node.get("isGateway"):
                        continue
                    node_id = node["id"]
                    gw_file_name = [
                        pod_file
                        for pod_file in list_dir
                        if node_id.lower() in pod_file.lower() and "tgz" not in pod_file
                    ]
                    if gw_file_name:
                        gw_path = os.path.join(logs_dir, gw_file_name[0])
                        logs_list.insert(0, logs_list.pop(logs_list.index(gw_path)))
                        break
        return logs_list


class SanityFactory(object):
    sanity_factory = None

    def __init__(self, outfile=None, outstyle="full"):
        self.device_type = None
        self.tables = None
        self.outfile = outfile
        self.outstyle = outstyle

    def load_tables(self, json_dump):
        """
        Parse Ovsdb to to load tables
        """
        self.tables = ovsdb.ovsdb_decode(json_dump)

    def get_sanity_model(self, model, gw, logs_dir=None):
        gw_tables = gw["gw_tables"] if gw else None
        sanity_path = os.path.join(BASE_DIR, "lib_testbed", "generic", "pod", "generic", "sanity", "sanity_lib.py")
        sanity_lib_class = ObjectResolver.resolve_model_path_class(sanity_path, "sanity_lib.py")
        model_capabilities = get_model_capabilities(model)
        return sanity_lib_class(
            self.tables, gw_tables, logs_dir, self.outfile, self.outstyle, capabilities=model_capabilities
        )
