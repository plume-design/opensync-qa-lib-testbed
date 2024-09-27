import json
import os
import urllib3.exceptions
import requests
from typing import Union
from requests.auth import HTTPBasicAuth
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.switch.generic.switch_lib_generic import SwitchLibGeneric
from lib_testbed.generic.switch.util import get_switch_config_path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SwitchLib(SwitchLibGeneric):
    def __init__(self, switch_name, user, password, ip, port, aliases, tb_config, **kwargs):
        super().__init__(switch_name, user, password, ip, port, aliases, tb_config, **kwargs)
        self.rest_api = MikrotikRestApi(user=user, password=password, ip=ip, port=port)
        self.port_interfaces_map = self.map_port_numbers()

    def generate_output(self, response, json_pretty=False):
        if error_output := self.generate_error_output(response):
            return error_output
        if json_pretty:
            response = self.json_pretty(response)
        return [0, response, ""]

    @staticmethod
    def generate_error_output(response):
        if not isinstance(response, dict) or not response.get("error"):
            return []
        return [response["error"], "", response.get("detail", "")]

    @staticmethod
    def json_pretty(response):
        return json.dumps(response, indent=2)

    # To get port vlan config required is interface_name
    def map_port_numbers(self):
        ethernet_interfaces = self.rest_api.get_interfaces_ethernet_config()
        if error_msg := self.generate_error_output(ethernet_interfaces):
            raise Exception(f"Can not reach Mikrotik RestAPI: {error_msg}")
        port_interfaces_map = dict()
        for interface in ethernet_interfaces:
            port_number = int(interface[".id"].lstrip("*"), 16)
            port_interfaces_map[port_number] = interface["name"]
        self.verify_init_ports(port_interfaces_map)
        return port_interfaces_map

    def verify_init_ports(self, port_interfaces_map):
        for port_number in self.get_all_config_ports():
            assert port_interfaces_map.get(port_number), (
                f"Port config for {port_number} port number did not init. "
                "Make sure bridge interface is enabled for this port"
            )

    def version(self):
        switch_version = self.rest_api.get_system_note().get("note", "")
        return [0, switch_version, ""] if switch_version else [1, "", "Can not get switch version"]

    def system_info(self):
        system_info = self.rest_api.get_system_info()
        system_info["note"] = self.rest_api.get_system_note().get("note", "")
        return self.generate_output(response=system_info, json_pretty=True)

    def get_model(self):
        switch_model = self.rest_api.get_system_info().get("board-name", "")
        return [0, switch_model, ""] if switch_model else [1, "", "Can not get switch model"]

    def restore_config(self):
        model = self.get_model()[1]
        client = self.get_host_client()
        config_path = get_switch_config_path(client, "mikrotik", model, self.switch_name)
        config_name = os.path.basename(config_path)
        target_path = f"flash/{config_name}"
        if not config_path:
            return [3, "", f'Restoring config not supported for {model} switches named "{self.switch_name}"']
        # Uploading files via REST API is not suported on Mikrotik in any practical way. Files can
        # be uploaded only to the top-lovel directory, where they don't persist across a reboot.
        # The contents of the uploaded file are also probably limited to only 4096 bytes, though I
        # haven't checked that. tool/fetch is also unavailable via the REST API, so we can't even
        # download the file from the testbed server. What does work is upload via ftp, but we don't
        # have port forwarding for that, hence these hardcoded NAT-side switch addresses.
        if self.switch_name.endswith("switch4"):
            switch_address = "192.168.5.251"
        elif self.switch_name.endswith("switch3"):
            switch_address = "192.168.5.252"
        elif self.switch_name.endswith("switch2"):
            switch_address = "192.168.5.253"
        else:
            switch_address = "192.168.5.254"
        res = client.run_raw(f"ftp -u ftp://{self.user}:{self.password}@{switch_address}/{target_path} {config_path}")
        if res[0]:
            return [4, "", f"Failed to upload {target_path} to {switch_address}: {res[2]}"]
        # system reset-configuration also isn't available via REST API, so we have to resort to ssh for that part :(
        res = client.run_raw(
            f"sshpass -p {self.password} ssh -o UserKnownHostsFile=/dev/null "
            f"-o StrictHostKeyChecking=no {self.user}@{switch_address} system reset-configuration "
            f"skip-backup=yes no-defaults=yes keep-users=no run-after-reset={target_path}"
        )
        # The above command caused the switch to reboot, which means that ssh connection to both switch and
        # server dropped. So best to ignore any error, and offer some words of encouragement to the user.
        return [0, "Switch configuration reset initiated,\ncheck in two minutes to see if it succeeded", res[2]]

    def list_pvid(self):
        bridge_ports = self.rest_api.get_bridge_ports_config()
        if error_msg := self.generate_error_output(bridge_ports):
            return error_msg
        lines = [
            "Port   Interface   PVID   Bridge   Trusted   HW-Offload   Comment",
            "----   ---------   ----   ------   -------   ----------   ---------------",
        ]
        row = "{port:>4}   {interface:<9}   {pvid:>4}   {bridge:<6}   {trusted:<7}   {hw_offload:<10}   {comment}"
        interface_port_map = {interface: port for port, interface in self.port_interfaces_map.items()}
        for bridge_port in bridge_ports:
            bridge_port["port"] = interface_port_map[bridge_port["interface"]]
            bridge_port["hw_offload"] = bridge_port["hw-offload"]
        bridge_ports.sort(key=lambda bridge_port: bridge_port["port"])
        for bridge_port in bridge_ports:
            lines.append(row.format(**bridge_port))
        return [0, "\n".join(lines), ""]

    def list_vlan(self):
        bridge_vlans = self.rest_api.get_bridge_vlans_config()
        if error_msg := self.generate_error_output(bridge_vlans):
            return error_msg
        lines = [
            "VLAN   Comment                Disabled   Ports",
            "----   --------------------   --------   --------------------",
        ]
        row = "{vlan:>4}   {comment:<20}   {disabled:<8}   {ports}"
        for bridge_vlan in bridge_vlans:
            bridge_vlan["vlan"] = int(bridge_vlan["vlan-ids"])
            bridge_vlan["comment"] = bridge_vlan.get("comment", "")
            ports = set()
            for kind in "tagged", "untagged", "current-tagged", "current-untagged":
                ports.update(port for port in bridge_vlan[kind].split(",") if port)
            bridge_vlan["ports"] = ", ".join(sorted(ports))
        bridge_vlans.sort(key=lambda bridge_vlan: bridge_vlan["vlan"])
        for bridge_vlan in bridge_vlans:
            lines.append(row.format(**bridge_vlan))
        return [0, "\n".join(lines), ""]

    def no_shutdown_interface(self, ports):
        payload_data = dict(disabled=False)
        retval = []
        for port in ports:
            interface_name = self.port_interfaces_map[port]
            response = self.rest_api.patch_interface_config(interface_name, data=payload_data)
            if error_output := self.generate_error_output(response):
                retval.append(error_output)
                continue
            retval.append([0, f"{interface_name}  Enabled", ""])
        return retval

    def shutdown_interface(self, ports):
        payload_data = dict(disabled=True)
        retval = []
        for port in ports:
            interface_name = self.port_interfaces_map[port]
            response = self.rest_api.patch_interface_config(interface_name, data=payload_data)
            if error_output := self.generate_error_output(response):
                retval.append(error_output)
                continue
            retval.append([0, f"{interface_name}  Disabled", ""])
        return retval

    def interface_status(self, ports):
        retval = []
        for port in ports:
            interface_name = self.port_interfaces_map[port]
            interface_config = self.rest_api.get_interface_config(interface_name)
            if error_output := self.generate_error_output(interface_config):
                retval.append(error_output)
                continue
            port_status = "Enabled" if interface_config["disabled"] == "false" else "Disabled"
            retval.append([0, f"{interface_name}  {port_status}", ""])
        return retval

    def set_vlan(self, ports, vlan, vlan_type):
        vlan_number = str(vlan)
        retval = []
        for port in ports:
            interface_name = self.port_interfaces_map[port]
            target_vlan_conf = self.rest_api.get_port_vlan_config(vlan_number)
            if not target_vlan_conf:
                retval.append([1, "", f"Vlan {vlan_number} does not exist. Please create it manually."])
                continue

            if vlan_type == "untagged":
                # Remove old untagged vlan
                self.clear_port_untagged_vlans(interface_name)
                # Mikrotik doesn't allow an interface to be in a VLAN as both tagged and untagged
                # at the same time, but a lot of our code expects we can first set untagged vlan,
                # and only then clear the tagged one. Work around that by removing the tagged VLAN
                # first, but warn about it, to avoid any larger surpises.
                tagged_interfaces = target_vlan_conf["tagged"].split(",")
                if interface_name in tagged_interfaces:
                    log.warning(
                        f"removing tagged vlan {vlan_number} from port {port}, "
                        f"it cannot be tagged and untagged at the same time"
                    )
                    self.delete_vlan([port], vlan_number)

            port_bridge_conf = self.rest_api.get_port_bridge_conf(interface_name)
            if not port_bridge_conf:
                retval.append([1, "", f"Port {port} (interface {interface_name}) is not part of the bridge."])
                continue
            port_id = port_bridge_conf[".id"]
            vlan_id = target_vlan_conf[".id"]
            current_vlans = target_vlan_conf[vlan_type].split(",")
            if interface_name in current_vlans:
                retval.append([0, f"Vlan {vlan_id} and Type: {vlan_type} is already added for port number: {port}", ""])
                continue
            current_vlans.append(interface_name)
            response = self.rest_api.patch_vlan_config(vlan_id, data={vlan_type: ",".join(current_vlans)})
            if error_output := self.generate_error_output(response):
                retval.append(error_output)
                continue

            if vlan_type == "untagged":
                response = self.rest_api.patch_port_bridge_conf(port_id, data={"pvid": vlan_number})
                if error_output := self.generate_error_output(response):
                    retval.append(error_output)
                    continue

            retval.append([0, f"{interface_name} - VLAN '{vlan_number}' Type: '{vlan_type}' Set Successfully", ""])
        return retval

    def delete_vlan(self, ports, vlan):
        vlan_number = str(vlan)
        retval = []
        for port in ports:
            interface_name = self.port_interfaces_map[port]
            target_vlan_conf = self.rest_api.get_port_vlan_config(vlan_number)
            if not target_vlan_conf:
                retval.append([1, "", f"Vlan {vlan_number} does not exist. Please create it manually."])
                continue
            vlan_tagged_interfaces = target_vlan_conf["tagged"]
            vlan_untagged_interfaces = target_vlan_conf["untagged"]
            if interface_name not in vlan_tagged_interfaces and interface_name not in vlan_untagged_interfaces:
                retval.append([0, f"{interface_name} - is already removed from '{vlan}' vlan", ""])
                continue
            vlan_id = target_vlan_conf[".id"]
            new_tagged_interfaces = self.prepare_list_of_vlan_interfaces(
                vlan_interfaces=vlan_tagged_interfaces, interface_to_remove=interface_name
            )
            new_untagged_interfaces = self.prepare_list_of_vlan_interfaces(
                vlan_interfaces=vlan_untagged_interfaces, interface_to_remove=interface_name
            )
            response = self.rest_api.patch_vlan_config(
                vlan_id, data=dict(untagged=new_untagged_interfaces, tagged=new_tagged_interfaces)
            )
            if error_output := self.generate_error_output(response):
                retval.append(error_output)
                continue
            retval.append([0, f"{interface_name} removed successfully from VLAN '{vlan_number}'", ""])
        return retval

    def interface_info(self, ports):
        retval = []
        for port in ports:
            port_config = self.port_info_parsed(port)
            if not port_config:
                retval.append([1, "", f"Problems to find info for port {port}"])
            interface_info_output = ""
            if port_pvid := port_config["pvid"]:
                interface_info_output += "{:^8} {:^6}".format("PVID", port_pvid)
            for tagged_vlan in port_config["tagged"]:
                vlan_description = port_config["vlans"][tagged_vlan]
                interface_info_output += "\n{:^8} {:^6} {:^8}".format("Tagged", tagged_vlan, vlan_description)
            for untagged_vlan in port_config["untagged"]:
                vlan_description = port_config["vlans"][untagged_vlan]
                interface_info_output += "\n{:^8} {:^6} {:^8}".format("Untagged", untagged_vlan, vlan_description)
            retval.append([0, interface_info_output, ""])
        return retval

    @staticmethod
    def prepare_list_of_vlan_interfaces(vlan_interfaces, interface_to_remove):
        vlan_interfaces = vlan_interfaces.split(",")
        new_vlan_interfaces = [vlan_ifname for vlan_ifname in vlan_interfaces if vlan_ifname != interface_to_remove]
        return ",".join(new_vlan_interfaces)

    def clear_port_untagged_vlans(self, interface_name):
        port_untagged_vlans = self.get_interface_vlans(interface_name, vlan_type="untagged")
        for port_untagged_vlan in port_untagged_vlans:
            vlan_id = port_untagged_vlan[".id"]
            untagged_interfaces = port_untagged_vlan["untagged"].split(",")
            new_untagged_interfaces = [
                untagged_ifname for untagged_ifname in untagged_interfaces if untagged_ifname != interface_name
            ]
            self.rest_api.patch_vlan_config(vlan_id, data=dict(untagged=",".join(new_untagged_interfaces)))

    def interface_info_parsed(self, ports):
        parsed_ports_info = list()
        for port in ports:
            parsed_ports_info.append(self.port_info_parsed(port))
        return parsed_ports_info

    def port_info_parsed(self, port_number):
        port_info = {"pvid": None, "tagged": [], "untagged": [], "vlans": {}}
        interface_name = self.port_interfaces_map[port_number]
        port_bridge_conf = self.rest_api.get_port_bridge_conf(interface_name)
        if port_bridge_conf.get("pvid") is None:
            return {}
        port_info["pvid"] = port_bridge_conf["pvid"]
        for tagged_vlan in self.get_interface_vlans(interface_name, vlan_type="tagged"):
            port_info["tagged"].append(tagged_vlan["vlan-ids"])
            port_info["vlans"].update({tagged_vlan["vlan-ids"]: tagged_vlan.get("comment", "")})
        for untagged_vlan in self.get_interface_vlans(interface_name, vlan_type="untagged"):
            port_info["untagged"].append(untagged_vlan["vlan-ids"])
            port_info["vlans"].update({untagged_vlan["vlan-ids"]: untagged_vlan.get("comment", "")})
        return port_info

    def get_interface_vlans(self, interface_name, vlan_type):
        bridge_vlans = self.rest_api.get_bridge_vlans_config()
        interface_vlans = []
        for bridge_vlan in bridge_vlans:
            configured_vlans = bridge_vlan.get(f"current-{vlan_type}", "") + bridge_vlan.get(vlan_type, "")
            if interface_name not in configured_vlans:
                continue
            interface_vlans.append(bridge_vlan)
        return interface_vlans


REST_API_SERVICE = "https://{0}:{1}/rest"


class MikrotikRestApi:
    def __init__(self, user, password, ip, port):
        self.base_url = REST_API_SERVICE.format(ip, port)
        self.basic_auth = HTTPBasicAuth(user, password)

    # Get RAW restAPI response
    def execute_request_raw(self, req_method, uri, request_timeout=30, payload_data=None, query=None, **kwargs):
        url = f"{self.base_url}{uri}"
        request_method = getattr(requests, req_method.lower())
        payload_data = self.add_query(query=query, payload_data=payload_data)
        try:
            response = request_method(
                url, auth=self.basic_auth, json=payload_data, verify=False, timeout=request_timeout, **kwargs
            )
        except Exception as exception:
            log.error(f"Error occurred during calling to switch API:\n{str(exception)}")
            raise exception
        return response

    # get parsed JSON response
    def execute_request(self, req_method, uri, request_timeout=30, payload_data=None, query=None, **kwargs):
        raw_response = self.execute_request_raw(
            req_method=req_method,
            uri=uri,
            request_timeout=request_timeout,
            payload_data=payload_data,
            query=query,
            **kwargs,
        )
        response = self.parse_response(raw_response.text)
        return response

    @staticmethod
    def add_query(query, payload_data):
        if not query:
            return payload_data
        query_payload = {".query": [query]}
        if payload_data:
            query_payload.update(payload_data)
        return query_payload

    @staticmethod
    def parse_response(response):
        try:
            result = json.loads(response)
        except json.JSONDecodeError as exception:
            log.error("Can not parse response from REST API")
            raise exception
        return result

    def get_system_info(self):
        return self.execute_request(req_method="GET", uri="/system/resource")

    def get_system_note(self):
        return self.execute_request(req_method="GET", uri="/system/note")

    def get_interfaces_config(self):
        return self.execute_request(req_method="GET", uri="/interface")

    def get_interfaces_ethernet_config(self):
        return self.execute_request(req_method="GET", uri="/interface/ethernet")

    def get_bridge_ports_config(self):
        return self.execute_request(req_method="GET", uri="/interface/bridge/port")

    def get_interface_config(self, interface_name: str):
        return self.execute_request(req_method="GET", uri=f"/interface/{interface_name}")

    def patch_interface_config(self, interface_name: str, data=None):
        return self.execute_request(req_method="PATCH", uri=f"/interface/{interface_name}", payload_data=data)

    def get_port_bridge_conf(self, interface_name: str):
        response = self.execute_request(req_method="GET", uri=f"/interface/bridge/port?interface={interface_name}")
        return response[0] if response else {}

    def patch_port_bridge_conf(self, port_id: str, data):
        return self.execute_request(req_method="PATCH", uri=f"/interface/bridge/port/{port_id}", payload_data=data)

    def get_bridge_vlans_config(self):
        return self.execute_request(req_method="GET", uri="/interface/bridge/vlan")

    def get_port_vlan_config(self, vlan_number: Union[str, int]):
        response = self.execute_request(req_method="GET", uri=f"/interface/bridge/vlan?vlan-ids={vlan_number}")
        return response[0] if response else {}

    def patch_vlan_config(self, vlan_id: str, data=None):
        return self.execute_request(req_method="PATCH", uri=f"/interface/bridge/vlan/{vlan_id}", payload_data=data)
