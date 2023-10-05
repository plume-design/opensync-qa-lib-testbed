import os
import sys
import time
import terminaltables
from textwrap import wrap

from lib_testbed.generic.util import config
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.client import client as _client_factory
from lib_testbed.generic.pod import pod as _pod_factory
from lib_testbed.generic.util.base_tool import TOOLS_DIR
from lib_testbed.generic.util.opensyncexception import OpenSyncException


class TestBedToolLib:
    def __init__(self, **kwargs):
        self.tb_config = kwargs.get("config")
        self.json_output = kwargs.get("json")
        self.cb = None

    @staticmethod
    def tool_map(tools_list):
        """
        Creates a dictionary map of tools from list, with associated description and usage strings in nested dict
        Args:
            tools_list: (list) - listing of tools available in repo (typically gathered from tools/README.md)

        Returns: (dict) - Key == tool-name

        """
        tools_map = {}
        with open(os.path.join(TOOLS_DIR, "README.md")) as tr:
            tool_lines = [line.rstrip() for line in tr.readlines()]
        tool = ""
        description = ""
        usage = ""
        check_continuation = False
        # add a dummy tool (sentinel) to be able to handle the last tool within the loop
        tool_lines.append("###")
        for num, line in enumerate(tool_lines):
            if line.startswith("  -"):
                check_continuation = False
            elif line.startswith("- Notes:"):
                check_continuation = False
            if line.startswith("###"):
                if tool:
                    # we are at a start of a tool, push previous one to tools_map
                    # wrap long descriptions (while usage retains line breaks from the file)
                    description = "\n".join(wrap(description, 61))
                    tools_map[tool] = {"description": description, "usage": usage}
                    tool = ""
                    description = ""
                    usage = ""
                    check_continuation = False
                if line[line.rindex("#") + 2 :] in tools_list:
                    tool = line[line.rindex("#") + 2 :]
                continue
            if tool and not usage:
                if line.startswith("- Description:"):
                    description += line[line.index(":") + 2 :]
                    check_continuation = True
                    continue
                if line.startswith("- Usage:"):
                    check_continuation = False
                elif description and check_continuation:
                    # continuation of description
                    description += " " + line.strip()
                    continue
            if description:
                if line.startswith("- Usage:"):
                    usage += line[line.index(":") + 2 :].replace("`", "")
                    check_continuation = True
                    continue
                if usage and check_continuation:
                    # continuation of usage
                    usage += "\n" + line.strip().replace("`", "")
                    continue
        return tools_map

    def limited_tools_per_config(self, tools_list, debug=False):
        """
        Parses the available testbed components, and limits the output tools list if not available for tb location

        Args:
            tools_list: (list[str]) - total list of strings of available repo tools
            debug: (bool) - If set to True - adds explicit logging as available tools removed from output

        Notes:
            tool to config-key mapping:
                - server -> requires 'ssh_gateway'
                - switch -> requires 'Switch'
                - rpower -> requires 'rpower'
                - pod -> requires 'Nodes'
                - client -> requires 'Clients'

        Returns:
            (list): A full tools list if all available for tb, otherwise a stripped down list of capabilities
        """
        if not self.tb_config:
            log.error("Failed to get testbed config info")
            return tools_list
        tb_keys = [key.lower() for key in self.tb_config]
        # mapping of tool to list of required configs for tool to be available per TB
        tool_config_map = {
            "server": ["ssh_gateway"],
            "switch": ["switch"],
            "rpower": ["rpower"],
            "pod": ["nodes"],
            "client": ["clients"],
        }
        for tool_map in tool_config_map:
            if tool_map not in tools_list:
                continue
            for config_key in tool_config_map[tool_map]:
                if config_key in tb_keys:
                    continue
                if debug:
                    log.info(
                        f'[Debug]: Config key -> "{config_key}" not found for TB, '
                        f'removing tool -> "{tool_map}" from available list'
                    )
                tools_list.remove(tool_map)
        return tools_list

    def tb_tools_list(self):
        """
        List of available Testbed tools

        Found in tools directories.
        """
        tools_whitelist = [
            "pset",
            "reserve",
            "attenuator",
            "client",
            "cloud",
            "log-pull",
            "pod",
            "ptopo",
            "rpower",
            "sanity",
            "server",
            "switch",
            "osrt_snapshot_decoder",
        ]
        tools_whitelist = [
            tool
            for tool in tools_whitelist
            if tool in [tool_name for tool_name in os.listdir(TOOLS_DIR) if tool_name not in ["README.md"]]
        ]

        if tool_target := os.environ.get("OPENSYNC_TESTBED"):
            tools_whitelist = self.limited_tools_per_config(tools_whitelist, debug=False)
            tool_target = f"testbed {tool_target}"
        else:
            tool_target = "testbed environment"
            tools_whitelist = ["pset", "reserve"]
        table = [["Tool Name", "Description", "Usage"]]
        tool_mapping = __class__.tool_map(tools_whitelist)
        for tool in tools_whitelist:
            try:
                table.append([tool, tool_mapping[tool]["description"], tool_mapping[tool]["usage"]])
            except KeyError as e:
                print(f"Error loading tool ({tool}) description:", e)
        tools_str = f"Command-Line tools available for {tool_target}"
        delim = "=" * len(tools_str) + "=" * 6
        print(f"{delim}\n== {tools_str} ==\n{delim}")
        print(terminaltables.AsciiTable(table).table)

    def recover(self):
        """
        Recover testbed and its location to default state
        """

        def _print_state(state: str) -> None:
            table = [["Testbed recovery", state]]
            print(terminaltables.AsciiTable(table).table)

        try:
            from lib.cloud.custbase import CustBase
            from lib.cloud.userbase import UserBase
        except (ModuleNotFoundError, OpenSyncException):
            log.error("Cloud modules are not available, cannot perform recovery")
            _print_state("Failed")
            sys.exit(1)

        deployment_file = None
        try:
            loc_deployment = config.get_deployment(self.tb_config)
            deployment_file = config.find_deployment_file(loc_deployment)
        except (KeyError, OpenSyncException):
            log.info("Could not get deployment")
        if deployment_file:
            self.tb_config["deployment_file"] = deployment_file
            self.tb_config[config.TBCFG_PROFILE] = os.path.basename(deployment_file).split(".")[0]
            deployment_data = config.load_file(deployment_file)
            if deployment_data:
                config.update_config_with_admin_creds(deployment_data)
                self.tb_config = config.merge(self.tb_config, deployment_data)

        log.warning("Restoring testbed and its location to default state")

        # Consider uprise testbeds based on USTB only
        if ("UPRISE" in self.tb_config.get("capabilities", [])) and (
            self.tb_config["ssh_gateway"].get("location_file")
        ):
            from lib.util.uprisetoollib import UpRiseToolLib

            uprise_tool = UpRiseToolLib(config=self.tb_config)
            ustb_name = config.get_location_name(self.tb_config)
            log.warning("Moving UpRise location back to HomePass")
            uprise_tool.move_to_homepass(cfg_name=ustb_name)
            _print_state("Successful")
            return

        # Clear WANO config that might have been set due to use of mark.wan_connection()
        gw_pod = _pod_factory.Pod().resolve_obj(name="gw", role="gw", config=self.tb_config, multi_obj=False)
        gw_pod.set_wano_cfg({})
        # Use a (fake) node/test with none of the location, wan_connection, ... marks, so that
        # cloud_recovery puts the testbed and its location into a state that is close enough to
        # default. Calling cloud.setup_class_handler() is enough to get cloud_recovery to run.
        admin = CustBase(name="admin", role="admin", config=self.tb_config)
        user = UserBase(name="user", role="user", conf=self.tb_config)
        admin.own_markers = user.own_markers = {"session": []}
        admin.all_markers = user.all_markers = []
        admin.ub, user.cb = user, admin
        admin.initialize()
        admin.cloud_recovery.run(force=True)

        if self.tb_config.get("runtime_lte_only_uplink", False):
            log.warning("Restoring uplink connection for GW, after LTE run")
            client_api = _client_factory.Client().resolve_obj(name="host", config=self.tb_config, nickname="host")
            ret = client_api.run("sudo iptables --list FORWARD")
            if "DROP" in ret:
                timeout = time.time() + 20
                while time.time() < timeout:
                    client_api.run(
                        "sudo iptables -D FORWARD -i eth0 -o eth0.200 -m state --state RELATED,ESTABLISHED -j DROP",
                        skip_exception=True,
                    )
                    client_api.run("sudo iptables -D FORWARD -i eth0.200 -o eth0 -j DROP", skip_exception=True)
                    ret = client_api.run("sudo iptables --list FORWARD")
                    if "DROP" not in ret:
                        break
                else:
                    log.error("Unable to clear iptables rules on the testbed server, fingers crossed")
        _print_state("Successful")
