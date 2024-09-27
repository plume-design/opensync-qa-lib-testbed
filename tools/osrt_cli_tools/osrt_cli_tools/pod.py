import time
import traceback
import sys
import fnmatch
from pathlib import Path

import osrt_cli_tools.utils
from lib_testbed.generic.util.common import threaded
from lib_testbed.generic.util.logger import log
from osrt_cli_tools import tb_config_parser

if osrt_cli_tools.utils.is_autocomplete():
    import click
else:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True


def _process_nodes_arg(value: str, tb_name=None):
    """Helper function to process pods for specified tb_name."""
    from lib_testbed.generic.util.config import load_tb_config

    values = value.lstrip(",").rstrip(",").split(",")
    testbed_name = osrt_cli_tools.utils.get_testbed_name(tb_name)
    if not osrt_cli_tools.utils.is_autocomplete():
        config = load_tb_config(testbed_name, skip_deployment=True)
    else:
        config = tb_config_parser.load_config(testbed_name)
    names = [pod["name"] for pod in config["Nodes"]]

    if any([v in ["all", "*"] for v in values]):
        return names
    if "leaves" in value:
        values.remove("leaves")
        values.extend(names[1:])
    if "gateway" in value:
        values.remove("gateway")
        values.append(names[0])
    new_nodes = []
    for val in values:
        if val in names:
            new_nodes.append(val)
        elif "*" in val or "?" in val or "[" in val:
            if matched_list := fnmatch.filter(names, val):
                new_nodes.extend(matched_list)
    if not new_nodes:
        if not osrt_cli_tools.utils.is_autocomplete():
            click.echo(f"{value} is not a valid pod name", err=True)
            sys.exit(1)
        else:
            return value
    return new_nodes


def process_nodes_arg(ctx, param, value):
    """Helper function to process pods. Delay processing in case of multiple testbeds"""
    ctx.ensure_object(dict)
    if ctx.obj.get("TESTBEDS"):
        return value
    else:
        tb_name = osrt_cli_tools.utils.get_testbed_name()
        return _process_nodes_arg(value, tb_name=tb_name)


def process_node(ctx, param, value):
    """Helper function to process a single pod."""
    if len(value.split(",")) > 1:
        osrt_cli_tools.utils.print_command_output({"pod": [1, "", f"{value} matches more than 1 pod"]})


def complete_all_pods(ctx, param, incomplete):
    """Autocomplete all pod names helper."""
    testbed_name = osrt_cli_tools.utils.get_testbed_name()
    config = tb_config_parser.load_config(testbed_name)
    if config:
        nodes = [pod["name"] for pod in config["Nodes"]]
    else:
        nodes = []
    names = ["all", "gateway", "leaves"] + nodes
    return [p for p in names if p.startswith(incomplete)]


def complete_defined_pod_names(ctx, param, incomplete):
    """Autocomplete pod names as stored in config file/not matching all."""
    if osrt_cli_tools.utils.is_autocomplete():
        testbed_name = osrt_cli_tools.utils.get_testbed_name()
        config = tb_config_parser.load_config(testbed_name)
        if config:
            nodes = [pod["name"] for pod in config["Nodes"]]
            return [p for p in nodes if p.startswith(incomplete)]
        return incomplete


all_nodes_argument = click.argument(
    "nodes", default="all", callback=process_nodes_arg, shell_complete=complete_all_pods, required=False
)
defined_nodes_argument = click.argument(
    "nodes", default="all", callback=process_nodes_arg, shell_complete=complete_defined_pod_names, required=False
)
single_node_argument = click.argument("node", shell_complete=complete_defined_pod_names, required=True)


def get_pods_object(nicknames, tb_name: str = None):
    """Returns pods object."""
    from lib_testbed.generic.pod.pod import Pods
    from lib_testbed.generic.util.config import load_tb_config

    if not tb_name:
        tb_name = osrt_cli_tools.utils.get_testbed_name()
    config = load_tb_config(tb_name, skip_deployment=True)
    pods_obj = Pods()
    return pods_obj.resolve_obj(config=config, multi_obj=True, nicknames=nicknames)


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@osrt_cli_tools.utils.debug_option
@osrt_cli_tools.utils.json_option
@osrt_cli_tools.utils.disable_colors_option
@osrt_cli_tools.utils.timeout_option
@click.pass_context
def cli(ctx, debug, json, disable_colors, timeout):
    """Pod tool: control testbed nodes.

    **NODES** are the pods/nodes to run the command against. Can be one of the following:
    [<pod_name>[,...] | all | gateway | leaves].
    All commands are executed against all available nodes by default.
    """
    log.debug("Invoking pod tool context")
    ctx.ensure_object(dict)
    if not sys.stdout.isatty():
        json = True
    if not ctx.obj.get("DEBUG"):
        ctx.obj["DEBUG"] = debug
    if not ctx.obj.get("JSON"):
        ctx.obj["JSON"] = json
    if not ctx.obj.get("TIMEOUT"):
        ctx.obj["TIMEOUT"] = timeout
    if not ctx.obj.get("DISABLE_COLORS"):
        ctx.obj["DISABLE_COLORS"] = disable_colors
    if not osrt_cli_tools.utils.is_autocomplete():
        osrt_cli_tools.utils.prepare_logger(ctx.obj.get("DEBUG", False))


def _get_tb_cfg(tb_name):
    """Task for getting testbed config for given testbed."""
    from lib_testbed.generic.util.config import load_tb_config

    testbed_name = osrt_cli_tools.utils.get_testbed_name(tb_name=tb_name)
    return load_tb_config(testbed_name, skip_deployment=True)


@cli.command(name="list")
@all_nodes_argument
@click.pass_context
def list_(ctx, nodes):
    """List pods."""
    import json
    from concurrent.futures import ProcessPoolExecutor

    testbeds = ctx.obj.get("TESTBEDS") if ctx.obj.get("TESTBEDS") else [osrt_cli_tools.utils.get_testbed_name()]

    futures, results = {}, {}
    with ProcessPoolExecutor() as executor:
        for tb_name in testbeds:
            futures[tb_name] = executor.submit(_get_tb_cfg, tb_name)
        for tb_name in futures:
            try:
                results[tb_name] = futures[tb_name].result()
            except Exception as err:
                click.secho(
                    f"Could not get pods list for testbed {tb_name}",
                    fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
                    err=True,
                )
                log.debug("Got error: %s", "".join(traceback.format_exception(err)))

    if ctx.obj.get("JSON"):
        new_results = {}
        for tb_name in results:
            new_results[tb_name] = [pod["name"] for pod in results[tb_name]["Nodes"]]
        click.echo(json.dumps(new_results, indent=2))
    else:
        for tb_name in results:
            if len(results) != 1:
                click.echo(f"{tb_name}:")
            for pod in results[tb_name]["Nodes"]:
                click.echo(pod["name"])


@cli.command(name="run")
@click.argument("command")
@all_nodes_argument
@click.pass_context
def run(ctx, command, nodes):
    """Run a command on **NODES**."""
    _lib_tool_cmd_action(ctx=ctx, nodes=nodes, action="run", command=command)


@cli.command(name="version")
@all_nodes_argument
@click.pass_context
def version(ctx, nodes):
    """Display **NODES** version."""
    _lib_tool_cmd_action(ctx=ctx, nodes=nodes, action="version")


@cli.command(name="uptime")
@all_nodes_argument
@click.pass_context
def uptime(ctx, nodes):
    """Display **NODES** uptime."""
    return ctx.invoke(run, command="uptime", nodes=nodes)


@cli.command(name="ssh")
@single_node_argument
@click.pass_context
def ssh(ctx, node):
    """Open interactive ssh session to **NODE**.

    Note that this command opens an interactive SSH session, and can only be executed against a single node at a time.
    """
    if len(ctx.obj.get("TESTBEDS", [])) > 1:
        click.secho(
            "Interactive SSH cannot be started against multiple testbeds",
            err=True,
            fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
        )
        sys.exit(1)
    else:
        tb_name = ctx.obj.get("TESTBEDS", [None])[0]
    pods = get_pods_object([node], tb_name=tb_name)
    ret = pods.lib.ssh(timeout=ctx.obj["TIMEOUT"])
    osrt_cli_tools.utils.print_command_output(ctx, {node: ret[0]})


def _pods_ret_to_results_table(pods, ret: list) -> dict:
    """Utility function to parse pods results into printable results map - mapping pod name to
    a list with exit code, stdout and stderr.
    """
    results_dict = {}
    for i, pod_name in enumerate(pods.nickname):
        if isinstance(ret[i], Exception):
            results_dict[pod_name] = [1, "", "".join(traceback.format_exception(ret[i]))]
        else:
            results_dict[pod_name] = ret[i]

    return results_dict


@cli.command(name="upgrade")
@click.argument("image", required=False)
@click.option("-p", help="Encryption key")
@click.option("-e", is_flag=True, help="Erase certificates")
@click.option("-n", is_flag=True, help="Skip version check")
@click.option("--version-list", is_flag=True, help="When provided, only version list is displayed.")
@click.option("--check-latest", is_flag=True, help="Check latest released versions for provided FW branch.")
@all_nodes_argument
@click.pass_context
def upgrade(ctx, image, nodes, p, e, n, version_list, check_latest):
    """Upload image/firmware to specified pod/pods. Image/version needs to be specified.
    The **IMAGE** argument is mandatory, unless the command is called with `--version-list` flag
    which only displays available versions for each node.

    The newest image version:

    `osrt pod upgrade <version|native-version|master> <optional>  <gw|l1|l2|all> `


    Example commands:

    ```
    osrt pod upgrade master gw
    osrt pod upgrade native-master gw
    osrt pod upgrade legacy-native-master gw
    osrt pod upgrade 4.2.0 all
    osrt pod upgrade native-5.8.0 gw
    osrt pod upgrade 6.2.0 gw -> Note missing "native" prefix
    ```


    Requested image build:

    `osrt pod upgrade <version|native-version|master|fbb>-<build_num> <optional> <gw|l1|l2|all>`


    Example commands:

    ```
    osrt pod upgrade master-1777 all
    osrt pod upgrade native-master-1777 all
    osrt pod upgrade legacy-master-1777 all
    osrt pod upgrade 4.2.0-15 l1
    osrt pod upgrade fbb-13422 gw
    osrt pod upgrade native-fbb-13422 gw
    osrt pod upgrade native-5.8.0-12 gw
    osrt pod upgrade 6.2.0-3 gw
    ```
    -> Note missing "native" prefix in the last example
    """
    if ctx.obj.get("TESTBEDS"):
        click.secho(
            "Executing upgrade against multiple testbeds is currently not supported",
            fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
            err=True,
        )
        sys.exit(1)
    from lib_testbed.generic.util.artifactory_lib import get_map

    pods = get_pods_object(nodes)
    if version_list:
        results_table = {}
        for pod in pods.obj_list:
            build_map = get_map(pod.model)
            versions = [v for v in build_map if v not in ["short-name", "s3-bucket"]]
            results_table[pod.nickname] = ["0", ", ".join(versions), ""]
        osrt_cli_tools.utils.print_command_output(ctx, results_table)
        return

    if check_latest:
        results_table = {}
        for pod in pods.obj_list:
            build_map = get_map(pod.model)
            branch_details = build_map.get(image)
            if not branch_details:
                results_table[pod.nickname] = [
                    "1",
                    "",
                    f"Unknown FW branch: {image} for {pod.model} model. "
                    f"Check allowed FW branches with use: `osrt pod upgrade --version-list`",
                ]
                continue
            status, branch_builds = pod.lib.artifactory.get_list_of_files(version=None, final_version=image)
            if status:
                results_table[pod.nickname] = [status, "", f"Artifactory API request failed with: {status} status code"]
                continue
            branch_builds = branch_builds[-1:]
            # From new to old one
            fw_builds_to_print = [fw_name.lstrip("/") for fw_name in branch_builds[::-1]]
            results_table[pod.nickname] = ["0", "\n".join(fw_builds_to_print[-5:]), ""]
        osrt_cli_tools.utils.print_command_output(ctx, results_table)
        return

    if not image:
        raise ValueError("**IMAGE** is a mandatory argument for upgrade")

    if not ctx.obj.get("DEBUG"):
        import logging
        from osrt_cli_tools.utils import set_log_level

        set_log_level(logging.INFO)

    args = []
    if p:
        args.append(f"-p={p}")
    if e:
        args.append("-e")
    if n:
        args.append("-n")

    ret = pods.lib.tool.upgrade(image, *args)
    for i, pod_ret in enumerate(ret):
        if isinstance(pod_ret, KeyError):  # likely could not determine version location
            ret[i] = [1, "", f"Cloud not determine version location for: {image}. Is the build_map up to date?"]
    results_table = _pods_ret_to_results_table(pods, ret)
    osrt_cli_tools.utils.print_command_output(ctx, results_table)


@threaded
def upgrade_single_pod(pod_tool, version):
    """This task it to upgrade a single pod to specified version."""

    return pod_tool.upgrade(version)


@cli.command
@click.argument("versions", type=click.STRING, required=True)
@all_nodes_argument
@click.pass_context
def upgrade_multi(ctx, versions, nodes):
    """Upgrade location pods with different firmware **VERSIONS**.

    The user is expected to provide a comma-separated list of versions. The length of the list **MUST** be equal
    to the number of pods (defaults to all pods).

    Example command - this will upgrade 3 pods in the order as listed in the config file:

    ```
    pod upgrade-multi 6.2.0,6.4.0,5.8.0

    ```

    Another example, only upgrade 2 leaves: l2 leaf to 6.4.0 and l1 leaf to 5.8.0:

    ```
    pod upgrade-multi 6.4.0,5.8.0 l2,l1
    ```


    """
    versions = versions.split(",")
    pods = get_pods_object(nodes)
    if len(pods.lib.tool.obj_list) != len(versions):
        click.echo(f"Provided {len(versions)} versions for {len(pods.lib.tool.obj_list)} pods: {nodes}.", err=True)
        sys.exit(1)
    ret = []
    futures = []
    if not ctx.obj.get("DEBUG"):
        import logging
        from osrt_cli_tools.utils import set_log_level

        set_log_level(logging.INFO)

    for i, pod_tool in enumerate(pods.lib.tool.obj_list):
        futures.append(upgrade_single_pod(pod_tool, versions[i]))

    for f in futures:
        ret.append(f.result())
    results_table = _pods_ret_to_results_table(pods, ret)
    osrt_cli_tools.utils.print_command_output(ctx, results_table)


def _lib_tool_cmd_action_parallel(ctx, nodes, action, *args, **kwargs):
    """Execute tool action in parallel for multiple testbeds - passed over in the click context."""
    from lib_testbed.generic.util.common import threaded
    from osrt_cli_tools import reserve

    testbeds = ctx.obj.get("TESTBEDS")
    futures = {}
    results = {}

    @threaded
    def _cmd_task(tb_name, ctx, nodes, action, *args, **kwargs):
        nodes = _process_nodes_arg(nodes, tb_name)
        reservation_obj = reserve.get_reserve_object(tb_name, json=ctx.obj.get("JSON", False))
        dry_run, skip_reservation = ctx.obj.get("DRY_RUN", False), ctx.obj.get("SKIP_RESERVATION", False)
        reserved = True
        if not skip_reservation:
            if dry_run:
                click.secho(f"DRY-RUN: Reserving testbed {tb_name}")
            else:
                log.debug("Reserving testbed %s", tb_name)
                reservation_status = reservation_obj.reserve_test_bed()
                if not reservation_status["status"]:
                    click.secho(
                        f"Could not obtain reservation for testbed {tb_name}.",
                        err=True,
                        fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
                    )
                    reserved = False
        else:
            click.secho(
                f"Skipping reservation for testbed {tb_name}",
                fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
                err=True,
            )
        try:
            if reserved:
                if dry_run:
                    click.secho(
                        f"DRY-RUN: executing command {action} against {nodes} with {args} {kwargs} on testbed {tb_name}"
                    )
                    results_table = {f"dry-run: {tb_name}": [0, f"dry-run: {action}", ""]}
                else:
                    pods = get_pods_object(nodes, tb_name=tb_name)
                    method = getattr(pods.lib.tool, action)
                    ret = method(*args, **kwargs)
                    results_table = _pods_ret_to_results_table(pods, ret)
        finally:
            if not skip_reservation and reserved:
                if dry_run:
                    click.secho(f"DRY-RUN: Unreserving testbed {tb_name}")
                else:
                    log.info("Unreserving testbed %s", tb_name)
                    unreserve_status = reservation_obj.unreserve()
                    log.debug("Unreserve status: %s", unreserve_status)
        return results_table

    for tb_name in testbeds:
        futures[tb_name] = _cmd_task(tb_name=tb_name, ctx=ctx, nodes=nodes, action=action, *args, **kwargs)

    for tb_name in futures:
        try:
            results[tb_name] = futures[tb_name].result()
        except Exception as err:
            results[tb_name] = {}
            click.secho(
                f"Command {action} failed on testbed {tb_name}. Use --debug for more output.",
                fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
                err=True,
            )
            log.debug("Captured error: %s", "".join(traceback.format_exception(err)))

    comma_counter = 1
    if ctx.obj.get("JSON", False):
        click.echo("[")

    for tb_name in results:
        osrt_cli_tools.utils.print_command_output(ctx=ctx, output=results[tb_name], title=tb_name)
        if ctx.obj.get("JSON", False) and comma_counter < len(results):
            click.echo(",")
            comma_counter += 1

    if ctx.obj.get("JSON", False):
        click.echo("]")


def _lib_tool_cmd_action(ctx, nodes, action: str, *args, **kwargs):
    """Trigger action (this is the method name) on all nodes (pods), passing all keyword args.
    Print out command output. This function encapsulates the lib/tool-mapping."""
    if "timeout" not in kwargs and action not in [
        "info",
        "get_logs",
        "role",
        "recover",
        "get_crash",
        "get_ips",
        "list_builds",
        "is_fuse_burned",
        "set_region",
        "set_wano_config",
        "get_wano_config",
    ]:
        kwargs["timeout"] = ctx.obj.get("TIMEOUT", 30)
    if action in ["sanity"]:
        del kwargs["timeout"]
    if ctx.obj.get("TESTBEDS"):
        return _lib_tool_cmd_action_parallel(ctx=ctx, nodes=nodes, action=action, *args, **kwargs)
    pods = get_pods_object(nodes)
    method = getattr(pods.lib.tool, action)  # this maps lib method by name (string)
    ret = method(*args, **kwargs)
    results_table = _pods_ret_to_results_table(pods, ret)
    osrt_cli_tools.utils.print_command_output(ctx, results_table)


@cli.command("file-put")
@click.option(
    "--timeout",
    default=10 * 60,
    type=click.INT,
    help="Timeout for scp, overwrites the tool-global timeout",
    show_default=True,
)
@click.argument("source", type=click.Path())
@click.argument("target", type=click.Path())
@all_nodes_argument
@click.pass_context
def put_file(ctx, timeout, source, target, nodes):
    """Put file or directory on **NODES** using scp."""
    ctx.obj["TIMEOUT"] = timeout
    _lib_tool_cmd_action(ctx, nodes, "put_file", local_pth=source, remote_pth=target)


@cli.command("file-get")
@click.option(
    "--timeout",
    default=10 * 60,
    type=click.INT,
    help="Timeout for scp, overwrites the tool-global timeout",
    show_default=True,
)
@click.argument("source", type=click.Path(), nargs=1)
@click.argument("target", type=click.Path(), nargs=1)
@all_nodes_argument
@click.pass_context
def get_file(ctx, timeout, source, target, nodes):
    """Get file or directory from **NODES** to local disk using scp."""
    ctx.obj["TIMEOUT"] = timeout
    _lib_tool_cmd_action(ctx, nodes, "get_file", remote_pth=source, local_pth=target, create_dir=False)


@cli.command("reboot")
@all_nodes_argument
@click.pass_context
def reboot(ctx, nodes):
    """Reboot **NODES**."""
    return ctx.invoke(run, command="reboot", nodes=nodes)


@cli.command("wait")
@click.option(
    "--timeout",
    default=5,
    show_default=True,
    help="Timeout in seconds; it overwrites the default pod-tool-wide timeout.",
)
@all_nodes_argument
@click.pass_context
def wait(ctx, timeout, nodes):
    """Wait for pod to be available."""
    _lib_tool_cmd_action(ctx, nodes, "wait_available", timeout=timeout)


@cli.command("restart")
@all_nodes_argument
@click.pass_context
def restart(ctx, nodes):
    """Restart managers."""
    _lib_tool_cmd_action(ctx, nodes, "restart")


@cli.command("ping")
@all_nodes_argument
@click.option("--host", is_flag=False, type=click.STRING, help="host to ping.", default=None)
@click.option("--v6", default=False, help="Perform ipv6 check instead of ipv4. (flag)", is_flag=True)
@click.pass_context
def ping(ctx, nodes, host, v6):
    """Ping given host. If no host is given, then the pod pings itself."""
    _lib_tool_cmd_action(ctx, nodes, "ping", host=host, v6=v6)


@cli.command("ping-check")
@click.option(
    "--ipaddr",
    default="",
    help="The ip address to use for checking connectivity. The default for ipv4 is 8.8.8.8 and google.com for ipv6.",
)
@click.option("--count", default=1, show_default=True, help="Number of ICMP requests to perform.")
@click.option("--fqdn-check", default=False, help="Perform fqdn check. (flag)", is_flag=True)
@click.option("--v6", default=False, help="Perform ipv6 check instead of ipv4. (flag)", is_flag=True)
@all_nodes_argument
@click.pass_context
def ping_check(ctx, ipaddr, count, fqdn_check, v6, nodes):
    """Check **NODES** connectivity (ICMP)."""
    _lib_tool_cmd_action(ctx, nodes, "ping_check", ipaddr=ipaddr, count=count, fqdn_check=fqdn_check, v6=v6)


@cli.command("check")
@all_nodes_argument
@click.pass_context
def check(ctx, nodes):
    """**NODES** health check."""
    _lib_tool_cmd_action(ctx, nodes, "check")


@cli.command("enable")
@all_nodes_argument
@click.pass_context
def enable(ctx, nodes):
    """Enable wifi radios."""
    _lib_tool_cmd_action(ctx, nodes, "enable")


@cli.command("disable")
@all_nodes_argument
@click.pass_context
def disable(ctx, nodes):
    """Disable wifi radios."""
    _lib_tool_cmd_action(ctx, nodes, "disable")


@cli.command("info")
@all_nodes_argument
@click.pass_context
def info(ctx, nodes):
    """Display pod connection information."""
    _lib_tool_cmd_action(ctx, nodes, "info")


@cli.command("model")
@click.option(
    "--wait-non-empty",
    type=click.INT,
    help="Optional timeout [in seconds] for model information fetched from ovsdb.",
    default=0,
)
@all_nodes_argument
@click.pass_context
def model(ctx, wait_non_empty, nodes):
    """Get pod model."""
    _lib_tool_cmd_action(ctx, nodes, "get_model", wait_non_empty=wait_non_empty)


@cli.command("role")
@all_nodes_argument
@click.pass_context
def role(ctx, nodes):
    """Get pod role."""
    _lib_tool_cmd_action(ctx, nodes, "role")


@cli.command("bssid")
@click.option("--bridge", default="both", show_default=True, help="display only 'br-wan'|'br-home'.")
@all_nodes_argument
@click.pass_context
def bssid(ctx, bridge, nodes):
    """Get **NODES** bssid."""
    if bridge in ["", "both"]:
        bridge = ""
    _lib_tool_cmd_action(ctx, nodes, "bssid", bridge=bridge)


@cli.command("recover")
@all_nodes_argument
@click.pass_context
def recover(ctx, nodes):
    """Recover **NODES** to allow management access."""
    _lib_tool_cmd_action(ctx, nodes, "recover")


@cli.command("eth-connect")
@click.argument("pod_name", type=click.STRING)
@single_node_argument
@click.pass_context
def eth_connect(ctx, pod_name, node):
    """Connect single **NODE** to an Ethernet port of another pod.

    Connect **NODE** to **POD_NAME**, pay attention to the order of arguments.

    Also note that **NODE** needs to be power cycled before the command takes effect.

    Example usage:
    `osrt-pod eth-connect l2 l1` -> connect l1 to l2 pods with Ethernet.
    """

    pods = get_pods_object([node])
    ret = pods.lib.tool.eth_connect(pod_name=pod_name)
    osrt_cli_tools.utils.print_command_output(ctx, {node: ret[0]})


@cli.command("eth-disconnect")
@single_node_argument
@click.pass_context
def eth_disconnect(ctx, node):
    """Disconnect all Ethernet ports from pod."""
    pods = get_pods_object([node])
    ret = pods.lib.tool.eth_disconnect()
    osrt_cli_tools.utils.print_command_output(ctx, {node: ret[0]})


@cli.command("serial")
@all_nodes_argument
@click.pass_context
def serial(ctx, nodes):
    """Get pod serial number."""
    _lib_tool_cmd_action(ctx, nodes, "get_serial_number")


@cli.command("sanity")
@click.option("--nocolor", default=False, is_flag=True, help="Add flag for simple output, stripped of colors.")
@all_nodes_argument
@click.pass_context
def sanity(ctx, nodes, nocolor):
    """Run pod sanity."""
    if nocolor:
        _lib_tool_cmd_action(ctx, nodes, "sanity", "--nocolor")
    else:
        _lib_tool_cmd_action(ctx, nodes, "sanity")


@cli.command("crash-get")
@all_nodes_argument
@click.pass_context
def get_crash(ctx, nodes):
    """Get crash log file from pod."""
    _lib_tool_cmd_action(ctx, nodes, "get_crash")


@cli.command("logs-get")
@all_nodes_argument
@click.argument("directory", type=click.Path(), default=None, required=False)
@click.pass_context
def get_logs(ctx, nodes, directory):
    """Download logs from **NODES**."""
    _lib_tool_cmd_action(ctx, nodes, "get_logs", directory=directory)


@cli.command("connected")
@all_nodes_argument
@click.pass_context
def connected(ctx, nodes):
    """Returns cloud connection state."""
    _lib_tool_cmd_action(ctx, nodes, "connected")


@cli.command("table-get")
@click.argument("table", type=click.STRING)
@all_nodes_argument
@click.pass_context
def get_table(ctx, table, nodes):
    """Get ovsh table from pod. Table name must be provided, e.g. `AWLAN_Node`."""
    _lib_tool_cmd_action(ctx, nodes, "get_ovsh_table_tool", table=table)


@cli.command("ips-get")
@click.argument("iface", type=click.STRING)
@all_nodes_argument
@click.pass_context
def get_ips(ctx, iface, nodes):
    """Get ipv4 and ipv6 for specified IFACE."""
    _lib_tool_cmd_action(ctx, nodes, "get_ips", iface=iface)


@cli.command("wps-start")
@all_nodes_argument
@click.argument("iface", type=click.STRING, required=False, default=None)
@click.argument("psk", type=click.STRING, required=False, default=None)
@click.pass_context
def start_wps(ctx, iface, psk, nodes):
    """Start WPS session. Optionally provide IFACE name and PSK."""
    _lib_tool_cmd_action(ctx, nodes, "start_wps_session", if_name=iface, psk=psk)


@cli.command("region-get")
@all_nodes_argument
@click.pass_context
def get_region(ctx, nodes):
    """Get DFS regional domain."""
    _lib_tool_cmd_action(ctx, nodes, "get_region")


@cli.command("region-set")
@click.argument(
    "region", type=click.Choice(choices=["EU", "US", "UK", "AU", "CA", "HK", "IL","JP", "KR", "KW", "MA", "NZ", "PH", "SG"])
)
@all_nodes_argument
@click.pass_context
def set_region(ctx, region, nodes):
    """Set DFS regional domain to **REGION**.

    The regions: NZ, SG, IL, HK are only available for Ceasar."""
    _lib_tool_cmd_action(ctx, nodes, "set_region", region=region)


@cli.command("radar-trigger")
@all_nodes_argument
@click.pass_context
def trigger_radar(ctx, nodes):
    """Trigger radar event."""
    _lib_tool_cmd_action(ctx, nodes, "trigger_radar")


@cli.command("clients-simulate")
@all_nodes_argument
@click.argument("count", type=click.INT, default=1, required=False)
@click.pass_context
def simulate_clients(ctx, nodes, count):
    """Simulate COUNT (default=1) of Ethernet clients."""
    _lib_tool_cmd_action(ctx, nodes, "simulate_clients", count=count)


@cli.command("local-mqtt-broker")
@all_nodes_argument
@click.pass_context
def local_mqtt_broker(ctx, nodes):
    """Redirect stats to local mqtt broker."""
    _lib_tool_cmd_action(ctx, nodes, "local_mqtt_broker")


@cli.command("wano-config-get")
@all_nodes_argument
@click.pass_context
def get_wano_config(ctx, nodes):
    """Get WANO configuration from **NODES**. The config is printed out to stdout in JSON format."""
    _lib_tool_cmd_action(ctx, nodes, "get_wano_config")


@cli.command("wano-config-set")
@click.argument("config", type=click.STRING)
@all_nodes_argument
@click.pass_context
def set_wano_config(ctx, config, nodes):
    """Set WANO configuration. CONFIG needs to be provided as text in JSON format."""
    _lib_tool_cmd_action(ctx, nodes, "set_wano_config", config=config)


@cli.command("builds-list")
@click.argument("requested_version", type=click.STRING)
@all_nodes_argument
@click.pass_context
def list_builds(ctx, requested_version, nodes):
    """List builds for REQUESTED_VERSION.

    `osrt-pod builds-list <version|master|native-version> <gw|l1|l2|all>`

    Example usage:

    `pod list-builds 4.2.0 gw`

    `pod list-builds master l1`

    `pod list-builds native-5.8.0 l1`
    """
    _lib_tool_cmd_action(ctx, nodes, "list_builds", requested_version=requested_version)


@cli.command("fused")
@all_nodes_argument
@click.pass_context
def fused(ctx, nodes):
    """Checks if pod firmware fuse is burned.

    True - firmware fuse is burned (is locked), False - firmware fuse is not burned (is unlocked).
    """
    _lib_tool_cmd_action(ctx, nodes, "is_fuse_burned")


@cli.command
@all_nodes_argument
@click.pass_context
def boot_partition_switch(ctx, nodes):
    """**IT'S DANGEROUS!** Switch boot partition for specified **NODES** [defaults to all].

    This action is acomplished by power cycling selected nodes 15 times.
    **THIS ACTION CAN ONLY BE PERFORMED 1 TIME, AND PODS CANNOT BE RECOVERED WITHOUT ADDITIONAL WORK!**

    **THIS COMMAND CANNOT BE COMBINED WITH LAB TOOL**
    """
    pods = get_pods_object(nodes)
    for i in range(16):
        click.echo(f"Power cycling nodes {nodes}, iteration {i + 1}")
        results = pods.lib.rpower[0].cycle(device_names=nodes, timeout=10)
        log.debug("Power cycle result: %s. Sleeping 20 seconds before continuing...", results)
        time.sleep(20)


@cli.command
@all_nodes_argument
@click.pass_context
def radio_temperatures_get(ctx, nodes):
    """Get all radio temperatures."""
    _lib_tool_cmd_action(ctx, nodes, "get_radio_temperatures")


for cmd in ["all", "gw", "l1", "l2"]:

    @cli.command(cmd, hidden=True)
    @click.argument("opts", nargs=-1)
    @click.pass_context
    def _legacy(ctx, opts):
        """LEGACY/DO NOT USE!"""
        click.echo(f"Did you mean: osrt pod {' '.join(opts)} {ctx.command.name}?", err=True)
        sys.exit(1)


def get_bash_complete() -> Path:
    """Returns a path to ``pod`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "pod-complete.bash"
