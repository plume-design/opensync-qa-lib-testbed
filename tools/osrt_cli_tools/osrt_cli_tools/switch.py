import sys
import fnmatch
from pathlib import Path


from lib_testbed.generic import WAN_VLAN
from lib_testbed.generic.util.logger import log
from osrt_cli_tools import tb_config_parser
from osrt_cli_tools.pod import single_node_argument, all_nodes_argument, process_nodes_arg, complete_all_pods
from osrt_cli_tools.client import single_eth_client_argument
from osrt_cli_tools.utils import (
    json_option,
    debug_option,
    print_command_output,
    bool_choices_to_bool,
    prepare_logger,
    get_testbed_name,
    is_autocomplete,
    disable_colors_option,
)

if is_autocomplete():
    import click
else:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True


def get_switch_object(config: dict = None):
    """Lazy load SwitchController."""
    from lib_testbed.generic.switch.generic.switch_tool_generic import SwitchToolGeneric
    from lib_testbed.generic.util.config import load_tb_config

    if not config:
        testbed_name = get_testbed_name()
        config = load_tb_config(testbed_name, skip_deployment=True)
    return SwitchToolGeneric(config=config)


def process_ports_arg(ctx, param, value):
    """Helper function to process ports."""
    from lib_testbed.generic.util.config import load_tb_config

    testbed_name = get_testbed_name()
    config = load_tb_config(testbed_name, skip_deployment=True)
    names = _get_all_port_names(config)
    value = value.lstrip(",").rstrip(",").split(",")
    if any([v in ["all", "*"] for v in value]):
        return names
    new_ports = []
    for val in value:
        if val in names:
            new_ports.append(val)
        elif "*" in val or "?" in val or "[" in val:
            if matched_list := fnmatch.filter(names, val):
                new_ports.extend(matched_list)
    if not new_ports:
        return names
    return new_ports


def complete_port_names(ctx, param, incomplete):
    """Autocomplete pod names as stored in config file/not matching all."""
    testbed_name = get_testbed_name()
    config = tb_config_parser.load_config(testbed_name)
    if config:
        ports = _get_all_port_names(config)
        ports.append("all")
        return [p for p in ports if p.startswith(incomplete)]
    return incomplete


def _get_all_port_names(config):
    """Return names of all network switch ports in testbed config"""
    return [port["name"] for switch in config["Switch"] for port in switch["alias"]]


all_ports_optional_argument = click.argument(
    "ports", default="all", callback=process_ports_arg, shell_complete=complete_port_names, required=False
)
all_ports_argument = click.argument(
    "ports", default="all", callback=process_ports_arg, shell_complete=complete_port_names, required=True
)


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@debug_option
@json_option
@disable_colors_option
@click.pass_context
def cli(ctx, debug, json, disable_colors):
    """Network switch control tool."""
    log.debug("Entering switch tool context")
    if not sys.stdout.isatty():
        json = True
    ctx.ensure_object(dict)
    if not ctx.obj.get("DEBUG"):
        ctx.obj["DEBUG"] = debug
    if not ctx.obj.get("JSON"):
        ctx.obj["JSON"] = json
    if not ctx.obj.get("DISABLE_COLORS"):
        ctx.obj["DISABLE_COLORS"] = disable_colors
    if not is_autocomplete():
        prepare_logger(ctx.obj["DEBUG"])


def _execute_switch_command(ctx, command: str, *args, **kwargs):
    """Wrapper for executing and printing out switch command result."""
    switch = get_switch_object()
    meth = getattr(switch, command)
    result = meth(*args, **kwargs)
    print_command_output(ctx, result)


@cli.command
@click.pass_context
def version(ctx):
    """Get config version."""
    _execute_switch_command(ctx, "version")


@cli.command
@click.pass_context
def model(ctx):
    """Get switch model."""
    _execute_switch_command(ctx, "model")


@cli.command("system-info")
@click.pass_context
def system_info(ctx):
    """Get switch information."""
    _execute_switch_command(ctx, "system_info")


@cli.command("config-restore")
@click.pass_context
def restore_config(ctx):
    """Restore switch config.

    Note that this operation requires restarting of the switch, which takes some extra
    time after the command exits.
    """
    _execute_switch_command(ctx, "restore_config")


@cli.command("list")
@click.pass_context
def list_(ctx):
    """List all ports configured.

    The output format is kept for backwards compatibility.
    """
    switch = get_switch_object()
    ret = switch.switch_interface_list()
    click.echo("\n".join(ret[1]))


@cli.command("pvid-list")
@click.pass_context
def pvid_list(ctx):
    """List of all PVIDs."""
    _execute_switch_command(ctx, "pvid_list")


@cli.command("vlan-list")
@click.pass_context
def vlan_list(ctx):
    """List of all VLANs."""
    _execute_switch_command(ctx, "vlan_list")


@cli.command
@all_ports_optional_argument
@click.pass_context
def status(ctx, ports):
    """Get interface status (enable/disable).

    Optionally provide a list of **PORTS** to query, default=all.
    """
    _execute_switch_command(ctx, "switch_status", port_names=ports)


@cli.command
@all_ports_optional_argument
@click.pass_context
def info(ctx, ports):
    """Get info about VLANs."""
    _execute_switch_command(ctx, "info", port_names=ports)


@cli.command
@all_ports_optional_argument
@click.pass_context
def up(ctx, ports):
    """Turn **PORTS** up."""
    _execute_switch_command(ctx, "interface_up", port_names=ports)


@cli.command
@all_ports_optional_argument
@click.pass_context
def down(ctx, ports):
    """Shut **PORTS** down."""
    _execute_switch_command(ctx, "interface_down", port_names=ports)


@cli.command("vlan-set")
@click.argument("vlan", type=click.INT)
@click.argument("vlan_type", type=click.Choice(choices=["tagged", "untagged"]))
@all_ports_argument
@click.pass_context
def vlan_set(ctx, vlan, vlan_type, ports):
    """Set VLAN to **VLAN_TYPE** for selected **PORTS**."""
    _execute_switch_command(ctx, "vlan_set", port_names=ports, vlan=vlan, vlan_type=vlan_type)


@cli.command("vlan-delete")
@click.argument("vlan", type=click.INT)
@all_ports_optional_argument
@click.pass_context
def vlan_delete(ctx, vlan, ports):
    """Delete **VLAN** for **PORTS**."""
    _execute_switch_command(ctx, "vlan_remove", port_names=ports, vlan=vlan)


@cli.command("ip-type-set")
@click.argument("addressing", type=click.Choice(choices=[vlan.lower() for vlan in WAN_VLAN.__members__.keys()]))
@click.argument("nodes", callback=process_nodes_arg, shell_complete=complete_all_pods, required=True)
@click.pass_context
def set_ip_type(ctx, nodes, addressing):
    """Set connection IP type **ADDRESSING** for **NODES**.

    Example: `switch ip-type-set ipv4 gw`."""
    for node in nodes:
        _execute_switch_command(ctx, "set_connection_ip_type", pod_name=node, ip_type=addressing)


@cli.command("client-connect")
@single_eth_client_argument
@single_node_argument
@click.argument("port", default=None, type=click.STRING, required=False)
@click.pass_context
def connect_client(ctx, client, node, port):
    """Connect Ethernet **CLIENT** to **NODE**.

    If PORT is not specified, then a random one is picked."""
    _execute_switch_command(ctx, "connect_eth_client_tool", node, client, port)


@cli.command("client-disconnect")
@single_eth_client_argument
@single_node_argument
@click.option(
    "--disable-unused-ports",
    type=click.Choice(choices=["True", "False"]),
    default="True",
    show_default=True,
    help="Disable unused switch ports.",
)
@click.pass_context
def disconnect_client(ctx, client, node, disable_unused_ports):
    """Disconnect Ethernet **CLIENT** from **NODE**."""
    disable_no_used_ports = bool_choices_to_bool(disable_unused_ports)
    _execute_switch_command(
        ctx, "disconnect_eth_client", pod_name=node, client_name=client, disable_no_used_ports=disable_no_used_ports
    )


@cli.command
@all_nodes_argument
@click.option("-f", "--force", is_flag=True, default=False, help="Force operation.")
@click.option(
    "--set-default-wan",
    is_flag=True,
    default=False,
    help="Set default wan to port which is marked as uplink in cfg - applies only to devices with more than one port.",
)
@click.pass_context
def recovery(ctx, nodes, force, set_default_wan):
    """Set default configuration on switch for **NODES** (default=all)."""
    _execute_switch_command(ctx, "recovery_switch_cfg", pod_name=nodes, force=force, set_default_wan=set_default_wan)


@cli.command("isolation-disable")
@click.pass_context
def disable_isolation(ctx):
    """Disable port isolation on all ports."""
    _execute_switch_command(ctx, "disable_port_isolations")


@cli.command("isolation-enable")
@click.pass_context
def enable_isolation(ctx):
    """Enable port isolations on all ports."""
    _execute_switch_command(ctx, "enable_port_isolations")


@cli.command("port-isolation-get")
@all_ports_optional_argument
@click.pass_context
def get_port_isolation(ctx, ports):
    """Get port isolations."""
    _execute_switch_command(ctx, "get_port_isolations", ports)


@cli.command("link-status-get")
@all_ports_optional_argument
@click.pass_context
def get_link_status(ctx, ports):
    """Get PORTS link status."""
    _execute_switch_command(ctx, "get_link_status", ports)


@cli.command("link-speed-set")
@click.pass_context
@click.argument("speed", type=click.Choice(choices=["10", "100", "1000", "2500", "auto"]))
@click.argument("port", default=None, type=click.STRING)
@click.option(
    "--duplex",
    type=click.Choice(choices=["half", "full", "auto"]),
    default=None,
    help="Configure the Duplex Mode for an Ethernet port.",
)
def set_link_speed(ctx, speed, port, duplex):
    """Set PORT link speed limit."""
    _execute_switch_command(ctx, "set_link_speed", port, speed)
    if duplex:
        _execute_switch_command(ctx, "set_port_duplex", port, duplex)


@cli.command("daisy-chain-set")
@click.argument("connect_to_device", default=None, type=click.STRING)
@click.argument("target_device", default=None, type=click.STRING)
@click.pass_context
def set_daisy_chain(ctx, connect_to_device, target_device):
    """Set daisy chain connection between two pods **CONNECT_TO_DEVICE** <--eth--> **TARGET_DEVICE**"""
    _execute_switch_command(ctx, "set_daisy_chain_connection", target_device, connect_to_device)


def get_bash_complete() -> Path:
    """Returns a path to ``switch`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "switch-complete.bash"
