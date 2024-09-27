import sys
from pathlib import Path

import osrt_cli_tools.utils
from lib_testbed.generic.util.logger import log

if osrt_cli_tools.utils.is_autocomplete():
    import click
else:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True


ALL_CLIENT_TYPES = ["wifi", "eth", "bt"]


def _execute_tool_command(ctx, command_, *args, **kwargs):
    """Execute a command on the tool object, pass arguments and print out the result."""
    from osrt_cli_tools.client import _execute_tool_command as _execute_client_tool_command

    return _execute_client_tool_command(ctx, ["host"], command_, *args, show_names=False, **kwargs)


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@osrt_cli_tools.utils.debug_option
@osrt_cli_tools.utils.json_option
@osrt_cli_tools.utils.disable_colors_option
@osrt_cli_tools.utils.dry_run_option
@osrt_cli_tools.utils.timeout_option
@click.pass_context
def cli(ctx, debug, json, disable_colors, dry_run, timeout):
    """OSRT server tool."""
    log.debug("Entering server tool context")
    if not sys.stdout.isatty():
        json = True
    ctx.ensure_object(dict)
    if not ctx.obj.get("DEBUG"):
        ctx.obj["DEBUG"] = debug
    if not ctx.obj.get("JSON"):
        ctx.obj["JSON"] = json
    if not ctx.obj.get("TIMEOUT"):
        ctx.obj["TIMEOUT"] = timeout
    if not ctx.obj.get("DRY_RUN"):
        ctx.obj["DRY_RUN"] = dry_run
    if not ctx.obj.get("DISABLE_COLORS"):
        ctx.obj["DISABLE_COLORS"] = disable_colors
    if not osrt_cli_tools.utils.is_autocomplete():
        osrt_cli_tools.utils.prepare_logger(ctx.obj["DEBUG"])


@cli.command(name="run")
@click.argument("command")
@click.pass_context
def run(ctx, command):
    """Run a command on server."""
    _execute_tool_command(ctx, "run", command=command)


@cli.command
@click.option("--host", is_flag=False, type=click.STRING, help="host to ping.", default=None)
@click.option("--v6", default=False, help="Perform ipv6 check instead of ipv4. (flag)", is_flag=True)
@click.pass_context
def ping(ctx, host, v6):
    """Perform a single ping (ICMP) from server to **HOST**.

    If custom **HOST** is not specified, then it defaults to the OSRT server/host/rpi.
    """
    _execute_tool_command(ctx, "ping", host=host, v6=v6)


@cli.command(name="uptime")
@click.pass_context
def uptime(ctx):
    """Display uptime."""
    return ctx.invoke(run, command="uptime")


@cli.command
@click.option("--short", is_flag=True, help="Display short version.")
@click.pass_context
def version(ctx, short):
    """Display firmware version."""
    _execute_tool_command(ctx, "version", short=short)


@cli.command
@click.pass_context
def ssh(ctx):
    """Open interactive ssh session to OSRT server."""
    from osrt_cli_tools.client import get_client_object

    client_obj = get_client_object(["host"])
    ret = client_obj.lib[0].ssh(timeout=ctx.obj["TIMEOUT"])
    osrt_cli_tools.utils.print_command_output(ctx, {client_obj.lib[0].name: ret})


@cli.command("file-put")
@click.argument("source", type=click.Path())
@click.argument("target", type=click.Path())
@click.pass_context
def put_file(ctx, source, target):
    """Put file or directory on OSRT server using scp."""
    _execute_tool_command(ctx, "put_file", file_name=source, location=target)


@cli.command("file-get")
@click.argument("source", type=click.Path(), nargs=1)
@click.argument("target", type=click.Path(), nargs=1)
@click.pass_context
def get_file(ctx, source, target):
    """Get file or directory from OSRT server to local disk using scp."""
    _execute_tool_command(ctx, "get_file", remote_file=source, location=target, create_dir=False)


@cli.command
@click.pass_context
def reboot(ctx):
    """Reboot OSRT."""
    _execute_tool_command(ctx, "reboot")


@cli.command
@click.option("--fw-path", default=None, type=click.Path())
@click.option(
    "--restore-cfg",
    default="True",
    type=click.Choice(choices=["True", "False"]),
    show_default=True,
    help="Restore config file.",
)
@click.option("--force", is_flag=True, help="Force operation.")
@click.option("--version", type=click.STRING, help="Specify version.", default="stable", show_default=True)
@click.option(
    "--mirror-url",
    type=click.STRING,
    default=None,
    help="HTTP address to a mirror with images. Only supported for rpi type servers.",
)
@click.option(
    "--download-locally",
    default="True",
    type=click.Choice(choices=["True", "False"]),
    help="If True download upgrade files to local machine. [Only Debian-type servers]",
    show_default=True,
)
@click.pass_context
def upgrade(ctx, fw_path, restore_cfg, force, version, download_locally, mirror_url):
    """Upgrade OSRT server with FW from fw_path or download build version from artifactory."""
    restore_cfg = osrt_cli_tools.utils.bool_choices_to_bool(restore_cfg)
    download_locally = osrt_cli_tools.utils.bool_choices_to_bool(download_locally)
    _execute_tool_command(
        ctx,
        "upgrade",
        fw_path=fw_path,
        restore_cfg=restore_cfg,
        force=force,
        version=version,
        mirror_url=mirror_url,
        download_locally=download_locally,
    )


@cli.command("tb-nat-get")
@click.pass_context
def get_tb_nat(ctx):
    """Get NAT mode for the testbed."""
    _execute_tool_command(ctx, "get_tb_nat")


@cli.command("tb-nat-set")
@click.argument("mode", type=click.Choice(choices=["NAT64", "NAT66"]))
@click.pass_context
def set_tb_nat(ctx, mode):
    """Set NAT **MODE** for the testbed."""
    _execute_tool_command(ctx, "set_tb_nat", mode=mode)


@cli.command("dhcp-reservation")
@click.pass_context
def dhcp_reservation(ctx):
    """Create dhcp reservation for testbed devices."""
    _execute_tool_command(ctx, "testbed_dhcp_reservation")


@cli.command("tx-power-limit")
@click.option(
    "--state",
    default="True",
    type=click.Choice(choices=["True", "False"]),
    show_default=True,
    help="Enable or disable tx power limitation",
)
@click.option(
    "--value",
    default=None,
    type=int,
    show_default=False,
    help="Limit tx power to value, in dBm",
)
@click.pass_context
def limit_tx_power(ctx, state, value):
    """Limit Wi-Fi Tx power on the devices in the testbed."""
    state = True if state == "True" else False
    _execute_tool_command(ctx, "limit_tx_power", state=state, value=value)


@cli.command("mqtt-broker-start")
@click.pass_context
def start_mqtt_broker(ctx):
    """Start local mqtt broker on the rpi-server."""
    _execute_tool_command(ctx, "start_local_mqtt_broker")


@cli.command("mqtt-broker-stop")
@click.pass_context
def stop_mqtt_broker(ctx):
    """Stop local mqtt broker on the rpi-server."""
    _execute_tool_command(ctx, "stop_local_mqtt_broker")


@cli.command
@click.option("--last-hours", type=click.INT, show_default=True, default=1)
@click.option("--max-lines-to-print", type=click.INT, show_default=True, default=100)
@click.pass_context
def ssh_login_logs(ctx, last_hours, max_lines_to_print):
    """Get SSH login logs."""
    _execute_tool_command(ctx, "get_ssh_login_logs", last_hours=last_hours, max_lines_to_print=max_lines_to_print)


def get_bash_complete() -> Path:
    """Returns a path to ``server`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "server-complete.bash"
