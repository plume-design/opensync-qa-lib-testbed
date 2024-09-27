import os
import sys
import time
import importlib
import traceback
from importlib.metadata import entry_points
from pathlib import Path

from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.opensyncexception import OpenSyncException

from osrt_cli_tools.utils import (
    print_table,
    debug_option,
    prepare_logger,
    complete_testbeds,
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


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@debug_option
@disable_colors_option
@click.pass_context
def cli(ctx, debug, disable_colors):
    """Testbed recovery and information tool."""
    log.debug("Entering testbed tool context")
    ctx.ensure_object(dict)
    if not ctx.obj.get("DEBUG"):
        ctx.obj["DEBUG"] = debug
    if not ctx.obj.get("DISABLE_COLORS"):
        ctx.obj["DISABLE_COLORS"] = disable_colors
    if not is_autocomplete():
        prepare_logger(ctx.obj["DEBUG"])


@cli.command
@click.pass_context
def tools(ctx):
    """List all available testbed tools."""

    rows = []
    for ep in entry_points().select(group="osrt"):
        ep_obj = ep.load()
        ep_module_name, _ = ep.value.split(":")
        ep_module = importlib.import_module(ep_module_name)
        show_tool_help = getattr(ep_module, "__show_tool__", True)
        if show_tool_help:
            short_doc = ""
            tool_docstring = ep_obj.__doc__
            if tool_docstring:
                # do not add help to undocumented tools
                lines = tool_docstring.splitlines()
                for line in lines:
                    if line:
                        short_doc += line + "\n"
                    else:
                        break
                rows.append([ep.name, short_doc.rstrip("\n")])

    if "tb_name" in ctx.obj:
        testbed_name = ctx.obj["tb_name"]
    else:
        testbed_name = os.environ.get("OPENSYNC_TESTBED")
    rows = sorted(rows, key=lambda x: x[0])
    print_table(rows, headers=["tool", "short description"], title=f"Commandline tools available for: {testbed_name}")

    click.secho("Invoke any of the tools above with --help for usage", bold=True)
    if not testbed_name:
        click.secho(
            "Testbed not set. Use 'osrt shell' command to select desired testbed, "
            "or set OPENSYNC_TESTBED environment variable to use all available tools.",
            err=True,
            fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
        )


@cli.command
@click.argument("name", type=click.STRING, default=None, shell_complete=complete_testbeds, required=False)
@click.pass_context
def recover(ctx, name):
    """Recover testbed with **NAME** to its location default state.

    If **NAME** of testbed is not specified, the environment variable OPENSYNC_TESTBED is used to
    determine the current testbed."""
    from lib_testbed.generic.util.logger import log
    from lib_testbed.generic.util.config import load_tb_config

    try:
        from lib.cloud.custbase import CustBase
        from lib.cloud.userbase import UserBase
        from lib.util.tb_recovery import TbRecovery
        from lib_testbed.generic.rpower.rpowerlib import PowerControllerApi
        from lib_testbed.generic.switch.switch_api_resolver import SwitchApiResolver
    except (ModuleNotFoundError, OpenSyncException):
        log.error("Cloud modules are not available, cannot perform recovery")
        print_table(rows=[["Testbed recovery", "Failed"]])
        sys.exit(1)

    from lib_testbed.generic.client import client as _client_factory
    from lib_testbed.generic.pod import pod as _pod_factory

    if not name:
        name = get_testbed_name()
    config = load_tb_config(name, skip_deployment=True)

    log.warning("Restoring testbed and its location to default state")

    # Consider MDU testbeds based on USTB only
    if ("MDU" in config.get("capabilities", [])) and (config["ssh_gateway"].get("location_file")):
        from lib.util.mdutoollib import MduToolLib

        mdu_tool = MduToolLib(config=config)
        ustb_name = config.get_location_name(config)
        log.warning("Moving MDU location back to HomePass")
        mdu_tool.move_to_homepass(cfg_name=ustb_name)
        print_table(rows=[["Testbed recovery", "Successful"]])
        return

    # Clear WANO config that might have been set due to use of mark.wan_connection()
    gw_pod = _pod_factory.Pod().resolve_obj(name="gw", role="gw", config=config, multi_obj=False)
    gw_pod.set_wano_cfg({})
    # Use a (fake) node/test with none of the location, wan_connection, ... marks, so that
    # tb_recovery puts the testbed and its location into a state that is close enough to default.
    admin = CustBase(name="admin", role="admin", config=config)
    user = UserBase(name="user", role="user", conf=config)
    admin.own_markers = user.own_markers = {"session": []}
    admin.all_markers = user.all_markers = []
    admin.ub, user.cb = user, admin
    admin.initialize()
    rpower = PowerControllerApi(config)
    switch = SwitchApiResolver(**{"config": config})
    tb_recovery = TbRecovery(user, rpower, switch, scope="testbed_tool", all_markers=[], own_markers=[])
    tb_recovery.run()

    if config.get("runtime_lte_only_uplink", False):
        log.warning("Restoring uplink connection for GW, after LTE run")
        client_api = _client_factory.Client().resolve_obj(name="host", config=config, nickname="host")
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
    print_table(rows=[["Testbed recovery", "Successful"]])


def wait_for_server_availability(reboot_timeout: int, level: int):
    """Wait for server availability with reboot_timeout (in minutes) and log level."""
    from lib_testbed.generic.util.logger import log
    from osrt_cli_tools.client import get_client_object
    from osrt_cli_tools.utils import log_level

    now = time.time()
    while time.time() < now + 60 * reboot_timeout:
        try:
            srv_obj = get_client_object(clients=["host"])
            with log_level(level):
                response = srv_obj.version()
                if response[0][0] == 0:
                    log.info("Server rebooted, waiting 60 seconds before continuing")
                    time.sleep(60)
                    return
        except Exception:  # intentionally broad
            log.debug("Server has not rebooted yet.")


@cli.command
@click.option("--client-fw-path", default=None, type=click.Path())
@click.option(
    "--client-cfg-restore",
    default="True",
    type=click.Choice(choices=["True", "False"]),
    show_default=True,
    help="Restore clients config file.",
)
@click.option("--client-force", is_flag=True, help="Force client upgrade operation.")
@click.option(
    "--client-version", type=click.STRING, help="Specify client version.", default="stable", show_default=True
)
@click.option(
    "--client-download-locally",
    default="True",
    type=click.Choice(choices=["True", "False"]),
    help="If True download upgrade files to local machine. [Only applicable to Debian-type clients/server]",
    show_default=True,
)
@click.option("--server-fw-path", default=None, type=click.Path())
@click.option(
    "--server-cfg-restore",
    default="True",
    type=click.Choice(choices=["True", "False"]),
    show_default=True,
    help="Restore OSRT server config file.",
)
@click.option("--server-force", is_flag=True, help="Force OSRT server upgrade operation.")
@click.option(
    "--server-version", type=click.STRING, help="Specify OSRT server version.", default="stable", show_default=True
)
@click.option("--skip-waiting", is_flag=True, help="Skip waiting for switch to start up after restoring config.")
@click.option(
    "--reboot-timeout", default=10, type=click.INT, help="Time to wait for reboot [in minutes].", show_default=True
)
@click.option(
    "--mirror-url",
    type=click.STRING,
    default=None,
    help="HTTP address to a mirror with images. Only supported for debian and rpi type clients.",
)
@click.option(
    "--server-download-locally",
    default="True",
    type=click.Choice(choices=["True", "False"]),
    help="If True download upgrade files to local machine. [Only applicable to Debian-type clients/server]",
    show_default=True,
)
@click.pass_context
def upgrade(
    ctx,
    client_fw_path,
    client_cfg_restore,
    client_force,
    client_version,
    client_download_locally,
    server_fw_path,
    server_cfg_restore,
    server_force,
    server_version,
    server_download_locally,
    skip_waiting,
    reboot_timeout,
    mirror_url,
):
    """Upgrades all testbed clients, server and restores switch configuration in one command.

    This command is equivalent to calling the following commands consecutively:
    ```
    osrt rpower cycle all
    osrt server reboot
    # wait for server to start up before continuing
    osrt client upgrade all
    osrt server upgrade
    osrt switch restore-config
    ```
    And then wait for all clients, server, and switch to restore connectivity.
    """
    import logging
    import re
    from lib_testbed.generic.util.logger import log
    from osrt_cli_tools.client import upgrade as upgrade_client
    from osrt_cli_tools.client import process_clients_arg, version as client_version_cmd, get_client_object
    from osrt_cli_tools.server import upgrade as upgrade_server, reboot as reboot_server, version as server_version_cmd
    from osrt_cli_tools.switch import restore_config, get_switch_object
    from osrt_cli_tools.rpower import cycle
    from osrt_cli_tools.utils import log_level, bool_choices_to_bool

    client_cfg_restore = bool_choices_to_bool(client_cfg_restore)
    server_cfg_restore = bool_choices_to_bool(server_cfg_restore)
    client_download_locally = bool_choices_to_bool(client_download_locally)
    server_download_locally = bool_choices_to_bool(server_download_locally)

    level = logging.DEBUG if ctx.obj.get("DEBUG") else logging.CRITICAL
    version_pattern = r"(\d+\.\d+(?:\.|-)\d+)"
    skip_clients = skip_server = False
    if not client_force and client_version in {"latest", "stable"}:
        click.echo("Checking client target versions...", err=True)
        try:
            all_clients_arg = process_clients_arg(ctx=ctx, param="clients", value="all")
            all_clients = get_client_object(clients=all_clients_arg)
            all_target_versions = dict(zip(all_clients_arg, all_clients.get_target_version(version=client_version)))
            all_current_versions = dict(
                zip(all_clients_arg, [re.findall(version_pattern, v[1])[0] for v in all_clients.version()])
            )
            if all_current_versions == all_target_versions:
                click.echo(f"Client versions are already {client_version}", err=True)
                for client in all_current_versions:
                    click.echo(f"Client {client}: \t{all_current_versions[client]}")
                click.echo("Skipping client upgrade. Use the flag --client-force to force clients upgrade.")
                skip_clients = True
        except Exception as err:
            click.echo("Could not establish client versions, will make an attempt to upgrade", err=True)
            log.debug(
                "Tryign to establish client versions resulted with an exception:\n%s",
                "".join(traceback.format_exception(err)),
            )

    if not server_force and server_version in {"latest", "stable"}:
        srv_obj = get_client_object(clients=["host"])
        target_version = srv_obj.get_target_version(version=server_version)
        current_version = re.findall(version_pattern, srv_obj.version()[0][1])[0]
        if target_version == current_version:
            click.echo(
                f"Server version is already {server_version}: {current_version}. Skipping server upgrade. "
                "Use the flag --server-force to force server upgrade.",
                err=True,
            )
            skip_server = True

    if skip_server and skip_clients:
        click.echo("Nothing to upgrade.", err=True)
        sys.exit(0)
    click.echo("Power cycling all testbed devices...", err=True)
    ctx.invoke(cycle, devices="all", timeout=0)
    click.echo("Rebooting server...", err=True)
    ctx.invoke(reboot_server)
    click.echo("Waiting for server to start up...", err=True)
    time.sleep(10)
    wait_for_server_availability(reboot_timeout=reboot_timeout, level=level)
    log.info("Server rebooted successfully")
    if not skip_clients:
        click.echo("Upgrading clients...", err=True)
        ctx.invoke(
            upgrade_client,
            fw_path=client_fw_path,
            restore_cfg=client_cfg_restore,
            force=client_force,
            version=client_version,
            mirror_url=mirror_url,
            clients=process_clients_arg(ctx=ctx, param="clients", value="all"),
            download_locally=client_download_locally,
        )
    if not skip_server:
        click.echo("Upgrading server...", err=True)
        ctx.invoke(
            upgrade_server,
            fw_path=server_fw_path,
            restore_cfg=server_cfg_restore,
            force=server_force,
            version=server_version,
            mirror_url=mirror_url,
            download_locally=server_download_locally,
        )
    time.sleep(10)
    wait_for_server_availability(reboot_timeout=reboot_timeout, level=level)
    click.echo("Restoring switch configuration...", err=True)
    ctx.invoke(restore_config)
    if not skip_waiting:
        click.echo("Checking testbed connectivity...", err=True)
        now = time.time()
        while time.time() < now + 60 * reboot_timeout:
            try:
                with log_level(logging.DEBUG):
                    switch = get_switch_object()
                    resp = switch.version()
                    if resp:
                        break
            except Exception:  # catching broad-exception intentionally
                log.debug("Switch has not yet rebooted")
        else:
            log.error("Did not regain connectivity within %s minutes", reboot_timeout)
        click.echo("Checking client versions.", err=True)
        ctx.invoke(client_version_cmd, clients=process_clients_arg(ctx=ctx, param="clients", value="all"))
        click.echo("Checking server version.", err=True)
        ctx.invoke(server_version_cmd)


def get_bash_complete() -> Path:
    """Returns a path to ``testbed`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "testbed-complete.bash"
