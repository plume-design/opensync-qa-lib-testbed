import sys
import fnmatch
import traceback
from functools import partial
from typing import Literal
from pathlib import Path

import osrt_cli_tools.utils
from lib_testbed.generic.util.logger import log

if osrt_cli_tools.utils.is_autocomplete():
    # speed up auto-complete
    import click

    def threaded(f):
        return f

else:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True

    from lib_testbed.generic.util.common import threaded

from osrt_cli_tools import tb_config_parser


ALL_CLIENT_TYPES = ["wifi", "eth", "bt"]


def get_client_object(clients, tb_name: str = None, skip_deployment: bool = True):
    """Lazy load client tool object."""
    from lib_testbed.generic.client.client import Clients
    from lib_testbed.generic.util.config import load_tb_config

    testbed_name = osrt_cli_tools.utils.get_testbed_name(tb_name)
    config = load_tb_config(testbed_name, skip_deployment=skip_deployment)
    kwargs = {"config": config, "multi_obj": True}
    if clients:
        kwargs["nicknames"] = clients
    kwargs["type"] = "linux|rpi|pod|hydra|pp403z|pp603x|windows|debian"  # TODO: remove once MacOS support is ready
    clients_obj = Clients(**kwargs)
    clients_api = clients_obj.resolve_obj(**kwargs)
    return clients_api.lib.tool


def _filter_existing_clients(all_clients: list[dict]) -> list[dict]:
    """Utility function which filters out all clients as parsed by loading config with only wifi+eth+bluetooth types,
    getting rid of iptv_host, etc."""
    clients = []
    for client in all_clients:
        for c_type in ALL_CLIENT_TYPES:
            if client.get(c_type, False):
                clients.append(client)
    return clients


def complete_defined_clients(ctx, param, incomplete, client_type: Literal["wifi", "eth", "bt"] = None):
    """Autocomplete client names as stored in config file/not matching all.

    This callback can filter out client type. If no type provided then filtering is not performed.
    """
    testbed_name = osrt_cli_tools.utils.get_testbed_name()
    config = tb_config_parser.load_config(testbed_name)
    if config:
        all_clients = [client for client in config["Clients"]]
        clients = _filter_existing_clients(all_clients)

        if not client_type:
            return [c["name"] for c in clients if c["name"].startswith(incomplete)]
        return [c["name"] for c in clients if c.get(client_type, False) and c["name"].startswith(incomplete)]
    return incomplete


def complete_pod_or_port(ctx, param, incomplete):
    """Complete pod names and ports aliases as defined in testbed config."""
    testbed_name = osrt_cli_tools.utils.get_testbed_name()
    config = tb_config_parser.load_config(testbed_name)
    pods = [pod["name"] for pod in config["Nodes"]]
    ports = [port["name"] for port in config["Switch"][0].get("alias", [])]
    all_options = pods + ports
    return [opt for opt in all_options if opt.startswith(incomplete)]


def complete_all_clients(ctx, param, incomplete, client_type: Literal["wifi", "eth", "bt"] = None) -> list[str]:
    """Complete all clients callback, including filtering by client type."""
    testbed_name = osrt_cli_tools.utils.get_testbed_name()
    config = tb_config_parser.load_config(testbed_name)
    if config:
        all_clients = [client for client in config["Clients"]]
    else:
        return []
    clients = _filter_existing_clients(all_clients)
    if client_type:
        names = [client["name"] for client in clients if client.get(client_type, False)] + [client_type]
    else:
        names = ALL_CLIENT_TYPES + ["all"] + [client["name"] for client in clients]
    return [c for c in names if c.startswith(incomplete)]


def _process_clients(tb_name: str, value: str, client_type: Literal["wifi", "eth", "bt"] = None) -> list[str]:
    """Actually process clients argument. Returns a list of clients matching value for given client type
    for the specified testbed name.
    """
    if osrt_cli_tools.utils.is_autocomplete():
        config = tb_config_parser.load_config(tb_name)
    else:
        from lib_testbed.generic.util.config import load_tb_config

        config = load_tb_config(tb_name, skip_deployment=True)
    clients = [
        client
        for client in config["Clients"]
        if client.get("wifi", False) or client.get("eth", False) or client.get("bt", False)
    ]
    names = [client["name"] for client in clients]
    value = value.lstrip(",").rstrip(",").split(",")
    if any([v in ["all", "*"] for v in value]):
        if client_type:
            return [c["name"] for c in clients if c.get(client_type, False)]
        return [c["name"] for c in clients]
    new_clients = []
    for ctype in ALL_CLIENT_TYPES:
        if any([v == ctype for v in value]):
            new_clients.extend([c["name"] for c in clients if c.get(ctype, False)])
    for val in value:
        if val in names:
            new_clients.append(val)
        elif "*" in val or "?" in val or "[" in val:
            if matched_list := fnmatch.filter(names, val):
                new_clients.extend(matched_list)
    if not new_clients:
        if client_type:
            return [c["name"] for c in clients if c.get(client_type, False) and c["name"] in names]
        return names
    if client_type:
        return [c["name"] for c in clients if c.get(client_type, False) and c["name"] in new_clients]
    return new_clients


def process_clients_arg(ctx, param, value, client_type: Literal["wifi", "eth", "bt"] = None) -> list[str] | str:
    """Helper function to process clients, with sorting by type. Majority of the logic is delegated
    the :py:func:`_process_clients()` function actually filling out the clients list.
    If testbed name cannot be determined, return just the value as-is for processing at a later time.
    """
    testbed_name = osrt_cli_tools.utils.get_testbed_name(no_tb_ok=True)
    if not testbed_name:
        # when no testbed is available at the time of this callback - delay clients processing
        return value
    return _process_clients(tb_name=testbed_name, value=value, client_type=client_type)


single_client_argument = click.argument("client", shell_complete=complete_defined_clients, required=True)
single_wifi_client_argument = click.argument(
    "client", shell_complete=partial(complete_defined_clients, client_type="wifi"), required=True
)
single_eth_client_argument = click.argument(
    "client", shell_complete=partial(complete_defined_clients, client_type="eth"), required=True
)
all_clients_argument = click.argument(
    "clients", default="all", callback=process_clients_arg, shell_complete=complete_all_clients, required=False
)
all_wifi_clients_argument = click.argument(
    "clients",
    default="all",
    callback=partial(process_clients_arg, client_type="wifi"),
    shell_complete=partial(complete_all_clients, client_type="wifi"),
    required=False,
)
all_eth_clients_argument = click.argument(
    "clients",
    default="all",
    callback=partial(process_clients_arg, client_type="eth"),
    shell_complete=partial(complete_all_clients, client_type="eth"),
    required=False,
)
ipv4_option = click.option(
    "--ipv4", type=click.Choice(choices=["True", "False"]), default="True", show_default=True, help="Get IPv4 address."
)
ipv6_option = click.option(
    "--ipv6",
    type=click.Choice(choices=["False", "stateful", "stateless", "slaac"]),
    default="False",
    show_default=True,
    help="IPv6 addressing.",
)
skip_ns_option = click.option("--skip-ns", is_flag=True, help="Skip network namespace.", default=False)


def _ip_addressing_params_to_flags(ipv4: str, ipv6: str) -> tuple[bool, bool, bool, bool]:
    """Based on arguments return the values of dhclient, ipv4, ipv6 and ipv6_stateless in a tuple
    as expected by connect(), eth_connect() or start_dhclient() API calls to client."""
    #                  | --ipv4=True          | --ipv4=False
    # -----------------+----------------------+---------------------
    # --ipv6=False     | dhclient=True        | dhclient=False
    #                  | ipv4=True            | ipv4=False
    #                  | ipv6=False           | ipv6=False
    #                  | ipv6_stateless=False | ipv6_stateless=False
    # -----------------+----------------------+---------------------
    # --ipv6=stateful  | dhclient=True        | dhclient=True
    #                  | ipv4=True            | ipv4=False
    #                  | ipv6=True            | ipv6=True
    #                  | ipv6_stateless=False | ipv6_stateless=False
    # -----------------+----------------------+---------------------
    # --ipv6=stateless | dhclient=True        | dhclient=True
    #                  | ipv4=True            | ipv4=False
    #                  | ipv6=True            | ipv6=True
    #                  | ipv6_stateless=True  | ipv6_stateless=True
    # -----------------+----------------------+---------------------
    # --ipv6=slaac     | dhclient=True        | dhclient=False
    #                  | ipv4=True            | ipv4=False
    # (same as         | ipv6=False           | ipv6=False
    # --ipv6=False)    | ipv6_stateless=False | ipv6_stateless=False
    ipv4 = osrt_cli_tools.utils.bool_choices_to_bool(ipv4)
    match ipv6:
        case "False" | "slaac":
            if ipv4:
                return True, True, False, False
            return False, False, False, False
        case "stateful":
            if ipv4:
                return True, True, True, False
            return True, False, True, False
        case "stateless":
            if ipv4:
                return True, True, True, True
            return True, False, True, True


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@osrt_cli_tools.utils.debug_option
@osrt_cli_tools.utils.json_option
@osrt_cli_tools.utils.disable_colors_option
@osrt_cli_tools.utils.dry_run_option
@osrt_cli_tools.utils.timeout_option
@click.pass_context
def cli(ctx, debug, json, disable_colors, dry_run, timeout):
    """OSRT client tool: manage, connect and disconnect testbed clients.

    **CLIENTS** is the client/clients to run the command against. Can be one of the following:
    [<client_name>[,...] | all | wifi | eth | bt ].
    All commands are executed against all available clients by default. Some commands only
    get executed on given type of clients, e.g. eth-connect is only executed on Ethernet clients.
    Additionally, **CLIENTS** can be only filtered set of clients, e.g. `osrt-client run uptime wifi,bt`
    will limit the command to be executed on all Wifi and Bluetooth clients, and not on Ethernet clients.

    Some commands require a single **CLIENT** name to be provided, e.g. interactive ssh
    session can only be opened against a single client: `osrt-client ssh w1`.
    """
    log.debug("Entering client tool context")
    ctx.ensure_object(dict)
    if not sys.stdout.isatty():
        json = True
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
        # this saves a lot of time - skip logger initialization in autocomplete
        osrt_cli_tools.utils.prepare_logger(ctx.obj["DEBUG"])


@cli.command(name="list")
@all_clients_argument
@click.pass_context
def list_(ctx, clients):
    """List all clients."""
    testbed_name = osrt_cli_tools.utils.get_testbed_name()
    clients_cfg = tb_config_parser.load_config(testbed_name)["Clients"]
    for client in clients_cfg:
        if client["name"] in clients:
            click.echo(client["name"])


@threaded
def _reserve_and_execute_against_tb(
    ctx, tb_name: str, clients: str | list[str], command_: str, *args, show_names: bool = True, **kwargs
):
    """Reserve and execute task a single command against a testbed - task."""
    from lib_testbed.generic.util.logger import log
    from osrt_cli_tools import reserve

    if not isinstance(clients, list):
        clients = _process_clients(tb_name=tb_name, value=clients)

    reservation_obj = reserve.get_reserve_object(tb_name, json=ctx.obj["JSON"])
    dry_run, skip_reservation = ctx.obj["DRY_RUN"], ctx.obj["SKIP_RESERVATION"]
    results, reservation_status, reserved = None, None, True
    if not skip_reservation:
        if not dry_run:
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
            click.secho(f"DRY-RUN: Reserving testbed {tb_name}")
    else:
        click.secho(
            f"Skipping reservation for testbed {tb_name}",
            fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
            err=True,
        )
    if reserved:
        try:
            if not dry_run:
                log.info("Testbed %s reserved succesfully", tb_name)
                log.debug("Reservation status: %s", reservation_status)
                if command_ != "start_simulate_client":
                    clients_obj = get_client_object(clients, tb_name)
                else:
                    clients_obj = get_client_object(clients, tb_name, skip_deployment=False)
                commands_without_timeout_arg = [
                    "info",
                    "upgrade",
                    "get_clients_to_simulate",
                    "start_simulate_client",
                    "mocha_enable",
                    "mocha_disable",
                    "testbed_dhcp_reservation",
                ]
                if "timeout" not in kwargs and command_ not in commands_without_timeout_arg:
                    kwargs["timeout"] = ctx.obj["TIMEOUT"]
                meth = getattr(clients_obj, command_)
                log.info("Executing command against testbed %s [args=%s, kwargs=%s]", command_, args, kwargs)
                res = meth(*args, **kwargs)
                results = {}
                for i, name in enumerate([c.name for c in clients_obj.lib]):
                    log.debug("Command results for client %s : %s", name, res[i])
                    results[name] = res[i]
            else:
                click.secho(
                    f"DRY-RUN: executing command {command_} with {args} {kwargs} on testbed {tb_name}", bold=True
                )
        finally:
            if not skip_reservation and reserved:
                if not dry_run:
                    log.info("Unreserving testbed %s", tb_name)
                    unreserve_status = reservation_obj.unreserve()
                    log.debug("Unreserve status: %s", unreserve_status)
                else:
                    click.secho(f"DRY-RUN: Unreserving testbed {tb_name}")
            return tb_name, results
    return tb_name, {}


def _execute_tool_command_parallel(ctx, clients: str | list[str], command_: str, *args, show_names=True, **kwargs):
    """Schedule tasks for each testbed and gather results."""
    from lib_testbed.generic.util.logger import log

    testbeds = ctx.obj.get("TESTBEDS")
    tb_tasks = []
    results = []
    for tb_name in testbeds:
        log.info("Starting work on testbed %s", tb_name)
        tb_tasks.append(
            _reserve_and_execute_against_tb(
                ctx=ctx, tb_name=tb_name, clients=clients, command_=command_, *args, show_names=show_names, **kwargs
            )
        )
    for task in tb_tasks:
        try:
            results.append(task.result())
        except Exception as e:
            results.append(["EXECUTION ERROR", {"CLIENTS": [1, "", "".join(traceback.format_exception(e))]}])
    if ctx.obj.get("JSON", False):
        click.echo("[")
    for tb_name, result in results[:-1]:
        osrt_cli_tools.utils.print_command_output(ctx, output=result, show_names=show_names, title=tb_name)
        if ctx.obj.get("JSON", False):
            click.echo(",")
    # the last element must not end with a comma to get a valid json, so we iterate over [:-1] first, and only then
    # print out the last remaining element without the trailing comma:
    osrt_cli_tools.utils.print_command_output(ctx, output=results[-1][1], show_names=show_names, title=results[-1][0])
    if ctx.obj.get("JSON", False):
        click.echo("]")


def _execute_tool_command(ctx, clients, command_: str, *args, show_names: bool = True, **kwargs):
    """Execute a command on the tool object, pass arguments and print out the result."""
    if ctx.obj.get("TESTBEDS"):
        _execute_tool_command_parallel(
            ctx=ctx, clients=clients, command_=command_, *args, show_names=show_names, **kwargs
        )
    else:
        if command_ != "start_simulate_client":
            clients_obj = get_client_object(clients)
        else:
            clients_obj = get_client_object(clients, skip_deployment=False)
        commands_without_timeout_arg = [
            "info",
            "upgrade",
            "get_clients_to_simulate",
            "start_simulate_client",
            "mocha_enable",
            "mocha_disable",
            "testbed_dhcp_reservation",
        ]
        if "timeout" not in kwargs and command_ not in commands_without_timeout_arg:
            kwargs["timeout"] = ctx.obj.get("TIMEOUT", 60)
        meth = getattr(clients_obj, command_)
        if not ctx.obj.get("DRY_RUN"):
            try:
                res = meth(*args, **kwargs)
            except Exception as err:
                log.debug("Encountered an error executing client command: %s", "".join(traceback.format_exception(err)))
                try:
                    if isinstance(err.message, list):
                        res = [[1, "", exc] for exc in err.message]
                    else:
                        res = [1, "", err]
                except AttributeError:
                    res = [[1, "", err]] * len(clients_obj.lib)
            results = {}
            for i, name in enumerate([c.name for c in clients_obj.lib]):
                results[name] = res[i]
            osrt_cli_tools.utils.print_command_output(ctx, results, show_names=show_names)
        else:
            click.secho(f"DRY-RUN: Executing client command {command_} with {args}, {kwargs}", bold=True)


@cli.command(name="run")
@click.argument("command")
@all_clients_argument
@click.pass_context
def run(ctx, command, clients):
    """Run a command on **CLIENTS**."""
    _execute_tool_command(ctx, clients, "run", command=command)


@cli.command
@all_clients_argument
@click.option("--host", is_flag=False, type=click.STRING, help="host to ping.", default=None)
@click.option("--v6", default=False, help="Perform ipv6 check instead of ipv4. (flag)", is_flag=True)
@click.pass_context
def ping(ctx, clients, host, v6):
    """Perform a single ping (ICMP) from **CLIENTS** to **HOST**.

    If custom **HOST** is not specified, then it defaults to the OSRT server/host/rpi.
    """
    _execute_tool_command(ctx, clients, "ping", host=host, v6=v6)


@cli.command("ping-check")
@click.option(
    "--ipaddr",
    default="",
    help="The ip address to use for checking connectivity. The default for ipv4 is 8.8.8.8 and google.com for ipv6.",
)
@click.option("--count", default=1, show_default=True, help="Number of ICMP requests to perform.")
@click.option("--fqdn-check", default=False, help="Perform fqdn check. (flag)", is_flag=True)
@click.option("--v6", default=False, help="Perform ipv6 check instead of ipv4. (flag)", is_flag=True)
@all_clients_argument
@click.pass_context
def ping_check(ctx, ipaddr, count, fqdn_check, v6, clients):
    """Check **CLIENTS** connectivity (ICMP)."""
    _execute_tool_command(ctx, clients, "ping_check", ipaddr=ipaddr, count=count, fqdn_check=fqdn_check, v6=v6)


@cli.command(name="uptime")
@all_clients_argument
@click.pass_context
def uptime(ctx, clients):
    """Display **CLIENTS** uptime."""
    return ctx.invoke(run, command="uptime", clients=clients)


@cli.command
@all_clients_argument
@click.option("--short", is_flag=True, help="Display short version.")
@click.pass_context
def version(ctx, short, clients):
    """Display **CLIENTS** firmware version."""
    _execute_tool_command(ctx, clients, "version", short=short)


@cli.command
@skip_ns_option
@single_client_argument
@click.pass_context
def ssh(ctx, skip_ns, client):
    """Open interactive ssh session to **CLIENT**.

    Note that this command opens an interactive SSH session, and can only be executed against a single client at a time.
    """
    client_obj = get_client_object([client])
    ret = client_obj.lib[0].ssh(timeout=ctx.obj["TIMEOUT"], skip_ns=skip_ns)
    osrt_cli_tools.utils.print_command_output(ctx, {client_obj.lib[0].name: ret})


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
@all_clients_argument
@click.pass_context
def file_put(ctx, timeout, source, target, clients):
    """Put file or directory on **CLIENTS** using scp."""
    ctx.obj["TIMEOUT"] = timeout
    _execute_tool_command(ctx, clients, "put_file", file_name=source, location=target)


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
@all_clients_argument
@click.pass_context
def file_get(ctx, timeout, source, target, clients):
    """Get file or directory from **CLIENTS** to local disk using scp."""
    ctx.obj["TIMEOUT"] = timeout
    _execute_tool_command(ctx, clients, "get_file", remote_file=source, location=target, create_dir=False)


@cli.command
@all_wifi_clients_argument
@click.option("--ifname", is_flag=False, default="", type=click.STRING, help="Provide interface name.")
@click.option("--params", is_flag=False, default="", type=click.STRING, help="Custom arguments for `iw scan` command.")
@click.option("--flush", is_flag=True, default=False, help="Add for flush scan.")
@click.pass_context
def scan(ctx, clients, ifname, params, flush):
    """Trigger scan on **CLIENTS**."""
    _execute_tool_command(ctx, clients, "scan", ifname=ifname, params=params, flush=flush)


@cli.command
@all_wifi_clients_argument
@click.option("--ssid", is_flag=False, default=None, type=click.STRING, help="Specify custom ssid.")
@click.option("--psk", is_flag=False, default=None, type=click.STRING, help="Specify custom psk.")
@click.option("--bssid", is_flag=False, default=None, type=click.STRING, help="Custom bssid.")
@click.option(
    "--country", is_flag=False, type=click.STRING, default="US", show_default=True, help="client country code."
)
@click.option(
    "--key-mgmt",
    type=click.STRING,
    help="wpa_supplicant key management. Possible one or more comma-separated from the following: "
    "WPA-PSK, WPA-PSK-SHA256, WPA-EAP, WPA-EAP-SHA256, WPA-EAP-SUITE-B, WPA-EAP-SUITE-B-192, WPA-NONE,"
    "FT-PSK, FT-EAP, FT-SAE, FT-EAP-SHA384, FT-FILS-SHA256, FT-FILS-SHA384, FILS-SHA256, FILS-SHA384, SAE, "
    "IEEE8021X, OSEN, OWE, DPP, or NONE for open network. Default value is in the config under the "
    "`runtime_wpa_mode` key.",
    default=None,
)
@ipv4_option
@ipv6_option
@click.option(
    "--wps",
    type=click.Choice(choices=["True", "False"]),
    default="False",
    show_default=True,
    help="Connect using WPS-PBC.",
)
@click.option(
    "--eap", type=click.STRING, default=None, help="Enterprise authentication method (e.g. PEAP, TTLS, PWD, ...)."
)
@click.option("--identity", type=click.STRING, default=None, help="User name or id for EAP authentication.")
@click.option("--password", type=click.STRING, default=None, help="Password used for EAP authentication.")
@click.option("--global-params", type=click.STRING, default=None, help="Extra wpa_supplicant config global parameters.")
@click.option("--net-params", type=click.STRING, default=None, help="Extra wpa_supplicant config network parameters.")
@click.option(
    "--node-name", type=click.STRING, default=None, help="Testbed node name to associate with (requires cloud access)."
)
@click.option(
    "--node-band",
    type=click.Choice(choices=["2.4G", "5G", "5GL", "5GU", "6G"]),
    default=None,
    help="Testbed node band to associate with (requires cloud access).",
)
@skip_ns_option
@click.pass_context
def connect(
    ctx,
    ssid,
    psk,
    bssid,
    country,
    key_mgmt,
    ipv4,
    ipv6,
    wps,
    eap,
    global_params,
    net_params,
    identity,
    password,
    node_name,
    node_band,
    skip_ns,
    clients,
):
    """Connect WiFi **CLIENTS**.

    By default **CLIENTS** will be connected to the testbed default ssid as specified
    in the config file.

    Note that the tool global --timeout option can be used with connect too.

    Example: `osrt client connect --bssid=86:9f:07:00:d1:45 --ip-v4=False --ipv6=stateful w2`.
    """
    wps = osrt_cli_tools.utils.bool_choices_to_bool(wps)

    dhclient, ipv4, ipv6, ipv6_stateless = _ip_addressing_params_to_flags(ipv4, ipv6)

    _execute_tool_command(
        ctx,
        clients,
        "connect",
        ssid=ssid,
        psk=psk,
        bssid=bssid,
        key_mgmt=key_mgmt,
        dhclient=dhclient,
        country=country,
        ipv4=ipv4,
        ipv6=ipv6,
        ipv6_stateless=ipv6_stateless,
        wps=wps,
        eap=eap,
        global_params=global_params,
        net_params=net_params,
        identity=identity,
        password=password,
        node_name=node_name,
        node_band=node_band,
        skip_ns=skip_ns,
    )


@cli.command
@all_wifi_clients_argument
@click.option("--ifname", type=click.STRING, default=None, help="Interface name.")
@click.option("--clear-dhcp", is_flag=True, default=False, help="Clear dhcp cache and configuration files.")
@skip_ns_option
@click.pass_context
def disconnect(ctx, ifname, clear_dhcp, skip_ns, clients):
    """Disconnect WiFi **CLIENTS**.

    Kills wpa_supplicant and dhclient (if exists) based on the pid file in name.
    """
    _execute_tool_command(ctx, clients, "disconnect", ifname=ifname, clear_dhcp=clear_dhcp, skip_ns=skip_ns)


@cli.command("eth-connect")
@click.argument("pod_or_port", type=click.STRING, shell_complete=complete_pod_or_port)
@single_eth_client_argument
@click.option("--ifname", type=click.STRING, default=None, help="Interface name.")
@ipv4_option
@ipv6_option
@click.pass_context
def eth_connect(ctx, pod_or_port, client, ifname, ipv4, ipv6):
    """Connect Ethernet **CLIENT** to specified **POD_OR_PORT**."""
    dhclient, ipv4, ipv6, ipv6_stateless = _ip_addressing_params_to_flags(ipv4, ipv6)
    _execute_tool_command(
        ctx,
        [client],
        "eth_connect",
        pod_or_port=pod_or_port,
        ifname=ifname,
        dhclient=dhclient,
        ipv4=ipv4,
        ipv6=ipv6,
        ipv6_stateless=ipv6_stateless,
    )


@cli.command("eth-disconnect")
@all_eth_clients_argument
@click.option("--ifname", type=click.STRING, default=None, help="Interface name.")
@click.option(
    "--disable-unused-ports",
    type=click.Choice(choices=["True", "False"]),
    default="True",
    show_default=True,
    help="Disable unused switch ports.",
)
@click.pass_context
def eth_disconnect(ctx, clients, disable_unused_ports, ifname):
    """Disconnect **CLIENT** from all Ethernet pod ports."""
    disable_unused_ports = osrt_cli_tools.utils.bool_choices_to_bool(disable_unused_ports)
    _execute_tool_command(ctx, clients, "eth_disconnect", ifname=ifname, disable_unused_ports=disable_unused_ports)


@cli.command
@all_wifi_clients_argument
@click.pass_context
def winfo(ctx, clients):
    """Display **CLIENTS** wireless information."""
    _execute_tool_command(ctx, clients, "wifi_winfo")


@cli.command
@all_clients_argument
@click.pass_context
def info(ctx, clients):
    """Pretty **CLIENTS** information."""
    _execute_tool_command(ctx, clients, "info")


@cli.command
@click.argument("command", type=click.Choice(choices=["stop", "start", "restart"]))
@all_wifi_clients_argument
@click.pass_context
def ep(ctx, command, clients):
    """Control IxChariot endpoint on **CLIENTS**."""
    _execute_tool_command(ctx, clients, "ep", command=command)


@cli.command
@all_clients_argument
@click.pass_context
def reboot(ctx, clients):
    """Reboot **CLIENTS**."""
    _execute_tool_command(ctx, clients, "reboot")


@cli.command
@click.argument("channel", type=click.INT)
@all_wifi_clients_argument
@click.option("--ht", type=click.STRING, help="Bandwidth in MHz.", default="HT20", show_default=True)
@click.option("--ifname", type=click.STRING, default="", help="Interface name.")
@click.pass_context
def wmonitor(ctx, channel, ht, ifname, clients):
    """Set **CLIENTS** interfaces to monitor mode. **CHANNEL** must be specified."""
    _execute_tool_command(ctx, clients, "wifi_monitor", channel=channel, ht=ht, ifname=ifname)


@cli.command
@all_wifi_clients_argument
@click.option("--ifname", type=click.STRING, default="", help="Interface name.")
@click.pass_context
def wstation(ctx, ifname, clients):
    """Set **CLIENTS** interfaces to station mode."""
    _execute_tool_command(ctx, clients, "wifi_monitor", ifname=ifname)


@cli.command("ifaces-get")
@all_clients_argument
@click.pass_context
def ifaces_get(ctx, clients):
    """List all **CLIENT** interfaces."""
    _execute_tool_command(ctx, clients, "get_ifaces")


@cli.command("mac-get")
@all_clients_argument
@click.option("--ifname", type=click.STRING, default="", help="Interface name.")
@click.pass_context
def mac_get(ctx, ifname, clients):
    """Get mac address of **CLIENTS** interfaces."""
    _execute_tool_command(ctx, clients, "get_mac", ifname=ifname)


@cli.command("pod-to-client")
@all_wifi_clients_argument
@click.pass_context
def pod_to_client(ctx, clients):
    """Change **NODES** from pod role to client."""
    _execute_tool_command(ctx, clients, "pod_to_client")


@cli.command("client-to-pod")
@all_wifi_clients_argument
@click.pass_context
def client_to_pod(ctx, clients):
    """Change **NODES** from client role to pod."""
    _execute_tool_command(ctx, clients, "client_to_pod")


@cli.command
@all_clients_argument
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
    help="HTTP address to a mirror with images. Only supported for debian and rpi type clients.",
)
@click.option(
    "--download-locally",
    default="True",
    type=click.Choice(choices=["True", "False"]),
    help="If True download upgrade files to local machine. [Only Debian-type clients]",
    show_default=True,
)
@click.pass_context
def upgrade(ctx, fw_path, restore_cfg, force, version, mirror_url, download_locally, clients):
    """Upgrade **CLIENTS** with FW from fw_path or download build version from artifactory."""
    restore_cfg = osrt_cli_tools.utils.bool_choices_to_bool(restore_cfg)
    download_locally = osrt_cli_tools.utils.bool_choices_to_bool(download_locally)
    _execute_tool_command(
        ctx,
        clients,
        "upgrade",
        fw_path=fw_path,
        restore_cfg=restore_cfg,
        force=force,
        version=version,
        mirror_url=mirror_url,
        download_locally=download_locally,
    )


@cli.command("region-get")
@all_wifi_clients_argument
@click.pass_context
def region_get(ctx, clients):
    """Get region code for **CLIENTS**."""
    _execute_tool_command(ctx, clients, "get_region")


@cli.command("region-set")
@click.argument("region", type=click.Choice(choices=["EU", "US", "UK", "CA", "JP", "KR", "PH"]))
@all_wifi_clients_argument
@click.pass_context
def region_set(ctx, clients):
    """Set **REGION** code for **CLIENTS**."""
    _execute_tool_command(ctx, clients, "set_region")


@cli.command("adt-list-devices")
@all_clients_argument
@click.pass_context
def adt_list_devices(ctx, clients):
    """Get available devices to simulate for **CLIENTS**."""
    _execute_tool_command(ctx, clients, "get_clients_to_simulate")


@cli.command("adt-start")
@click.argument("device", type=click.STRING)
@click.option("--ifname", is_flag=False, default="", type=click.STRING, help="Provide interface name.")
@click.option("--ssid", is_flag=False, default=None, type=click.STRING, help="Specify custom ssid.")
@click.option("--psk", is_flag=False, default=None, type=click.STRING, help="Specify custom psk.")
@click.option("--bssid", is_flag=False, default=None, type=click.STRING, help="Custom bssid - only for WiFi clients.")
@click.option("--fake-mac", default=None, type=click.STRING, help="Specify custom fake mac address.")
@click.option("--force", default=False, is_flag=True, help="Force device typing for testing.")
@single_client_argument
@click.pass_context
def adt_start(ctx, device, ifname, ssid, psk, bssid, fake_mac, force, client):
    """Start simulate **DEVICE** type on **CLIENT**. List available devices with
    `osrt client adt-list-devices` command.
    """
    _execute_tool_command(
        ctx,
        [client],
        "start_simulate_client",
        device_to_simulate=device,
        ifname=ifname,
        ssid=ssid,
        psk=psk,
        bssid=bssid,
        fake_mac=fake_mac,
        force=force,
    )


@cli.command("adt-clear")
@click.option("--ifname", is_flag=False, default="", type=click.STRING, help="Provide interface name.")
@all_clients_argument
@click.pass_context
def adt_clear(ctx, ifname, clients):
    """Clear custom device type for **CLIENTS**."""
    _execute_tool_command(ctx, clients, "clear_adt", ifname=ifname)


@cli.command("ap-start")
@click.argument("channel", type=click.INT)
@click.option("--ifname", is_flag=False, default="", type=click.STRING, help="Provide interface name.")
@click.option("--ssid", is_flag=False, default="test", type=click.STRING, help="Network ssid.", show_default=True)
@click.option(
    "--timeout",
    default=120,
    type=click.INT,
    help="Timeout in seconds for hostapd to go into AP-ENABLED state, overrides the global --timeout option.",
    show_default=True,
)
@click.option("--country", is_flag=False, type=click.STRING, default="US", show_default=True, help="Country code.")
@click.option("--dhcp", is_flag=True, default=False, help="Start DHCP server.")
@click.option(
    "--extra-param", type=click.STRING, default="", help="Extra parameters passed to the hostapd config file."
)
@single_wifi_client_argument
def ap_start(ctx, channel, ifname, ssid, timeout, country, dhcp, extra_param, client):
    """Start hostapd on **CLIENT** for **CHANNEL**."""
    # timeout is passed and processed with the context object
    _execute_tool_command(
        ctx,
        [client],
        "create_ap",
        channel=channel,
        ifname=ifname,
        ssid=ssid,
        country=country,
        dhcp=dhcp,
        extra_param=extra_param,
    )


@cli.command("ap-stop")
@click.option("--ifname", is_flag=False, default="", type=click.STRING, help="Provide interface name.")
@all_wifi_clients_argument
@click.pass_context
def ap_stop(ctx, ifname, clients):
    """Stop hostapd on **CLIENTS**."""
    _execute_tool_command(ctx, clients, "disable_ap", ifname=ifname)


@cli.command("dhclient-start")
@click.option("--ifname", is_flag=False, default=None, type=click.STRING, help="Provide interface name.")
@ipv4_option
@ipv6_option
@click.option(
    "--reuse",
    type=click.Choice(choices=["True", "False"]),
    default="False",
    show_default=True,
    help="Restart dhclient with current dhclient arguments.",
)
@click.option(
    "--static-ip",
    type=click.STRING,
    default=None,
    help="If specified, use this static IP address instead of starting dhclient.",
)
@click.option(
    "--clear-dhcp",
    type=click.Choice(choices=["True", "False"]),
    default="True",
    show_default=True,
    help="Stop dhcp client before refresh IP address.",
)
@all_clients_argument
@click.pass_context
def dhclient_start(ctx, ifname, ipv4, ipv6, reuse, static_ip, clear_dhcp, clients):
    """(Re)start dhclient on **CLIENTS** interface."""
    start_dhclient, ipv4, ipv6, ipv6_stateless = _ip_addressing_params_to_flags(ipv4, ipv6)
    if not start_dhclient:
        click.secho("This combination of flags is illegal, requires stopping dhclient.", err=True)
        sys.exit(1)
    reuse, clear_dhcp = osrt_cli_tools.utils.bool_choices_to_bool(reuse), osrt_cli_tools.utils.bool_choices_to_bool(
        clear_dhcp
    )
    _execute_tool_command(
        ctx,
        clients,
        "refresh_ip_address",
        iface=ifname,
        ipv4=ipv4,
        ipv6=ipv6,
        ipv6_stateless=ipv6_stateless,
        reuse=reuse,
        static_ip=static_ip,
        clear_dhcp=clear_dhcp,
    )


@cli.command("temperature-get")
@all_clients_argument
@click.pass_context
def temperature_get(ctx, clients):
    """Get temperature from **CLIENTS** devices."""
    _execute_tool_command(ctx, clients, "get_temperature")


@cli.command("mocha-enable")
@all_wifi_clients_argument
@click.pass_context
def mocha_enable(ctx, clients):
    """Enable mocha mode: **CLIENTS** automatically connect to ap and periodically generate traffic."""
    _execute_tool_command(ctx, clients, "mocha_enable")


@cli.command("mocha-disable")
@all_wifi_clients_argument
@click.pass_context
def mocha_disable(ctx, clients):
    """Disable mocha mode."""
    _execute_tool_command(ctx, clients, "mocha_disable")


def get_bash_complete() -> Path:
    """Returns a path to ``client`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "client-complete.bash"
