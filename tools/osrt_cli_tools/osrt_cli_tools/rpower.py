import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from lib_testbed.generic.util.common import threaded
from lib_testbed.generic.util.logger import log
from osrt_cli_tools.utils import (
    print_command_output,
    devices_argument,
    devices_optional_argument,
    debug_option,
    json_option,
    verbosity_option,
    disable_colors_option,
    prepare_logger,
    set_log_verbosity,
    get_testbed_name,
    is_autocomplete,
)
from lib_testbed.generic.util.config import load_tb_config
from lib_testbed.generic.rpower.rpowerlib import PowerControllerLib

if is_autocomplete():
    import click
else:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True


def print_tasks_output(ctx, output) -> str | None:
    """Print rpower tasks output to json/table."""
    if ctx.obj.get("JSON"):
        return print_command_output(ctx=ctx, output=output)

    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()
    for title in output.keys():
        table = Table(show_header=True, box=box.ROUNDED, caption_style="not dim", title=title)
        table.add_column("NAME", justify="left", header_style="bold")
        table.add_column("$?", justify="left", header_style="bold")
        table.add_column("STDOUT", justify="left", header_style="bold white", overflow="fold")
        table.add_column("STDERR", justify="left", header_style="bold red", overflow="fold")
        for key, value in output[title].items():
            table.add_row(key, str(value[0]), str(value[1]), str(value[2]))
        console.print(table)


def get_rpower_object(tb_name: str = None):
    """Lazy load PowerControllerLib. Speeds up the help."""
    if not tb_name:
        tb_name = get_testbed_name()
    config = load_tb_config(tb_name, skip_deployment=True)
    return PowerControllerLib(config)


def rpower_task(ctx, command: str, tb_name: str, devices: str = None, **kwargs) -> dict[str, list[int, str, str]]:
    """Task for setting status for devices for given testbed name. If command is on/off/cycle, then reservation
    is performed. The testbed is reeserved before executing the command (hardcoded to 15 minutes), and then it
    is unreserved after the command.

    Raises :py:exc:`ValueError` when incorrect/not supported command is passed over.
    """
    from osrt_cli_tools.reserve import get_reserve_object

    reservation_status = None
    skip_reservation = ctx.obj.get("SKIP_RESERVATION")
    try:
        if command in ["on", "off", "cycle"]:
            if not skip_reservation:
                reserve_obj = get_reserve_object(tb_name=tb_name)
                current_reservation = reserve_obj.get_reservation_status()
                if current_reservation.get("busyByMe"):
                    skip_reservation = True
                else:
                    log.debug("Reserving testbed '%s'", tb_name)
                    reservation_status = reserve_obj.reserve_test_bed(timeout=15).get("status")
                    if reservation_status is False:
                        click.echo(f"Could not reserve testbed {tb_name}")
                        return {command: [1, "", "Could not set reservation"]}

        rpower = get_rpower_object(tb_name=tb_name)
        if devices:
            devices = rpower.verify_requested_devices(devices)
        if ctx.obj.get("DRY_RUN"):
            log.info("DRY-RUN: Will execute command: '%s', devices '%s'", command, devices)
            return {command: [0, f"dry-run: {command} devices: {devices}", ""]}

        log.debug("Executing command against testbed '%s': '%s', devices '%s'", tb_name, command, devices)
        match command:
            case "on":
                return rpower.on(devices)
            case "off":
                return rpower.off(devices)
            case "cycle":
                return rpower.cycle(devices, **kwargs)
            case "status":
                return rpower.status(devices)
            case "model":
                return rpower.model()
            case "version":
                return rpower.version()
            case _:
                raise ValueError(f"Command '{command}' not supportred by rpower_task")
    finally:
        if command in ["on", "off", "cycle"]:
            if not skip_reservation:
                if reservation_status:
                    log.debug("Unreserving testbed '%s'", tb_name)
                    reserve_obj.unreserve()


# Rpower threads are IO-bound, so allow more workers than Python's default
_rpower_executor = ThreadPoolExecutor(min(32, (os.cpu_count() or 5) * 5))
threaded_rpower_task = threaded(rpower_task, executor=_rpower_executor)


def exeute_tasks(ctx, command: str, devices: str = None, **kwargs) -> None:
    """Execute tasks for given command across testbeds as defined in the provided click context.
    For rpower it cannot be performed in parallel due to threading issues of Python's requests when
    combined with :py:mod:`concurrent.futures`.
    """
    futures, results = {}, {}
    # Don't execute `rpower on` and `rpower cycle` in parallel, since it could result in big power spikes
    if command not in ("on", "cycle"):
        for tb_name in ctx.obj.get("TESTBEDS"):
            futures[tb_name] = threaded_rpower_task(
                ctx=ctx, command=command, tb_name=tb_name, devices=devices, **kwargs
            )
    for tb_name in ctx.obj.get("TESTBEDS"):
        try:
            if command in ("on", "cycle"):
                results[tb_name] = rpower_task(ctx=ctx, command=command, tb_name=tb_name, devices=devices, **kwargs)
            else:
                results[tb_name] = futures[tb_name].result()
        except Exception as err:
            err_str = "".join(traceback.format_exception(err))
            log.debug("Testbed %s resulted with error:\n%s", tb_name, err_str)
            results[tb_name] = {command: [1, "", err_str]}
    print_tasks_output(ctx, results)


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@debug_option
@json_option
@verbosity_option
@disable_colors_option
@click.pass_context
def cli(ctx, debug, json, verbosity, disable_colors):
    """Rpower control tool.

    **DEVICES** are the devices to run the command on. Can be one of the following:
    `{<device_name>[,...] | all | pods | clients}`. A device name or a comma-separated list of devices is accepted.

    Example usage:

    ```
    rpower status gw,l2,w1
    rpower on pods
    rpower cycle w1,w2,gw
    ```
    """
    log.debug("Entering rpower tool context")
    if not sys.stdout.isatty():
        json = True
    ctx.ensure_object(dict)
    if not ctx.obj.get("DEBUG"):
        ctx.obj["DEBUG"] = debug
    if not is_autocomplete():
        prepare_logger(ctx.obj["DEBUG"])
    if not ctx.obj.get("VERBOSITY"):
        ctx.obj["VERBOSITY"] = verbosity
    if not ctx.obj.get("JSON"):
        ctx.obj["JSON"] = json
    if not ctx.obj.get("DISABLE_COLORS"):
        ctx.obj["DISABLE_COLORS"] = disable_colors
    if not is_autocomplete():
        if ctx.obj.get("VERBOSITY"):
            set_log_verbosity(ctx.obj["VERBOSITY"])
        else:
            prepare_logger(ctx.obj["DEBUG"])


@cli.command()
@devices_optional_argument
@click.pass_context
def status(ctx, devices):
    """Return the power state of **DEVICES**.

    The **DEVICES** can either be a device name or a comma-separated list of devices.

    Example usage:

    ```
    rpower status gw
    rpower status pods
    rpower status l2,l1,w2
    ```
    """
    if ctx.obj.get("TESTBEDS"):
        exeute_tasks(ctx=ctx, command="status", devices=devices)
    else:
        rpower = get_rpower_object()
        devices = rpower.verify_requested_devices(devices)
        print_command_output(ctx, rpower.status(devices))


@cli.command()
@devices_optional_argument
@click.pass_context
def consumption(ctx, devices):
    """Return power consumption of **DEVICES**. Supported only on Shelly PDUs.

    The **DEVICES** can either be a device name or a comma-separated list of devices.
    """
    if ctx.obj.get("TESTBEDS"):
        exeute_tasks(ctx=ctx, command="consumption", devices=devices)
    else:
        rpower = get_rpower_object()
        devices = rpower.verify_requested_devices(devices)
        print_command_output(ctx, rpower.consumption(devices))


@cli.command()
@devices_argument
@click.pass_context
def on(ctx, devices):
    """Turns on specified **DEVICES**.

    The **DEVICES** can either be a device name or a comma-separated list of devices.

    Example usage:

    ```
    rpower on gw
    rpower on pods
    rpower on l2,l1,w2
    ```
    """
    if ctx.obj.get("TESTBEDS"):
        exeute_tasks(ctx=ctx, command="on", devices=devices)
    else:
        rpower = get_rpower_object()
        devices = rpower.verify_requested_devices(devices)
        print_command_output(ctx, rpower.on(devices))


@cli.command()
@devices_argument
@click.pass_context
def off(ctx, devices):
    """Turns off specified **DEVICES**.

    The **DEVICES** can either be a device name or a comma-separated list of devices.

    Example usage:

    ```
    rpower off gw
    rpower off pods
    rpower off l2,l1,w2
    ```
    """
    if ctx.obj.get("TESTBEDS"):
        exeute_tasks(ctx=ctx, command="off", devices=devices)
    else:
        rpower = get_rpower_object()
        devices = rpower.verify_requested_devices(devices)
        print_command_output(ctx, rpower.off(devices))


@cli.command()
@click.option(
    "-t",
    "--timeout",
    default=5,
    type=int,
    show_default=True,
    help="How long to sleep (in seconds) between off and on operations",
)
@devices_argument
@click.pass_context
def cycle(ctx, devices, timeout):
    """Power cycles (off->wait timeout->on) **DEVICES**.

    The **DEVICES** can either be a device name or a comma-separated list of devices.

    Example usage:

    ```
    rpower cycle gw
    rpower cycle pods
    rpower cycle l2,l1,w2
    ```
    """
    if ctx.obj.get("TESTBEDS"):
        exeute_tasks(ctx=ctx, command="cycle", devices=devices, timeout=timeout)
    else:
        rpower = get_rpower_object()
        devices = rpower.verify_requested_devices(devices)
        print_command_output(ctx, rpower.cycle(devices, timeout=timeout))


@cli.command()
@click.pass_context
def model(ctx):
    """Return the model of the PDU."""
    if ctx.obj.get("TESTBEDS"):
        exeute_tasks(ctx=ctx, command="model")
    else:
        rpower = get_rpower_object()
        print_command_output(ctx, rpower.model())


@cli.command()
@click.pass_context
def version(ctx):
    """Return the FW version of the PDU."""
    if ctx.obj.get("TESTBEDS"):
        exeute_tasks(ctx=ctx, command="version")
    else:
        rpower = get_rpower_object()
        print_command_output(ctx, rpower.version())


def get_bash_complete() -> Path:
    """Returns a path to ``rpower`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "rpower-complete.bash"
