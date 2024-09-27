"""
This file holds the common utility methods for osrt cli tools package. It is worth
noting that the best practice is to keep everything as lazy as possible. Imports
inside of functions are postponed as late as they can be to speed up previous
parts of the command e.g. --help.
"""

import os
import sys
import logging
import traceback
import json
from pathlib import Path

from lib_testbed.generic.util.logger import log
from osrt_cli_tools import tb_config_parser


def is_autocomplete() -> bool:
    """Returns True when the tool is in autocomplete context."""
    if (
        os.environ.get("_OSRT_COMPLETE")
        or os.environ.get("_LAB_COMPLETE")
        or os.environ.get("_CLIENT_COMPLETE")
        or os.environ.get("_POD_COMPLETE")
        or os.environ.get("_RESERVE_COMPLETE")
        or os.environ.get("_RPOWER_COMPLETE")
        or os.environ.get("_SERVER_COMPLETE")
        or os.environ.get("_SWITCH_COMPLETE")
        or os.environ.get("_TESTBED_COMPLETE")
        or os.environ.get("_CONFIG_COMPLETE")
    ):
        return True
    return False


if is_autocomplete():
    import click
else:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True


def get_locations_path() -> Path:
    """Return locations path."""
    from lib_testbed.generic.util.config import get_config_dir, LOCATIONS_DIR

    return Path(get_config_dir()) / LOCATIONS_DIR


def get_testbed_name(tb_name: str = None, no_tb_ok: bool = False) -> str | None:
    """Return testbed name."""
    if tb_name:
        return tb_name
    testbed_name = os.environ.get("OPENSYNC_TESTBED")
    if not testbed_name and no_tb_ok:
        return None
    if not testbed_name:
        click.echo("Testbed not found. Use 'osrt shell' command to configure testbed.")
        sys.exit(1)
    return testbed_name


def get_excluded_testbeds() -> set[str]:
    """Returns a set of testbeds to be not-reserved."""
    import fnmatch

    all_loc_list = list(get_locations_path().iterdir())
    file_exclusions = set()

    try:
        with (get_locations_path() / "_testbed_reserve_exclude.txt").open() as exclude_list:
            for excluded_tb in exclude_list.readlines():
                for tb_name in all_loc_list:
                    if fnmatch.fnmatch(os.path.basename(tb_name), excluded_tb.strip()):
                        file_exclusions.add(tb_name)
    except FileNotFoundError:
        pass
    return file_exclusions


def print_command_output(ctx, output, show_names=True, return_text: bool = False, title: str = None) -> str | None:
    """Print out command output, exit program with exit code as provided by the very first item in the
    output dictionary."""
    log.debug("Printing command output")
    max_exit_code = None
    if ctx.obj and ctx.obj.get("JSON", False):
        # we take the maximum exit code value that we get from all devices:
        try:
            max_exit_code = int(max([result[1] for result in output.items()], key=lambda x: abs(int(x[0])))[0])
        except Exception:
            max_exit_code = 0

        if max_exit_code:
            ctx.call_on_close(lambda: sys.exit(max_exit_code))
        try:
            if title:
                return click.echo(json.dumps({title: output}, indent=2))
            return click.echo(json.dumps(output, indent=2))
        except TypeError as err:
            click.echo(f"Error creating json output, fallback to tables: \n{traceback.format_exception(err)}")

    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console() if not return_text else Console(record=True)

    table = Table(show_header=True, box=box.ROUNDED, caption_style="not dim", title=title)
    if show_names:
        table.add_column("NAME", justify="left", header_style="bold")
    table.add_column("$?", justify="left", header_style="bold")
    table.add_column("STDOUT", justify="left", header_style="bold white", overflow="fold")
    table.add_column("STDERR", justify="left", header_style="bold red", overflow="fold")
    if output is None:
        raise RuntimeError(f"Command did not result with output, {ctx.command.path}")
    for key, value in output.items():
        if isinstance(value, Exception):
            value = [1, "", "".join(traceback.format_exception(value))]
            max_exit_code = 1
        if show_names:
            table.add_row(key, str(value[0]), str(value[1]), str(value[2]))
        else:
            table.add_row(str(value[0]), str(value[1]), str(value[2]))

    if return_text:
        return console.export_text()
    try:
        if not max_exit_code:
            max_exit_code = int(max([result[1] for result in output.items()], key=lambda x: abs(int(x[0])))[0])
    except Exception:
        # no need to expose an exception if this fails
        max_exit_code = 0
    if max_exit_code:
        ctx.call_on_close(lambda: sys.exit(max_exit_code))
    return console.print(table)


def print_table(
    rows: list[list[str]],
    headers: list[str] = None,
    title: str = None,
    return_text: bool = False,
    ctx=None,
    **kwargs,
) -> str | None:
    """Simple print table with provided headers and rows. Headers and title are optional. Optional ctx is
    click context to discover json-mode."""

    if ctx is not None and ctx.obj.get("JSON", False):
        return click.echo(json.dumps(rows, indent=2))
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console() if not return_text else Console(record=True)
    show_header = True if headers else False
    table = Table(box=box.ROUNDED, caption_style="not dim", title=title, show_header=show_header, **kwargs)
    if headers:
        for header in headers:
            table.add_column(header, justify="left", header_style="bold", overflow="fold")
    for row in rows:
        table.add_row(*row)
    if return_text:
        return console.export_text()
    return console.print(table)


# Common arguments/options section


def complete_devices(ctx, param, incomplete):
    """Autocomplete device names helper function."""
    config = tb_config_parser.load_config(os.environ.get("OPENSYNC_TESTBED"))
    if config:
        nodes, clients = [pod["name"] for pod in config["Nodes"]], [client["name"] for client in config["Clients"]]
    else:
        nodes = clients = []  # just stop autocomplete on nodes and clients if no cached config
    names = ["all", "clients", "pods"] + nodes + clients
    # autocomplete when specifying multiple devices separated by a comma
    if (comma := incomplete.rfind(",")) != -1:
        [names.remove(x) for x in incomplete[:comma].split(",")]
        names.remove("all")
        complete = incomplete[: comma + 1]
        incomplete = incomplete[comma + 1 :]
        return [complete + k for k in names if k.startswith(incomplete)]
    return [k for k in names if k.startswith(incomplete)]


def complete_testbeds(ctx, param, incomplete):
    """Autocomplete testbed names - helper function.
    Autocomplete does not include excluded/hidden testbeds.
    """
    if incomplete == "*":
        return ["all"]

    all_testbeds = tb_config_parser.load_locations()
    return [name for name in all_testbeds if name.startswith(incomplete)]


def check_debug(ctx, param, value):
    """Print out information when debug is enabled by env variable."""
    if value:
        if not is_autocomplete() and os.environ.get("PSET_DEBUG"):
            click.secho("Debug enabled by environment variable PSET_DEBUG", bold=True, err=True)
    return value


def check_json(ctx, param, value):
    """Print out information when json output is enabled by env variable."""
    if value:
        if not is_autocomplete() and os.environ.get("PSET_JSON"):
            click.secho("JSON output enabled by environment variable PSET_JSON", bold=True, err=True)
    return value


devices_argument = click.argument("devices", shell_complete=complete_devices)
devices_optional_argument = click.argument("devices", shell_complete=complete_devices, default="all")
debug_option = click.option(
    "-D",
    "--debug",
    is_flag=True,
    envvar="PSET_DEBUG",
    callback=check_debug,
    help="Enable debug logs. Currently debug logging is "
    + (
        "**enabled** by environment variable. Can be disabled by `export PSET_DEBUG=`"
        if os.environ.get("PSET_DEBUG")
        else "**disabled** by environment variable. Can be enabled by `export PSET_DEBUG=True`"
    ),
)
json_option = click.option(
    "-j",
    "--json",
    is_flag=True,
    envvar="PSET_JSON",
    callback=check_json,
    help="Outputs everything in JSON format. Currently JSON output is "
    + (
        "**enabled** by environment variable. Can be disabled by `export PSET_JSON=`"
        if os.environ.get("PSET_JSON")
        else "**disabled** by environment variable. Can be enabled by `export PSET_JSON=True`"
    ),
)
timeout_option = click.option(
    "-t",
    "--timeout",
    is_flag=False,
    type=click.INT,
    default=30,
    help="SSH command timeout (in seconds).",
    show_default=True,
)
dry_run_option = click.option("--dry-run", is_flag=True, help="Only log steps, do not perform any action.")
disable_colors_option = click.option(
    "--disable-colors",
    is_flag=True,
    envvar="PSET_DISABLE_COLORS",
    help="Disable colors across tool output to improve readability. Currently colored output is "
    + (
        "**enabled** by environment variable. Can be disabled by `export PSET_DISABLE_COLORS=True`"
        if not os.environ.get("PSET_DISABLE_COLORS")
        else "**disabled** by environment variable. Can be enabled by `export PSET_DISABLE_COLORS=`"
    ),
)


def bool_choices_to_bool(selected: str | bool) -> bool:
    """Converts bool choices (True/on/1/False/off/0) strings to actual bool value. Ignores case.
    Raises :py:exc:`ValueError` when the provided string cannot be converted to bool.
    """
    if isinstance(selected, bool):
        return selected
    match selected.lower():
        case "true" | "1" | "on":
            return True
        case "false" | "0" | "off":
            return False
    raise ValueError(f"The string '{selected}' does not match any bool value.")


def set_log_level(level: int):
    """Set automation logger to desired level. Configure it if not configured already."""
    from lib_testbed.generic.util.logger import log

    log.debug("Setting log level to %s", level)
    logger = logging.getLogger("automation")
    configured_stream_handlers = [hnd for hnd in logger.handlers if isinstance(hnd, logging.StreamHandler)]
    if configured_stream_handlers:
        stream_hdlr = configured_stream_handlers[0]
    else:
        stream_hdlr = logging.StreamHandler()
        logger.addHandler(stream_hdlr)
        # create formatter and add it to the handlers
        formatter = logging.Formatter("%(asctime)s.%(msecs)03d [%(levelname).4s] %(message)s", "%H:%M:%S")
        stream_hdlr.setFormatter(formatter)
    configured_handlers = [hnd for hnd in logger.handlers]

    logger.setLevel(level)
    stream_hdlr.setLevel(level)
    for hdlr in configured_handlers:
        hdlr.setLevel(level)


class log_level:
    """Set log level for context.

    Usage - suppressing errors for context:

    .. code-block::py

        with log_level(logging.CRITICAL):
            do_not_see_any_errors_here()

    The function emitting errors will not be visible in logs.

    The intention for this class is to silence expected errors while performing certain operation
    within tools, e.g. ssh errors immediately after reboot - displaying them brings no added value
    to the users, so this class can be used to silence them.
    """

    def __init__(self, level: int):
        self.level = level
        self._prev_log_level = logging.getLogger("automation").level

    def __enter__(self):
        set_log_level(self.level)

    def __exit__(self, exc_type, exc_val, exc_tb):
        set_log_level(self._prev_log_level)


def prepare_logger(debug: bool = False):
    """Get and configure logger for tool session."""
    if debug:
        set_log_level(logging.DEBUG)
    else:
        set_log_level(logging.WARNING)


def save_to_file(file_path: str | Path, content: str) -> None:
    """Create a new text file with file_name file with content
    Args:
        file_path (str): File path
        content (str): File content
    """
    with open(file_path, "w") as out_file:
        out_file.write(content)


def size_to_human(num: int | float) -> str:
    """Convert size in human readable format
    Args:
        num (int): Size in bytes
    Returns:
        String in human readable format
    """
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}B"
        num /= 1024.0
    return f"{num:.1f}YiB"
