import atexit
import os
import sys
import fnmatch
import traceback
import logging
import datetime
from pathlib import Path

from lib_testbed.generic.util.logger import log
from osrt_cli_tools.utils import (
    json_option,
    debug_option,
    disable_colors_option,
    get_locations_path,
    get_excluded_testbeds,
    prepare_logger,
    complete_testbeds,
    get_testbed_name,
    is_autocomplete,
    set_log_level,
)

if is_autocomplete():
    import click
else:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True
    if os.environ.get("PSET_DISABLE_COLORS"):
        click.rich_click.COLOR_SYSTEM = None


def print_reservation(ctx, output, columns=None, all_columns: bool = False):
    """Print reservation result - fill table according to click context/command."""
    log.debug("Printing reservation results")
    if ctx.obj.get("JSON", False):
        import json
        from click import echo

        return echo(json.dumps(output, indent=2))

    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console(emoji=False)
    if ctx.obj.get("NOT_TTY"):
        table = Table(show_header=True, box=None, show_edge=False, show_lines=False)
    else:
        table = Table(show_header=True, box=box.ROUNDED, caption_style="not dim")
    command_columns = ["name"]
    for res in output:
        if isinstance(res, dict):
            # handle deprecated message decorator
            if res.get("message") == "" or res.get("message") == "-":
                res["message"] = res.get("reservation message", "")
    if not columns:
        match ctx.command.name:
            case "get":
                command_columns.extend(
                    ["busy", "busyByMe", "owner", "since", "expiration", "team_responsible", "purpose", "message"]
                )
                if all_columns:
                    command_columns.extend(["version", "is_forced"])
            case "set":
                command_columns.extend(["status", "owner", "since", "expiration", "purpose", "message"])
                if all_columns:
                    command_columns.extend(["version", "is_forced", "team_responsible"])
            case "free":
                command_columns.extend(["status", "owner", "since", "expiration", "purpose"])
                if all_columns:
                    command_columns.extend(["version", "is_forced", "team_responsible"])
            case "history-clear":
                command_columns.extend(["status", "message"])
                if all_columns:
                    command_columns.extend(["version", "team_responsible"])
            case "stats":
                command_columns.append("stats")
            case "history-get":
                command_columns.extend(["owner", "since", "expiration", "message", "version", "is_forced"])
                if all_columns:
                    command_columns.extend(["team_responsible"])
            case "file-format-update":
                command_columns.extend(["status"])
    else:
        command_columns = columns
    if not isinstance(output, list):
        output = [output]
    for col in command_columns:
        table.add_column(
            col,
            justify="left",
            header_style="bold",
            overflow="ignore" if col in ["purpose", "is_forced", "version"] else "fold",
            min_width=5,
        )
    for tb in output:
        style = None
        if not isinstance(tb, list):  # it's a list of status rows for reservation history
            row = []
            for col in table.columns:
                row.append(str(tb.get(col.header, "-")))
            if ctx.command.name == "get" and row[1] == "True" and row[2] == "False":
                style = "red"  # busy by someone else
            elif ctx.command.name == "get" and row[1] == "True" and row[2] == "True":
                style = "green"  # busy by me
            elif ctx.command.name in {"set", "free"} and row[1] == "False":
                style = "red"  # set/free unsuccessful
            table.add_row(*row, style=style if not ctx.obj.get("DISABLE_COLORS") else None)
        else:
            # this is history-get command with rows
            for status_row in tb:
                row = []
                style = None
                if status_row.get("is_forced"):
                    style = "red"
                for col in table.columns:
                    row.append(str(status_row.get(col.header, "-")))
                table.add_row(*row, style=style if not ctx.obj.get("DISABLE_COLORS") else None)

    return console.print(table)


def process_testbed_arg(ctx, param, value):
    """Process testbed name argument."""
    if value in [".", None]:
        value = os.environ.get("OPENSYNC_TESTBED")
    if value is None:
        return None

    file_exclusions = get_excluded_testbeds()
    all_loc_list = sorted(get_locations_path().iterdir())

    values = None

    if "," in value:
        values = value.split(",")

    if value == "all":
        values = ["*"]
    testbeds = []
    if values is None:
        values = [value]
    for value in values:
        # handle wildcards (*, ?, [seq], [!seq]) in tb name
        if any(x in value for x in ("*", "?")) or all(x in value for x in ("[", "]")):
            n_hidden = 0
            n_excluded = 0

            for loc_file in all_loc_list:
                if loc_file.suffix not in (".yaml", ".yml"):
                    # typically .swp and .swo files, log all here, skip (and count) later
                    log.debug("Found a non-yaml file: %s", loc_file)
                if not fnmatch.fnmatch(loc_file.stem, value):
                    continue  # no match
                if loc_file.suffix not in (".yaml", ".yml"):
                    continue  # skip non-yaml files
                if loc_file.stem.startswith("."):
                    log.debug("Skipping a hidden file: %s", loc_file.stem)
                    n_hidden += 1
                    continue  # skip hidden files
                if loc_file.stem.startswith("_"):  # skip files starting with _ as that are not testbed files
                    continue
                if loc_file in file_exclusions:
                    n_excluded += 1
                    continue
                testbeds.append(loc_file.stem)
            if not testbeds:
                click.echo("No testbeds found", err=True)
                sys.exit(3)
            if n_hidden > 0:
                if not is_autocomplete():
                    click.echo(f"{n_hidden} hidden testbeds excluded from processing", err=True)
            if n_excluded > 0:
                if not is_autocomplete():
                    click.echo(f"{n_excluded} restricted testbeds excluded from processing", err=True)
        else:
            testbeds.append(value)

    return testbeds


testbeds_optional_argument = click.argument(
    "testbeds", callback=process_testbed_arg, shell_complete=complete_testbeds, required=False, default=None
)
all_columns_option = click.option(
    "--all-columns", is_flag=True, help="Display all columns. Some columns are hidden from default view."
)


def get_reserve_object(
    tb_name: str = None, json: bool = False, force: bool = False, message: str = "", skip_tz_conversion=False
):
    """Return reserve lib instance. The force and message arguments are required for
    setting reservation only - the ReserveLib expects a modified testbed config dictionary with
    ``"message"`` and ``"force"`` keys.
    """
    from lib_testbed.generic.util.reservelib import ReserveLib
    from lib_testbed.generic.util.config import load_tb_config

    if not tb_name:
        tb_name = get_testbed_name()
    config = load_tb_config(tb_name, skip_deployment=True)
    if force:
        config["force"] = force
    if message:
        config["message"] = message
    return ReserveLib(config=config, json=json, skip_tz_conversion=skip_tz_conversion)


def check_reservelib_version(reserve):
    """Check the latest version of reservation; when newer available display a warning."""

    def _old_version_warning():
        with open(Path(os.path.dirname(__file__)) / "osrt_warning.txt", "rt") as warning_text:
            click.secho(warning_text.read(), bold=True, fg="red")
        click.secho("YOU MIGHT BE USING OUTDATED VERSION OF RESERVELIB!\n", bold=True, blink=True, fg="red", err=True)
        click.echo(f"{reserve.tb_name}: update reservelib to the latest version to get/set reservation.\n", err=True)

    if reserve.is_newer_available():
        atexit.register(_old_version_warning)


def exit_on_outdated_file(reserve, tb_name: str):
    """Exit when reservation file for given testbed is outdated."""
    if reserve.check_outdated_reserve_format():
        click.secho(
            f"Outdated reservation file format! Fix it with the command: reserve file-format-update {tb_name}",
            bold=True,
        )
        sys.exit(1)


# the tasks defined below are needed to query multiple testbeds in parallel.
# they are invoked for all matching testbeds, each launched in an individual thread.
if not is_autocomplete():
    from lib_testbed.generic.util.common import threaded

    @threaded
    def get_reservation_task(tb_name: str, json: bool = False, skip_tz_conversion=False):
        """Parallel task for getting reservation from given testbed."""
        reserve = get_reserve_object(tb_name=tb_name, json=json, skip_tz_conversion=skip_tz_conversion)
        exit_on_outdated_file(reserve, tb_name)
        check_reservelib_version(reserve)
        return reserve.get_reservation_status()

    @threaded
    def set_reservation_task(
        tb_name: str,
        json: bool = False,
        force: bool = False,
        message: str = "",
        reservation_time: int = 120,
        skip_tz_conversion: bool = False,
    ):
        """Parallel task for setting reservation for given testbed."""
        reserve = get_reserve_object(
            tb_name=tb_name, json=json, force=force, message=message, skip_tz_conversion=skip_tz_conversion
        )
        if reservation_time > reserve.max_reserv_time and not message:
            click.echo(
                f"Requested reservation time of {reservation_time} minutes for testbed {reserve.tb_name} exceeds "
                f"max configured reservation time of {reserve.max_reserv_time} minutes, "
                f"please provide a reason  (--message) for exceeding the maximum!",
                err=True,
            )
            return {
                "name": reserve.tb_name,
                "status": False,
                "owner": "EXCEEDED MAXIMUM RESERVATION TIME",
                "message": message,
            }
        else:
            exit_on_outdated_file(reserve, tb_name)
            check_reservelib_version(reserve)
            return reserve.reserve_test_bed(timeout=reservation_time)

    @threaded
    def free_reservation_task(tb_name: str, json: bool = False, force: bool = False, skip_tz_conversion=False):
        """Parallel task for freeing reservation for given testbed."""
        reserve = get_reserve_object(tb_name=tb_name, json=json, skip_tz_conversion=skip_tz_conversion)
        exit_on_outdated_file(reserve, tb_name)
        reserve.tb_config["force"] = force
        return reserve.unreserve()

    @threaded
    def clear_history_reservation_task(tb_name: str, json: bool = False, skip_tz_conversion=False):
        """Parallel task for clearing reservation history for given testbed."""
        reserve = get_reserve_object(tb_name=tb_name, json=json, skip_tz_conversion=skip_tz_conversion)
        exit_on_outdated_file(reserve, tb_name)
        return reserve.clear_reservation_history()

    @threaded
    def stats_reservation_task(tb_name: str, json: bool = False, time_res: str = "week", skip_tz_conversion=False):
        """Parallel task for getting reservation stats for given testbed."""
        reserve = get_reserve_object(tb_name=tb_name, json=json, skip_tz_conversion=skip_tz_conversion)
        exit_on_outdated_file(reserve, tb_name)
        return reserve.usage_statistics(time_res=time_res)

    @threaded
    def history_get_reservation_task(tb_name: str, json: bool = False, days: int = 0, skip_tz_conversion=False):
        """Parallel task for getting reservation history for given testbed."""
        reserve = get_reserve_object(tb_name=tb_name, json=json, skip_tz_conversion=skip_tz_conversion)
        exit_on_outdated_file(reserve, tb_name)
        return reserve.get_history(days=days)

    @threaded
    def update_reservation(tb_name: str, json: bool = False):
        reserve = get_reserve_object(tb_name=tb_name, json=json)
        return reserve.update_old_reservation_format()


def reservation_execute_tasks(ctx, testbeds: list[str], task: callable, **kwargs) -> list:
    """Perform reservation task, return results.

    Launches tasks across all testbeds, **kwargs being passed over to the reservation task.
    Collects results and retunrs a list of results.
    """
    reserve_tasks = {}
    kwargs["skip_tz_conversion"] = ctx.obj.get("SKIP_TZ_CONVERSION", False)
    for tb_name in testbeds:
        reserve_tasks[tb_name] = task(tb_name=tb_name, **kwargs)
    reservation_results = []
    for tb_name in reserve_tasks:
        try:
            result = reserve_tasks[tb_name].result()
        except Exception as err:
            log.debug("Error executing reservation task. Traceback: %s", "".join(traceback.format_exception(err)))
            result = {
                "name": tb_name,
                "busy": True,
                "busyByMe": False,
                "owner": "ERROR GETTING RESERVATION",
                "since": "-",
                "expiration": "-",
                "version": "-",
                "is_forced": False,
                "message": "-",
            }
            result = [result] if "history-get" in ctx.command_path else result
            # not possible to easily pass testbed name to atexit call.
            atexit.register(
                lambda: click.secho(
                    "Reservation task finished with an error, add --debug for more information.",
                    fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
                    err=True,
                )
            )
        reservation_results.append(result)
    return reservation_results


# the actual command implementation of all commands:


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@debug_option
@json_option
@disable_colors_option
@click.option(
    "--skip-timezone-conversion", is_flag=True, help="Do not convert timestamps from UTC to machine-local timezone."
)
@click.pass_context
def cli(ctx, debug, json, disable_colors, skip_timezone_conversion):
    """Testbed reservation tool.

    All commands can be executed across multiple testbeds in parallel. The results
    will be printed out in a table, with result for each testbed represented as a table row.
    All locations stored in config/locations/ directory are matched, and wildcard
    matching is supported to match multiple testbeds at a time.
    """
    log.debug("Entering reserve tool context")
    ctx.ensure_object(dict)
    ctx.obj["NOT_TTY"] = not sys.stdout.isatty()
    if not ctx.obj.get("DISABLE_COLORS"):
        ctx.obj["DISABLE_COLORS"] = disable_colors
    if not ctx.obj.get("DEBUG"):
        ctx.obj["DEBUG"] = debug
    if not ctx.obj.get("JSON"):
        ctx.obj["JSON"] = json
    if not ctx.obj.get("SKIP_TZ_CONVERSION"):
        ctx.obj["SKIP_TZ_CONVERSION"] = skip_timezone_conversion
    if not is_autocomplete():
        if ctx.obj["DEBUG"]:
            prepare_logger(ctx.obj["DEBUG"])
        else:
            set_log_level(logging.ERROR)


@cli.command(name="set")
@click.option("-f", "--force", is_flag=True, help="Force reservation.")
@click.option("-m", "--message", type=click.STRING, help="Add message denoting reason for TB reservation.", default="")
@click.option("--skip-countdown", is_flag=True, help="Skip remaining time countdown mechanism.")
@testbeds_optional_argument
@all_columns_option
@click.argument("reservation_time", type=click.STRING, required=False, default=120)
@click.pass_context
def set_(ctx, testbeds, reservation_time, force, message, skip_countdown, all_columns):
    """Set testbed reservation.

    The argument **TESTBEDS** might contain a wildcard, for example `slobox*`.
    Be careful - the **TESTBEDS** wildcard must not match any files in your current working directory.

    Optionally provide **RESERVATION_TIME** value in minutes (default: 120), or human-readable time-string, e.g.
    `1d1h` (1 day 1 hour) for 25 hour or `1w` (1 week) for 7 days.

    Setting custom reservation time for the current testbed - as specified in the environment variable
    `OPENSYNC_TESTBED` requires this command:

    ```
    reserve set . <RESERVATION-TIME>
    ```

    If reservation time is not given in minutes, then the provided string is parsed using Python library dateparser,
    so the reservation end time can be provided as "in 1 week" or "in a month". In addition, multiple languages are
    parsed depending on dateparser version installed on your system. A valid reservation request example:

    ```
    reserve set . "20 September 2026"
    ```

    **NOTE** If the reservation end date falls in the past, the tool is going to try to convert it into a
    valid date, so it will calculate the difference between the parsed date and now, and flip it to be a positive
    timedelta. You have been warned!
    """
    import subprocess
    import dateparser
    from lib_testbed.generic.util.common import CACHE_DIR

    try:
        reservation_time = int(reservation_time)
    except ValueError:
        log.info("Trying to convert reservation time into minutes")
        now = datetime.datetime.now()
        # note that the timestamps parsed here are not timezone-aware and are in the local machine timezone.
        parsed_timestamp = dateparser.parse(reservation_time)
        if not parsed_timestamp:
            click.echo(f"Provided reservation time of '{reservation_time}' could not be parsed.", err=True)
            sys.exit(1)
        if parsed_timestamp < now:
            reservation_time = now - parsed_timestamp
        else:
            reservation_time = parsed_timestamp - now
        log.debug("Parsed reservation time is: %s", reservation_time)
        reservation_time = int(reservation_time.total_seconds() / 60)
        log.debug("Converted reservation time in minutes: %s", reservation_time)

    if message and (":::" in message or "\n" in message):
        click.secho(
            "Reservation message MUST NOT contain the symbol ':::' [triple colon] or a new line character.",
            fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
            err=True,
        )
        sys.exit(1)
    # to speed things up all commands are launched as tasks in parallel
    # because they can be executed across multiple testbeds at the same time.
    reservation_results = reservation_execute_tasks(
        ctx=ctx,
        testbeds=testbeds,
        task=set_reservation_task,
        json=ctx.obj.get("JSON", False),
        force=force,
        message=message,
        reservation_time=reservation_time,
    )
    print_reservation(ctx, reservation_results, all_columns=all_columns)
    for row in reservation_results:
        reserve_file = f"{CACHE_DIR}/.reserve_{row.get('name')}"
        if not skip_countdown and row.get("status"):
            log.debug("Storing reservation expiration '%s' to file %s", row, reserve_file)
            subprocess.run(f"flock -x {reserve_file} echo \"{row['expiration']}\" > {reserve_file}", shell=True)
        else:
            log.debug("Reserve result: '%s'. Removing the file %s", row, reserve_file)
            subprocess.run(f"flock -x {reserve_file} rm {reserve_file}", shell=True)
    if not all(state.get("status", False) for state in reservation_results):
        click.secho(
            "Reservation was not successful!", err=True, fg="red" if not ctx.obj.get("DISABLE_COLORS") else None
        )
        sys.exit(1)


@cli.command
@click.option("--only-free", is_flag=True, help="Only display free testbeds, extends get command.")
@click.option(
    "--owner",
    type=click.STRING,
    help="Only display testbeds that belong to given owner. This option might contain a wildcard, "
    "or just part of the searched name. This option will also match last owner.",
    default=None,
)
@testbeds_optional_argument
@all_columns_option
@click.pass_context
def get(ctx, testbeds, only_free, owner, all_columns):
    """Get testbed reservation information.

    The argument **TESTBEDS** might contain a wildcard, for example `slobox*`.
    Be careful - the **TESTBEDS** wildcard must not match any files in your current working directory.

    Example:
    ```
    osrt reserve get pl-box* --only-free
    ```

    will print out all testbeds with name starting with the string `pl-box` that are currently not reserved.
    """
    if testbeds is None:
        click.secho("Could not establish testbed name. Have you used 'osrt shell' command?", bold=True, err=True)
        sys.exit(1)

    reservation_results = reservation_execute_tasks(
        ctx=ctx, testbeds=testbeds, task=get_reservation_task, json=ctx.obj.get("JSON", False)
    )

    if only_free:
        reservation_results = [tb for tb in reservation_results if not tb["busy"]]
    if owner:
        if "*" in owner or "?" in owner or "[" in owner or "]" in owner:
            reservation_results = [tb for tb in reservation_results if fnmatch.fnmatch(tb["owner"], owner)]
        else:
            reservation_results = [tb for tb in reservation_results if owner in tb["owner"]]
    print_reservation(ctx, reservation_results, all_columns=all_columns)


@cli.command
@click.option("-f", "--force", is_flag=True, help="Force free reservation.")
@testbeds_optional_argument
@all_columns_option
@click.pass_context
def free(ctx, testbeds, force, all_columns):
    """Free **TESTBEDS**.

    The argument **TESTBEDS** might contain wildcard, for example `slobox*`.
    Be careful - the **TESTBEDS** wildcard must not match any files in your current working directory.

    """
    import subprocess
    from lib_testbed.generic.util.common import CACHE_DIR

    reservation_results = reservation_execute_tasks(
        ctx=ctx, testbeds=testbeds, task=free_reservation_task, json=ctx.obj.get("JSON", False), force=force
    )
    for row in reservation_results:
        if row.get("status"):
            # this is local reservation status just to keep track of time remaining.
            reserve_file = f"{CACHE_DIR}/.reserve_{row['name']}"
            log.debug("Removing local reservation time: %s", reserve_file)
            subprocess.run(f"flock -x {reserve_file} rm {reserve_file}", shell=True)
    print_reservation(ctx, reservation_results, all_columns=all_columns)


@cli.command("history-clear")
@testbeds_optional_argument
@click.pass_context
def hist_clear(ctx, testbeds):
    """Clear reservation history for **TESTBEDS**.

    Removes reservation file from testbed."""
    affected_testbeds = ", ".join(testbeds)
    if click.confirm(
        f"You are about to clear history for the following testbeds: {affected_testbeds}. Do you want to continue?"
    ):
        reservation_results = reservation_execute_tasks(
            ctx=ctx, testbeds=testbeds, task=clear_history_reservation_task, json=ctx.obj.get("JSON", False)
        )
        print_reservation(ctx, reservation_results)
    else:
        click.echo("Clearing history cancelled.")


@cli.command
@testbeds_optional_argument
@click.option(
    "-t", "--time-res", type=click.Choice(["day", "week", "month", "year"]), default="week", help="Time resolution."
)
@click.pass_context
def stats(ctx, testbeds, time_res):
    """Display **TESTBEDS** usage statistics."""
    reservation_results = reservation_execute_tasks(
        ctx=ctx, testbeds=testbeds, task=stats_reservation_task, json=ctx.obj.get("JSON", False), time_res=time_res
    )
    print_reservation(ctx, reservation_results)


@cli.command
@testbeds_optional_argument
@click.option(
    "-d",
    "--days",
    type=click.INT,
    default=0,
    help="Show history for last X days. All history is shown when `--days` are not specified.",
)
@all_columns_option
@click.pass_context
def history_get(ctx, testbeds, days, all_columns):
    """Display testbed usage history."""
    reservation_results = reservation_execute_tasks(
        ctx=ctx, testbeds=testbeds, task=history_get_reservation_task, json=ctx.obj.get("JSON", False), days=days
    )
    print_reservation(ctx, reservation_results, all_columns=all_columns)


@cli.command
@testbeds_optional_argument
@click.pass_context
def file_format_update(ctx, testbeds):
    """Update reservation file format.

    Use this command to update reservation file format to the most recent file format specification.
    """
    if ctx.obj.get("SKIP_TZ_CONVERSION"):
        click.echo("The flag --skip-timezone-conversion does not make sense in this context, ignoring it.", err=True)
    reservation_results = reservation_execute_tasks(
        ctx=ctx, testbeds=testbeds, task=update_reservation, json=ctx.obj.get("JSON", False)
    )
    print_reservation(ctx, reservation_results)


def get_bash_complete() -> Path:
    """Returns a path to ``reserve`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "reserve-complete.bash"
