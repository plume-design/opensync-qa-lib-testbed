import fnmatch
import os
import subprocess
import sys
import time
import marshal
from pathlib import Path
from importlib.metadata import entry_points

from osrt_cli_tools.utils import complete_testbeds, is_autocomplete

from lib_testbed.generic.tools.osrt_cli_tools.osrt_cli_tools.utils import (
    debug_option,
    json_option,
    disable_colors_option,
    prepare_logger,
    set_log_level,
    print_table,
)

if is_autocomplete():
    import click

    Group = click.Group
else:
    from lib_testbed.generic.util.common import is_ci, BASE_DIR
    import rich_click as click

    Group = click.RichGroup
    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True
    if is_ci():
        click.rich_click.COLOR_SYSTEM = None


class OSRTGroup(Group):
    def list_commands(self, ctx):
        from lib_testbed.generic.util.common import CACHE_DIR

        commands_cache = Path(CACHE_DIR) / "completions" / "osrt_commands.marshal"

        if commands_cache.exists() and commands_cache.stat().st_mtime < time.time() + 3600.0:
            with open(commands_cache, "rb") as commands_file:
                return marshal.load(commands_file)
        else:
            commands = sorted(super().list_commands(ctx) + list(entry_points().select(group="osrt").names))
            try:
                with open(commands_cache, "wb") as commands_file:
                    marshal.dump(commands, commands_file)
            except FileNotFoundError:
                pass
        return commands

    def get_command(self, ctx, name):
        # this pattern is to speed up tab-completions/lazy load commands

        for ep in entry_points().select(group="osrt", name=name):
            cli = ep.load()
            return cli

        return super().get_command(ctx, name)


@click.group(cls=OSRTGroup, context_settings=dict(help_option_names=["-h", "--help"]))
@debug_option
@disable_colors_option
@click.pass_context
def osrt(ctx, debug, disable_colors):
    """OSRT toolset to control testbed clients, nodes, switch, power and cloud."""
    ctx.ensure_object(dict)
    if not ctx.obj.get("DEBUG"):
        ctx.obj["DEBUG"] = debug
    if not ctx.obj.get("DISABLE_COLORS"):
        ctx.obj["DISABLE_COLORS"] = disable_colors
    if not is_autocomplete():
        prepare_logger(ctx.obj["DEBUG"])


@osrt.command
@click.argument("testbed_name", type=click.STRING, default=None, shell_complete=complete_testbeds)
@click.pass_context
def shell(ctx, testbed_name):
    """Launch new subshell for specified **TESTBED_NAME**."""
    from osrt_cli_tools.utils import prepare_logger
    from osrt_cli_tools.reserve import get_reserve_object, print_reservation

    ctx.ensure_object(dict)
    prepare_logger(False)
    os.environ["OPENSYNC_TESTBED"] = testbed_name
    reserve_obj = get_reserve_object(testbed_name)
    reservation_results = reserve_obj.get_reservation_status()
    print_reservation(
        ctx,
        reservation_results,
        columns=["name", "busy", "busyByMe", "owner", "since", "expiration", "team_responsible", "message"],
    )
    if reservation_results and reservation_results.get("busy") and not reservation_results.get("busyByMe"):
        try:
            with open(Path(os.path.dirname(__file__)) / "osrt_warning.txt", "rt") as warning_text:
                click.secho(warning_text.read(), bold=True, fg="red" if not ctx.obj.get("DISABLE_COLORS") else None)
        except FileNotFoundError:
            pass
        if reservation_results.get("owner") == "CANNOT GET RESERVATION":
            if ctx.obj.get("DISABLE_COLORS"):
                click.echo("           CANNOT GET RESERVATION!\n\n")
            else:
                click.secho("           CANNOT GET RESERVATION!\n\n", bold=True, blink=True, fg="red", err=True)
        else:
            if ctx.obj.get("DISABLE_COLORS"):
                click.echo("     TESTBED IS RESERVED BY SOMEONE ELSE!\n\n")
            else:
                click.secho("     TESTBED IS RESERVED BY SOMEONE ELSE!\n\n", bold=True, blink=True, fg="red", err=True)

    args = ["/bin/bash"]
    # if FRAMEWORK_CACHE_DIR is not set, assume the custom bashrc file is inside .venv
    docker_rcfile = os.path.join(os.environ.get("FRAMEWORK_CACHE_DIR", ".venv"), "bashrc")
    if os.path.isfile(docker_rcfile):
        args.extend(["--rcfile", docker_rcfile])
    os.execvpe("/bin/bash", args, os.environ)


@osrt.command
@click.argument("testbed_name", type=click.STRING, required=True, shell_complete=complete_testbeds)
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
@click.pass_context
def run(ctx, testbed_name, command):
    """Execute **COMMAND** for **TESTBED_NAME**.

    When options (example command: `ls -al`) need to be passed as the command to be executed, then they
    should be separated with double dash - this means that the command `ls -al` will be executed in the
    shell for `my-testbed`. This double dash is required to skip Python-click option parsing logic.

    ```
    osrt run my-testbed -- ls -al
    ```

    """
    from lib_testbed.generic.util.logger import log

    log.debug("Invoking run command '%s'", command)
    cmd_args = list(command)
    proc = subprocess.run(f"which {cmd_args[0]}", shell=True, capture_output=True)
    if proc.returncode != 0:
        click.echo(f"Could not establish {cmd_args[0]} path", err=True)
        sys.exit(1)
    command_path = next(iter(proc.stdout.splitlines()), None)
    log.debug("Command %s path: %s", cmd_args[0], command_path)
    os.environ["OPENSYNC_TESTBED"] = testbed_name
    os.execvpe(command_path, cmd_args, os.environ)


@osrt.command
@click.argument("locations", type=click.Path(exists=True), default=None, required=False)
@click.option(
    "--schema",
    "-s",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="Optional path to a custom schema",
)
@click.option(
    "--exclude",
    "-x",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="Text file containing a list of files to exclude from validation, each in a new line.",
)
@debug_option
@json_option
@click.option("--quiet", "-q", help="Silence logging. Overwrites --debug.", is_flag=True, default=False)
@click.option(
    "--logfile",
    "-l",
    type=click.Path(exists=False, dir_okay=False, file_okay=True),
    help="Store logs into file instead of printing to terminal.",
)
@click.pass_context
def validate_locations(ctx, locations, schema, exclude, debug, json, quiet, logfile):
    """Validate **LOCATIONS** config file/files.

    The argument **LOCATIONS** can either be a path to a directory with all locations, or a path
    to a single yaml file. Defaults to framework-default directory.

    Returns exit code 1 if any location file does not adhere to the provided schema file.

    Example usage against a custom location file:
    ```
    osrt validate-locations path/to/my-location.yaml
    ```
    """
    ctx.ensure_object(dict)
    if not ctx.obj.get("JSON"):
        ctx.obj["JSON"] = json
    if not ctx.obj.get("DEBUG"):
        ctx.obj["DEBUG"] = debug
    prepare_logger(ctx.obj["DEBUG"])
    import logging
    import json
    import traceback
    import concurrent.futures
    from lib_testbed.generic.util.logger import log
    from lib_testbed.generic.util.config import CONFIG_DIR, LOCATIONS_DIR

    if locations is None:
        locations = BASE_DIR / CONFIG_DIR / LOCATIONS_DIR

    valid_input_types = [".yaml", ".json"]
    valid_files = []
    invalid_files = []

    if not ctx.obj["DEBUG"]:
        set_log_level(logging.INFO)
    if quiet:
        set_log_level(logging.CRITICAL)
    logging_handlers = logging.getLogger().handlers
    if logfile:
        logging_handlers.append(logging.FileHandler(logfile, mode="w+"))

    if schema is None:
        schema = Path(__file__).parent / "locations_schema.json"
    try:
        with open(schema, "r") as schema_file:
            schema_data = json.load(schema_file)
        log.info("✅ %s loaded successfully", schema)
    except Exception as exception:
        log.error("Error loading json schema file: %s, Use --debug for more info", exception)
        log.debug("Traceback:\n%s", "".join(traceback.format_exception(exception)))
        sys.exit(1)

    if Path(locations).is_file():
        input_files = [Path(locations).resolve().as_posix()]
    elif Path(locations).is_dir():
        input_files = sorted(
            file.resolve().as_posix() for file in Path(locations).iterdir() if file.suffix in valid_input_types
        )
    else:
        raise TypeError(f"Input should be path to directory or file with extensions {valid_input_types}.")

    if exclude:
        with open(exclude) as exclude_file:
            raw_lines = [line.rstrip() for line in exclude_file]
        filtered_files = [
            tb_name
            for tb_name in input_files
            for pattern in raw_lines
            if not fnmatch.fnmatch(name=tb_name, pat=pattern) or tb_name == pattern
        ]
        input_files = filtered_files

    locations_futures = {}
    location_results = {}
    with concurrent.futures.ProcessPoolExecutor() as executor:
        for input_file in input_files:
            locations_futures[input_file] = executor.submit(
                validate_location_file, input_file=input_file, schema_data=schema_data
            )
    for input_file in locations_futures:
        try:
            location_status = locations_futures[input_file].result()
            if location_status:
                log.info("✅ File %s is according to schema", input_file)
                location_results[input_file] = location_status
                valid_files.append(input_file)
        except Exception as exception:
            log.error(
                "❌ An error occurred validating %s against the schema %s, use --debug for more information",
                input_file,
                schema_file.name,
            )
            log.debug("Captured traceback:\n%s", "".join(traceback.format_exception(exception)))
            invalid_files.append(input_file)
    result_table_rows = []
    if valid_files:
        result_table_rows.append(["valid location files", ",\n".join(valid_files)])
    if invalid_files:
        result_table_rows.append(["invalid location files", ",\n".join(invalid_files)])
    print_table(rows=result_table_rows, headers=["status", "list of files"], ctx=ctx, show_lines=True)
    if invalid_files:
        exit(1)


def validate_location_file(input_file, schema_data) -> bool:
    """Task checking a single location file with provided schema. Returns True
    when validation passes, raises an exception otherwise."""
    import jsonschema
    from lib_testbed.generic.util.config import load_file

    input_file = Path(input_file)
    if not input_file.exists():
        raise FileNotFoundError(f"Requested file {input_file} does not exist!")
    posix_path = input_file.as_posix()
    test_data = load_file(posix_path)
    jsonschema.validate(instance=test_data, schema=schema_data)
    return True


def get_bash_complete() -> Path:
    """Returns a path to ``ostr`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "osrt-complete.bash"
