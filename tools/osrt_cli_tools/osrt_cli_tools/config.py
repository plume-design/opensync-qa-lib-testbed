import os
import sys
import tempfile
import traceback
from pathlib import Path

from yaml.scanner import ScannerError

from lib_testbed.generic.util.config import get_config_dir, LOCATIONS_DIR
from lib_testbed.generic.util.logger import log
import osrt_cli_tools.utils
import osrt_cli_tools.tb_config_parser
import osrt_cli_tools.reserve

if osrt_cli_tools.utils.is_autocomplete():
    import click
else:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@osrt_cli_tools.utils.disable_colors_option
@click.pass_context
def cli(ctx, disable_colors):
    """Configuration helper toolset (location).

    Parts of cached config files are available to access in a user-friendly way."""
    log.debug("Entering config tool context")
    ctx.ensure_object(dict)
    if not ctx.obj.get("DISABLE_COLORS"):
        ctx.obj["DISABLE_COLORS"] = disable_colors


@cli.command
@click.pass_context
def tool_cache_clear(ctx):
    """Clear all tools cache.

    **Tools cache is only used in autocomplete and help-output contexts.**
    Some location config-data is cached to speed-up autocomplete. This command deletes that cache.
    It should get re-generated on next tab-completion attempt or tool invocation.
    """
    from lib_testbed.generic.util.common import CACHE_DIR

    tempdir = tempfile.gettempdir()
    deleted = 0
    completions_dir = Path(tempdir) / "completions"
    if completions_dir.exists():
        for path in completions_dir.iterdir():
            if path.suffix == ".marshal":
                click.echo(f"Deleting {path}")
                deleted += 1
                path.unlink()
    commands_cache = Path(CACHE_DIR) / "completions" / "osrt_commands.marshal"
    if commands_cache.exists():
        click.echo(f"Deleting commands cache: {commands_cache}")
        deleted += 1
        commands_cache.unlink()

    click.echo(f"Deleted total of {deleted} tool cache files.")


def path_autocomplete(ctx, param, incomplete):
    """Autocomplete location config/parse keys separated by dots/int numbers are used to enumerate
    list items. Fallback to no-error in case index is out of range or key/sub-key does not exist, as this
    is a helper function only used in tab-complete.
    """
    if "." in incomplete:
        completed_incompleted = incomplete.split(".")
        last_incomplete = completed_incompleted[-1]
        prefix = ".".join(completed_incompleted[:-1]) + "."
        if completed_incompleted[0] == "locations":
            if len(completed_incompleted) <= 2:
                hints = [
                    prefix + key
                    for key in osrt_cli_tools.tb_config_parser.load_locations()
                    if key.startswith(last_incomplete)
                ]
                return hints + [res + "." for res in hints]
            if len(completed_incompleted) > 2:
                if completed_incompleted[1] not in ["", "*"]:
                    tb_name = osrt_cli_tools.utils.get_testbed_name(completed_incompleted[1])
                else:
                    tb_name = osrt_cli_tools.utils.get_testbed_name(osrt_cli_tools.tb_config_parser.load_locations()[0])
        else:
            tb_name = osrt_cli_tools.utils.get_testbed_name()
        tb_config = osrt_cli_tools.tb_config_parser.load_config(tb_name)
        for key in completed_incompleted[1:-1]:
            try:
                if isinstance(tb_config, list):
                    tb_config = tb_config[int(key)]
                else:
                    tb_config = tb_config[key]
            except (KeyError, IndexError):
                pass
        try:
            hints = [prefix + key for key in tb_config.keys() if key.startswith(last_incomplete)]
            return hints + [res + "." for res in hints]
        except AttributeError:
            # fallback for lists
            hints = [prefix + str(key) for key in range(len(tb_config)) if str(key).startswith(last_incomplete)]
            return hints + [res + "." for res in hints]

    return [pre for pre in ["location", "location.", "locations."] if pre.startswith(incomplete)]


def _get_location_config(ctx, tb_name: str, keys: list[str, int], full: bool) -> dict:
    """Returns parsed section of tb_config. Prints out error in case given keys are not found.
    The full flag indicates whether the config should be fully-parsed as opposed to just loading
    the location file as-is.
    """
    from lib_testbed.generic.util.config import load_tb_config, load_file, find_location_file

    if not full:
        tb_config = load_file(find_location_file(tb_name))
    else:
        tb_config = load_tb_config(tb_name, skip_deployment=True)
    if keys:
        full_path = ""
        for key in keys:
            full_path += key
            if isinstance(tb_config, list):
                try:
                    if int(key) < len(tb_config):
                        tb_config = tb_config[int(key)]
                        full_path += "."
                    else:
                        click.secho(
                            f"List is too short, there is no index {key} in '{full_path}' for testbed name: {tb_name}",
                            fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
                            err=True,
                        )
                        sys.exit(1)
                except ValueError:
                    click.secho(
                        f"Trying to index a list with '[{key}]' could not be completed. Testbed name: {tb_name}",
                    )
                    sys.exit(1)
            elif isinstance(tb_config, list):
                click.secho(
                    f"The list index '[{key}]' is incorrect in the location config path '{full_path}' "
                    f"for the location config {tb_name}.",
                    err=True,
                    fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
                )
                if not full:
                    click.echo("Re-try the command with --full flag.", err=True)
                sys.exit(1)
            elif key in tb_config:
                tb_config = tb_config.get(key)
                full_path += "."
            else:
                click.secho(
                    f"The key: '{full_path}' does not exist in the location config: {tb_name}.",
                    err=True,
                    fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
                )
                if not full:
                    click.echo("Re-try the command with --full flag.", err=True)
                sys.exit(1)
    return tb_config


@cli.command
@click.argument("path", default="location", shell_complete=path_autocomplete)
@click.option(
    "--full",
    is_flag=True,
    default=False,
    help="Parse full location config. Only plain text file is loaded without this flag.",
)
@click.pass_context
def get(ctx, path, full):
    """Print out configuration file. At this time only location config can be parsed.

    Example usage:
    ```
    config get location.Nodes.0
    config get --full locations.<my-location-name>.Nodes.2.capabilities.supported_bands
    ```

    It is also possible to extract data across locations. This command:
    ```
    config get locations.*.Nodes.0.id
    ```
    will print out a dictionary mapping location to gateway serial number

    It is possible to parse and print out all location configs with just:
    ```
    config get locations.*
    ```
    """
    import json

    match path.split("."):
        case ["location", *keys]:
            tb_name = osrt_cli_tools.utils.get_testbed_name()
            tb_config = _get_location_config(ctx, tb_name, keys, full)
            click.echo(json.dumps(tb_config, indent=2))
        case ["locations", tb_name, *keys]:
            if tb_name in ["*", ""]:
                to_print = {}
                locations_path = Path(get_config_dir()) / LOCATIONS_DIR
                for tb_config in locations_path.iterdir():
                    if tb_config.suffix == ".yaml":
                        try:
                            to_print[tb_config.stem] = _get_location_config(ctx, str(tb_config.name), keys, full)
                        except ScannerError:
                            log.error("Error parsing location file: %s", tb_config)
                click.echo(json.dumps(to_print, indent=2))
            else:
                tb_config = _get_location_config(ctx, tb_name, keys, full)
                click.echo(json.dumps(tb_config, indent=2))
        case _:
            click.secho(
                "Usage error, the get command PATH is incorrect!",
                err=True,
                fg="red" if not ctx.obj.get("DISABLE_COLORS") else None,
                bold=True,
            )
            ctx.get_help()
            sys.exit(1)


@cli.command
@osrt_cli_tools.reserve.testbeds_optional_argument
@click.pass_context
def ssh(ctx, testbeds):
    """Generate ssh config file for given **TESTBEDS**.

    The generated ssh config file will be printed out on stdout.
    """
    from lib_testbed.generic.util.config import load_tb_config

    click.echo(f"Generating ssh config for testbeds: {testbeds}", err=True)
    ssh_config = "host *.nodes.*.tb *.clients.*.tb bastion.*.tb\n"
    ssh_config += "stricthostkeychecking no\n"
    ssh_config += "userknownhostsfile /dev/null\n\n"
    for tb_name in testbeds:
        try:
            log.debug("Preparing ssh config for testbed: %s", tb_name)
            tld = tb_name + ".tb"
            tb_config = load_tb_config(tb_name, skip_deployment=True)

            ssh_config += f"host bastion.{tld}\n"
            ssh_config += f"hostname {tb_config['ssh_gateway']['hostname']}\n"
            ssh_config += f"user {tb_config['ssh_gateway']['user']}\n\n"

            for node in tb_config["Nodes"]:
                log.debug("Adding node: %s", node)
                ssh_config += f"host {node['name']}.nodes.{tld} bare.{node['name']}.nodes.{tld}\n"
                ssh_config += f"hostname {node['host']['name']}\n"
                ssh_config += f"proxyjump bastion.{tld}\n"
                ssh_config += f"user {node['host']['user']}\n\n"

            for client in tb_config["Clients"]:
                log.debug("Adding client: %s", client)
                if not client.get("host"):
                    # this is the tb-server, skipping it
                    continue
                if client["host"].get("netns"):
                    ssh_config += f"host {client['name']}.clients.{tld}\n"
                    ssh_config += (
                        f"proxycommand ssh bare.{client['name']}.clients.{tld} -- "
                        f"sudo ip netns exec {client['host']['netns']} /usr/sbin/sshd -i\n\n"
                    )

                ssh_config += f"host {client['name']}.clients.{tld} bare.{client['name']}.clients.{tld}\n"
                ssh_config += f"hostname {client['host']['name']}\n"
                ssh_config += f"proxyjump bastion.{tld}\n"
                ssh_config += f"user {client['host']['user']}\n\n"
        except Exception as err:
            log.debug("Error occurred: %s", "\n".join(traceback.format_exception(err)))
            click.secho(f"Error preparing reservation file for {tb_name}, use --debug for more information", err=True)

    click.echo(ssh_config)


@cli.command("list")
@click.pass_context
def list_(ctx):
    """List all available locations.

    Prints all available location configs, ignores all restrictions or hidden flags.
    """
    import columnify
    from lib_testbed.generic.util.config import get_config_dir, LOCATIONS_DIR

    locations_path = Path(get_config_dir()) / LOCATIONS_DIR
    all_locations = [loc.name for loc in locations_path.iterdir() if loc.is_file() and loc.suffix == ".yaml"]
    location_names = sorted([name[:-5] for name in all_locations])  # drop the .yaml extension
    try:
        line_width = os.get_terminal_size().columns
    except OSError:  # no tty
        line_width = 25  # with the assumption that it will all display in a single column, e.g. for grep
    click.echo(columnify.columnify(location_names, line_width=line_width))


def get_bash_complete() -> Path:
    """Returns a path to ``config`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "config-complete.bash"
