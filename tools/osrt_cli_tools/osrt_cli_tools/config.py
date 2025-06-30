import os
import sys
import tempfile
import traceback
import fnmatch
import re
from concurrent.futures.process import ProcessPoolExecutor
from pathlib import Path

from yaml.scanner import ScannerError

from lib_testbed.generic.util.config import (
    get_config_dir,
    MODEL_PROPERTIES_DIR,
    LOCATIONS_DIR,
    MISCS_DIR,
    MODEL_INTERNAL_DIR,
    MODEL_REFERENCE_DIR,
    load_tb_config,
    load_file,
)
from lib_testbed.generic.util.logger import log
import osrt_cli_tools.utils
import osrt_cli_tools.tb_config_parser
import osrt_cli_tools.reserve
import osrt_cli_tools.pod


if osrt_cli_tools.utils.is_autocomplete():
    import click
else:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@osrt_cli_tools.utils.disable_colors_option
@osrt_cli_tools.utils.verbosity_option
@click.pass_context
def cli(ctx, disable_colors, verbosity):
    """Configuration helper toolset (location).

    Parts of cached config files are available to access in a user-friendly way."""
    log.debug("Entering config tool context")
    ctx.ensure_object(dict)
    if not ctx.obj.get("DISABLE_COLORS"):
        ctx.obj["DISABLE_COLORS"] = disable_colors
    if not ctx.obj.get("VERBOSITY"):
        ctx.obj["VERBOSITY"] = verbosity
    if not osrt_cli_tools.utils.is_autocomplete():
        osrt_cli_tools.utils.set_log_verbosity(ctx.obj["VERBOSITY"])


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

    tb_config = {}
    if not full:
        try:
            tb_config = load_file(find_location_file(tb_name))
        except Exception as err:
            log.debug("Caught exception: %s", "".join(traceback.format_exception(err)))
    else:
        try:
            tb_config = load_tb_config(tb_name, skip_deployment=True)
        except Exception as err:
            log.debug("Caught exception: %s", "".join(traceback.format_exception(err)))
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
            if "*" in tb_name or "?" in tb_name:
                to_print = {}
                locations_path = Path(get_config_dir()) / LOCATIONS_DIR
                all_matched_locations = fnmatch.filter(
                    [filepath.name[:-5] for filepath in locations_path.iterdir() if filepath.name.endswith(".yaml")],
                    tb_name,
                )
                for tb_config in all_matched_locations:
                    try:
                        to_print[tb_config] = _get_location_config(ctx, str(tb_config), keys, full)
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
            click.secho(
                f"Error preparing reservation file for {tb_name}, increase tool verbosity with -vv for more information.",
                err=True,
            )

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


def _complete_model(ctx, param, incomplete) -> list[str]:
    """Returns a list of available models out of all available for autocompletion."""
    internal_models = (Path(get_config_dir()) / MODEL_PROPERTIES_DIR / MODEL_INTERNAL_DIR).glob("*.yaml")
    reference_models = (Path(get_config_dir()) / MODEL_PROPERTIES_DIR / MODEL_REFERENCE_DIR).glob("*.yaml")
    all_models = [x.name for x in list(internal_models) + list(reference_models)]
    return [x.rstrip(".yaml") for x in sorted(all_models) if x.startswith(incomplete)]


@cli.command
@click.argument("model", required=False, default=None, shell_complete=_complete_model)
@click.option(
    "--version",
    help="Version/branche to validate. When not specified, all versions from model-properties are checked.",
    type=click.STRING,
    default=None,
    shell_complete=osrt_cli_tools.pod.complete_upgrade_image,
)
@click.pass_context
def build_map_validate(ctx, model, version):
    """Validate build map for specified **MODEL**.

    If not specified and a testbed is active through the environment variable `OPENSYNC_TESTBED`, then the
    current gateway model is checked.

    It is expected for featurebranches to be reported as invalid as the repository structure does not conform
    to the actual versions. Featurebranches are supposed to be tested manually.
    """
    from lib_testbed.generic.util.artifactory_lib import get_map, query_artifactory_search

    valid_versions, invalid_versions = [], []
    if not model:
        tb_name = osrt_cli_tools.utils.get_testbed_name()
        cfg = load_tb_config(tb_name, skip_deployment=True)
        model = cfg["Nodes"][0]["model_org"]
    else:
        model = model.upper()
        artifactory_cfg_path = Path(get_config_dir()) / MISCS_DIR / "artifactory.yaml"
        if not artifactory_cfg_path.exists():
            click.echo("Missing artifactory config, nothing to check")
            sys.exit(1)
        cfg = load_file(artifactory_cfg_path)

    fw_map_full = get_map(model, "build_map.json")

    if version:
        versions = version.split(",")
    else:
        versions = [
            ver for ver in fw_map_full.keys() if ver not in ["short-name", "s3-bucket", "build-profile", "fn-regex"]
        ]
    log.info("Total number of versions to process: %s.", len(versions))
    log.trace("All versions: %s", versions)
    for ver in versions:
        fw_map = fw_map_full[ver]
        fw_regex = fw_map.get("fn-regex", fw_map_full.get("fn-regex"))
        if ver in ["short-name", "s3-bucket", "build-profile", "fn-regex"]:
            continue
        click.echo(f"Testing version '{ver}'", err=True, nl=False)
        try:
            log.info("Checking firmware status of version '%s'.", ver)
            build_profile = fw_map.get("use-build-map-build-profile", fw_map.get("build_profile", "dev-debug"))
            build_name = fw_map["proj-name"].split("/")[0]
            suffix = fw_map["enc-suffix"] if fw_map["encryption"] else fw_map.get("img-suffix", "")
            response = query_artifactory_search(cfg, build_name, "LATEST")
            if response.status_code == 504:
                log.debug("Gateway timeout, skipping this check")
                click.echo(" ⇨ [skip]", err=True)
                continue
            elif response.status_code == 404:
                log.debug("Response 404, firmware doesn't exist in artifactory")
                click.echo(" ❌ [fail]", err=True)
                invalid_versions.append(ver)
                continue

            fw_json = response.json()
            all_urls = [url["downloadUri"] for url in fw_json["results"]]

            filter_urls, fw_artifacts = [], []
            # Filter out only the correct build_profile and suffix
            for url in all_urls:
                if build_profile in url and url.endswith(suffix):
                    filter_urls.append(url)
            # Use fn-regex to match filenames if available
            if fw_regex:
                fw_artifacts = [url for url in filter_urls if re.findall(fw_regex, url)]
                if len(fw_artifacts) == 1:
                    return fw_artifacts[0]
            # Alternatively use fn-prefix
            tmp_urls = filter_urls if len(fw_artifacts) == 0 else fw_artifacts
            urls = []
            for url in tmp_urls:
                if fw_map["fn-prefix"] in url:
                    urls.append(url)

            if len(urls) != 1:
                log.debug("More than 1 URL matching LATEST version, entry incorrect")
                click.echo(" ❌ [fail]", err=True)
                invalid_versions.append(ver)
                continue

            click.echo(" ✅ [ok]", err=True)
            valid_versions.append(ver)
        except Exception as err:
            click.echo(" ❌ [fail]", err=True)
            log.info("An error occurred checking version '%s' - %s: %s.", ver, type(err).__name__, err)
            log.debug("Traceback: %s", "".join(traceback.format_exception(err)))
            invalid_versions.append(ver)
    result_table_rows = []
    if valid_versions:
        result_table_rows.append(["valid", ",\n".join(valid_versions)])
    if invalid_versions:
        result_table_rows.append(["invalid", ",\n".join(invalid_versions)])
    osrt_cli_tools.utils.print_table(
        rows=result_table_rows, headers=["status", "firmware versions"], ctx=ctx, show_lines=True
    )
    if invalid_versions:
        click.echo("Increase tool verbosity with -vv for more information about invalid versions.", err=True)


def match_serial(location: str | Path, serial: str) -> bool:
    """Helper function to match provided serial to nodes in a given location. Returns True if serial matches any
    nodes in given location.
    """
    # intentionally do not load tb-config, we only need nodes here:
    config = load_file(location)
    serials = [node.get("id") for node in config.get("Nodes")]
    if fnmatch.filter(serials, serial):
        return True


@cli.command
@click.argument("serial", required=True, type=click.STRING)
@click.pass_context
def node_find(ctx, serial):
    """Finds location configs containing the specified node serial.

    Wildcards are allowed in **SERIAL** argument.
    """
    from lib_testbed.generic.util.config import get_config_dir, LOCATIONS_DIR

    locations_path = Path(get_config_dir()) / LOCATIONS_DIR
    all_locations = [loc.absolute() for loc in locations_path.iterdir() if loc.is_file() and loc.suffix == ".yaml"]
    # location_names = sorted([name[:-5] for name in all_locations])  # drop the .yaml extension
    location_futures = {}
    matched_locations = []
    with ProcessPoolExecutor() as ppe:
        for location in all_locations:
            location_futures[location] = ppe.submit(match_serial, location=location, serial=serial)

    for location in location_futures:
        try:
            status = location_futures[location].result()
            if status:
                matched_locations.append(location.name[:-5])
        except Exception as err:
            click.secho(f"Error processing {location}", err=True)
            log.debug("Captured error: %s", "".join(traceback.format_exception(err)))
    osrt_cli_tools.utils.print_table(
        rows=[["locations", ",\n".join(matched_locations)]],
        headers=["", f"node '{serial}'"],
        ctx=ctx,
        show_lines=True,
    )


def get_bash_complete() -> Path:
    """Returns a path to ``config`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "config-complete.bash"
