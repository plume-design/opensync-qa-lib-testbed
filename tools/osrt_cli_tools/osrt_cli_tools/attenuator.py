import sys
import traceback
from typing import TYPE_CHECKING
from pathlib import Path

import osrt_cli_tools.utils
from osrt_cli_tools import tb_config_parser
from lib_testbed.generic.util.config import load_tb_config
from lib_testbed.generic.util.logger import log

if osrt_cli_tools.utils.is_autocomplete():
    import click
else:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True

if TYPE_CHECKING:
    from lib_testbed.generic.util.attenuatorlib import AttenuatorLib


def get_attenuator_lib() -> "AttenuatorLib":
    """Return an instance of :py:class:`lib_testbed.generic.util.AttenuatorLib` for the current testbed."""
    # lazy load, slow import:
    from lib_testbed.generic.util.attenuatorlib import AttenuatorLib

    tb_name = osrt_cli_tools.utils.get_testbed_name()
    tb_config = load_tb_config(tb_name)
    return AttenuatorLib(tb_config=tb_config)


def _tab_complete_attenuator_names(ctx, param, incomplete):
    """Return a list of tab-completed attenuator names/attenuation links that can be used with the tool."""
    testbed_name = osrt_cli_tools.utils.get_testbed_name(no_tb_ok=True)
    if not testbed_name:
        return []
    config = tb_config_parser.load_config(testbed_name)
    attenuators = config.get("Attenuators")
    att_names = [att["name"] for att in attenuators if att["name"]] + ["all"]
    links = ["-".join(att["links"]) for att in attenuators if att.get("links")]
    return [x for x in att_names + links if x.startswith(incomplete)]


def process_atenuator_name_arg(ctx, param, value) -> list[str]:
    """Return list attenuator names (str) for provided value or comma-separated list of values.
    The value can either correspond to the name defined in the location config, or to defined attenuation link.
    """
    tb_name = osrt_cli_tools.utils.get_testbed_name()
    tb_config = load_tb_config(tb_name)
    attenuators: list = tb_config.get("Attenuators")

    if not value or value == "all":
        return [att["name"] for att in attenuators]
    if "," in value:
        value = value.split(",")
    else:
        value = [value]
    matched_names = []
    for v in value:
        if v in [att["name"] for att in attenuators]:
            matched_names.append(v)
        elif v in ["-".join(att["links"]) for att in attenuators if att.get("links")]:
            for att in attenuators:
                if v == "-".join(att.get("links")):
                    matched_names.append(att["name"])
    return matched_names


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@osrt_cli_tools.utils.json_option
@osrt_cli_tools.utils.verbosity_option
@osrt_cli_tools.utils.disable_colors_option
@click.pass_context
def cli(ctx, json, verbosity, disable_colors):
    """Attenuator tool."""
    log.debug("Invoking attenuator tool context")
    ctx.ensure_object(dict)
    if not sys.stdout.isatty():
        json = True
    if not ctx.obj.get("JSON"):
        ctx.obj["JSON"] = json
    if not ctx.obj.get("VERBOSITY"):
        ctx.obj["VERBOSITY"] = verbosity
    if not ctx.obj.get("DISABLE_COLORS"):
        ctx.obj["DISABLE_COLORS"] = disable_colors
    osrt_cli_tools.utils.set_log_level(log.WARNING)
    if not osrt_cli_tools.utils.is_autocomplete():
        if ctx.obj.get("VERBOSITY"):
            osrt_cli_tools.utils.set_log_verbosity(ctx.obj["VERBOSITY"])


@cli.command("set")
@click.argument("names", shell_complete=_tab_complete_attenuator_names, callback=process_atenuator_name_arg)
@click.argument("level", type=click.FloatRange(min=0, max=95))
@click.pass_context
def set_(ctx, names, level):
    """Set attenuation **LEVEL** for attenuator with given **NAMES**.

    The **NAMES** argument can be a single name or a comma-separated names or links. Use tab-complete for hints.
    The **LEVEL** must be a number in range 0 to 95, with a 0.25 resolution.
    """
    attenuator_lib = get_attenuator_lib()
    att_action_results = {}
    log.debug("Matched attenuator names: %s", names)
    for name in names:
        log.debug("Setting attenuation to %s dB for attenuator %s", level, name)
        result = None
        try:
            att_link = attenuator_lib.attenuators[name][1]
            att_link = "-".join(att_link) if att_link else ""
            result = attenuator_lib.set_att(name, level)
            att_action_results[f"set-attenuation {name} {att_link}: {level} dB"] = [0, f"{result:.2f} dB", ""]
        except Exception as err:
            att_action_results[f"set-attenuation  {name}: {level} dB"] = result
            log.debug("Captured error: %s", "".join(traceback.format_exception(err)))
            click.secho(
                "Use -vv (multiple v flags) to increase verbosity and get more information about the error.",
                fg="red",
                err=True,
            )

    osrt_cli_tools.utils.print_command_output(ctx, att_action_results)


@cli.command
@click.argument(
    "names", required=False, shell_complete=_tab_complete_attenuator_names, callback=process_atenuator_name_arg
)
@click.pass_context
def get(ctx, names):
    """Get attenuation level status for attenuator with **NAMES**.

    Defaults to all attenuators if no name is given.
    """
    attenuator_lib = get_attenuator_lib()
    outputs = {}
    for name in names:
        level = attenuator_lib.get_att(name)

        att_link = attenuator_lib.attenuators[name][1]
        att_link = "-".join(att_link) if att_link else ""
        outputs[f"get-attenuation {name} {att_link}"] = [0, f"{level:.2f} dB", ""]
    osrt_cli_tools.utils.print_command_output(ctx, outputs)


@cli.command
@click.pass_context
def config_get(ctx):
    """Print out attenuators config."""
    import json

    tb_name = osrt_cli_tools.utils.get_testbed_name()
    tb_config = load_tb_config(tb_name)
    attenuators_section = tb_config.get("Attenuators")

    if not attenuators_section:
        click.secho(f"Attenuators not configured for testbed {tb_name}.", fg="red", err=True)
        sys.exit(1)
    click.secho(json.dumps({"Attenuators": attenuators_section}, indent=2))


@cli.command
@click.pass_context
def names_get(ctx):
    """Get attenuator aliases and links."""
    tb_name = osrt_cli_tools.utils.get_testbed_name()
    tb_config = load_tb_config(tb_name)
    attenuators_section = tb_config.get("Attenuators")
    if not attenuators_section:
        click.secho(f"Attenuators not configured for testbed {tb_name}.", fg="red", err=True)
        sys.exit(1)

    all_attenuators = {}
    for attenuator in attenuators_section:
        all_attenuators[attenuator["name"]] = [0, f"link: {"-".join(attenuator["links"])}", ""]

    osrt_cli_tools.utils.print_command_output(ctx, all_attenuators)


def get_bash_complete() -> Path:
    """Returns a path to ``attenuator`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "attenuator-complete.bash"
