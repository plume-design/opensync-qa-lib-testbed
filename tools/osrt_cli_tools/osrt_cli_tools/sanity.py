import os
import sys
from pathlib import Path

from lib_testbed.generic.util.logger import log
from osrt_cli_tools.utils import is_autocomplete

if is_autocomplete():
    import click
else:
    import rich_click as click

    click.rich_click.SHOW_ARGUMENTS = True
    click.rich_click.USE_MARKDOWN = True


def get_sanity_tool_object(outstyle, outfile=None):
    """Lazy load sanity tool object"""
    from lib_testbed.generic.util.sanity.sanity import Sanity

    return Sanity(outfile=outfile, outstyle=outstyle)


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option(
    "--dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    default=os.getcwd(),
    show_default=True,
    help="Directory on which sanity tool is executed, defaults to current working directory.",
)
@click.option("--simple-output", is_flag=True, default=False, help="Print output without colors.")
@click.option(
    "--file",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="Run sanity check against an ovsdb json dump file.",
)
def cli(dir, simple_output, file):
    """Sanity checker tool."""
    log.debug("Entering sanity tool context")
    outstyle = "simple" if simple_output else "full"
    santool = get_sanity_tool_object(outstyle=outstyle)
    if file:
        click.echo(f"Sanity check for: {file}")
        ev = santool.sanity_single(file)
    else:
        click.echo(f"Sanity check for: {dir}")
        ev = santool.sanity_location(dir)
    sys.exit(int(not ev["ret"]))


def get_bash_complete() -> Path:
    """Returns a path to ``sanity`` bash autocomplete script."""
    # Each tool should define a function returning path to its autocomplete script location.
    return Path(__file__).parent / ".." / "autocomplete_scripts" / "sanity-complete.bash"
