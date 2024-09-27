"""Testbed config serialization and deserialization utility.

.. warning::
    
    This utility code is supposed to be used only for autocomplete scripts. It will not update
    the cached config files automatically with the config file content change. The changes will
    only be updated when the dumping mechanism is triggered manually.

YAML parsing is very resrouce consuming because of the complexity of YAML specification it takes a lot of resources
to parse YAML files. A lot of resources = a lot of time. To speed things up the yaml file is loaded
once and dumped locally using the Python marshal format. That's by far the fastest Python serialization
mechanism, at the cost of not being cross-interpreter compatible. **Use it with caution, keeping in
mind that it was supposed to only be used for autocomplete of commandline tools.**
"""

import sys
import os
import marshal
import fnmatch
import tempfile
from functools import cache

from pathlib import Path

__show_tool__ = False
"""Indicator for testbed tool to skip help output for the entry points in this module."""


def ensure_cache_dir() -> None:
    """Ensure that cache directory exists."""
    tempdir = tempfile.gettempdir()

    if not (Path(tempdir) / "completions").exists():
        (Path(tempdir) / "completions").mkdir(exist_ok=True)


def dump_config(config_name: str, deployment: str = None):
    """Serializes given tb config yaml into marshal. Skips deployment unless deployment is requested."""
    from lib_testbed.generic.util.config import load_tb_config
    from lib_testbed.generic.util.opensyncexception import OpenSyncException

    try:
        ensure_cache_dir()
        dump_locations()
        if deployment is None:
            tb_config_data = load_tb_config(config_name, skip_deployment=True)
        else:
            tb_config_data = load_tb_config(config_name, deployment_file=deployment)
        config_file_name = f"{config_name}-{deployment}.marshal"
        with open(Path(tempfile.gettempdir()) / "completions" / config_file_name, "wb") as cache_file:
            marshal.dump(tb_config_data, cache_file)
        return tb_config_data
    except OpenSyncException:
        # Could not load tb config. We can pass this error silently since this does not affect anything
        # except for auto-completions.
        return {}


def dump_config_cli():
    """CLI wrapper for caching config/only used as a console script."""
    dump_locations()
    if len(sys.argv) < 2:
        try:
            testbed_name = os.environ["OPENSYNC_TESTBED"]
        except KeyError:  # no testbed, no config to cache for autocomplete
            sys.exit(0)  # exit successfully, nothing to generate
    else:
        testbed_name = sys.argv[1]
    dump_config(testbed_name)


@cache
def load_config(config_name: str = None, deployment: str = None) -> dict | None:
    """Loads deserialized config name from cache."""
    if not config_name:
        config_name = os.environ.get("OPENSYNC_TESTBED", None)
    config_file_name = f"{config_name}-{deployment}.marshal"
    ensure_cache_dir()
    config_path = Path(tempfile.gettempdir()) / "completions" / config_file_name
    if config_name:
        if config_path.exists():
            with open(config_path, "rb") as cache_file:
                return marshal.load(cache_file)
        else:
            return dump_config(config_name=config_name, deployment=deployment)


@cache
def load_locations() -> list[str]:
    """Load the list of all available locations from cache. If cache is not present, try to create it."""
    all_locations_file = Path(tempfile.gettempdir()) / "completions" / "config_locations.marshal"

    if not all_locations_file.is_file():
        dump_locations()

    with open(all_locations_file, "rb") as cache_file:
        return marshal.load(cache_file)


def dump_locations() -> None:
    """Store all available locations to cache. Excluded locations are filtered out."""
    from lib_testbed.generic.util.config import get_config_dir, LOCATIONS_DIR

    locations_path = Path(get_config_dir()) / LOCATIONS_DIR
    all_locations_file = Path(tempfile.gettempdir()) / "completions" / "config_locations.marshal"
    excluded_file = locations_path / "_testbed_reserve_exclude.txt"

    excluded_tbs = None
    if excluded_file.is_file():
        with (locations_path / "_testbed_reserve_exclude.txt").open("rt") as excluded_file:
            excluded_tbs = excluded_file.read().splitlines()

    all_locations = [loc.name for loc in locations_path.iterdir() if loc.is_file() and loc.suffix == ".yaml"]

    if excluded_tbs:
        matched_testbeds = []
        for tb_name in all_locations:
            to_add = True
            for pattern in excluded_tbs:
                if fnmatch.fnmatch(name=tb_name, pat=pattern) or tb_name == pattern:
                    to_add = False
            if to_add:
                matched_testbeds.append(tb_name)

        all_locations = matched_testbeds

    ensure_cache_dir()

    all_locations = [name[:-5] for name in all_locations]  # get rid of .yaml extension
    with open(all_locations_file, "wb") as cache_file:
        marshal.dump(all_locations, cache_file)
