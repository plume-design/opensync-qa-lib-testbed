import os
import pytest
import subprocess
from lib_testbed.generic.util.common import CACHE_DIR
from lib_testbed.generic.util.logger import log


@pytest.fixture(scope="session", autouse=True)
def framework_cache_management(request):
    """Create and maintain framework cache directory"""
    if not os.path.exists(CACHE_DIR):
        log.info("Creating framework cache directory: %s" % CACHE_DIR)
        os.mkdir(CACHE_DIR)

    yield

    # clear cache directory by removing files older than 7 days
    log.info("Cleaning framework cache directory")
    subprocess.call(
        ["find", CACHE_DIR, "-type", "f", "-mtime", "+7", "-not", "-path", f"{CACHE_DIR}/.local*", "-delete"],
        stdout=None,
    )
