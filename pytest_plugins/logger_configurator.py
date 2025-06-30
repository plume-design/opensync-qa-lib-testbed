"""Pytest OpenSync test framework logger configuration. It exposes log configuration to the users.

It sets the desired log levels at the start of pytest session.
"""

import logging
import pytest

from lib_testbed.generic.util.logger import log


@pytest.hookimpl
def pytest_addoption(parser):
    """Register logging options."""
    parser.addoption(
        "--log-level-file",
        help="Log file level to be specified. It can accept the value 'critical', 'error', 'warning', "
        "'info', 'debug' or 'trace'. Defaults to None (no log level at all). When provided, it will log file name "
        "on the console",
        default=None,
    )
    parser.addoption(
        "--log-level-console",
        help="Log console level to be specified by the user. It can accept the value 'critical', 'error', 'warning', "
        "'info', 'debug' or 'trace'. Defaults to 'info'.",
        default="info",
    )


def _check_log_level_value(value: str):
    if value and value not in ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"]:
        raise ValueError(f"Provided value {value} is not a valid log level name.")


@pytest.hookimpl
def pytest_sessionstart(session):
    """Configure log levels based on provided configuration."""
    log_level_console = session.config.getoption("log_level_console")
    log_level_file = session.config.getoption("log_level_file")
    if isinstance(log_level_file, str):
        log_level_file = log_level_file.upper()
    log_level_console = log_level_console.upper()
    _check_log_level_value(log_level_file)
    _check_log_level_value(log_level_console)
    if log_level_file:
        log.ensure_file_handler()  # the file path will not print so early into pytest run

    # we need to prevent getattr from throwing AttributeError in case log_level_file is of type None:
    file_level = None if log_level_file is None else getattr(log, log_level_file, None)
    log.set_log_levels(console_level=getattr(log, log_level_console, None), file_level=file_level)


@pytest.hookimpl
def pytest_collection_finish():
    """Print out log file name IF any handlers are present after all tests have been collected."""
    file_handlers = [hnd for hnd in log.handlers if isinstance(hnd, logging.FileHandler)]
    for handle in file_handlers:  # theoretically there might be multiple handlers, let's log all of them
        log.info("Log file path: %s", handle.baseFilename)
