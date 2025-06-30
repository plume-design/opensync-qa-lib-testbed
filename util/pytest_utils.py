import pytest
import xdist
from filelock import FileLock, Timeout

from lib_testbed.generic.util.common import CACHE_DIR
from lib_testbed.generic.util.logger import log

from _pytest.mark import MarkDecorator

XDIST_STATUS_PATH = CACHE_DIR / "xdist"


def add_custom_mark(config, item, mark):
    if isinstance(mark, MarkDecorator):
        mark_name = mark.markname
    else:
        mark_name = str(mark)
    # register the mark only if it hasn't been registered before
    if not any(m.startswith(mark_name) for m in config.inicfg.get("markers", [])):
        config.addinivalue_line("markers", mark_name)
    if item:
        item.add_marker(mark)


def change_nextitem_parent(item, nextitem):
    """Force to call teardown class. It's done by removing parent that includes Class object in nextitem.
    Then, in teardown_exact method, the current stack is tor down until reaching nodes that nextitem
    also descends from - in this case teardown will be called in scope function and class.
    """
    _item = None
    parent = nextitem
    if nextitem and item.parent == nextitem.parent:
        while parent is not None:
            _item = parent
            parent = parent.parent
            if str(parent).startswith("<Class"):
                _item.parent = parent.parent
                return _item, parent
    return None, None


def safe_exit_pytest(request, msg: str):
    """Safely exit from pytest session/xdist worker.

    Calling :py:func:`pytest.exit` from within xdist worker closes the whole pytest session, so it shouldn't ever
    be called from a pytest session considering that we're using our own LoadScope scheduler. Calling this function
    instead, is safe, and should result with the worker being closed safely and all remaining tests being re-distributed
    across all other/remaining nodes/testbeds.

    .. warning::

        This function only works properly when combined with tb-configurator plugin, where the actual
        xdist exit is implemented in the ``pytest_runtest_logreport`` hook.
    """
    if not xdist.is_xdist_worker(request):
        log.error("Exiting pytest due to: %s", msg)
        pytest.exit(msg)
    else:
        workerid = request.config.workerinput.get("workerid", "unknown")
        log.error("Xdist worker %s failed, will be shutting down worker due to: %s", workerid, msg)
        lock_path = XDIST_STATUS_PATH / (workerid + ".lock")
        status_path = XDIST_STATUS_PATH / workerid
        lock = FileLock(lock_path, timeout=5)
        try:
            with lock:
                with open(status_path, "wt") as status_file:
                    status_file.write("FAILED")
        except Timeout:
            log.error("Could not pass error status to the controller process.")
