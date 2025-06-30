import pytest

from lib_testbed.generic.util.common import threaded, is_unit_test
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.allure_util import MyAllureListener


POD_FIXTURE_NAMES = ["gw", "l1", "l2"]


@threaded
def kernel_log_test_start(pods, item, tr):
    """Start test with logging test id for given test case."""
    parametrize_id = item.callspec.id if hasattr(item, "callspec") else ""
    msg = f"Autotestrunner {tr.strip()}"
    if parametrize_id:
        msg += f", parametrized with: {parametrize_id}"
    pods.run(f'echo "{msg}" > /dev/kmsg', skip_exception=True, skip_logging=True, retry=0, timeout=5)


def pytest_runtest_protocol(item, nextitem):
    """Print test case separator for allure-step approach.
    For test classes separator is printed by `lib.util.base_case.py`."""

    def _print_test_case_separator():
        indent = 4
        separator = "#"
        title = _get_title(item)
        automatics = ""
        if tc_ := next((m for m in item.iter_markers() if m.name.startswith("TC_")), None):
            automatics = f"{indent * ' '}Automatics: {tc_.name}\n"
        tr = _get_qase_id_separator(item)

        log.info(
            f"\n\n{80 * separator}\n"
            f"{indent * ' '}Test case: \"{title}\"\n"
            f"{tr}"
            f"{automatics}"
            f"{80 * separator}",
            show_file=False,
        )

    if not getattr(item, "cls", None):
        # allure.step approach test case separator printer
        _print_test_case_separator()


@pytest.fixture(autouse=True)
def print_test_separator(request):
    """
    Print test method separator for test class approach.
    For allure-steps separator is printed by `start_step()` hook.
    """

    def _print_test_method_separator():
        indent = 8
        separator = "~"
        if not hasattr(request.cls, "_item") or not hasattr(request.cls._item, "own_markers"):
            return
        # skip unit tests, which often to not have titles
        if "gen_unit_test" in [mark.name for mark in request.cls._item.own_markers]:
            return
        name = request.cls._item.nodeid if hasattr(request.cls, "_item") else ""
        title = request.cls._get_title(request.cls._item._obj, name)
        log.info(
            f"\n\n{80 * separator}\n" f"{indent * ' '}Test method: \"{title}\"\n" f"{80 * separator}", show_file=False
        )

    def log_kernel_separator():
        if is_unit_test(request._pyfuncitem.own_markers):
            return
        # only add kernel entry for tests not marked as unit tests:
        tr = _get_qase_id_separator(request.node)
        pods = get_dut_objects(request)
        if pods is None or not pods.obj_list:
            return
        future = kernel_log_test_start(pods, request._pyfuncitem, tr)
        try:
            future.result()  # joins thread
        except Exception:
            # intentionally ignore catastrophic errors, this is a nice-to-have
            return

    if hasattr(request, "cls") and request.cls:
        # class based approach test method separator printer
        _print_test_method_separator()
    else:
        log_kernel_separator()


def _get_qase_id_separator(item, indent: int = 4) -> str:
    tr = ""
    if qase_id := next((m for m in item.iter_markers() if m.name == "qase_id"), None):
        tr = qase_id.kwargs.get("id", "")
    tr = f"{indent * ' '}TC ID: {tr}\n" if tr else ""
    return tr


def _get_title(item) -> str:
    name = "::".join(item.nodeid.split("::")[0:2]) if hasattr(item, "nodeid") else ""
    title = MyAllureListener.get_allure_title(item)
    if not title:
        title = f"Missing allure title for test: {name}"
    param_id = " [" + item.callspec.id + "]" if hasattr(item, "callspec") else ""
    return title + param_id


def get_dut_objects(request):
    try:
        pods_obj = request.getfixturevalue("_pods_object")
    except Exception:
        return None
    dut_objects = []
    for pod_fixture_name in POD_FIXTURE_NAMES:
        if pod_fixture_name not in request.fixturenames:
            continue
        try:
            dut_objects.append(request.getfixturevalue(pod_fixture_name))
        except pytest.FixtureLookupError:
            continue
    return pods_obj.use_devices(dut_objects)
