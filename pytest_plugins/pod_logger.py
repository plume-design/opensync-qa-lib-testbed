import pytest

from lib_testbed.generic.util.common import threaded, skip_exception
from lib_testbed.generic.util.logger import log, LogCatcher
from lib_testbed.generic.pytest_plugins.separator_printer import get_dut_objects


@pytest.hookimpl
def pytest_addoption(parser):
    """Register logging options."""
    parser.addoption(
        "--attach-syslog",
        help="Attach syslog to allure for every pod used in a test case.",
        default=False,
        action="store_true",
    )


@threaded
@skip_exception(Exception)
def get_pod_cursor(pod) -> float:
    """Return cursor for a single pod."""
    return pod.msg.get_cursor()


@threaded
@skip_exception(Exception)
def download_logs_from_pod(pod, cursor):
    """Download and return logs from specified pods for provided cursor."""
    return pod.msg.get_service_log(cursor=cursor)


@threaded
@skip_exception(Exception)
def attach_logs(pod, log_catcher, captured_log):
    """Attach captured log file to pod allure report."""
    log_str = ""
    for line in captured_log:
        timestamp = line.get("date_timestamp")
        module = line.get("module", " ")
        if module == "Unknown":
            module = " "
        severity = line.get("severity", " ")
        if severity == "Unknown":
            severity = " "
        value = line.get("value")
        log_line = f"{timestamp}\t{module}\t{severity}\t{value}\n"
        log_str += log_line
    log_catcher.add_to_logs(log_str, name=f"syslog_{pod.nickname}")


@pytest.fixture(autouse=True, scope="function")
def nodes_syslog(tb_config, request: pytest.FixtureRequest):
    """Attach syslog to allure report for every test function, for every node - as long as its fixture is used by test."""
    if not request.config.option.attach_syslog:
        yield None
    else:
        log_catcher = LogCatcher(default_name="syslog_gw")
        log_catcher.initial_logger(name="syslog_gw")
        log_catcher.initial_logger(name="syslog_l1")
        log_catcher.initial_logger(name="syslog_l2")
        try:
            # this is required to make sure that the classes are with DUT fixtures associated already
            request.getfixturevalue("pods_fixtures_autouse")
        except pytest.FixtureLookupError:
            pass
        log.info("Starting to collect messages on nodes")
        dut_objects = get_dut_objects(request)
        # drop not initialized objects/None
        dut_obj_list = [x for x in dut_objects.obj_list if x is not None]
        log.debug("Storing syslog for %s", [x.nickname for x in dut_obj_list])
        cursor_futures, cursors = {}, {}
        for pod in dut_obj_list:
            cursor_futures[pod.nickname] = get_pod_cursor(pod)
        for pod in dut_obj_list:
            cursors[pod.nickname] = cursor_futures[pod.nickname].result()
        yield
        log_futures, logs = {}, {}
        log.info("Downloading logs from all nodes used in test function '%s'", request._pyfuncitem.name)
        for pod in dut_obj_list:
            log_futures[pod.nickname] = download_logs_from_pod(pod, cursors[pod.nickname])
        for pod in dut_obj_list:
            logs[pod.nickname] = log_futures[pod.nickname].result()
        log.debug("Attaching logs to report")
        attach_futures = []
        for pod in dut_obj_list:
            attach_futures.append(attach_logs(pod, log_catcher, logs[pod.nickname]))
        for future in attach_futures:
            future.result()
        log_catcher.attach_to_allure([log_catcher.loggers])
