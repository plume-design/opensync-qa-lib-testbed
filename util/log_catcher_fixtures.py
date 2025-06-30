import pytest
from lib_testbed.generic.util.logger import LogCatcher


class LogCatcherContainer:
    def __init__(self, thread_jobs: list, collected_objs: list, results_dict: dict):
        self.thread_jobs = thread_jobs
        self.collected_objs = collected_objs
        self.results_dict = results_dict


def _start_log_catcher(
    opensync_obj, configuration_name: str, failed: bool, has_steps: bool, scope: str, log_catcher_objs: list
):
    # Consider multi-objects as single object
    obj_list = opensync_obj.obj_list if hasattr(opensync_obj, "obj_list") else [opensync_obj]
    for obj in obj_list:
        # Don't call collect twice for the same object
        if is_log_catcher_started(obj, log_catcher_objs):
            continue
        thread_jobs, collected_objs, results_dict = LogCatcher.collect_logs_in_thread(
            opensync_obj=[obj],
            configuration_name=configuration_name,
            failed=failed,
            has_steps=has_steps,
            scope=scope,
        )
        log_catcher_objs.append(LogCatcherContainer(thread_jobs, collected_objs, results_dict))


def is_log_catcher_started(opensync_obj, log_catcher_objs: list) -> bool:
    collected_object = next(filter(lambda obj: opensync_obj in obj.collected_objs, log_catcher_objs), None)
    return True if collected_object else False


@pytest.fixture(scope="session")
def log_catcher_session():
    """Collect logs for given opensync objects, session-scoped.
    Log collection is initialized per `lib_testbed.generic.util.fixture_utils` module."""
    log_catcher_objs = list()

    def _log_catcher_session(opensync_obj, configuration_name: str, failed: bool, has_steps: bool, scope: str):
        _start_log_catcher(opensync_obj, configuration_name, failed, has_steps, scope, log_catcher_objs)

    yield _log_catcher_session
    for log_catcher_obj in log_catcher_objs:
        LogCatcher.attach_logs(
            log_catcher_obj.thread_jobs, log_catcher_obj.collected_objs, log_catcher_obj.results_dict
        )


@pytest.fixture(scope="package")
def log_catcher_package():
    """Collect logs for given opensync objects, package-scoped.
    Log collection is initialized per `lib_testbed.generic.util.fixture_utils` module."""
    log_catcher_objs = list()

    def _log_catcher_package(opensync_obj, configuration_name: str, failed: bool, has_steps: bool, scope: str):
        _start_log_catcher(opensync_obj, configuration_name, failed, has_steps, scope, log_catcher_objs)

    yield _log_catcher_package
    for log_catcher_obj in log_catcher_objs:
        LogCatcher.attach_logs(
            log_catcher_obj.thread_jobs, log_catcher_obj.collected_objs, log_catcher_obj.results_dict
        )


@pytest.fixture(scope="module")
def log_catcher_module():
    """Collect logs for given opensync objects, module-scoped.
    Log collection is initialized per `lib_testbed.generic.util.fixture_utils` module."""
    log_catcher_objs = list()

    def _log_catcher_module(opensync_obj, configuration_name: str, failed: bool, has_steps: bool, scope: str):
        _start_log_catcher(opensync_obj, configuration_name, failed, has_steps, scope, log_catcher_objs)

    yield _log_catcher_module
    for log_catcher_obj in log_catcher_objs:
        LogCatcher.attach_logs(
            log_catcher_obj.thread_jobs, log_catcher_obj.collected_objs, log_catcher_obj.results_dict
        )


@pytest.fixture(scope="function")
def log_catcher_function():
    """Collect logs for given opensync objects, function-scoped.
    Log collection is initialized per `lib_testbed.generic.util.fixture_utils` module."""
    log_catcher_objs = list()

    def _log_catcher_function(opensync_obj, configuration_name: str, failed: bool, has_steps: bool, scope: str):
        _start_log_catcher(opensync_obj, configuration_name, failed, has_steps, scope, log_catcher_objs)

    yield _log_catcher_function
    for log_catcher_obj in log_catcher_objs:
        LogCatcher.attach_logs(
            log_catcher_obj.thread_jobs, log_catcher_obj.collected_objs, log_catcher_obj.results_dict
        )
