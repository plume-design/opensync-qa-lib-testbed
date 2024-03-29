import sys

from lib_testbed.generic.util.logger import log, LogCatcher
from pytest import CollectReport, StashKey

phase_report_key = StashKey[dict[str, CollectReport]]()
""" This variable holds the item stash key, to be imported and used within fixtures.
    The report contains either "setup", "call" or "teardown".

    Example code using test result for a recovery:

    .. code-block:: py

        @pytest.fixture
        def something(request):
            yield
            report = request.node.stash[phase_report_key]
            if "call" in report and report["call"].failed:
                # handle failed test/recovery here
                log.info("Handling test call failed")
"""


class safe_setup:
    """
    Ensure that teardown is called even if setup fails
    """

    def __init__(self, obj, scope, request=None):
        self.obj = obj
        self.main_obj = obj.obj if isinstance(obj, OSRTFixtureTestObject) else obj
        self.scope = scope
        # forcing obj._request name to indicate that if this attribute should not be used
        # whenever possible:
        self.request = self.main_obj._request = request

    def __enter__(self):
        self.obj.setup(self.scope, self.request)
        return self.main_obj

    def __exit__(self, exc_type, exc_value, tb):
        setup_exception = {"exc_type": exc_type, "exc_value": exc_value, "tb": tb} if exc_type else None
        teardown_exception = None
        try:
            self.obj.teardown(self.scope, self.request)
        except Exception:
            teardown_exception = sys.exc_info()
            raise
        finally:
            nickname = self.obj.get_nickname()
            try:
                failed = self.is_failed(self.scope, self.request, setup_exception, teardown_exception)
            except Exception:
                log.exception("Failed to check failure state!")
                failed = True
            try:
                has_steps = self.has_steps(self.scope, self.request, setup_exception, teardown_exception)
            except Exception:
                log.exception("Failed to check whether test has steps!")
                has_steps = False
            LogCatcher.attach_logs(
                opensync_obj=[self.main_obj],
                configuration_name=nickname,
                failed=failed,
                has_steps=has_steps,
                scope=self.scope,
            )

    @staticmethod
    def is_failed(scope, request, setup_exception, teardown_exception):
        if not request or request.config.option.skip_init or request.config.option.skip_logs:
            return False
        if setup_exception or teardown_exception:
            return True
        if (
            scope == "function"
            and hasattr(request, "node")
            and hasattr(request.node, "stash")
            and (stash := request.node.stash)
        ):
            for when, test_report in stash[phase_report_key].items():
                if test_report.failed:
                    return True
                elif hasattr(test_report, "wasxfail") and test_report.wasxfail:
                    return True
                # Don't consider test_report.skipped as failure
        # TODO: Fix detecting failure for scopes: method, package and session for sub-fixture/parent-fixture failure
        return False

    @staticmethod
    def has_steps(scope, request, setup_exception, teardown_exception):
        """Returns True if the given test had steps."""
        if not request or request.config.option.skip_init or request.config.option.skip_logs:
            return False
        if setup_exception or teardown_exception:
            return False
        if item := getattr(request, "_pyfuncitem", None):
            for plugin in request.config.pluginmanager.get_plugins():
                if plugin.__class__.__name__ == "MyAllureListener":
                    allure_listener = plugin
                    break
            uuid = allure_listener._cache.get(item.nodeid)
            if (test := allure_listener.allure_logger.get_test(uuid)) and test.steps:
                return True
        return False


class OSRTFixtureTestObject:
    """Helper class to streamline setup/teardown calls for various
    OSRT objects."""

    def __init__(self, obj):
        self.obj = obj

    def setup(self, scope, request):
        self.obj.all_markers = list(request.node.iter_markers())
        match scope:
            case "class" | "module" | "package" | "session":
                if hasattr(self.obj, "setup_class_handler"):
                    self.obj.setup_class_handler(request=request)
            case "function":
                if hasattr(self.obj, "setup_method_handler"):
                    self.obj.setup_method_handler(request=request)
            case _:
                raise ValueError(f"Scope {scope} not expected")

    def teardown(self, scope, request):
        match scope:
            case "class" | "module" | "package" | "session":
                if hasattr(self.obj, "teardown_class_handler"):
                    self.obj.teardown_class_handler(request=request)
            case "function":
                if hasattr(self.obj, "teardown_method_handler"):
                    self.obj.teardown_method_handler(request=request)
            case _:
                raise ValueError(f"Scope {scope} not expected")

    def get_nickname(self):
        """Call the method ``get_nickname`` on the :py:attr:`OSTRFixtureTestObject.obj`.
        If the object does not implement the method, return a lambda call to the object
        ``__name__`` attribute.

        At the time of implementation, rpower and switch objects do not implement the
        ``get_nickname()`` interface."""
        try:
            return self.obj.get_nickname()
        except AttributeError:
            return lambda: self.obj.__name__
