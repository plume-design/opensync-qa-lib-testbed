import hashlib
import os
import json
import jproperties
import logging

from collections.abc import Iterable
from typing import Literal
from filelock import FileLock
from allure_pytest.listener import AllureListener
from allure_pytest.utils import allure_title
from allure_commons import hookimpl
from allure_commons.types import AttachmentType
from allure_commons.model2 import Parameter, Label
from allure_commons.utils import represent, SafeFormatter
from lib_testbed.generic.util.common import BASE_DIR, CACHE_DIR, get_modified_params
from lib_testbed.generic.util.common import is_jenkins, SKIP_RESULT
from lib_testbed.generic.util.logger import log, LOGGER_NAME, AllureLogger

# Disable info logs for filelock module
logging.getLogger("filelock").setLevel(logging.ERROR)


class AllureUtil:
    """Acts as a global, process-wide cache for information about testing environment.

    Used for often needed information about cloud and testbed components that is relatively expensive to retrieve,
    but doesn't (or at least shouldn't) change during the test run. The collected information also gets attached
    to test reports.
    """

    # Global cache for testing environment information. Keys in the cache are always strings, while values
    # can be either strings or dictionaries with the same restrictions.
    _environment_info: dict[str, str | dict] = {}

    def __init__(self, config):
        self.config = config
        option_config = config.option.config_name if "config_name" in config.option else None
        if location_file := getattr(config, "tb_config", {}).get("location_file"):
            self.testbed = os.path.basename(location_file).split(".")[0]
        elif option_config:
            self.testbed = option_config
        else:
            self.testbed = "<unknown>"
        self.lock_timeout = 120
        result_dir = self._get_results_dir()
        os.makedirs(result_dir, exist_ok=True)
        self.cache_environment_value("config", self.testbed)
        # these lines are for debugging CI purposes, feel free to remove them
        job_name = os.environ.get("JOB_NAME", "not_jenkins").replace("/", "_")
        job_file_build_id = os.path.join(result_dir, job_name)
        if not os.path.exists(job_file_build_id):
            build_url = os.environ.get("BUILD_URL", None)
            with open(job_file_build_id, "wt") as job_file:
                job_file.write(f"{job_name}\n{build_url}\n")

    def _get_results_dir(self):
        report_dir = self.config.option.allure_report_dir
        if not report_dir:
            # this check for jenkins is temporary, should be removed in the future
            report_dir = os.path.join(BASE_DIR, "allure-results") if is_jenkins() else "%s/allure-results" % CACHE_DIR
        return report_dir

    def _get_properties_path(self):
        allure_dir = self._get_results_dir()
        if not allure_dir:
            raise Exception("Missing pytest option --alluredir")
        return os.path.join(allure_dir, "environment.properties")

    def _get_lock_file(self):
        return f"{self._get_properties_path()}.lock"

    def _read_properties(self, properties):
        with open(self._get_properties_path(), "rb") as configfile:
            properties.load(configfile, encoding="utf-8")

    def _write_properties(self, properties):
        with open(self._get_properties_path(), "wb") as configfile:
            properties.store(configfile, encoding="utf-8")

    def _init(self):
        # Clear the properties file first.
        open(self._get_properties_path(), "w")
        return self._init_and_read_properties()

    def init_categories(self):
        categories_path = os.path.join(self._get_results_dir(), "categories.json")
        if not os.path.exists(categories_path):
            data = [{"name": "Detected issues", "messageRegex": ".*Detected issue.*", "matchedStatuses": ["skipped"]}]
            with open(categories_path, "w") as fh:
                fh.write(json.dumps(data))

    def init(self):
        """Called by xdist autouse fixture, only in the main pytest process."""
        with FileLock(self._get_lock_file(), timeout=self.lock_timeout):
            if "allure_keep_env" not in self.config.option or not self.config.option.allure_keep_env:
                self._init()
            else:
                self._init_and_read_properties()
            self.init_categories()

    def _init_and_read_properties(self):
        if not os.path.exists(self._get_properties_path()):
            return self._init()
        properties = jproperties.Properties()
        self._read_properties(properties)
        return properties

    @staticmethod
    def get_allure_plugin(session_config):
        for plugin in session_config.pluginmanager._name2plugin.values():
            # pytest assigns random number to plugin name, so we're using class name
            if plugin.__class__.__name__ == "MyAllureListener":
                return plugin

    def get_cached_environment_value(self, name: str) -> str | dict | None:
        """Get information about testing environment from process-wide cache.

        Return `None` if `name` information hasn't been cached yet.
        """
        return self._environment_info.get(name)

    def cache_environment_value(self, name: str, value: str | dict) -> str | dict:
        """Store information about testing environment in process-wide cache.

        Return the canonical cached value, which needs to get used to prevent races.
        """
        return self._environment_info.setdefault(name, value)

    def _get_testbed_cache(self) -> dict:
        return self._environment_info.setdefault("testbed", {}).setdefault(self.testbed, {})

    def get_cached_testbed_value(self, name: str) -> str | dict | None:
        """Get information about testbed from process-wide cache.

        Return `None` if `name` information hasn't been cached yet.
        """
        return self._get_testbed_cache().get(name)

    def cache_testbed_value(self, name: str, value: str | dict) -> str | dict:
        """Store information about testbed in process-wide cache.

        Return the canonical cached value, which needs to get used to prevent races.
        """
        return self._get_testbed_cache().setdefault(name, value)

    def get_cached_node_value(self, node_id: str, name: Literal["model", "version", "region", "modules"]) -> str | None:
        """Return cached model, version, region for node with `nide_id` serial or `None` if not yet in cache."""
        nodes_cache = self._get_testbed_cache().setdefault("node", {})
        for node_cache in nodes_cache.values():
            if node_cache.get("serial") == node_id:
                return node_cache.get(name)
        return None

    def cache_node_value(self, node, name: Literal["serial", "model", "version", "region", "modules"]) -> str | None:
        """Return serial, model, version or region info about a node and cache it if not already cached.

        `node` needs to be a `PodApi` object.
        """
        node_cache = self._get_testbed_cache().setdefault("node", {}).setdefault(node.nickname, {})
        if name in node_cache:
            return node_cache[name]
        value = None
        if name == "serial":
            value = node.serial
        elif name == "model":
            value = node.model
        elif name == "version":
            value = node.version(skip_exception=True)
        elif name == "region":
            value = node.get_region(skip_exception=True)
        elif name == "modules":
            value = node.module_versions(skip_exception=True)
        else:
            raise ValueError(f"unsupported cached node info: '{name}'")
        if value is not None:
            # Node's firmware version and region can in theory change, but all tests
            # must restore them in cleanup, so we can treat them as constant.
            value = node_cache.setdefault(name, value)
        return value

    def cache_client_value(self, client, name: Literal["version", "hw_info", "region"]) -> str | None:
        """Return version, hw_info or region info about a client and cache it if not already cached.

        `client` needs to be a `ClientApi` object.
        """
        client_cache = self._get_testbed_cache().setdefault("client", {}).setdefault(client.nickname, {})
        if name in client_cache:
            return client_cache[name]
        value = None
        if name == "version":
            value = client.version()
        elif name == "hw_info":
            value = client.hw_info()
        elif name == "region":
            value = client.get_region(skip_exception=True)
        else:
            raise ValueError(f"unsupported cached client info: '{name}'")
        if value is not None:
            # Client's region can change, but we capture it at the end of tests anyway, so treat it as constant.
            value = client_cache.setdefault(name, value)
        return value

    def get_cached_cloud_value(self, name: str) -> str | None:
        """Get information about cloud from process-wide cache.

        Return `None` if `name` information hasn't been cached yet.
        """
        return self._environment_info.setdefault("cloud", {}).get(name)

    def cache_cloud_value(self, cloud, name: str) -> str | None:
        """Return deployment or version info about cloud and cache it if not already cached.

        `cloud` needs to be a `CloudBase` object.
        """
        cloud_cache = self._environment_info.setdefault("cloud", {})
        cloud_cache.setdefault("noc_url", cloud._config["noc_url"])
        if name in cloud_cache:
            return cloud_cache[name]
        if name == "deployment":
            cloud_info = {"deployment": cloud._config["deployment_id"]}
        else:
            from lib.util.common import get_cloud_version

            cloud_info = get_cloud_version(cloud)
            cloud_info["version"] = cloud_info.get("cloud_version", "")
        for n, v in cloud_info.items():
            cloud_cache.setdefault(n, v)
        return cloud_cache.get(name)

    def cache_web_value(self, location: str, name: str, value: str, root_url: str) -> str | None:
        """Cache information about web location, if not already cached, and return it."""
        location_cache = self._environment_info.setdefault("web", {}).setdefault(location, {})
        if name in location_cache:
            return location_cache[name]
        return location_cache.setdefault(name, value)

    def flatten_environment_info(self) -> dict[str, str]:
        """
        Return the complete cached testing environment info collected so far in a flattened `str->str` dict.

        Dictionary typed values get prefixed with their parent keys, e.g.::

            {'a': 'b', 'c': {'d': 'e', 'f': 'g'}}

        would get converted to:

            {'a': 'b', 'c.d': 'e', 'c.f': 'g'}

        The returned dictionary can be serialized as a .properties file.
        """
        return dict(sorted(self._flatten_environment_info(self._environment_info, "")))

    def _flatten_environment_info(self, info: dict, prefix: str) -> Iterable[tuple[str, str]]:
        for name, value in info.items():
            qualified_name = f"{prefix}.{name}" if prefix else name
            if isinstance(value, dict):
                for qn, v in self._flatten_environment_info(value, qualified_name):
                    yield qn, v
            elif not isinstance(value, str):
                log.warning(f"AllureUtil: {qualified_name} contains unexpected value of type {type(value)}")
                yield qualified_name, str(value)
            else:
                yield qualified_name, value

    def summarize_environment_info(self) -> dict[str, object]:
        """Return the most often used testing environment information collected so far.

        Returns dict with the following items:
            cloud_version: (str) cloud matrix version
            deployment: (str) cloud deployment
            node_models: (set[str]) all models of nodes cached so far
            node_versions: (set[str]) all firmware versions of nodes cached so far
            testbeds: (set[str]) all testbeds cached so far
        """
        summary = {}
        summary["cloud_version"] = self.get_cached_cloud_value("version") or ""
        summary["deployment"] = self.get_cached_cloud_value("deployment") or ""
        summary["node_models"] = node_models = set()
        summary["node_versions"] = node_versions = set()
        summary["testbeds"] = testbeds = set()
        config = self.get_cached_environment_value("config")
        if config is not None:
            testbeds.update(config.split(","))
        for tb_name, tb_cache in self._environment_info.get("testbed", {}).items():
            testbeds.add(tb_name)
            for node_cache in tb_cache.get("node", {}).values():
                if "model" in node_cache:
                    node_models.add(node_cache["model"])
                if "version" in node_cache:
                    node_versions.add(node_cache["version"])
        return summary

    def save_cached_environment_info(self):
        """Save testing environment information collected so far in Allure's environment.properties file."""
        with FileLock(self._get_lock_file(), timeout=self.lock_timeout):
            properties = self._init_and_read_properties()
            properties.update(self.flatten_environment_info())
            self._write_properties(properties)


class MyAllureListener(AllureListener):
    import pytest

    def __init__(self, config):
        self.last_error = None
        self.test_result_parameters = {}  # additional test parameters visible in allure
        self.callbacks = []
        self.deregister_on_teardown = False
        self.step_idx = 1
        super().__init__(config)

    @hookimpl
    def start_step(self, uuid, title, params):
        def _print_test_step_separator():
            indent = 8
            separator = "~"
            step_idx = str(self.step_idx).zfill(2)
            log.info(
                f"\n\n{80 * separator}\n" f"{indent * ' '}Test step {step_idx}: \"{title}\"\n" f"{80 * separator}",
                show_file=False,
            )

        super().start_step(uuid, title, params)
        _print_test_step_separator()
        self.step_idx += 1

    @hookimpl
    def stop_step(self, uuid, exc_type, exc_val, exc_tb):
        logger = logging.getLogger(LOGGER_NAME)
        handler = next(h for h in logger.handlers if type(h) is AllureLogger)
        self.attach_data(
            handler.get_logs_and_clear_buffer(),
            name="log",
            attachment_type=AttachmentType.TEXT,
            extension="txt",
        )
        super().stop_step(uuid, exc_type, exc_val, exc_tb)

    @staticmethod
    def get_test_class_path(node_id):
        return "::".join(node_id.split("::")[:-1])

    @staticmethod
    def is_xfailed(test_result):
        if test_result.status == "skipped" and "XFailed" in test_result.statusDetails.message:
            return True
        return False

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_setup(self, item):
        self.deregister_on_teardown = False
        # overwritten to add custom test parameters
        yield from super().pytest_runtest_setup(item)
        uuid = self._cache.get(item.nodeid)
        test_result = self.allure_logger.get_test(uuid)

        params = get_modified_params(item)
        for i, (param_key, param_value) in enumerate(params.items()):
            if test_result_param := next((param for param in test_result.parameters if param.name == param_key), None):
                test_result_param.value = represent(param_value)

        if title := self.get_allure_title(item):
            # Override allure title implementation to use parametrize id instead of parametrize value
            test_result.name = title

        if qase_id_marker := item.get_closest_marker("qase_id"):
            qase_id = qase_id_marker.kwargs.get("id")
            # expose qase id in the output csv file (using description)
            if qase_id:
                test_result.description = str(qase_id)

        # Update allure test_result parameters with self.test_result_parameters
        test_result.parameters.extend(
            [Parameter(name=name, value=represent(value)) for name, value in self.test_result_parameters.items()]
        )

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_teardown(self, item):
        uuid = self._cache.get(item.nodeid)
        test_result = self.allure_logger.get_test(uuid)

        skip_item = False
        if test_result.status == "skipped" and SKIP_RESULT in item.test_report.longreprtext:
            skip_item = True
        if skip_item:
            yield
            uuid = self._cache.get(item.nodeid)
            self._cache.pop(item.nodeid)
            self.allure_logger.drop_test(uuid)
            self.clean_callbacks()
            return

        # overwritten to add custom test parameters
        yield from super().pytest_runtest_teardown(item)
        uuid = self._cache.get(item.nodeid)
        test_result = self.allure_logger.get_test(uuid)

        session_config = item.session.config
        if hasattr(session_config, "workerinput"):
            extra_parameters = dict()
            config_name = None
            worker = session_config.workerinput["workerid"]
            if "tb_config" in item.funcargs:
                config_name = item.funcargs["tb_config"].get("user_name", "")
            elif hasattr(item, "cls") and hasattr(item.cls, "tb_config"):
                config_name = item.cls.tb_config.get("user_name", "")
            if config_name and "--dist=each" in session_config.workerinput["mainargv"]:
                # Display test results separately for each testbed
                config_hash = int.from_bytes(hashlib.sha256(config_name.encode("utf-8")).digest()[:1], byteorder="big")
                test_result.historyId = test_result.historyId[0:-2] + f"{config_hash:02x}"
            if config_name:
                extra_parameters["config"] = config_name
            extra_parameters["worker"] = worker
            test_result.parameters.extend(
                [Parameter(name=name, value=represent(value)) for name, value in extra_parameters.items()]
            )

        if item.get_closest_marker("rerun"):
            test_result.labels.extend([Label(name="feature", value="Rerun tests")])
        self.call_callbacks(test_result)

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        uuid = self._cache.get(item.nodeid)
        if not self.allure_logger.get_test(uuid):
            # self._cache.set(item.nodeid)
            yield
            return
        yield from super().pytest_runtest_makereport(item, call)
        self.step_idx = 1
        if self.allure_logger._items[uuid].steps:  # removes duplicated log from test body, logs are attached per step
            attachments = [x for x in self.allure_logger._items[uuid].attachments if x.name != "log"]
            self.allure_logger._items[uuid].attachments = attachments

    @pytest.hookimpl
    def pytest_runtest_logfinish(self, nodeid, location):
        logger = logging.getLogger(LOGGER_NAME)
        handler = next(h for h in logger.handlers if type(h) is AllureLogger)
        # It's ok to clear buffer,
        # because all logs which weren't attached within test-step are attached per `pytest_runtest_makereport()` hook
        handler.clear_log_buffer()

    @pytest.hookimpl
    def pytest_sessionfinish(self, session, exitstatus):
        """
        Update testing environment information (testbed, cloud info) in Allure's environment.properties.

        This relies on pytest_sessionfinish() getting called last in xdist master process, since that updates
        testbed info ("config" key) with all the testbeds used.
        """
        allure_util = AllureUtil(session.config)
        allure_util.save_cached_environment_info()

    def add_test_result_parameter(self, parameters):
        # sets additional test parameters showed in allure report
        for name, value in parameters.items():
            self.test_result_parameters[name] = value

    @staticmethod
    def get_allure_title(item):
        title = allure_title(item)
        if not title:
            if mark := item.get_closest_marker("qase_title"):
                title = mark.kwargs.get("title")
        if title:
            params = get_modified_params(item)
            # Override allure title implementation to use parametrize id instead of parametrize value
            return SafeFormatter().format(title, **{**item.funcargs, **params})
        else:
            return None

    def clean_callbacks(self):
        if self.callbacks and self.deregister_on_teardown:
            self.callbacks = []

    def call_callbacks(self, test_result):
        for callback in self.callbacks[:]:
            try:
                callback(test_result)
            except Exception:
                log.exception(f"[MyAllureListener] failed to call: {callback.__name__}")
                self.deregister_callback(callback)
        self.clean_callbacks()

    def register_callback(self, callback):
        if callback not in self.callbacks:
            self.callbacks.append(callback)

    def deregister_callback(self, callback):
        if callback in self.callbacks:
            self.callbacks.remove(callback)

    def deregister_callbacks_on_teardown(self, state=True):
        self.deregister_on_teardown = state


class DummyConfig:
    class Option:
        def __init__(self):
            if is_jenkins():
                self.allure_report_dir = os.path.join(BASE_DIR, "allure-results")
            else:
                self.allure_report_dir = "%s/allure-results" % CACHE_DIR
            self.allure_keep_env = True
            self._current_idx = 0
            self._option_names = [name for name in list(set(dir(self))) if not name.startswith("_")]

        def __iter__(self):
            return self

        def __next__(self):
            if self._current_idx >= len(self._option_names):
                self._current_idx = 0
                raise StopIteration
            current = self._option_names[self._current_idx]
            self._current_idx += 1
            return current

    def __init__(self):
        self.option = DummyConfig.Option()
