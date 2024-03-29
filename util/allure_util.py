import hashlib
import os
import re
import json
import configparser
import logging

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

DEFAULT_SECTION = "Global"

# Disable info logs for filelock module
logging.getLogger("filelock").setLevel(logging.ERROR)


class AllureUtil:
    def __init__(self, config):
        self.config = config
        self.option_config = config.option.config_name if "config_name" in config.option else None
        if location_file := getattr(config, "tb_config", {}).get("location_file"):
            self.section = os.path.basename(location_file).split(".")[0]
        elif self.option_config:
            self.section = self.option_config
        else:
            self.section = DEFAULT_SECTION
        self.lock_timeout = 120
        result_dir = self._get_results_dir()
        os.makedirs(result_dir, exist_ok=True)
        # these lines are for debugging CI purposes, feel free to remove them
        job_name = os.environ.get("JOB_NAME", "not_jenkins").replace("/", "_")
        job_file_build_id = os.path.join(result_dir, job_name)
        if not os.path.exists(job_file_build_id):
            build_url = os.environ.get("BUILD_URL", None)
            with open(job_file_build_id, "wt") as job_file:
                job_file.write(f"{job_name}\n{build_url}\n")

    def _get_results_dir(self):
        # this check for jenkins is temporary, should be removed in the future
        if is_jenkins():
            return os.path.join(BASE_DIR, "allure-results")
        report_dir = self.config.option.allure_report_dir
        if not report_dir:
            report_dir = "%s/allure-results" % CACHE_DIR
        return report_dir

    def _get_properties_path(self):
        allure_dir = self._get_results_dir()
        if not allure_dir:
            raise Exception("Missing pytest option --alluredir")
        return os.path.join(allure_dir, "environment.properties")

    def _get_lock_file(self):
        return f"{self._get_properties_path()}.lock"

    def _read_config(self, config_parser):
        properties_file = self._get_properties_path()
        config_parser.read(properties_file)

    def _write_config(self, config_parser):
        with open(self._get_properties_path(), "w") as configfile:
            config_parser.write(configfile)

    def _init(self):
        config_parser = configparser.ConfigParser()
        config_parser.clear()
        config_parser.add_section(self.section)
        self._write_config(config_parser)
        return config_parser

    def init_categories(self):
        categories_path = os.path.join(self._get_results_dir(), "categories.json")
        if not os.path.exists(categories_path):
            data = [{"name": "Detected issues", "messageRegex": ".*Detected issue.*", "matchedStatuses": ["skipped"]}]
            with open(categories_path, "w") as fh:
                fh.write(json.dumps(data))

    def init(self):
        with FileLock(self._get_lock_file(), timeout=self.lock_timeout):
            if "allure_keep_env" not in self.config.option or not self.config.option.allure_keep_env:
                self._init()
            else:
                self._init_and_read_config()
            self.init_categories()

    def _set_config(self, name, value):
        config_parser = self._init_and_read_config()
        try:
            config_parser.set(self.section, self.get_option_name(name), value)
        except configparser.NoSectionError as e:
            log.warning(f"{e}, skip setting config: {name}")
            return
        self._write_config(config_parser)

    def _init_and_read_config(self):
        config_parser = configparser.ConfigParser()
        try:
            self._read_config(config_parser)
            sections = config_parser.sections()
            if self.section == DEFAULT_SECTION and sections:
                self.section = sections[0]
            if self.section not in sections:
                config_parser.add_section(self.section)
                self._write_config(config_parser)
            config_parser.items(self.section)
        except Exception:
            log.exception("Recreate allure file for environment.properties")
            config_parser = self._init()
        return config_parser

    def _get_environment(self, name):
        config_parser = self._init_and_read_config()
        try:
            value = config_parser.get(self.section, self.get_option_name(name))
        except configparser.NoOptionError:
            value = None
        except configparser.NoSectionError:
            value = None
        return value

    def _get_environments(self):
        config_parser = self._init_and_read_config()
        try:
            return list(config_parser.items(self.section))
        except configparser.NoSectionError as e:
            log.warning(f"{e}, skip getting environment variables")
            return []

    def get_option_name(self, name):
        if not self.option_config or "," not in self.option_config or self.section not in self.option_config.split(","):
            return name
        config_idx = self.option_config.split(",").index(self.section)
        return f"{name}_{config_idx}"

    def get_environment(self, name):
        with FileLock(self._get_lock_file(), timeout=self.lock_timeout):
            config_parser = self._init_and_read_config()
            try:
                value = config_parser.get(self.section, self.get_option_name(name))
            except configparser.NoOptionError:
                value = None
            except configparser.NoSectionError:
                value = None
            return value

    def get_environments(self, all_sections=False):
        with FileLock(self._get_lock_file(), timeout=self.lock_timeout):
            config_parser = self._init_and_read_config()
            try:
                return list(config_parser.items()) if all_sections else list(config_parser.items(self.section))
            except configparser.NoSectionError as e:
                log.warning(f"{e}, skip getting environment variables")
                return []

    def add_environment(self, name, value, optional_suffix=None, warn_override=True):
        if value in [None, ""]:
            return
        with FileLock(self._get_lock_file(), timeout=self.lock_timeout):
            prev_value = self._get_environment(name)
            # in case of config just add config files names. It's needed for CRF, FRV runs with multiple test beds
            if name in ["config"] and prev_value:
                value = f"{prev_value}, {value}" if value not in prev_value else prev_value
            elif optional_suffix and prev_value and prev_value != value:
                name = f"{name}_{optional_suffix}"
                prev_value = self._get_environment(name)
            if warn_override and prev_value and prev_value != value:
                log.warning(f"Overriding: {name}, previous value: {prev_value}")
            self._set_config(name, value)

    def remove_environment(self, name):
        with FileLock(self._get_lock_file(), timeout=self.lock_timeout):
            config_parser = self._init_and_read_config()
            try:
                config_parser.remove_option(self.section, self.get_option_name(name))
            except configparser.NoSectionError:
                log.warning(f"No {self.section} section in allure environment")
            self._write_config(config_parser)

    @staticmethod
    def get_allure_plugin(session_config):
        for plugin in session_config.pluginmanager._name2plugin.values():
            # pytest assigns random number to plugin name, so we're using class name
            if plugin.__class__.__name__ == "MyAllureListener":
                return plugin

    def add_allure_group_envs(self, group, name, value, root_url=None, fixed_value=False):  # noqa: C901
        def add_value(data, key, value, fixed_value=False):
            value = value.replace(", ", ",_").replace(": ", ":_")
            for str in [", ", ": "]:
                assert str not in key
            if not data:
                data = ""
            env_values = self.get_value(data, key)
            if not env_values:
                # env does not exist, create it
                delimiter = "<br>" if data else ""
                data += f"{delimiter}<code>{key}: {value}</code>"
                return data
            # there is already a value, so we do not want to extend it, like FW version or model
            if fixed_value:
                return
            if value in env_values.split(", "):
                # value already set
                return data
            new_loc_data = []
            envs = [e.removesuffix("</code>") for e in data.split("<br><code>")]
            for env in envs:
                if env.startswith(key):
                    env = f"{env}, {value}"
                if "://" not in env:
                    env = "<code>" + env + "</code>"
                new_loc_data.append(env)
            return "<br>".join(new_loc_data)

        if value in [None, ""]:
            log.info(f"Skip setting empty value for: {name}")
            return
        if not root_url:
            root_url = "file://"
        group_value = self.get_environment(group)
        if not group_value:
            # <br> tag works only first part of value is url link
            # loc_value = add_value('', 'url', url)
            group_value = root_url
        group_value = add_value(group_value, name, value, fixed_value)
        if group_value:
            self.add_environment(group, group_value, warn_override=False)

    def get_allure_group_env(self, group, name):
        group_value = self.get_environment(group)
        if not group_value:
            return None
        return self.get_value(group_value, name)

    @staticmethod
    def get_value(data, name):
        if not data:
            return None
        envs = [e.removesuffix("</code>") for e in data.split("<br><code>")]
        for env in envs:
            if env.startswith(name):
                return env.split(": ")[1]
        return None

    @staticmethod
    def parse_allure_env(allure_env: [str, str], values_to_parse: list = None) -> str:
        """Parse all values from allure environment to readable text.
        If specified values_to_parse consider only provided value names."""
        env_name = allure_env[0]
        env_values = allure_env[1].split("<br>")
        parsed_values = list()
        for env_value in env_values:
            if (
                env_value.startswith("file:")
                or values_to_parse
                and not any(value_to_parse in env_value for value_to_parse in values_to_parse)
            ):
                continue
            parsed_values.append(re.sub(r"\<.*?\>", "", env_value))
        allure_env_values = "\t".join(parsed_values)
        parsed_allure_env = f"{env_name}: {allure_env_values}"
        return parsed_allure_env


class MyAllureListener(AllureListener):
    import pytest

    def __init__(self, config):
        self.last_error = None
        self.test_result_parameters = {}  # additional test parameters visible in allure
        self.callbacks = []
        self.deregister_on_teardown = False
        super().__init__(config)

    @hookimpl
    def start_step(self, uuid, title, params):
        def _print_test_step_separator():
            indent = 8
            separator = "~"
            log.info(
                f"\n\n{80 * separator}\n" f"{indent * ' '}Test step: \"{title}\"\n" f"{80 * separator}",
                show_file=False,
            )

        super().start_step(uuid, title, params)
        _print_test_step_separator()

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
    def pytest_runtest_makereport(self, item, call):
        uuid = self._cache.get(item.nodeid)
        if not self.allure_logger.get_test(uuid):
            # self._cache.set(item.nodeid)
            yield
            return
        yield from super().pytest_runtest_makereport(item, call)
        if self.allure_logger._items[uuid].steps:  # removes duplicated log from test body, logs are attached per step
            attachments = [x for x in self.allure_logger._items[uuid].attachments if x.name != "log"]
            self.allure_logger._items[uuid].attachments = attachments

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
