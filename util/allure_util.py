import os
import json
import configparser
import logging
from filelock import FileLock
from allure_pytest.listener import AllureListener
from allure_commons.model2 import Parameter, Label
from allure_commons.utils import represent
from lib_testbed.generic.util.common import BASE_DIR
from lib_testbed.generic.util.common import is_jenkins, SKIP_RESULT
from lib_testbed.generic.util.logger import log

DEFAULT_SECTION = 'Global'

# Disable info logs for filelock module
logging.getLogger("filelock").setLevel(logging.ERROR)


class AllureUtil:
    def __init__(self, config):
        self.config = config
        if 'config_name' in config.option and config.option.config_name:
            self.section = config.option.config_name
        else:
            self.section = DEFAULT_SECTION
        os.makedirs(self._get_results_dir(), exist_ok=True)

    def _get_results_dir(self):
        report_dir = self.config.option.allure_report_dir
        if not report_dir:
            report_dir = '/tmp/automation/allure-results'
        return report_dir

    def _get_properties_path(self):
        allure_dir = self._get_results_dir()
        if not allure_dir:
            raise Exception("Missing pytest option --alluredir")
        return os.path.join(allure_dir, 'environment.properties')

    def _get_lock_file(self):
        return f'{self._get_properties_path()}.lock'

    def _read_config(self, config_parser):
        properties_file = self._get_properties_path()
        config_parser.read(properties_file)

    def _write_config(self, config_parser):
        with open(self._get_properties_path(), 'w') as configfile:
            config_parser.write(configfile)

    def _init(self):
        config_parser = configparser.ConfigParser()
        config_parser.clear()
        config_parser.add_section(self.section)
        self._write_config(config_parser)

    def init_categories(self):
        categories_path = os.path.join(self._get_results_dir(), 'categories.json')
        if not os.path.exists(categories_path):
            data = [{
                "name": "Detected issues",
                "messageRegex": ".*Detected issue.*",
                "matchedStatuses": [
                    "skipped"
                ]}]
            with open(categories_path, 'w') as fh:
                fh.write(json.dumps(data))

    def init(self):
        with FileLock(self._get_lock_file()):
            if 'allure_keep_env' not in self.config.option or not self.config.option.allure_keep_env:
                self._init()
            else:
                self._init_and_read_config()
            self.init_categories()

    def _set_config(self, name, value):
        config_parser = self._init_and_read_config()
        try:
            config_parser.set(self.section, name, value)
        except configparser.NoSectionError as e:
            log.warning(f'{e}, skip setting config: {name}')
            return
        self._write_config(config_parser)

    def _init_and_read_config(self):
        config_parser = configparser.ConfigParser()
        self._read_config(config_parser)
        try:
            if self.section == DEFAULT_SECTION:
                sections = config_parser.sections()
                if sections:
                    self.section = sections[0]
            config_parser.items(self.section)
        except Exception:
            log.warning('Initialize allure environment.properties')
            self._init()
        return config_parser

    def _get_environment(self, name):
        config_parser = self._init_and_read_config()
        try:
            value = config_parser.get(self.section, name)
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
            log.warning(f'{e}, skip getting environment variables')
            return []

    def get_environment(self, name):
        with FileLock(self._get_lock_file()):
            config_parser = self._init_and_read_config()
            try:
                value = config_parser.get(self.section, name)
            except configparser.NoOptionError:
                value = None
            except configparser.NoSectionError:
                value = None
            return value

    def get_environments(self):
        with FileLock(self._get_lock_file()):
            config_parser = self._init_and_read_config()
            try:
                return list(config_parser.items(self.section))
            except configparser.NoSectionError as e:
                log.warning(f'{e}, skip getting environment variables')
                return []

    def add_environment(self, name, value, optional_suffix=None, warn_override=True):
        if value in [None, '']:
            return
        with FileLock(self._get_lock_file()):
            prev_value = self._get_environment(name)
            # in case of config just add config files names. It's needed for CRF, FRV runs with multiple test beds
            if name in ['config'] and prev_value:
                value = f"{prev_value}, {value}" if value not in prev_value else prev_value
            elif optional_suffix and prev_value and prev_value != value:
                name = f'{name}_{optional_suffix}'
                prev_value = self._get_environment(name)
            if warn_override and prev_value and prev_value != value:
                log.warning(f'Overriding: {name}, previous value: {prev_value}')
            self._set_config(name, value)

    def remove_environment(self, name):
        with FileLock(self._get_lock_file()):
            config_parser = self._init_and_read_config()
            try:
                config_parser.remove_option(self.section, name)
            except configparser.NoSectionError:
                log.warning(f"No {self.section} section in allure environment")
            self._write_config(config_parser)

    @staticmethod
    def get_allure_plugin(session_config):
        for plugin in session_config.pluginmanager._name2plugin.values():
            # pytest assigns random number to plugin name, so we're using class name
            if plugin.__class__.__name__ == 'MyAllureListener':
                return plugin

    def add_allure_group_envs(self, group, name, value, root_url=None, fixed_value=False):
        def get_value(data, name):
            if not data:
                return None
            envs = data.split('<br>')
            for env in envs:
                if env.startswith(name):
                    return env.split(': ')[1]
            return None

        def add_value(data, key, value, fixed_value=False):
            value = value.replace(', ', ',_').replace(': ', ':_')
            for str in [', ', ': ']:
                assert str not in key
            if not data:
                data = ''
            env_values = get_value(data, key)
            if not env_values:
                # env does not exist, create it
                delimiter = '<br>' if data else ''
                data += f'{delimiter}{key}: {value}'
                return data
            # there is already a value, so we do not want to extend it, like FW version or model
            if fixed_value:
                return
            if value in env_values.split(', '):
                # value already set
                return data
            new_loc_data = []
            envs = data.split('<br>')
            for env in envs:
                if env.startswith(key):
                    env += f', {value}'
                new_loc_data.append(env)
            return '<br>'.join(new_loc_data)

        if value in [None, '']:
            log.info(f'Skip setting empty value for: {name}')
            return
        if not root_url:
            root_url = 'file://'
        group_value = self.get_environment(group)
        if not group_value:
            # <br> tag works only first part of value is url link
            # loc_value = add_value('', 'url', url)
            group_value = root_url
        group_value = add_value(group_value, name, value, fixed_value)
        if group_value:
            self.add_environment(group, group_value, warn_override=False)

    def get_allure_group_env(self, group, name):
        def get_value(data, name):
            if not data:
                return None
            envs = data.split('<br>')
            for env in envs:
                if env.startswith(name):
                    return env.split(': ')[1]
            return None
        group_value = self.get_environment(group)
        if not group_value:
            return None
        return get_value(group_value, name)


class MyAllureListener(AllureListener):
    import pytest

    def __init__(self, config):
        self.last_error = None
        self.test_result_parameters = {}  # additional test parameters visible in allure
        self.callbacks = []
        self.deregister_on_teardown = False
        super().__init__(config)

    @staticmethod
    def get_test_class_path(node_id):
        return "::".join(node_id.split("::")[:-1])

    @staticmethod
    def is_xfailed(test_result):
        if test_result.status == 'skipped' and 'XFailed' in test_result.statusDetails.message:
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

    def add_test_result_parameter(self, parameters):
        # sets additional test parameters showed in allure report
        for name, value in parameters.items():
            self.test_result_parameters[name] = value

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_setup(self, item):
        self.deregister_on_teardown = False
        # overwritten to add custom test parameters
        yield from super().pytest_runtest_setup(item)
        uuid = self._cache.get(item.nodeid)
        test_result = self.allure_logger.get_test(uuid)
        test_result.parameters.extend(
            [Parameter(name=name, value=represent(value)) for name, value in self.test_result_parameters.items()]
        )

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_teardown(self, item):
        uuid = self._cache.get(item.nodeid)
        test_result = self.allure_logger.get_test(uuid)

        skip_item = False
        if test_result.status == 'skipped' and SKIP_RESULT in item.test_report.longreprtext:
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
        if item.get_closest_marker('rerun'):
            test_result.labels.extend([Label(name='feature', value='Rerun tests')])
        self.call_callbacks(test_result)

    def clean_callbacks(self):
        if self.callbacks and self.deregister_on_teardown:
            self.callbacks = []

    def call_callbacks(self, test_result):
        for callback in self.callbacks[:]:
            try:
                callback(test_result)
            except Exception:
                log.exception(f'[MyAllureListener] failed to call: {callback.__name__}')
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
                self.allure_report_dir = os.path.join(BASE_DIR, 'allure-results')
            else:
                self.allure_report_dir = '/tmp/automation/allure-results'
            self.allure_keep_env = True
            self._current_idx = 0
            self._option_names = [name for name in list(set(dir(self))) if not name.startswith('_')]

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
