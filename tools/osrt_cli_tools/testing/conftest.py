import pytest

import lib_testbed.generic.util.ssh.parallelssh
import lib_testbed.generic.switch.generic.switch_api_generic
from lib_testbed.generic.util.config import load_tb_config

pytest_plugins = ["lib_testbed.generic.util.osrt_fixtures", "lib.util.pytest_plugins.tb_configurator"]


@pytest.fixture(scope="session")
def switch_session(tb_config, request):
    return None


@pytest.fixture(scope="session")
def common_session_markers(request):
    return []


@pytest.fixture(scope="session")
def tb_config():
    """Load example test config."""
    return load_tb_config("example")


@pytest.fixture(scope="session", autouse=True)
def allure_environment(request):
    pass


@pytest.fixture(scope="function")
def cli_runner():
    """Return a new instance of :py:class:`click.testing.CliRunner` with mix_stderr=False flag."""
    import click.testing

    return click.testing.CliRunner(mix_stderr=False)


@pytest.fixture(scope="function")
def mock_opensync_testbed(monkeypatch):
    """Set OPENSYNC_TESTBED variable to "example" for tests."""
    monkeypatch.setenv("OPENSYNC_TESTBED", "example")


@pytest.fixture(scope="function")
def ssh_mock(monkeypatch, mock_opensync_testbed):
    class _ssh_mock:
        def __init__(self, sequence):
            self.sequence = iter(sequence)
            self.ssh_args_history = []

        def call_ssh(self, *args, **kwargs):
            self.ssh_args_history.append([args, kwargs])
            return next(self.sequence)

    def _ssh_mocker(sequence):
        mocker = _ssh_mock(sequence)
        monkeypatch.setattr(lib_testbed.generic.util.ssh.parallelssh, "execute_command", mocker.call_ssh)
        # return reference to called args, so that it can be inspected in the tests
        return mocker.ssh_args_history

    return _ssh_mocker
