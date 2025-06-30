import tempfile
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
    """Return a new instance of :py:class:`click.testing.CliRunner`."""
    import click.testing

    return click.testing.CliRunner()


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


@pytest.fixture(scope="function")
def mock_osrt_testbed(monkeypatch):
    monkeypatch.setenv("OPENSYNC_TESTBED", "example")


@pytest.fixture(scope="function")
def custom_temp_dir(tmp_path, monkeypatch):
    """Patch python's tempdir to use pytest's temporary directory."""
    monkeypatch.setattr(tempfile, "gettempdir", lambda: tmp_path)


# osrt fixtures patched with None below this line:


@pytest.fixture(scope="session")
def _gw_object(tb_config, request) -> None:
    """Returns gw pod session object."""
    return None


@pytest.fixture(scope="session")
def gw_session(request, _gw_object) -> None:
    """Pod ``gw`` object, session-scoped."""
    return None


@pytest.fixture(scope="module")
def gw_module(gw_session, request) -> None:
    """Pod ``gw`` object, module-scoped."""
    return None


@pytest.fixture(scope="function")
def gw(gw_module, request) -> None:
    """Yields ``gw`` pod to be used by tests."""
    return None


@pytest.fixture(scope="session")
def _l1_object(tb_config, request) -> None:
    """Returns l1 pod session object."""
    return None


@pytest.fixture(scope="session")
def l1_session(request, _l1_object) -> None:
    """Pod ``l1``, leaf, session-scoped"""
    return None


@pytest.fixture(scope="module")
def l1_module(l1_session, request) -> None:
    """Pod ``l1``, leaf, module-scoped"""
    return None


@pytest.fixture(scope="function")
def l1(l1_module, request) -> None:
    """Yields ``l1`` pod."""
    return None


@pytest.fixture(scope="session")
def _l2_object(tb_config, request) -> None:
    """Returns l2 pod session object."""
    return None


@pytest.fixture(scope="session")
def l2_session(request, _l2_object) -> None:
    """Pod ``l2``, leaf, session-scoped"""
    return None


@pytest.fixture(scope="module")
def l2_module(l2_session, request) -> None:
    """Pod ``l2``, leaf, module-scoped"""
    return None


@pytest.fixture(scope="function")
def l2(l2_module, request) -> None:
    """Yields ``l2`` pod."""
    return None


@pytest.fixture(scope="session")
def pods_session(tb_config, request) -> None:
    """Pods object containing all pods from the config. Session-scoped."""
    return None


@pytest.fixture(scope="module")
def pods_module(pods_session, request) -> None:
    """Pods object containing all pods from the config. Module-scoped."""
    return None


@pytest.fixture(scope="function")
def pods(pods_module, request) -> None:
    """Pods object containing all pods from the config. All functions are run in parallel on all pods."""
    return None
