"""This module contains common and OSRT fixtures representing pods, clients,
rpower, switch, and cloud. All fixtures are of scope module, except for
tb_config which is of scope session (parse the config file once).

.. note::
    The fixtures intended to be used by tests are those **NOT** starting
    with an underscore. The fixtures starting with an underscore are
    only supposed to be used by other fixtures. They are needed to invoke
    ``setup_class()``, ``setup_method()``, ``teardown_class()``, and
    ``teardown_method()`` accordingly with well-defined scope.

.. warning::
    The fixtures can't be used across classes defined in a single
    module. Avoid mixing test classes and test functions!
"""
import urllib
import pytest
from copy import deepcopy

from lib_testbed.generic.client.models.generic.client_api import ClientApi
from lib_testbed.generic.pod.generic.pod_api import PodApi
from lib_testbed.generic.util.ssh.device_api import DeviceApi
from lib_testbed.generic.rpower.rpowerlib import PowerControllerApi
from lib_testbed.generic.switch.generic.switch_api_generic import SwitchApiGeneric
from lib_testbed.generic.util.fixture_utils import OSRTFixtureTestObject, safe_setup
from lib_testbed.generic.util.pytest_config_utils import get_option_config_name
from lib_testbed.generic.util.config import load_tb_config, TbConfig
from lib_testbed.generic.rpower import rpower as _rpower_factory
from lib_testbed.generic.switch import switch as _switch_factory
from lib_testbed.generic.client import client as _client_factory
from lib_testbed.generic.pod import pod as _pod_factory
from lib_testbed.generic.util.fw_manager import FwManager
from lib_testbed.generic.util.iperf import Iperf


class DeviceApiIterator:
    """Helper class to iterate over DeviceApi deriving classes. Works for
    :py:class:`lib_testbed.generic.client.models.generic.client_api.ClientApi` and
    :py:class:`lib_testbed.generic.pod.generic.pod_api.PodApi`"""

    def __iter__(self):
        return (obj for obj in self.__dict__.values() if isinstance(obj, DeviceApi))


@pytest.fixture(scope="session")
def tb_config(request, pytestconfig, reserve_fixture) -> TbConfig:
    """Returns an instance of test bed config."""
    loaded_config = None
    try:
        loaded_config = request.getfixturevalue("move_to_deployment_fixture")
    except pytest.FixtureLookupError:
        # for cases where deployment fixture is not available
        pass
    if not loaded_config:
        # if everything else fails, just load testbed config from config file:
        tb_config_name = get_option_config_name(pytestconfig)
        requested_deployment = pytestconfig.option.deployment_name
        loaded_config = load_tb_config(location_file=tb_config_name, deployment_file=requested_deployment)
    if "inside_infrastructure" not in loaded_config:
        # to not make inventory call twice, just get the value from pytestconfig if exists
        if hasattr(pytestconfig, "tb_config"):
            loaded_config["inside_infrastructure"] = pytestconfig.tb_config.get("inside_infrastructure", False)
        else:
            try:
                inv_resp = urllib.request.urlopen(
                    "http://inventory-development.shared.us-west-2.aws.plume.tech:3005" "/explorer/", timeout=2
                ).getcode()
            except Exception:
                inv_resp = 404
            loaded_config["inside_infrastructure"] = inv_resp == 200
    return loaded_config


@pytest.fixture(scope="session")
def tb_config_orig(tb_config) -> TbConfig:
    """Returns an instance of copy original test bed config."""
    return deepcopy(tb_config)


@pytest.fixture(scope="function")
def modify_config_for_local_mqtt_broker(tb_config, tb_config_orig) -> TbConfig:
    """Modify tb_config for stats redirection"""
    # do not use testbed server mqtt broker if there is possibility to connect to the cloud
    if tb_config.get("inside_infrastructure", False):
        yield
        return

    tb_config["local_mqtt_broker"] = True
    tb_config["mqtt_servers"] = ["rpi-server"]
    tb_config["mqtt_port"] = 8883
    yield
    tb_config.pop("local_mqtt_broker", None)
    if mqtt_servers := tb_config_orig.get("mqtt_servers"):
        tb_config["mqtt_servers"] = mqtt_servers[:]
    else:
        tb_config.pop("mqtt_servers", None)
    if mqtt_port := tb_config_orig.get("mqtt_port"):
        tb_config["mqtt_port"] = mqtt_port
    else:
        tb_config.pop("mqtt_port", None)


@pytest.fixture(scope="session")
def rpower_session(tb_config, request) -> PowerControllerApi:
    """Session-scoped rpower object"""
    rpower_obj = _rpower_factory.Rpower().create_obj(module_name="rpower", config=tb_config)
    with safe_setup(OSRTFixtureTestObject(rpower_obj), scope="session", request=request):
        yield rpower_obj


@pytest.fixture(scope="module")
def rpower_module(rpower_session, request) -> PowerControllerApi:
    """Module-scoped rpower object (not to be used by tests). This fixture is
    just to ensure proper setup and teardown."""
    with safe_setup(OSRTFixtureTestObject(rpower_session), scope="module", request=request):
        yield rpower_session


@pytest.fixture(scope="function")
def rpower(rpower_module, request) -> PowerControllerApi:
    """Represents rpower controller object to be used by tests. See the documentation
    of :py:class:`lib_testbed.generic.rpower.rpower_local_lib.PowerController`
    for API reference."""
    with safe_setup(OSRTFixtureTestObject(rpower_module), scope="function", request=request):
        yield rpower_module


@pytest.fixture(scope="session")
def switch_session(tb_config, request) -> SwitchApiGeneric:
    """Session-scoped switch object"""
    switch_obj = _switch_factory.Switch().create_obj(module_name="switch", config=tb_config)
    with safe_setup(OSRTFixtureTestObject(switch_obj), scope="session", request=request):
        yield switch_obj


@pytest.fixture(scope="module")
def switch_module(switch_session, request) -> SwitchApiGeneric:
    """Module-scoped switch object"""
    with safe_setup(OSRTFixtureTestObject(switch_session), scope="module", request=request):
        yield switch_session


@pytest.fixture(scope="function")
def switch(switch_module, request) -> SwitchApiGeneric:
    """Represents the network switch controller to be used in test implementation.
    See the documentation of
    :py:class:`lib_testbed.switch.generic.switch_api_generic.SwitchApiGeneric`
    for API reference."""
    with safe_setup(OSRTFixtureTestObject(switch_module), scope="function", request=request):
        yield switch_module


@pytest.fixture(scope="session")
def w1_session(tb_config, request) -> ClientApi:
    """``w1`` wifi client, session-scoped"""
    client = _client_factory.Client().resolve_obj(name="w1", config=tb_config, wifi=True, multi_obj=False)
    with safe_setup(OSRTFixtureTestObject(client), scope="session", request=request):
        yield client


@pytest.fixture(scope="module")
def w1_module(w1_session, request) -> ClientApi:
    """``w1`` wifi client, module-scoped"""
    with safe_setup(OSRTFixtureTestObject(w1_session), scope="module", request=request):
        yield w1_session


@pytest.fixture(scope="function")
def w1(w1_module, request) -> ClientApi:
    """``w1`` wifi client."""
    with safe_setup(OSRTFixtureTestObject(w1_module), scope="function", request=request):
        yield w1_module


@pytest.fixture(scope="session")
def w2_session(tb_config, request) -> ClientApi:
    """``w2`` wifi client, session-scoped"""
    client = _client_factory.Client().resolve_obj(name="w2", config=tb_config, wifi=True, multi_obj=False)
    with safe_setup(OSRTFixtureTestObject(client), scope="session", request=request):
        yield client


@pytest.fixture(scope="module")
def w2_module(w2_session, request) -> ClientApi:
    """``w2`` wifi client, module-scoped"""
    with safe_setup(OSRTFixtureTestObject(w2_session), scope="module", request=request):
        yield w2_session


@pytest.fixture(scope="function")
def w2(w2_module, request) -> ClientApi:
    """``w2`` wifi client."""
    with safe_setup(OSRTFixtureTestObject(w2_module), scope="function", request=request):
        yield w2_module


@pytest.fixture(scope="session")
def w3_session(tb_config, request) -> ClientApi:
    """``w3`` wifi client, session-scoped"""
    client = _client_factory.Client().resolve_obj(name="w3", config=tb_config, wifi=True, multi_obj=False)
    with safe_setup(OSRTFixtureTestObject(client), scope="session", request=request):
        yield client


@pytest.fixture(scope="module")
def w3_module(w3_session, request) -> ClientApi:
    """``w3`` wifi client, module-scoped."""
    with safe_setup(OSRTFixtureTestObject(w3_session), scope="module", request=request):
        yield w3_session


@pytest.fixture(scope="function")
def w3(w3_module, request) -> ClientApi:
    """``w3`` wifi client."""
    with safe_setup(OSRTFixtureTestObject(w3_module), scope="function", request=request):
        yield w3_module


@pytest.fixture(scope="session")
def e1_session(tb_config, request) -> ClientApi:
    """``e1`` ethernet client, session-scoped"""
    client = _client_factory.Client().resolve_obj(name="e1", config=tb_config, eth=True, multi_obj=False)
    with safe_setup(OSRTFixtureTestObject(client), scope="session", request=request):
        yield client


@pytest.fixture(scope="module")
def e1_module(e1_session, request) -> ClientApi:
    """``e1`` ethernet client, module-scoped"""
    with safe_setup(OSRTFixtureTestObject(e1_session), scope="module", request=request):
        yield e1_session


@pytest.fixture(scope="function")
def e1(e1_module, request) -> ClientApi:
    """``e1`` ethernet client"""
    with safe_setup(OSRTFixtureTestObject(e1_module), scope="function", request=request):
        yield e1_module


@pytest.fixture(scope="session")
def e2_session(tb_config, request) -> ClientApi:
    """``e2`` ethernet client, vlan351, session-scoped"""
    client = _client_factory.Client().resolve_obj(name="e2", config=tb_config, vlan="351", eth=True, multi_obj=False)
    with safe_setup(OSRTFixtureTestObject(client), scope="session", request=request):
        yield client


@pytest.fixture(scope="module")
def e2_module(e2_session, request) -> ClientApi:
    """``e2`` ethernet client, module-scoped"""
    with safe_setup(OSRTFixtureTestObject(e2_session), scope="module", request=request):
        yield e2_session


@pytest.fixture(scope="function")
def e2(e2_module, request) -> ClientApi:
    """``e2`` ethernet client"""
    with safe_setup(OSRTFixtureTestObject(e2_module), scope="function", request=request):
        yield e2_module


@pytest.fixture(scope="session")
def e3_session(tb_config, request) -> ClientApi:
    """``e3`` ethernet client, vlan 352, session-scoped."""
    client = _client_factory.Client().resolve_obj(name="e3", config=tb_config, vlan="352", eth=True, multi_obj=False)
    with safe_setup(OSRTFixtureTestObject(client), scope="session", request=request):
        yield client


@pytest.fixture(scope="module")
def e3_module(e3_session, request) -> ClientApi:
    """``e3`` ethernet client, module-scoped"""
    with safe_setup(OSRTFixtureTestObject(e3_session), scope="module", request=request):
        yield e3_session


@pytest.fixture(scope="function")
def e3(e3_module, request) -> ClientApi:
    """``e3`` ethernet client."""
    with safe_setup(OSRTFixtureTestObject(e3_module), scope="function", request=request):
        yield e3_module


@pytest.fixture(scope="session")
def server_session(tb_config, request) -> ClientApi:
    """OSRT server object, session-scoped."""
    client = _client_factory.Client().resolve_obj(name="host", config=tb_config, nickname="host")
    with safe_setup(OSRTFixtureTestObject(client), scope="session", request=request):
        yield client


@pytest.fixture(scope="module")
def server_module(server_session, request) -> ClientApi:
    """OSRT server object, module-scoped"""
    with safe_setup(OSRTFixtureTestObject(server_session), scope="module", request=request):
        yield server_session


@pytest.fixture(scope="function")
def server(server_session, request) -> ClientApi:
    """Represents OSRT server."""
    with safe_setup(OSRTFixtureTestObject(server_session), scope="function", request=request):
        yield server_session


@pytest.fixture(scope="session")
def gw_session(tb_config, request) -> PodApi:
    """Pod ``gw`` object, session-scoped."""
    gw = _pod_factory.Pod().resolve_obj(name="gw", index=0, config=tb_config, multi_obj=False)
    with safe_setup(OSRTFixtureTestObject(gw), scope="session", request=request):
        yield gw


@pytest.fixture(scope="module")
def gw_module(gw_session, request) -> PodApi:
    """Pod ``gw`` object, module-scoped."""
    with safe_setup(OSRTFixtureTestObject(gw_session), scope="module", request=request):
        yield gw_session


@pytest.fixture(scope="function")
def gw(gw_module, request) -> PodApi:
    """Yields ``gw`` pod to be used by tests."""
    with safe_setup(OSRTFixtureTestObject(gw_module), scope="function", request=request):
        yield gw_module


@pytest.fixture(scope="session")
def l1_session(tb_config, request) -> PodApi:
    """Pod ``l1``, leaf, session-scoped"""
    leaf = _pod_factory.Pod().resolve_obj(name="l1", index=1, config=tb_config, multi_obj=False)
    with safe_setup(OSRTFixtureTestObject(leaf), scope="session", request=request):
        yield leaf


@pytest.fixture(scope="module")
def l1_module(l1_session, request) -> PodApi:
    """Pod ``l1``, leaf, module-scoped"""
    with safe_setup(OSRTFixtureTestObject(l1_session), scope="module", request=request):
        yield l1_session


@pytest.fixture(scope="function")
def l1(l1_module, request) -> PodApi:
    """Yields ``l1`` pod."""
    with safe_setup(OSRTFixtureTestObject(l1_module), scope="function", request=request):
        yield l1_module


@pytest.fixture(scope="session")
def l2_session(tb_config, request) -> PodApi:
    """Pod ``l2``, leaf, session-scoped"""
    leaf = _pod_factory.Pod().resolve_obj(name="l2", index=2, config=tb_config, multi_obj=False)
    with safe_setup(OSRTFixtureTestObject(leaf), scope="session", request=request):
        yield leaf


@pytest.fixture(scope="module")
def l2_module(l2_session, request) -> PodApi:
    """Pod ``l2``, leaf, module-scoped"""
    with safe_setup(OSRTFixtureTestObject(l2_session), scope="module", request=request):
        yield l2_session


@pytest.fixture(scope="function")
def l2(l2_module, request) -> PodApi:
    """Yields ``l2`` pod."""
    with safe_setup(OSRTFixtureTestObject(l2_module), scope="function", request=request):
        yield l2_module


@pytest.fixture(scope="session")
def pods_session(tb_config, request) -> PodApi:
    """Pods object containing all pods from the config. Session-scoped."""
    pods = _pod_factory.Pods().resolve_obj(config=tb_config, multi_obj=True)
    with safe_setup(OSRTFixtureTestObject(pods), scope="session", request=request):
        yield pods


@pytest.fixture(scope="module")
def pods_module(pods_session, request) -> PodApi:
    """Pods object containing all pods from the config. Module-scoped."""
    with safe_setup(OSRTFixtureTestObject(pods_session), scope="module", request=request):
        yield pods_session


@pytest.fixture(scope="function")
def pods(pods_module, request) -> PodApi:
    """Pods object containing all pods from the config. All functions are run in parallel on all pods."""
    with safe_setup(OSRTFixtureTestObject(pods_module), scope="function", request=request):
        yield pods_module


@pytest.fixture(scope="session")
def leafs_session(tb_config, request) -> PodApi:
    """Leafs object containing all leafs from the config. Session-scoped."""
    leafs = _pod_factory.Pods().resolve_obj(role="leaf", config=tb_config)
    with safe_setup(OSRTFixtureTestObject(leafs), scope="session", request=request):
        yield leafs


@pytest.fixture(scope="module")
def leafs_module(leafs_session, request) -> PodApi:
    """Leafs object containing all leafs from the config. Module-scoped."""
    with safe_setup(OSRTFixtureTestObject(leafs_session), scope="module", request=request):
        yield leafs_session


@pytest.fixture(scope="function")
def leafs(leafs_module, request) -> PodApi:
    """Leafs object containing all leafs from the config. All functions are run in parallel on all leafs."""
    with safe_setup(OSRTFixtureTestObject(leafs_module), scope="function", request=request):
        yield leafs_module


@pytest.fixture(scope="module")
def iperf3_module(request) -> callable(Iperf):
    """iperf3 factory, module-scoped. Calling it creates a module-scoped instance of
    :py:class:`lib_testbed.generic.util.iperf.Iperf`."""

    def _iperf3(*args, **kwargs) -> Iperf:
        iperf_obj = Iperf(*args, iperf_ver=3, **kwargs)
        request.addfinalizer(lambda: iperf_obj.dispose())
        return iperf_obj

    yield _iperf3


@pytest.fixture(scope="function")
def iperf3(request) -> callable(Iperf):
    """iperf3 factory, function-scoped. Calling it creates a function/method-scoped instance of
    :py:class:`lib_testbed.generic.util.iperf.Iperf`.
    """

    def _iperf3(*args, **kwargs) -> Iperf:
        iperf_obj = Iperf(*args, iperf_ver=3, **kwargs)
        request.addfinalizer(lambda: iperf_obj.dispose())
        return iperf_obj

    yield _iperf3


@pytest.fixture(scope="function")
def iperf2(request) -> callable(Iperf):
    """iperf2 factory, function-scoped. Calling it creates a function/method-scoped instance of
    :py:class:`lib_testbed.generic.util.iperf.Iperf`.
    """

    def _iperf2(*args, **kwargs) -> Iperf:
        iperf_obj = Iperf(*args, iperf_ver=2, **kwargs)
        request.addfinalizer(lambda: iperf_obj.dispose())
        return iperf_obj

    yield _iperf2


@pytest.fixture(scope="function")
def fw_mng(tb_config):
    """Fixture for getting firmware candidates for test purposes"""
    yield FwManager(tb_config)
