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

import traceback
import urllib
import pytest
from copy import deepcopy

from lib_testbed.generic.util.opensyncexception import OpenSyncException
from lib_testbed.generic.util.pytest_utils import safe_exit_pytest
from lib_testbed.generic.client.models.generic.client_api import ClientApi
from lib_testbed.generic.pod.generic.pod_api import PodApi
from lib_testbed.generic.util.allure_util import AllureUtil
from lib_testbed.generic.util.attenuatorlib import AttenuatorLib
from lib_testbed.generic.util.common import compare_fw_versions, mark_failed_recovery_attempt
from lib_testbed.generic.util.logger import log
from lib_testbed.generic.util.ssh.device_api import DeviceApi, DevicesApi
from lib_testbed.generic.rpower.rpowerlib import PowerControllerApi
from lib_testbed.generic.switch.generic.switch_api_generic import SwitchApiGeneric
from lib_testbed.generic.util.fixture_utils import OSRTFixtureTestObject, safe_setup
from lib_testbed.generic.util.pytest_config_utils import get_option_config_name
from lib_testbed.generic.util.config import load_tb_config, TbConfig
from lib_testbed.generic.rpower import rpower as _rpower_factory
from lib_testbed.generic.switch import switch as _switch_factory
from lib_testbed.generic.client import client as _client_factory
from lib_testbed.generic.pod import pod as _pod_factory
from lib_testbed.generic.util.iperf import Iperf


@pytest.hookimpl
def pytest_addoption(parser: pytest.Parser):
    parser.addoption(
        "--skip-firmware-version-capabilities-check",
        action="store_true",
        default=False,
        dest="skip_firmware_version_capabilities_check",
        help="Skip firmware version and capability check",
    )


class DeviceApiIterator:
    """Helper class to iterate over DeviceApi deriving classes. Works for
    :py:class:`lib_testbed.generic.client.models.generic.client_api.ClientApi` and
    :py:class:`lib_testbed.generic.pod.generic.pod_api.PodApi`"""

    def __iter__(self):
        return (obj for obj in self.__dict__.values() if isinstance(obj, DeviceApi))


def setup_log_to_console(loaded_config, pytestconfig):
    if "log_to_console" not in loaded_config:
        if pytestconfig.option.log_to_console_full:
            log_to_console = "full"
        elif pytestconfig.option.log_to_console:
            log_to_console = "basic"
        else:
            log_to_console = ""
        loaded_config["log_to_console"] = log_to_console


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
                    "https://inventory-api.global.plume.tech/explorer/", timeout=2
                ).getcode()
            except Exception:
                inv_resp = 404
            loaded_config["inside_infrastructure"] = inv_resp == 200
    setup_log_to_console(loaded_config, pytestconfig)
    return loaded_config


@pytest.fixture(scope="session")
def tb_config_orig(tb_config) -> TbConfig:
    """Returns an instance of copy original test bed config."""
    return deepcopy(tb_config)


@pytest.fixture(scope="session")
def rpower_session(tb_config, request) -> PowerControllerApi:
    """Session-scoped rpower object"""
    rpower_obj = _rpower_factory.Rpower().create_obj(module_name="rpower", request=request, config=tb_config)
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
def switch_session(tb_config, request) -> SwitchApiGeneric | None:
    """Session-scoped switch object."""
    switch_obj = _switch_factory.Switch().create_obj(module_name="switch", request=request, config=tb_config)
    try:
        with safe_setup(OSRTFixtureTestObject(switch_obj), scope="session", request=request):
            yield switch_obj
    except Exception as err:
        log.error(
            "Failed to instantiate session-scoped switch object. Traceback: %s",
            "".join(traceback.format_exception(err)),
        )
        safe_exit_pytest(request=request, msg="Could not initialize switch object for session")
        yield None


@pytest.fixture(scope="module")
def switch_module(switch_session, request) -> SwitchApiGeneric | None:
    """Module-scoped switch object."""
    try:
        with safe_setup(OSRTFixtureTestObject(switch_session), scope="module", request=request):
            yield switch_session
    except Exception as err:
        log.error(
            "Failed to instantiate module-scoped switch object. Traceback: %s",
            "".join(traceback.format_exception(err)),
        )
        safe_exit_pytest(request=request, msg="Could not initialize switch object for module")
        yield None


@pytest.fixture(scope="function")
def switch(switch_module, request, tb_config) -> SwitchApiGeneric | None:
    """Represents the network switch controller to be used in test implementation. See the documentation of
    :py:class:`lib_testbed.switch.generic.switch_api_generic.SwitchApiGeneric` for API reference."""
    try:
        with safe_setup(OSRTFixtureTestObject(switch_module), scope="function", request=request):
            yield switch_module
    except Exception as err:
        log.error(
            "Failed to instantiate module-scoped switch object. Traceback: %s",
            "".join(traceback.format_exception(err)),
        )
        mark_failed_recovery_attempt(tb_config=tb_config)
        yield None


@pytest.fixture(scope="session")
def _w1_object(tb_config, request) -> ClientApi:
    """Returns w1 client session object."""
    w1 = _client_factory.Client().resolve_obj(name="w1", config=tb_config, wifi=True, multi_obj=False, request=request)
    return w1


@pytest.fixture(scope="session")
def w1_session(_w1_object, request) -> ClientApi:
    """``w1`` wifi client, session-scoped"""
    with safe_setup(OSRTFixtureTestObject(_w1_object), scope="session", request=request):
        yield _w1_object


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
def _w2_object(tb_config, request) -> ClientApi:
    """Returns w2 client session object."""
    w2 = _client_factory.Client().resolve_obj(name="w2", config=tb_config, wifi=True, multi_obj=False, request=request)
    return w2


@pytest.fixture(scope="session")
def w2_session(_w2_object, request) -> ClientApi:
    """``w2`` wifi client, session-scoped"""
    with safe_setup(OSRTFixtureTestObject(_w2_object), scope="session", request=request):
        yield _w2_object


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
def _w3_object(tb_config, request) -> ClientApi:
    """Returns w3 client session object."""
    w3 = _client_factory.Client().resolve_obj(name="w3", config=tb_config, wifi=True, multi_obj=False, request=request)
    return w3


@pytest.fixture(scope="session")
def w3_session(_w3_object, request) -> ClientApi:
    """``w3`` wifi client, session-scoped"""
    with safe_setup(OSRTFixtureTestObject(_w3_object), scope="session", request=request):
        yield _w3_object


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
def _e1_object(tb_config, request) -> ClientApi:
    """Returns e1 client session object."""
    e1 = _client_factory.Client().resolve_obj(name="e1", config=tb_config, eth=True, multi_obj=False, request=request)
    return e1


@pytest.fixture(scope="session")
def e1_session(_e1_object, request) -> ClientApi:
    """``e1`` ethernet client, session-scoped"""
    with safe_setup(OSRTFixtureTestObject(_e1_object), scope="session", request=request):
        yield _e1_object


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
def _e2_object(tb_config, request) -> ClientApi:
    """Returns e2 client session object."""
    e2 = _client_factory.Client().resolve_obj(
        name="e2", config=tb_config, vlan="351", eth=True, multi_obj=False, request=request
    )
    return e2


@pytest.fixture(scope="session")
def e2_session(_e2_object, request) -> ClientApi:
    """``e2`` ethernet client, vlan351, session-scoped"""
    with safe_setup(OSRTFixtureTestObject(_e2_object), scope="session", request=request):
        yield _e2_object


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
def _e3_object(tb_config, request) -> ClientApi:
    """Returns e3 client session object."""
    e3 = _client_factory.Client().resolve_obj(
        name="e3", config=tb_config, vlan="352", eth=True, multi_obj=False, request=request
    )
    return e3


@pytest.fixture(scope="session")
def e3_session(_e3_object, request) -> ClientApi:
    """``e3`` ethernet client, vlan 352, session-scoped."""
    with safe_setup(OSRTFixtureTestObject(_e3_object), scope="session", request=request):
        yield _e3_object


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
def _bt1_object(tb_config, request) -> ClientApi:
    """Returns bt client session object."""
    bt = _client_factory.Client().resolve_obj(name="bt1", config=tb_config, bt=True, multi_obj=False, request=request)
    return bt


@pytest.fixture(scope="session")
def bt1_session(_bt1_object, request) -> ClientApi:
    """``bt1`` bluetooth client, session-scoped."""
    with safe_setup(OSRTFixtureTestObject(_bt1_object), scope="session", request=request):
        yield _bt1_object


@pytest.fixture(scope="module")
def bt1_module(bt1_session, request) -> ClientApi:
    """``bt1`` bluetooth client, module-scoped"""
    with safe_setup(OSRTFixtureTestObject(bt1_session), scope="module", request=request):
        yield bt1_session


@pytest.fixture(scope="function")
def bt1(bt1_module, request) -> ClientApi:
    """``bt1`` bluetooth client."""
    with safe_setup(OSRTFixtureTestObject(bt1_module), scope="function", request=request):
        yield bt1_module


@pytest.fixture(scope="session")
def _host_object(tb_config, request) -> ClientApi:
    """Returns host client session object."""
    server = _client_factory.Client().resolve_obj(name="host", config=tb_config, nickname="host", request=request)
    return server


@pytest.fixture(scope="session")
def server_session(_host_object, request) -> ClientApi:
    """OSRT server object, session-scoped."""
    with safe_setup(OSRTFixtureTestObject(_host_object), scope="session", request=request):
        yield _host_object


@pytest.fixture(scope="module")
def server_module(server_session, request) -> ClientApi:
    """OSRT server object, module-scoped"""
    with safe_setup(OSRTFixtureTestObject(server_session), scope="module", request=request):
        yield server_session


@pytest.fixture(scope="function")
def server(server_module, request) -> ClientApi:
    """Represents OSRT server."""
    with safe_setup(OSRTFixtureTestObject(server_module), scope="function", request=request):
        yield server_module


@pytest.fixture(scope="session")
def _iptv_host_object(tb_config, request) -> ClientApi:
    """Returns iptv_host client session object."""
    iptv_host = _client_factory.Client().resolve_obj(
        name="iptv_host", config=tb_config, nickname="iptv_host", request=request
    )
    return iptv_host


@pytest.fixture(scope="session")
def _s2s_vpn_host_object(tb_config, request) -> ClientApi:
    """Returns s2s_vpn_host client session object."""
    s2s_vpn_host = _client_factory.Client().resolve_obj(
        name="s2s_vpn_host", config=tb_config, nickname="s2s_vpn_host", request=request
    )
    return s2s_vpn_host


@pytest.fixture(scope="session")
def _p2s_vpn_host_object(tb_config, request) -> ClientApi:
    """Returns p2s_vpn_host client session object."""
    p2s_vpn_host = _client_factory.Client().resolve_obj(
        name="p2s_vpn_host", config=tb_config, nickname="p2s_vpn_host", request=request
    )
    return p2s_vpn_host


@pytest.fixture(scope="session")
def _motion_host_object(tb_config, request) -> ClientApi:
    """Returns motion_host client session object."""
    motion_host = _client_factory.Client().resolve_obj(
        name="motion_host", config=tb_config, nickname="motion_host", request=request
    )
    return motion_host


@pytest.fixture(scope="session")
def _wag_host_object(tb_config, request) -> ClientApi:
    """Returns wag_host client session object."""
    wag_host = _client_factory.Client().resolve_obj(
        name="wag_host", config=tb_config, nickname="wag_host", request=request
    )
    return wag_host


@pytest.fixture(scope="session")
def wag_host_session(_wag_host_object, request) -> ClientApi:
    """Client object for wag namespace on testbed server, session-scoped."""
    with safe_setup(OSRTFixtureTestObject(_wag_host_object), scope="session", request=request):
        yield _wag_host_object


@pytest.fixture(scope="module")
def wag_host_module(wag_host_session, request) -> ClientApi:
    """Client object for wag namespace on testbed server, module-scoped"""
    with safe_setup(OSRTFixtureTestObject(wag_host_session), scope="module", request=request):
        yield wag_host_session


@pytest.fixture(scope="function")
def wag_host(wag_host_session, request) -> ClientApi:
    """Client object for wag namespace on testbed server."""
    with safe_setup(OSRTFixtureTestObject(wag_host_session), scope="function", request=request):
        yield wag_host_session


@pytest.fixture(scope="session")
def _iperf_host_object(tb_config, request) -> ClientApi:
    """Returns iperf_host client session object."""
    iperf_host = _client_factory.Client().resolve_obj(
        name="iperf_host", config=tb_config, nickname="iperf_host", request=request
    )
    return iperf_host


@pytest.fixture(scope="session")
def _dummy_client_object(tb_config, request) -> ClientApi:
    """Dummy client object for devices without mgmt access"""
    return _client_factory.Client().create_dummy_client_obj(tb_config)


@pytest.fixture(scope="session")
def _dummy_pod_object(tb_config, request) -> PodApi:
    """Dummy pod object for devices without mgmt access"""
    return _pod_factory.Pod().create_dummy_pod_obj(tb_config)


def skip_firmware_feature(pod: PodApi, feature: str, request: pytest.FixtureRequest):
    """Call ``pytest.not_applicable()`` based on pod, feature name and firmware version.

    This function might be useful to call on wider-scope setups to bulk-skip tests (with not applicable status),
    where given feature is not supported for certain firmware versions.

    Example - EAA feature combined with 5.6.0 firmware will result with tests status set as "not applicable":

    .. code-block:: py

        @pytest.fixture(scope="package", autouse=True)
        def skip_firmware_feature_eaa(pods_session, request):
            # the function below can also be called with a single pod object if needed:
            skip_firmware_feature(pods_session, "EAA", request)
    """
    if request.config.getoption("skip_firmware_version_capabilities_check"):
        log.warning("Skipping firmware version feature check")
        return
    allure_util = AllureUtil(request.config)
    if isinstance(pod.serial, list):
        # this means that we have a multi-device and we have to iterate over them
        pods = pod.get_devices()
    else:
        pods = [pod]

    for pod_obj in pods:
        fw_version = allure_util.cache_node_value(pod_obj, "version")
        if not fw_version:
            log.error(f"Cannot get FW version for {pod_obj.serial} node. Skipping feature check for {feature} feature.")
            continue
        pod_features = pod_obj.capabilities.device_capabilities.get("features", {})
        if feature in pod_features:
            min_fw = pod_obj.capabilities.device_capabilities["features"][feature].get("min_fw")
            eos_fw = pod_obj.capabilities.device_capabilities["features"][feature].get("eos_fw")
            if min_fw:
                if compare_fw_versions(fw_version, min_fw, condition="<"):
                    pytest.not_applicable(
                        f"{feature} feature is not supported on {fw_version} firmware/firmware too old. "
                        f"Feature requires at least version {min_fw}."
                    )
            if eos_fw:
                if compare_fw_versions(fw_version, eos_fw, condition=">"):
                    pytest.not_applicable(
                        f"{feature} feature is not supported on {fw_version} firmware. "
                        f"Feature end of life version was {eos_fw}."
                    )
        else:
            pytest.not_applicable(f"{feature} feature not in {pod_obj.serial} node features: {pod_features}")


def skip_opensync_version(
    pod: PodApi, opensync_min_version: str, opensync_max_version: str = None, request: pytest.FixtureRequest = None
):
    """Call ``pytest.not_applicable()`` based on pod and OpenSync version.

    This function might be useful to call on wider-scope setups to bulk-skip tests (with not applicable status),
    where OpenSync version is not in supported range.

    .. code-block:: py

        @pytest.fixture(scope="package", autouse=True)
        def check_min_opensync_version(pods_session, request):
            # the function below can also be called with a single pod object if needed:
            skip_opensync_version(pods_session, "7.0", request)
    """
    if request.config.getoption("skip_firmware_version_capabilities_check"):
        log.warning("Skipping firmware version feature check")
        return
    if isinstance(pod.serial, list):
        # this means that we have a multi-device and we have to iterate over them
        pods = pod.get_devices()
    else:
        pods = [pod]

    for pod_obj in pods:
        opensync_version = pod_obj.opensync_version(skip_exception=True, timeout=10)
        if not opensync_version:
            log.error(
                f"Cannot get OpenSync version for {pod_obj.serial} node. Skipping checking required OpenSync version."
            )
            continue

        if opensync_min_version:
            if compare_fw_versions(opensync_version, opensync_min_version, condition="<"):
                pytest.not_applicable(
                    f"OpenSync {opensync_version} on {pod_obj.nickname} is too old. "
                    f"Test case requires at least version OpenSync {opensync_min_version}."
                )
        if opensync_max_version:
            if compare_fw_versions(opensync_version, opensync_max_version, condition=">"):
                pytest.not_applicable(
                    f"OpenSync {opensync_version} on {pod_obj.nickname} is not supported."
                    f"OpenSync end of life version was {opensync_max_version}."
                )


def check_pod_features(pod: PodApi, request: pytest.FixtureRequest):
    """Inspect the current test against pod features.

    This utility function inspect firmware version for a pod and compares it against model-specific feature list.
    If model properties has a list with minimum and maximum firmware version specified, the corresponding
    test will be marked as NOT_APPLICABLE with corresponding message.

    This function is expected to be called by a pod fixture at the function-level.
    """
    all_capability_markers = [
        mark
        for mark in request._pyfuncitem.iter_markers()
        if mark.name == "capability" and mark.kwargs.get("source") == "model_properties"
    ]
    all_marked_features = set()
    for mark in all_capability_markers:
        for arg in mark.args:
            if isinstance(arg, dict) and "features" in arg:
                all_marked_features.add(arg["features"])
    for feature in all_marked_features:
        skip_firmware_feature(pod, feature, request)


@pytest.fixture(scope="session")
def _gw_object(tb_config, request) -> PodApi | None:
    """Returns gw pod session object."""
    try:
        gw = _pod_factory.Pod().resolve_obj(name="gw", index=0, config=tb_config, multi_obj=False, request=request)
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate session-scoped gw object. The error is: \n%s",
            "".join(traceback.format_exception(err)),
        )
        return None
    return gw


@pytest.fixture(scope="session")
def gw_session(request, _gw_object) -> PodApi | None:
    """Pod ``gw`` object, session-scoped."""
    try:
        if _gw_object is not None:
            with safe_setup(OSRTFixtureTestObject(_gw_object), scope="session", request=request):
                yield _gw_object
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate session-scoped gw object, with the error: %s",
            "".join(traceback.format_exception(err)),
        )
        yield None


@pytest.fixture(scope="module")
def gw_module(gw_session, request) -> PodApi | None:
    """Pod ``gw`` object, module-scoped."""
    try:
        if gw_session is not None:
            with safe_setup(OSRTFixtureTestObject(gw_session), scope="module", request=request):
                yield gw_session
        else:
            yield None
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate module-scoped gw object, with the error: %s",
            "".join(traceback.format_exception(err)),
        )
        yield None


@pytest.fixture(scope="function")
def gw(gw_module, request) -> PodApi | None:
    """Yields ``gw`` pod to be used by tests."""
    try:
        if gw_module is not None:
            with safe_setup(OSRTFixtureTestObject(gw_module), scope="function", request=request):
                check_pod_features(gw_module, request)
                yield gw_module
        else:
            yield None
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate function-scoped gw object, with the error: %s",
            "".join(traceback.format_exception(err)),
        )
        yield None


@pytest.fixture(scope="session")
def _l1_object(tb_config, request) -> PodApi | None:
    """Returns l1 pod session object."""
    try:
        leaf = _pod_factory.Pod().resolve_obj(name="l1", index=1, config=tb_config, multi_obj=False, request=request)
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate session-scoped l1 object. The error is: %s",
            "".join(
                traceback.format_exception(err),
            ),
        )
        return None
    return leaf


@pytest.fixture(scope="session")
def l1_session(request, _l1_object) -> PodApi | None:
    """Pod ``l1``, leaf, session-scoped"""
    try:
        if _l1_object is not None:
            with safe_setup(OSRTFixtureTestObject(_l1_object), scope="session", request=request):
                yield _l1_object
        else:
            yield None
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate session-scoped l1 object, with the error: %s",
            "".join(traceback.format_exception(err)),
        )
        yield None


@pytest.fixture(scope="module")
def l1_module(l1_session, request) -> PodApi | None:
    """Pod ``l1``, leaf, module-scoped"""
    try:
        if l1_session is not None:
            with safe_setup(OSRTFixtureTestObject(l1_session), scope="module", request=request):
                yield l1_session
        else:
            yield None
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate module-scoped l1 object, with the error: %s",
            "".join(traceback.format_exception(err)),
        )
        yield None


@pytest.fixture(scope="function")
def l1(l1_module, request) -> PodApi:
    """Yields ``l1`` pod."""
    try:
        if l1_module is not None:
            with safe_setup(OSRTFixtureTestObject(l1_module), scope="function", request=request):
                check_pod_features(l1_module, request)
                yield l1_module
        else:
            yield None
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate function-scoped l1 object, with the error: %s",
            "".join(traceback.format_exception(err)),
        )
        yield None


@pytest.fixture(scope="session")
def _l2_object(tb_config, request) -> PodApi | None:
    """Returns l2 pod session object."""
    try:
        leaf = _pod_factory.Pod().resolve_obj(name="l2", index=2, config=tb_config, multi_obj=False, request=request)
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate session-scoped l2 object. The error is: %s",
            "".join(
                traceback.format_exception(err),
            ),
        )
        return None
    return leaf


@pytest.fixture(scope="session")
def l2_session(request, _l2_object) -> PodApi | None:
    """Pod ``l2``, leaf, session-scoped"""
    try:
        if _l2_object is not None:
            with safe_setup(OSRTFixtureTestObject(_l2_object), scope="session", request=request):
                yield _l2_object
        else:
            yield None
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate session-scoped l2 object, with the error: %s",
            "".join(traceback.format_exception(err)),
        )
        yield None


@pytest.fixture(scope="module")
def l2_module(l2_session, request) -> PodApi | None:
    """Pod ``l2``, leaf, module-scoped"""
    try:
        if l2_module is not None:
            with safe_setup(OSRTFixtureTestObject(l2_session), scope="module", request=request):
                yield l2_session
        else:
            yield None
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate module-scoped l2 object, with the error: %s",
            "".join(traceback.format_exception(err)),
        )
        yield None


@pytest.fixture(scope="function")
def l2(l2_module, request) -> PodApi | None:
    """Yields ``l2`` pod."""
    try:
        if l2_module is not None:
            with safe_setup(OSRTFixtureTestObject(l2_module), scope="function", request=request):
                check_pod_features(l2_module, request)
                yield l2_module
        else:
            yield None
    except (OpenSyncException, ValueError, OSError, RuntimeError, TimeoutError, EnvironmentError) as err:
        log.warning(
            "Could not instantiate function-scoped l2 object, with the error: %s",
            "".join(traceback.format_exception(err)),
        )
        yield None


@pytest.fixture(scope="session")
def _pods_object(tb_config, request) -> DevicesApi:
    """Returns pods session object."""
    pods = _pod_factory.Pods().resolve_obj_by_fixture(request=request, config=tb_config, multi_obj=True)
    return pods


@pytest.fixture(scope="session")
def pods_session(request, _pods_object) -> DevicesApi:
    """Pods object containing all pods from the config. Session-scoped."""
    with safe_setup(OSRTFixtureTestObject(_pods_object), scope="session", request=request):
        yield _pods_object


@pytest.fixture(scope="module")
def pods_module(pods_session, request) -> DevicesApi:
    """Pods object containing all pods from the config. Module-scoped."""
    with safe_setup(OSRTFixtureTestObject(pods_session), scope="module", request=request):
        yield pods_session


@pytest.fixture(scope="function")
def pods(pods_module, request) -> DevicesApi:
    """Pods object containing all pods from the config. All functions are run in parallel on all pods."""
    with safe_setup(OSRTFixtureTestObject(pods_module), scope="function", request=request):
        yield pods_module


@pytest.fixture(scope="session")
def leafs_session(tb_config, request) -> DevicesApi:
    """Leafs object containing all leafs from the config. Session-scoped."""
    leafs = _pod_factory.Pods().resolve_obj_by_fixture(role="leaf", request=request, config=tb_config, multi_obj=True)
    with safe_setup(OSRTFixtureTestObject(leafs), scope="session", request=request):
        yield leafs


@pytest.fixture(scope="module")
def leafs_module(leafs_session, request) -> DevicesApi:
    """Leafs object containing all leafs from the config. Module-scoped."""
    with safe_setup(OSRTFixtureTestObject(leafs_session), scope="module", request=request):
        yield leafs_session


@pytest.fixture(scope="function")
def leafs(leafs_module, request) -> DevicesApi:
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
def connect_wifi_client(request):
    """Connect wireless client, function scoped"""

    def _connect_wifi_client(client_obj: ClientApi, **kwargs) -> str:
        response = client_obj.connect(**kwargs)
        request.addfinalizer(lambda: client_obj.disconnect(skip_exception=True))
        return response

    yield _connect_wifi_client


@pytest.fixture(scope="function")
def connect_eth_client(request):
    """Connect wireless client, function scoped"""

    def _connect_eth_client(client_obj: ClientApi, **kwargs) -> str:
        response = client_obj.eth_connect(**kwargs)
        request.addfinalizer(lambda: client_obj.eth_disconnect(skip_exception=True))
        return response

    yield _connect_eth_client


@pytest.fixture(scope="function")
def connect_client(connect_wifi_client, connect_eth_client):
    """Connect wireless or wired client, function scoped"""

    def _connect_client(client_obj: ClientApi, **kwargs) -> str:
        if client_obj.wlan_ifname:
            return connect_wifi_client(client_obj, **kwargs)
        else:
            return connect_eth_client(client_obj, **kwargs)

    yield _connect_client


@pytest.fixture(scope="function")
def continuous_ping(request):
    """Start continuous ping on wireless or wired client"""

    def _continuous_ping(client_obj: ClientApi, **kwargs):
        client_obj.start_continuous_ping(**kwargs)
        request.addfinalizer(lambda: client_obj.stop_continuous_ping(skip_exception=True))

    return _continuous_ping


@pytest.fixture(scope="session")
def attenuator(tb_config) -> AttenuatorLib:
    return AttenuatorLib(tb_config)
