import pytest
from lib_testbed.generic.util.allure_util import AllureUtil
from lib_testbed.generic.util.common import get_git_revision, get_framework_version


def get_osrt_snapshot(server_session):
    snapshot = server_session.run(
        'sudo osrt_snapshot && base64 -w0 "$(ls -A1 | grep snapshot_$(date -uI) | tail -n1)" '
        '&& sudo rm "$(ls -A1 | grep snapshot_$(date -uI) | tail -n1)"',
        skip_exception=True,
    )
    return snapshot


@pytest.fixture(scope="session", autouse=True)
def allure_environment(request):
    """Add information about testbed environment to Allure report."""
    if request.config.option.skip_init or request.config.option.skip_logs:
        return
    try:
        loaded_config = request.getfixturevalue("tb_config")
    except pytest.FixtureLookupError:
        # tb_config is not available, it happens if --config isn't used
        return
    upgrade_plugin = request.config.pluginmanager.get_plugin("upgrade")  # upgrade plugin is not always registered
    if upgrade_plugin:
        # we get upgrade fixture so that the upgrade is performed before we save information about pod versions
        request.getfixturevalue("upgrade_fixture")
    allure_util = AllureUtil(request.config)
    if loaded_config.get("ssh_gateway"):
        server_session = request.getfixturevalue("server_session")
        snapshot = get_osrt_snapshot(server_session)
        if snapshot:
            allure_util.cache_testbed_value("osrt_snapshot", snapshot)

    nodes = []
    for node_name in "gw", "l1", "l2":
        try:
            node = request.getfixturevalue(f"{node_name}_session")
        # catch also Exception raised by device_discovery in case there is no mgmt access
        except (pytest.FixtureLookupError, Exception):
            # config has already been loaded by now, however when only tests with modified tb-config are loaded
            # getting the pods and cloud objects might not always work.
            continue
        else:
            nodes.append(node)

    for node in nodes:
        if not node:
            continue
        # Cache information about node. The cached information also get attached to test report.
        for info_name in "serial", "model", "version", "region", "modules":
            allure_util.cache_node_value(node, info_name)

    git_ver = get_git_revision()
    if git_ver:
        allure_util.cache_environment_value("git_sha", git_ver)
    framework_version = get_framework_version()
    if framework_version:
        allure_util.cache_environment_value("framework_version", framework_version)

    if "LTE" in loaded_config.get("capabilities", []):
        lte_uplink = "LTE" if loaded_config.get("runtime_lte_only_uplink") else "WAN"
        allure_util.cache_testbed_value("uplink", lte_uplink)
