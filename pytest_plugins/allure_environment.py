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
            allure_util.add_environment("osrt_snapshot", "file://<br><code>" + snapshot + "</code>")

    try:
        gw = request.getfixturevalue("gw_session")
        l1, l2 = request.getfixturevalue("l1_session"), request.getfixturevalue("l2_session")
    # catch also Exception raised by device_discovery in case there is no mgmt access
    except (pytest.FixtureLookupError, Exception):
        # config has already been loaded by now, however when only tests with modified tb-config are loaded
        # getting the pods and cloud objects might not always work.
        return

    for node in [gw, l1, l2]:
        allure_util.add_allure_group_envs(
            f"node_{node.serial}",
            "version",
            node.version(),
            f"file://{node.serial}",
            fixed_value=True,
        )
        allure_util.add_allure_group_envs(
            f"node_{node.serial}", "model", node.model, f"file://{node.serial}", fixed_value=True
        )
        modules = node.ovsdb.get_json_table("Object_Store_State", where="status!='install-done'", skip_exception=True)
        if not modules:
            continue
        if isinstance(modules, dict):  # this happens when just one column is returned - just 1 module
            modules = [modules]
        for module in modules:
            allure_util.add_allure_group_envs(
                f"node_{node.serial}",
                module["name"],
                module.get("version", "unknown"),
                f"file://{node.serial}",
                fixed_value=True,
            )
    git_ver = get_git_revision()
    if git_ver:
        allure_util.add_environment("git_sha", git_ver, "_error")
    else:
        framework_version = get_framework_version()
        if framework_version:
            allure_util.add_environment("framework_version", framework_version, "_error")

    if "LTE" in loaded_config.get("capabilities", []):
        lte_uplink = "LTE" if loaded_config.get("runtime_lte_only_uplink") else "WAN"
        allure_util.add_environment("uplink", lte_uplink, "_error")
