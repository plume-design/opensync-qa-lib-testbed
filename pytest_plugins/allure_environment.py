import pytest
from lib_testbed.generic.util.allure_util import AllureUtil


@pytest.fixture(scope="session", autouse=True)
def allure_environment(tb_config, request):
    """Add information about testbed environment to Allure report."""
    if tb_config.get("ssh_gateway"):
        server_session = request.getfixturevalue("server_session")
        snapshot = server_session.run(
            'sudo osrt_snapshot && base64 -w0 "$(ls -A1 | grep snapshot_$(date -uI) | tail -n1)" '
            '&& sudo rm "$(ls -A1 | grep snapshot_$(date -uI) | tail -n1)"',
            skip_exception=True,
        )
        if snapshot:
            AllureUtil(request.config).add_environment("osrt_snapshot", "file://<br><code>" + snapshot + "</code>")
