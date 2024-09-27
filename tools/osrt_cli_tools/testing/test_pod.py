# NOTE: These are integration-tests, not real unit-level.
# The tests mock ssh calls and env-variables that extend beyond this python package.
import json
import collections
import pytest
from osrt_cli_tools import pod


def test_tb_not_set(cli_runner):
    result = cli_runner.invoke(pod.uptime, catch_exceptions=False)
    assert "Testbed not found. Use 'osrt shell' command to configure testbed." in result.output
    assert result.exit_code == 1


def test_run_uptime(cli_runner, ssh_mock):
    ssh_mock(sequence=[(0, "15:20:21 up 10 days,  2:45,  0 users,  load average: 0.00, 0.00, 0.00", "")] * 3)
    result = cli_runner.invoke(pod.run, "uptime", catch_exceptions=False)
    assert result.exit_code == 0
    assert result.output.count("15:20:21 up 10 days") == 3


def test_uptime(cli_runner, ssh_mock):
    # unlike the test before this, just invoke uptime command directly:
    ssh_mock(sequence=[(0, "15:20:21 up 10 days,  2:45,  0 users,  load average: 0.00, 0.00, 0.00", "")] * 3)
    result = cli_runner.invoke(pod.uptime, catch_exceptions=False)
    assert result.exit_code == 0
    assert result.output.count("15:20:21 up 10 days") == 3


def test_pod_version(cli_runner, ssh_mock):
    ssh_mock(sequence=[(0, "6.4.0-6-g5de877-dev-debug", "")])
    result = cli_runner.invoke(pod.version, "gw", catch_exceptions=False)
    assert result.exit_code == 0
    assert "6.4.0-6-g5de877-dev-debug" in result.output


def test_pod_list(cli_runner, mock_opensync_testbed):
    results = cli_runner.invoke(pod.list_)
    assert "gw\nl1\nl2\n" in results.stdout


def test_pod_list_testbeds_json(cli_runner, mock_opensync_testbed):
    results = cli_runner.invoke(pod.list_, obj={"JSON": True, "TESTBEDS": ["example", "test-tb"]})
    parsed_res = json.loads(results.stdout)
    assert parsed_res == {"example": ["gw", "l1", "l2"], "test-tb": ["gw", "leaf1", "leaf2"]}


def test_pod_parallel_run(cli_runner, ssh_mock):
    ssh_mock(sequence=[(0, "15:20:21 up 10 days,  2:45,  0 users,  load average: 0.00, 0.00, 0.00", "")] * 6)
    results = cli_runner.invoke(
        pod.run,
        "uptime",
        catch_exceptions=False,
        obj={"TESTBEDS": ["example", "test-tb"], "SKIP_RESERVATION": True, "JSON": False, "DRY_RUN": False},
    )
    assert results.exit_code == 0
    assert results.output.count("15:20:21 up 10 days") == 6


def test_pod_parallel_dry_run_info(cli_runner):
    results = cli_runner.invoke(
        pod.info,
        catch_exceptions=False,
        obj={"TESTBEDS": ["example", "test-tb"], "SKIP_RESERVATION": False, "JSON": False, "DRY_RUN": True},
    )
    lines = results.output.splitlines()
    assert 6 == len([line for line in lines if line.startswith("DRY-RUN:")])
    assert 2 == len([line for line in lines if line.startswith("DRY-RUN:") and "info" in line])
    assert 4 == len([line for line in lines if "info" in line])  # account for table!


@pytest.mark.parametrize("node_name_len", [("leaves", 2), ("gateway", 1), ("*", 3), ("l?", 2)])
def test_process_nodes_arg(mock_opensync_testbed, node_name_len):
    name, expected_len = node_name_len
    nodes = pod._process_nodes_arg(name)
    assert len(nodes) == expected_len


def test_autocomplete_when_not_in_context(mock_opensync_testbed):
    assert pod.complete_defined_pod_names("ctx", "param", "l") is None


def test_autocomplete_in_context(mock_opensync_testbed, monkeypatch):
    monkeypatch.setenv("_OSRT_COMPLETE", "true")
    assert pod.complete_defined_pod_names("ctx", "param", "l") == ["l1", "l2"]


def test_autocomplete_no_testbed(monkeypatch):
    monkeypatch.setenv("_OSRT_COMPLETE", "true")
    with pytest.raises(SystemExit):
        pod.complete_defined_pod_names("ctx", "param", "l")


def test_complete_all_pods(mock_opensync_testbed):
    pods = pod.complete_all_pods("ctx", "param", "l")
    assert pods == ["leaves", "l1", "l2"]


def test_main_entry_point_help(cli_runner):
    help_output = cli_runner.invoke(pod.cli, "--help")
    assert "Show this message and exit." in help_output.stdout


def test_load_tb_config_by_name():
    tb_cfg = pod._get_tb_cfg("example")
    assert [n["name"] for n in tb_cfg["Nodes"]] == ["gw", "l1", "l2"]


def test_upgrade_version_list(mock_opensync_testbed, cli_runner, ssh_mock):
    ssh_mock(sequence=[(0, "PP203X", "")] * 3)  # <- to allow creation of pods object
    version_list = cli_runner.invoke(pod.upgrade, "--version-list")
    assert version_list.exit_code == 0
    assert "6.2.0" in version_list.stdout


def test_upgrade_call(mock_opensync_testbed, cli_runner, ssh_mock, monkeypatch):
    import lib_testbed.generic.pod.generic.pod_tool

    ssh_mock(sequence=[(0, "PP203X", "")] * 3)  # <- to allow creation of pods object

    def _fake_upgrade(*args, **kwargs):
        return [0, "success", ""]

    monkeypatch.setattr(lib_testbed.generic.pod.generic.pod_tool.PodTool, "upgrade", _fake_upgrade)
    upgrade_result = cli_runner.invoke(pod.upgrade, "6.2.0")
    counter = collections.Counter(upgrade_result.stdout.split())
    assert counter["success"] == 3


def test_multiple_ssh_sessions(cli_runner):
    res = cli_runner.invoke(pod.ssh, "gw", obj={"TESTBEDS": ["example", "test-tb"]})
    assert isinstance(res.exception, SystemExit)
    assert "Interactive SSH cannot be started against multiple testbeds" in res.stderr


def test_parallel_reservation(cli_runner, ssh_mock, monkeypatch):
    import osrt_cli_tools.reserve

    class reserve_mock:
        def reserve_test_bed(self, *args, **kwargs):
            return {"status": True}

        def unreserve(self):
            return {"status": True}

    def _get_fake_reserve(*args, **kwargs):
        return reserve_mock()

    ssh_mock(sequence=[(0, "PP203X-mocked", "")] * 6)
    monkeypatch.setattr(osrt_cli_tools.reserve, "get_reserve_object", _get_fake_reserve)
    model_output = cli_runner.invoke(pod.model, obj={"TESTBEDS": ["example", "test-tb"], "JSON": True})
    parsed = json.loads(model_output.stdout)
    for item in parsed:
        tb_name = list(item.keys())[0]
        for node in item[tb_name]:
            assert item[tb_name][node][1] == "PP203X-mocked"
