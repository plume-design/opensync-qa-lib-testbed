from osrt_cli_tools import client


def test_uptime(cli_runner, ssh_mock):
    # unlike the test before this, just invoke uptime command directly:
    ssh_mock(sequence=[(0, "15:20:21 up 10 days,  2:45,  0 users,  load average: 0.00, 0.00, 0.00", "")] * 12)
    result = cli_runner.invoke(client.cli, ["uptime", "w1,w2,w3"], catch_exceptions=False)
    assert result.exit_code == 0
    assert result.output.count("15:20:21 up 10 days") == 3


def test_version_parallel_dry_run(cli_runner):
    result = cli_runner.invoke(
        client.version, obj={"TESTBEDS": ["example", "test-tb"], "SKIP_RESERVATION": True, "DRY_RUN": True}
    )
    assert "executing command version with" in result.stdout
    assert "Skipping reservation for testbed" in result.stderr


def test_complete_clients(mock_opensync_testbed):
    completed = client.complete_defined_clients(None, None, "w", client_type="wifi")
    assert "w1" in completed
    assert "w2" in completed
    assert "w3" in completed
    assert "e1" not in completed


def test_complete_pod_or_port(mock_opensync_testbed):
    completed = client.complete_pod_or_port(None, None, "g")
    assert "gw" in completed
    assert "gw_eth0" in completed
    assert "gw_eth1" in completed


def test_complete_all_clients(mock_opensync_testbed):
    completed = client.complete_all_clients(None, None, "e", client_type="eth")
    assert "e1" in completed
    assert "e2" in completed
    assert "e3" in completed
    assert "eth" in completed
    assert "all" not in completed
    completed2 = client.complete_all_clients(None, None, "")
    assert "all" in completed2
    assert "e1" in completed2
    assert "e2" in completed2
    assert "e3" in completed2
