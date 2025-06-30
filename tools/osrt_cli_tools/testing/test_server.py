from osrt_cli_tools import server


def test_uptime(cli_runner, ssh_mock):
    # unlike the test before this, just invoke uptime command directly:
    ssh_mock(sequence=[(0, "15:20:21 up 10 days,  2:45,  0 users,  load average: 0.00, 0.00, 0.00", "")] * 3)
    result = cli_runner.invoke(server.cli, ["uptime"], catch_exceptions=False)
    assert result.exit_code == 0
    assert result.output.count("15:20:21 up 10 days") == 1
