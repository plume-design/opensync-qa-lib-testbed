from osrt_cli_tools import testbed


def test_list_tools(cli_runner):
    ret = cli_runner.invoke(testbed.cli, ["tools"])
    assert "pod" in ret.stdout
    assert "client" in ret.stdout
    assert "config" in ret.stdout
    assert "testbed" in ret.stdout  # <- the tool should also report itself, right?
    assert "Testbed not set. Use 'osrt shell' command to select desired testbed" in ret.stderr
