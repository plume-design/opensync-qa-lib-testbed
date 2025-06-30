import json
from osrt_cli_tools import config


def test_cfg_path_complete(custom_temp_dir, mock_osrt_testbed):
    switch_complete = config.path_autocomplete(None, None, "location.Sw")
    assert "location.Switch" in switch_complete
    assert "location.Switch." in switch_complete

    nodes_complete = config.path_autocomplete(None, None, "location.Nodes.")
    for i in range(0, 3):
        assert f"location.Nodes.{i}" in nodes_complete
        assert f"location.Nodes.{i}." in nodes_complete

    loc_complete = config.path_autocomplete(None, None, "loc")
    for expected_complete in ["location", "location.", "locations."]:
        assert expected_complete in loc_complete

    # locations_complete = config.path_autocomplete(None, None, "locations.")
    # assert len(locations_complete) > 1


def test_get_nodes(mock_osrt_testbed, cli_runner):
    for cfg_path in ["location.Nodes", "locations.example.Nodes"]:
        res = cli_runner.invoke(config.cli, ["get", cfg_path])
        assert res.exit_code == 0
        assert res.stderr == ""
        assert json.loads(res.stdout)[0]["name"] == "gw"

    res = cli_runner.invoke(config.cli, ["get", "location.Nodes.0"])
    assert res.exit_code == 0
    assert res.stderr == ""
    assert json.loads(res.stdout)["name"] == "gw"


def test_get_retry_full(mock_osrt_testbed, cli_runner):
    res = cli_runner.invoke(config.cli, ["get", "location.Nodes.0.capabilities"])
    assert res.exit_code != 0
    assert "The key: 'Nodes.0.capabilities' does not exist in the location config" in res.stderr
    assert "Re-try the command with --full flag." in res.stderr
    res2 = cli_runner.invoke(config.cli, ["get", "--full", "location.Nodes.0.capabilities"])
    assert res2.exit_code == 0
    assert json.loads(res2.stdout)["model_string"] == "PP203X"


def test_gw_serial_wildcard_across_locations(cli_runner):
    res = cli_runner.invoke(config.cli, ["get", "locations.*a*.Nodes.0.id"])
    assert res.exit_code == 0
    assert json.loads(res.stdout)["example"] == "<device serial number, example 123456789A>"


def test_ssh_example(mock_osrt_testbed, cli_runner):
    res = cli_runner.invoke(config.cli, ["ssh"])
    assert res.exit_code == 0
    assert "proxycommand ssh bare.w1.clients.example.tb -- sudo ip netns exec nswifi1 /usr/sbin/sshd -i" in res.stdout
    assert "host l1.nodes.example.tb bare.l1.nodes.example.tb" in res.stdout


def test_list_config_files(cli_runner):
    res = cli_runner.invoke(config.cli, ["list"])
    assert "example" in res.stdout


def test_clear_cache(custom_temp_dir, cli_runner):
    res = cli_runner.invoke(config.cli, ["tool-cache-clear"])
    assert "Deleted total of" in res.stdout


def test_validate_locations(cli_runner):
    from osrt_cli_tools import osrt

    res = cli_runner.invoke(osrt.validate_locations, ["--json"])
    json_output = json.loads(res.stdout)
    assert "example.yaml" in json_output[0][1]
    assert "valid location files" == json_output[0][0]
