import json
from pathlib import Path

import responses

from osrt_cli_tools import rpower
from osrt_cli_tools import reserve


@responses.activate
def test_cycle(cli_runner, ssh_mock):
    # ssh mock is to mock testbed to example.yaml
    responses._add_from_file(file_path=Path(__file__).parent / "rpower_example_cycle_gw.yaml")
    res = cli_runner.invoke(rpower.cli, ["--json", "cycle", "gw"], obj={})

    assert res.exit_code == 0
    parsed = json.loads(res.stdout)
    assert parsed["gw"] == [0, "Port 1: ON", ""]


@responses.activate
def test_off(cli_runner, ssh_mock):
    responses._add_from_file(file_path=Path(__file__).parent / "rpower_example_cycle_gw.yaml")
    res = cli_runner.invoke(rpower.cli, ["--json", "off", "gw"], obj={})

    assert res.exit_code == 0
    parsed = json.loads(res.stdout)
    assert parsed["gw"] == [0, "Port 1: OFF", ""]


@responses.activate
def test_parallel_restart(cli_runner, ssh_mock):
    # mock reservation status to be successful:
    reserve_obj = reserve.get_reserve_object()
    machine_uuid = reserve_obj._get_machine_uuid()
    ssh_mock(
        sequence=[
            (
                0,
                f"QA/Automation/atr_dev_verification-8:::{machine_uuid}:::"
                "2024-08-02T08:37:44.647341+00:00:::2034-08-08T12:09:14.953311+00:00:::3.3.0:::False:::msg",
                "",
            )
        ]
        * 40
    )
    responses._add_from_file(file_path=Path(__file__).parent / "rpower_example_cycle_gw.yaml")
    res = cli_runner.invoke(rpower.cycle, ["gw"], obj={"TESTBEDS": ["example", "test-tb"], "JSON": False})
    assert res.exit_code == 0
    assert "Port 1: ON" in "".join(res.stdout)
    # fake pdu in the test-tb config file should result with an error, and it's split into 2 lines in CI:
    assert "ModuleNotFoundError: No module named" in "".join(res.stdout)
    assert "lib_testbed.generic.rpower.pdu_units.fake" in "".join(res.stdout)
