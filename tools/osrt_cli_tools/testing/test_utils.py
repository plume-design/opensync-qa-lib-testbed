import sys
import pytest
from osrt_cli_tools import utils


@pytest.fixture(scope="function")
def patch_sys_exit(monkeypatch):
    monkeypatch.setattr(sys, "exit", lambda x: x)


@pytest.fixture(scope="function")
def ctx():
    """Mocked click context."""

    class Ctx:
        def __init__(self):
            self.obj = {}
            self.call_on_close_result = None

        def call_on_close(self, func: callable):
            self.call_on_close_result = func()

    return Ctx()


@pytest.mark.parametrize("with_json", [True, False])
def test_simple_print_command(patch_sys_exit, ctx, capsys, with_json):
    output = {
        "w1": [10, "stdout_test_me", ""],
        "w2": ["20", "stdout", ""],
        "w3": [30, "", "stderr"],
        "e1": ["40", "1.2.3.4", "5.6.7.8"],
    }
    if with_json:
        ctx.obj["JSON"] = True
    utils.print_command_output(ctx, output)
    captured = capsys.readouterr()
    assert "10" in captured.out
    assert "20" in captured.out
    assert "30" in captured.out
    assert "40" in captured.out
    assert "e1" in captured.out
    assert "w1" in captured.out
    assert "stdout_test_me" in captured.out
    assert "5.6.7.8" in captured.out
    assert captured.err == ""
    assert ctx.call_on_close_result == 40


@pytest.mark.parametrize("with_json", [True, False])
def test_print_command_with_error(patch_sys_exit, ctx, capsys, with_json):
    output = {
        "w1": [0, "stdout_test_me", ""],
        "w2": IOError("test exception"),
        "w3": [0, "", "stderr"],
    }
    if with_json:
        ctx.obj["JSON"] = True
    utils.print_command_output(ctx, output)
    captured = capsys.readouterr()
    assert "OSError" in captured.out
    if with_json:
        assert "Error creating json output, fallback to tables:" in captured.out
    assert ctx.call_on_close_result == 1


def test_complete_devices(mock_osrt_testbed):
    results = utils.complete_devices(None, None, "l")
    assert "l1" in results
    assert "l2" in results


def test_complete_devices_comma(mock_osrt_testbed):
    results = utils.complete_devices(None, None, "w1,")
    for result in results:
        assert result.startswith("w1,")
    assert "w1,w1" not in results
    assert "w1,clients" in results
    assert "w1,pods" in results
    assert "w1,gw" in results
    assert "w1,e1" in results


def test_complete_testbeds():
    results = utils.complete_testbeds(None, None, "slo")
    assert results
    for res in results:
        assert res.startswith("slo")


@pytest.mark.parametrize("val", ["true", "on", "1", "True", "TRUE", True])
def test_bool_true(val):
    assert utils.bool_choices_to_bool(val)


@pytest.mark.parametrize("val", ["false", "off", "0", "False", "FALSE", False])
def test_bool_false(val):
    assert not utils.bool_choices_to_bool(val)
