import atexit
import re
import datetime
import pytest
from osrt_cli_tools import reserve


@pytest.mark.parametrize("with_force", [True, False])
def test_simple_set(with_force, ssh_mock, cli_runner):
    call_history = ssh_mock(
        sequence=[
            (
                0,
                "QA/Automation/atr_dev_verification-8:::drun:etc-docker-jenkins-slaveb42e994426d78:::"
                "2024-08-02T08:37:44.647341+00:00:::2024-08-02T08:55:33.947329+00:00 "
                "(Jenkins job on drun:etc-docker-jenkins-slave):::3.2.0:::False",
                "",
            )
        ]
        * 6
    )
    result = cli_runner.invoke(reserve.set_, [".", "1", "--force"] if with_force else [".", "1"], obj={})
    last_cmd = call_history[-1][1]["cmd"]  # this command is supposed to contain the reservation row (echo "...")
    echo_cmd = re.findall(r"echo\s+\".*\"\s+\|", last_cmd)[0].lstrip('echo "').rstrip('" |')
    columns = echo_cmd.split(":::")
    if with_force:
        assert columns[5] == "True"
    else:
        assert columns[5] == "False"
    # reservation was 1-minute long so the diff between end and start should be 60 seconds:
    assert (datetime.datetime.fromisoformat(columns[3]) - datetime.datetime.fromisoformat(columns[2])).seconds == 60
    assert "True" in result.stdout  # inspecting status, should be True either way


@pytest.mark.parametrize("with_force", [True, False])
def test_free(with_force, ssh_mock, cli_runner):
    call_history = ssh_mock(
        sequence=[
            (
                0,
                "QA/Automation/atr_dev_verification-8:::drun:etc-docker-jenkins-slaveb42e994426d78:::"
                "2024-08-02T08:37:44.647341+00:00:::"
                f"{datetime.datetime.isoformat(datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=5))} "
                "(Jenkins job on drun:etc-docker-jenkins-slave):::3.3.0:::False",
                "",
            )
        ]
        * 6
    )
    result = cli_runner.invoke(reserve.free, [".", "--force"] if with_force else ["."], obj={})
    if with_force:
        assert "forced-free" in call_history[-1][1]["cmd"]
        assert "True" in result.stdout
    else:
        assert "forced-free" not in call_history[-1][1]["cmd"]
        # since testbed is reserved by someone else, this operation should not end with a success:
        assert "False" in result.stdout


def test_history_clear_row_with_who_cleared_it(ssh_mock, cli_runner, monkeypatch):
    monkeypatch.setattr("click.confirm", lambda x: True)
    monkeypatch.setattr("rich_click.confirm", lambda x: True)
    call_history = ssh_mock(
        sequence=[
            (
                0,
                "QA/Automation/atr_dev_verification-8:::drun:etc-docker-jenkins-slaveb42e994426d78:::"
                "2024-08-02T08:37:44.647341+00:00:::2024-08-02T08:55:33.947329+00:00 "
                "(Jenkins job on drun:etc-docker-jenkins-slave):::3.2.0:::False",
                "",
            )
        ]
        * 6
    )
    result = cli_runner.invoke(reserve.hist_clear, ["."], obj={})
    assert "cleared-history" in call_history[-1][1]["cmd"]
    assert "True" in result.stdout


def test_wildcard_matching_excluded(cli_runner):
    result = cli_runner.invoke(reserve.history_get, ["exampl*"], obj={})
    assert result.exit_code == 3
    assert "No testbeds found" in result.stderr


def test_history_get_multiple_versions_history(ssh_mock, cli_runner):
    ssh_mock(
        sequence=[
            (
                0,
                "QA/Automation/autotest_daily_verification-2221:::drun:etc-docker-jenkins-slave18c04d0b28642221:::"
                "2024-08-07T16:47:50.095203+00:00:::2024-08-07T17:40:58.303171+00:00 "
                "(Jenkins job on drun:etc-docker-jenkins-slave):::3.1.1:::False\n"
                "aostrowski@aostrowski-lnb-PF3NLCW4:::aostrowski-lnb-PF3NLCW488a4c2984ca8:::"
                "2024-08-08T05:29:36.417333+00:00:::2024-08-08T07:44:41.138804+00:00:::3.1.2:::True\n"
                "aostrowski@aostrowski-lnb-PF3NLCW4:::aostrowski-lnb-PF3NLCW465ffc20cf3c8:::"
                "2024-08-08T10:09:26.410159+00:00:::2024-08-08T12:09:26.410191+00:00:::3.9.0:::True\n"
                "aostrowski@aostrowski-lnb-PF3NLCW4:::aostrowski-lnb-PF3NLCW488a4c2984ca8:::"
                "2024-08-08T10:09:26.410159+00:00:::2024-08-08T10:19:17.840499+00:00:::4.0.0:::False\n"
                "aostrowski@aostrowski-lnb-PF3NLCW4:::aostrowski-lnb-PF3NLCW488a4c2984ca8:::"
                "2024-08-08T10:19:22.020205+00:00:::2024-08-08T12:09:14.953311+00:00:::4.1.0:::False\n"
                "QA/Automation/autotest_daily_verification-2222:::drun:etc-docker-jenkins-slave18c04d0b28642222:::"
                "2024-08-08T16:47:46.671970+00:00:::"
                "2024-08-08T17:40:51.124639+00:00 (Jenkins job on drun:etc-docker-jenkins-slave):::5.0:::False",
                "",
            )
        ]
        * 2
    )
    result = cli_runner.invoke(reserve.history_get, ["."], obj={})
    assert result.exit_code == 0
    for ver in ["3.1.1", "3.1.2", "3.9.0", "4.0.0", "4.1.0", "5.0"]:
        assert ver in result.stdout


def test_outdated_version(ssh_mock, cli_runner, monkeypatch):
    registered = []

    def _register(*args, **kwargs):
        registered.append([args, kwargs])

    monkeypatch.setattr(atexit, "register", _register)
    ssh_mock(
        sequence=[
            (
                0,
                "aostrowski@aostrowski-lnb-PF3NLCW4:::aostrowski-lnb-PF3NLCW488a4c2984ca8:::"
                "2024-08-08T10:19:22.020205+00:00:::2024-08-08T12:09:14.953311+00:00:::4.1.0:::False:::\n"
                "QA/Automation/autotest_daily_verification-2222:::drun:etc-docker-jenkins-slave18c04d0b28642222:::"
                "2024-08-08T16:47:46.671970+00:00:::"
                "2024-08-08T17:40:51.124639+00:00 (Jenkins job on drun:etc-docker-jenkins-slave)"
                ":::50000.0:::False:::a-very-new-version",
                "",
            )
        ]
        * 10
    )
    result = cli_runner.invoke(reserve.get, ["."], obj={})
    assert result.exit_code == 0
    assert registered[0][0][0].__name__ == "_old_version_warning"  # registered a warning


@pytest.mark.parametrize("reservation_time", ["in a week", "8h", "tomorrow", "10"])
def test_reserve_set_human_readable(ssh_mock, cli_runner, reservation_time):
    call_history = ssh_mock(
        sequence=[
            (
                0,
                "QA/Automation/atr_dev_verification-8:::drun:etc-docker-jenkins-slaveb42e994426d78:::"
                "2024-08-02T08:37:44.647341+00:00:::2024-08-08T12:09:14.953311+00:00:::3.3.0:::False:::msg",
                "",
            )
        ]
        * 10
    )
    result = cli_runner.invoke(reserve.set_, [".", reservation_time], obj={"DEBUG": True})
    assert result.exit_code == 0
    res_end = call_history[-1][1]["cmd"].split(":::")[3]
    res_end_dt = datetime.datetime.fromisoformat(res_end)

    match reservation_time:
        # due to python casting as float seconds as int, it's always rounded down, i.e. 6.999999 days is 6d23h59m
        case "in a week":
            assert (res_end_dt - datetime.datetime.now(datetime.UTC)).days == 6
        case "8h":
            # note that "now" is a little off from "now" being processed by the reserve tool:
            assert 28600 < (res_end_dt - datetime.datetime.now(datetime.UTC)).total_seconds() < 28800
        case "tomorrow":
            # this should ideally be 24h, adding some wiggle room:
            assert 23.5 <= (res_end_dt - datetime.datetime.now(datetime.UTC)).total_seconds() / (60 * 60) <= 24.5
        case "10":
            # 10 minutes, +-100 seconds, again we need some wiggle room:
            assert 10 * 60 - 100 < (res_end_dt - datetime.datetime.now(datetime.UTC)).total_seconds() < 10 * 60 + 100
        case _:
            raise AssertionError("Not supported test parameter!")
