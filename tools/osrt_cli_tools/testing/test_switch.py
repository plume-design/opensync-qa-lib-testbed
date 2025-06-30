# due to difficulty with mocking pexpect, only utility code is tested for now

from osrt_cli_tools import switch


def test_process_ports_arg():
    ports = switch.process_ports_arg(None, None, "g*")
    assert "gw_eth0" in ports
    assert "gw_eth1" in ports


def test_complete_ports(mock_opensync_testbed):
    ports = switch.complete_port_names(None, None, "l")
    assert "l1_eth0" in ports
    assert "l1_eth1" in ports
    assert "l2_eth0" in ports
    assert "l2_eth1" in ports
