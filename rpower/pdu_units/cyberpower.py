from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    Integer32,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    Udp6TransportTarget,
    UdpTransportTarget,
    getCmd,
    setCmd,
)

SNMP_PORT = 161


class PduLib:
    """
    Represents a CyberPower Switched PDU with remote outlet control
    """

    # Some comments in this class refer to MIB variables extracted by running snmptranslate commands.
    # For those to work you'll need to install the CPS-MIB. You can do as follows (Ubuntu):
    #     sudo apt-get install snmp snmp-mibs-downloader
    #     sudo sed -i "s/^mibs/#mibs/" /etc/snmp/snmp.conf
    #     mkdir -p ~/.snmp/mibs
    # copy PDU MIB file to ~/.snmp/mibs
    #     echo mibs CPS-MIB | sudo tee --append /etc/snmp/snmp.conf
    # See snmptranslate -Td CPS-MIB::ePDUOutletControlOutletCommand

    def __init__(self, address: str, port: int, username: str, password: str, ipv6: bool, requests_session):
        # CyberPower uses SNMPv1, meaning unauthenticated access
        self.engine = SnmpEngine()
        self.auth = CommunityData("private")
        transport_class = Udp6TransportTarget if ipv6 else UdpTransportTarget
        self.transport = transport_class((address, SNMP_PORT))
        self.context = ContextData()

    def model(self):
        """Get PDU model"""
        # ...ePDU...ePDUIdentModelNumber.0
        response = self.send_get("1.3.6.1.4.1.3808.1.1.3.1.5.0")
        return self.response_to_result(response)

    def version(self):
        """Get PDU firmware version"""
        # ...ePDU...ePDUIdentFirmwareRev.0
        response = self.send_get("1.3.6.1.4.1.3808.1.1.3.1.3.0")
        return self.response_to_result(response)

    def status(self, ports):
        """Get power status of PDU outlets"""
        response = {}
        for port in ports:
            # ...ePDU2...ePDU2OutletSwitchedControlCommand.{outlet}
            resp = self.send_get(f"1.3.6.1.4.1.3808.1.1.6.6.1.5.1.5.{port}")
            result = self.response_to_result(resp)
            response[port] = self.port_result(port, result)
        return response

    def consumption(self, ports: list[str]):
        """Not supported on CyberPower PDUs"""
        return {port: [1, "", "Power metering not supported on CyberPower Switched PDUs"] for port in ports}

    def on(self, ports):
        """Turn PDU outlets on"""
        return self.set(ports, "ON")

    def off(self, ports):
        """Turn PDU outlets off"""
        return self.set(ports, "OFF")

    def set(self, ports, state):
        # immediateOn: 1
        # immediateOff: 2
        value = 1 if state == "ON" else 2
        value = Integer32(value)
        response = {}
        for port in ports:
            # ...ePDU2...ePDU2OutletSwitchedControlCommand.{outlet}
            resp = self.send_set(f"1.3.6.1.4.1.3808.1.1.6.6.1.5.1.5.{port}", value)
            result = self.response_to_result(resp)
            response[port] = self.port_result(port, result)
        return response

    def send_get(self, oid):
        command_generator = getCmd(
            self.engine,
            self.auth,
            self.transport,
            self.context,
            ObjectType(ObjectIdentity(oid)),
        )
        return next(command_generator)

    def send_set(self, oid, value):
        command_generator = setCmd(
            self.engine,
            self.auth,
            self.transport,
            self.context,
            ObjectType(ObjectIdentity(oid), value),
        )
        return next(command_generator)

    def response_to_result(self, response):
        error_indication, error_status, error_index, var_binds = response
        stdout = ""
        if var_binds:
            oid, value = var_binds[0]
            stdout = value.prettyPrint()
        stderr = error_indication if error_indication else ""
        # When SNMP isn't reachable we don't get any error code, just error message about timeout
        if stderr and not stdout and not error_index:
            error_index = 1
        return [error_index, stdout, stderr]

    def port_result(self, port, result):
        # immediateOn: 1
        # immediateOff: 2
        # immediateReboot: 3
        # delayedOn: 4
        # delayedOff: 5
        # delayedReboot: 6
        # cancelPendingCommand: 7
        # outletIdentify: 8
        status = "ON" if result[1] == "1" else "OFF"
        return [result[0], f"Port {port}: {status}", result[2]]
