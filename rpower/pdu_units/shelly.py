import ShellyPy


class PduLib:
    """
    Represents a Shelly smart relay with power metering
    """

    def __init__(self, address: str, port: int, username: str, password: str, ipv6: bool, requests_session):
        # Shelly  doesn't require authentication by default, but when it is configured,
        # this login dict is how it is supposed to be used.
        self.shelly = ShellyPy.Shelly(address, port, login=dict(username=username, password=password))

    def model(self):
        """Get PDU model"""
        # Not necessarily true, but model info is not present anywhere in Shelly API
        return [0, "Shelly Pro 4PM", ""]

    def version(self):
        """Get PDU firmware version"""
        return [0, self.shelly.settings()["device"]["fw_id"], ""]

    def status(self, ports: list[str]):
        """Get power status of PDU outlets"""
        response = {}
        for port in ports:
            relay_id = int(port) - 1
            status = "ON" if self.shelly.relay(relay_id).get("output") else "OFF"
            response[port] = [0, f"Port {port}: {status}", ""]
        return response

    def consumption(self, ports: list[str]):
        """Get power consumption of PDU outlets"""
        response = {}
        for port in ports:
            relay_id = int(port) - 1
            relay_status = self.shelly.relay(relay_id)
            if "apower" in relay_status:
                response[port] = [0, f"{relay_status['apower']}W", ""]
            else:
                response[port] = [1, "", "Power metering not supported"]
        return response

    def on(self, ports: list[str]):
        """Turn PDU outlets on"""
        return self.set(ports, "ON")

    def off(self, ports: list[str]):
        """Turn PDU outlets off"""
        return self.set(ports, "OFF")

    def set(self, ports, state):
        on = True if state == "ON" else False
        for port in ports:
            relay_id = int(port) - 1
            self.shelly.relay(relay_id, turn=on)
        return self.status(ports)
