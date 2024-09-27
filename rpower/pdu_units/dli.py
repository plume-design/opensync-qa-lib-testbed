import re

from html.parser import HTMLParser

_OUTLET_STATE_PATTERN = re.compile(r"state=(?P<outlet_strate>[0-9a-fA-F]+)")


class MyHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.cursor = False
        self.my_data = []

    def error(self, message):
        pass

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.cursor = True

    def handle_data(self, data):
        if self.cursor:
            if "XML" not in data and data.strip():
                self.my_data.append(data.strip())


class PduLib:
    """
    Represents a Digital Loggers Smart PDU
    """

    def __init__(self, address: str, port: int, username: str, password: str, ipv6: bool, requests_session):
        host = f"[{address}]" if ipv6 else address
        self.url_prefix = f"http://{host}:{port}"
        self.session = requests_session
        self.session.auth = (username, password)

    def model(self):
        """Get PDU model"""
        # Not listed anywhere in the PDU Web UI
        return [0, "DLI", ""]

    def version(self):
        """Get PDU firmware version"""
        response = self.execute_request("support.htm")
        if response[0]:
            return response
        parser = MyHtmlParser()
        parser.feed(response[1])
        stop = False
        for data in parser.my_data:
            if stop:
                return [0, data.split(" ")[0], ""]
            if "firmware version" in data.lower():
                stop = True
        return [1, "", "UNKNOWN"]

    def status(self, ports: list[str]):
        """Get power status of PDU outlets"""
        response = self.execute_request("index.htm")
        if response[0]:
            return {port: response for port in ports}
        match = _OUTLET_STATE_PATTERN.search(response[1])
        if match is None:
            return {port: [1, "", f"Could not read port: {port} state"] for port in ports}
        val = int(match["outlet_strate"], 16)
        return {port: [0, f"Port {port}: {'ON' if (val >> (int(port) - 1)) & 0x01 else 'OFF'}", ""] for port in ports}

    def consumption(self, ports: list[str]):
        """Not supported on Digital Loggers PDUs"""
        return {port: [1, "", "Power metering not supported on Digital Loggers Smart PDUs"] for port in ports}

    def on(self, ports: list[str]):
        """Turn PDU outlets on"""
        return self.set(ports, "ON")

    def off(self, ports: list[str]):
        """Turn PDU outlets off"""
        return self.set(ports, "OFF")

    def set(self, ports, state):
        for port in ports:
            self.execute_request(f"outlet?{port}={state}")
        # on and off requests return nonsense whether the request was successful or not,
        # that's how the DLI PDU just works.
        # We need to check status by requesting status to be sure that the connectivity
        # is not an issue, and that the outlet statuses are set correctly.
        return self.status(ports)

    def execute_request(self, url_suffix):
        response = self.session.get(f"{self.url_prefix}/{url_suffix}", timeout=10)
        if not response.ok:
            return [response.status_code, "", response.reason]
        else:
            return [0, response.text, ""]
