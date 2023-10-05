from lib_testbed.generic.rpower.pdu_units.common_pdu_lib import PduLib


class CyberPowerLib(PduLib):
    def status(self, device_names):
        ports = self.port_args(device_names)
        response = self.execute_request(ports=ports, action_name="status")
        return self.parse_response(response_output=response, device_names=device_names)

    def get_name(self):
        return "cyberpower"
