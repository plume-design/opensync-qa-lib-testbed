import xmltodict
from lib_testbed.generic.rpower.pdu_units.common_pdu_lib import PduLib


class EnergenieLib(PduLib):

    def on(self, device_names):
        ports = self.port_args(device_names)
        response = self.execute_request(ports=ports, action_name='on')
        if response[0]:
            return response
        return self.parse_response(response_output=response, device_names=device_names)

    def off(self, device_names):
        ports = self.port_args(device_names)
        response = self.execute_request(ports=ports, action_name='off')
        if response[0]:
            return response
        return self.parse_response(response_output=response, device_names=device_names)

    def status(self, device_names):
        response = self.execute_request(ports='1', action_name='status', args='--raw_data')
        if response[0]:
            return response
        respxml = xmltodict.parse(response[1])
        status = respxml['response']['pot0'].split(',')[10:18]
        device_names = self.get_devices_to_execute(device_names)
        responses = dict()
        for device_name in device_names:
            pdu_device_port = self.get_pdu_device_port(device_name)
            port_status = "ON" if status[pdu_device_port - 1] == '1' else "OFF"
            responses[device_name] = [0, port_status, '']
        return responses

    @staticmethod
    def get_name():
        return 'energenie'
