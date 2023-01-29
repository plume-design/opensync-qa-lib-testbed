from lib_testbed.generic.rpower.pdu_units.common_pdu_lib import PduLib


class DliLib(PduLib):

    def status(self, device_names):
        status = self.execute_request(ports='1', action_name='status', args='--raw_data')
        status_response = status[1].split(' ')
        val = None
        for token in status_response:
            if token.find('state=') >= 0:
                val = int(token.split('=')[1], 16)
        device_names = self.get_devices_to_execute(device_names)
        if val is None:
            return {device: [1, '', f'Could not read {device} state'] for device in device_names}

        responses = dict()
        for device_name in device_names:
            pdu_device_port = self.get_pdu_device_port(device_name)
            port_status = "ON" if (val >> (pdu_device_port - 1)) & 0x01 else "OFF"
            responses[device_name] = [0, port_status, '']
        return responses

    @staticmethod
    def get_name():
        return 'dli'
