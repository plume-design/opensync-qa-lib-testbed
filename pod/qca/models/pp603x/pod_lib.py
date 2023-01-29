import re

from lib_testbed.generic.pod.qca.pod_lib import PodLib as PodLibGeneric


class PodLib(PodLibGeneric):

    get_connection_flows = PodLibGeneric.get_connection_flows_ecm

    get_connection_flows_dump = PodLibGeneric.get_connection_flows_ecm_dump

    get_connection_flow_marks = PodLibGeneric.get_connection_flow_marks_ecm

    check_traffic_acceleration = PodLibGeneric.check_traffic_acceleration_ecm

    def get_region(self, **kwargs):
        response = self.run_command('iwpriv wifi0 getCountry; iwpriv wifi1 getCountry; iwpriv wifi2 getCountry',
                                    **kwargs)
        cc_codes = re.findall(r'(?<=getCountry:).*', response[1])
        if not cc_codes:
            return [1, '', 'Cannot get region']
        if len(set(cc_codes)) > 1:
            return [2, '', f'Different regions for different radios: {cc_codes}']
        return [0, cc_codes[0], '']
