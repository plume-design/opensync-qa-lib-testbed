import re
from lib_testbed.generic.mqtt.opensync_stats_pb2 import Report as StatsReportSchema
from lib_testbed.generic.mqtt.network_metadata_pb2 import FlowReport
from lib_testbed.generic.mqtt.mdns_records_telemetry_pb2 import MdnsRecordsReport
from lib_testbed.generic.mqtt.ip_dns_telemetry_pb2 import WCStatsReport
from lib_testbed.generic.mqtt.gatekeeper_hero_stats_pb2 import HeroReport
from lib_testbed.generic.mqtt.interface_stats_pb2 import IntfReport
from lib_testbed.generic.mqtt.time_event_pb2 import TimeEventsReport
from lib_testbed.generic.mqtt.wifi_blaster_pb2 import WifiBlastResult
from lib_testbed.generic.mqtt.adv_data_typing_pb2 import AdtReport
from lib_testbed.generic.mqtt.lte_info_pb2 import LteInfoReport
from lib_testbed.generic.mqtt.dpi_stats_pb2 import DpiStatsReport


PROTO_DECODER_MAP = {
    's1/': StatsReportSchema(),
    'DNS/Queries/': StatsReportSchema(),
    'SNI/Requests/': StatsReportSchema(),
    'IP/Threats/': StatsReportSchema(),
    'WC/Stats/Health/': WCStatsReport(),
    'WC/Stats/Hero/': HeroReport(),
    'IP/Flows/': FlowReport(),
    'lan/': FlowReport(),
    'MDNS/Records/': MdnsRecordsReport(),
    'DPI/ADT/': AdtReport(),
    'interfaceStats/': IntfReport(),
    'MqttLog/': TimeEventsReport(),
    'WifiBlaster/': WifiBlastResult(),
    'LteStats/': LteInfoReport(),
    'DpiStats/': DpiStatsReport()
}


class ProtoUtil:

    @staticmethod
    def get_proto_decoder(topic):
        proto_decoder = next(filter(lambda proto: re.search(proto, topic, re.IGNORECASE),
                                    PROTO_DECODER_MAP.keys()), None)
        assert proto_decoder, f'Can not find suitable proto decoder for: {topic} topic'
        return PROTO_DECODER_MAP[proto_decoder]
