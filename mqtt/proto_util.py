import re
from lib_testbed.generic.mqtt.opensync_stats_pb2 import Report as StatsReportSchema
from lib_testbed.generic.mqtt.latency_pb2 import Report as LatencyReport
from lib_testbed.generic.mqtt.network_metadata_pb2 import FlowReport
from lib_testbed.generic.mqtt.mdns_records_telemetry_pb2 import MdnsRecordsReport
from lib_testbed.generic.mqtt.ip_dns_telemetry_pb2 import WCStatsReport
from lib_testbed.generic.mqtt.gatekeeper_hero_stats_pb2 import HeroReport
from lib_testbed.generic.mqtt.interface_stats_pb2 import IntfReport
from lib_testbed.generic.mqtt.time_event_pb2 import TimeEventsReport

# TODO: re-generate wifi blaster once corresponding .proto is available
# from lib_testbed.generic.mqtt.wifi_blaster_pb2 import WifiBlastResult
from lib_testbed.generic.mqtt.adv_data_typing_pb2 import AdtReport
from lib_testbed.generic.mqtt.lte_info_pb2 import LteInfoReport
from lib_testbed.generic.mqtt.dpi_stats_pb2 import DpiStatsReport
from lib_testbed.generic.mqtt.thread_network_info_pb2 import ThreadNetworkScan

# TODO: similar to wifi blaster above
# from lib_testbed.generic.mqtt.veego_app_qoe_pb2 import AppQoeReport
from lib_testbed.generic.mqtt.cell_info_pb2 import CellularInfoReport


PROTO_DECODER_MAP = {
    "s1/": StatsReportSchema,
    "Crash/Reports/": StatsReportSchema,
    "DNS/Queries/": StatsReportSchema,
    "SNI/Requests/": StatsReportSchema,
    "IP/Threats/": StatsReportSchema,
    "WC/Stats/Health/": WCStatsReport,
    "WC/Stats/Hero/": HeroReport,
    "IP/Flows/": FlowReport,
    "lan/": FlowReport,
    "MDNS/Records/": MdnsRecordsReport,
    "DPI/ADT/": AdtReport,
    "interfaceStats/": IntfReport,
    "MqttLog/": TimeEventsReport,
    #    "WifiBlaster/": WifiBlastResult,
    "LteStats/": LteInfoReport,
    "DpiStats/": DpiStatsReport,
    "ThreadNetwork/": ThreadNetworkScan,
    #    "QoE/app_3rd_party/": AppQoeReport,
    "CellStats/": CellularInfoReport,
    "WE/": StatsReportSchema,
    "Latency/": LatencyReport,
}


class ProtoUtil:
    @staticmethod
    def get_proto_decoder(topic):
        proto_decoder = next(
            filter(lambda proto: re.search(proto, topic, re.IGNORECASE), PROTO_DECODER_MAP.keys()), None
        )
        assert proto_decoder, f"Can not find suitable proto decoder for: {topic} topic"
        proto_decoder_lib = PROTO_DECODER_MAP[proto_decoder]
        # Create new reference of object
        return proto_decoder_lib()
