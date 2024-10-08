# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: dpi_stats.proto
# Protobuf Python Version: 4.25.3
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0f\x64pi_stats.proto\x12\x14interfaces.dpi_stats\"@\n\x18\x44piStatsObservationPoint\x12\x0f\n\x07node_id\x18\x03 \x01(\t\x12\x13\n\x0blocation_id\x18\x04 \x01(\t\"\x9b\x02\n\x10\x44piStatsCounters\x12\x12\n\ncurr_alloc\x18\x01 \x01(\r\x12\x12\n\npeak_alloc\x18\x02 \x01(\r\x12\x12\n\nfail_alloc\x18\x03 \x01(\r\x12\x13\n\x0bmpmc_events\x18\x04 \x01(\r\x12\x14\n\x0cscan_started\x18\x05 \x01(\r\x12\x14\n\x0cscan_stopped\x18\x06 \x01(\r\x12\x12\n\nscan_bytes\x18\x07 \x01(\r\x12\x16\n\x0e\x65rr_incomplete\x18\x08 \x01(\r\x12\x12\n\nerr_length\x18\t \x01(\r\x12\x12\n\nerr_create\x18\n \x01(\r\x12\x10\n\x08\x65rr_scan\x18\x0b \x01(\r\x12\x13\n\x0b\x63onnections\x18\x0c \x01(\r\x12\x0f\n\x07streams\x18\r \x01(\r\"-\n\rErrorCounters\x12\r\n\x05\x65rror\x18\x01 \x01(\r\x12\r\n\x05\x63ount\x18\x02 \x01(\x04\"\xb0\x01\n\x14NfqueueStatsCounters\x12\x10\n\x08queueNum\x18\x01 \x01(\t\x12\x12\n\nqueueTotal\x18\x03 \x01(\r\x12\x14\n\x0cqueueDropped\x18\x05 \x01(\r\x12\x18\n\x10queueUserDropped\x18\x06 \x01(\r\x12\r\n\x05seqId\x18\x07 \x01(\r\x12\x33\n\x06\x65rrors\x18\t \x03(\x0b\x32#.interfaces.dpi_stats.ErrorCounters\"P\n\x11PcapStatsCounters\x12\x15\n\rpkts_received\x18\x01 \x01(\r\x12\x14\n\x0cpkts_dropped\x18\x02 \x01(\r\x12\x0e\n\x06ifname\x18\x03 \x01(\t\"h\n\x11\x43\x61llTraceCounters\x12\x11\n\tfunc_name\x18\x01 \x01(\t\x12\x12\n\ncall_count\x18\x02 \x01(\x04\x12\x14\n\x0cmax_duration\x18\x03 \x01(\x04\x12\x16\n\x0etotal_duration\x18\x04 \x01(\x04\"\xe2\x02\n\x0e\x44piStatsReport\x12I\n\x11observation_point\x18\x01 \x01(\x0b\x32..interfaces.dpi_stats.DpiStatsObservationPoint\x12\x0e\n\x06plugin\x18\x02 \x01(\t\x12\x38\n\x08\x63ounters\x18\x03 \x01(\x0b\x32&.interfaces.dpi_stats.DpiStatsCounters\x12\x41\n\rnfqueue_stats\x18\x04 \x03(\x0b\x32*.interfaces.dpi_stats.NfqueueStatsCounters\x12;\n\npcap_stats\x18\x05 \x03(\x0b\x32\'.interfaces.dpi_stats.PcapStatsCounters\x12;\n\ncall_stats\x18\x06 \x03(\x0b\x32\'.interfaces.dpi_stats.CallTraceCountersb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'dpi_stats_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_DPISTATSOBSERVATIONPOINT']._serialized_start=41
  _globals['_DPISTATSOBSERVATIONPOINT']._serialized_end=105
  _globals['_DPISTATSCOUNTERS']._serialized_start=108
  _globals['_DPISTATSCOUNTERS']._serialized_end=391
  _globals['_ERRORCOUNTERS']._serialized_start=393
  _globals['_ERRORCOUNTERS']._serialized_end=438
  _globals['_NFQUEUESTATSCOUNTERS']._serialized_start=441
  _globals['_NFQUEUESTATSCOUNTERS']._serialized_end=617
  _globals['_PCAPSTATSCOUNTERS']._serialized_start=619
  _globals['_PCAPSTATSCOUNTERS']._serialized_end=699
  _globals['_CALLTRACECOUNTERS']._serialized_start=701
  _globals['_CALLTRACECOUNTERS']._serialized_end=805
  _globals['_DPISTATSREPORT']._serialized_start=808
  _globals['_DPISTATSREPORT']._serialized_end=1162
# @@protoc_insertion_point(module_scope)
