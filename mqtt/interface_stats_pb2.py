# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: interface_stats.proto
# Protobuf Python Version: 4.25.3
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x15interface_stats.proto\x12\x15interfaces.intf_stats\"8\n\x10ObservationPoint\x12\x0f\n\x07node_id\x18\x01 \x01(\t\x12\x13\n\x0blocation_id\x18\x02 \x01(\t\"v\n\tIntfStats\x12\x0f\n\x07if_name\x18\x01 \x01(\t\x12\x10\n\x08tx_bytes\x18\x02 \x01(\x04\x12\x10\n\x08rx_bytes\x18\x03 \x01(\x04\x12\x12\n\ntx_packets\x18\x04 \x01(\x04\x12\x12\n\nrx_packets\x18\x05 \x01(\x04\x12\x0c\n\x04role\x18\x06 \x01(\t\"o\n\x11ObservationWindow\x12\x12\n\nstarted_at\x18\x01 \x01(\x04\x12\x10\n\x08\x65nded_at\x18\x02 \x01(\x04\x12\x34\n\nintf_stats\x18\x03 \x03(\x0b\x32 .interfaces.intf_stats.IntfStats\"\xac\x01\n\nIntfReport\x12\x13\n\x0breported_at\x18\x01 \x01(\x04\x12\x42\n\x11observation_point\x18\x02 \x01(\x0b\x32\'.interfaces.intf_stats.ObservationPoint\x12\x45\n\x13observation_windows\x18\x03 \x03(\x0b\x32(.interfaces.intf_stats.ObservationWindow')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'interface_stats_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_OBSERVATIONPOINT']._serialized_start=48
  _globals['_OBSERVATIONPOINT']._serialized_end=104
  _globals['_INTFSTATS']._serialized_start=106
  _globals['_INTFSTATS']._serialized_end=224
  _globals['_OBSERVATIONWINDOW']._serialized_start=226
  _globals['_OBSERVATIONWINDOW']._serialized_end=337
  _globals['_INTFREPORT']._serialized_start=340
  _globals['_INTFREPORT']._serialized_end=512
# @@protoc_insertion_point(module_scope)
