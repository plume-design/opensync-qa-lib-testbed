# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: adv_data_typing.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x15\x61\x64v_data_typing.proto\x12\x0einterfaces.adt"I\n\nAdtAttrKey\x12*\n\x04\x61ttr\x18\x01 \x01(\x0e\x32\x1c.interfaces.adt.AdtEnumAttrs\x12\x0f\n\x07\x61\x64t_key\x18\x02 \x01(\t"8\n\x0c\x41\x64tAttrValue\x12\x12\n\nbyte_value\x18\x01 \x01(\x0c\x12\x14\n\x0cstring_value\x18\x02 \x01(\t"y\n\tAdtKVPair\x12\'\n\x03key\x18\x01 \x01(\x0b\x32\x1a.interfaces.adt.AdtAttrKey\x12+\n\x05value\x18\x02 \x01(\x0b\x32\x1c.interfaces.adt.AdtAttrValue\x12\x16\n\x0e\x63\x61ptured_at_ms\x18\x03 \x01(\x04"\x7f\n\x0c\x41\x64tIpv4Tuple\x12\x13\n\x0bsource_ipv4\x18\x01 \x01(\r\x12\x18\n\x10\x64\x65stination_ipv4\x18\x02 \x01(\r\x12\x11\n\ttransport\x18\x03 \x01(\r\x12\x13\n\x0bsource_port\x18\x04 \x01(\r\x12\x18\n\x10\x64\x65stination_port\x18\x05 \x01(\r"\x7f\n\x0c\x41\x64tIpv6Tuple\x12\x13\n\x0bsource_ipv6\x18\x01 \x01(\x0c\x12\x18\n\x10\x64\x65stination_ipv6\x18\x02 \x01(\x0c\x12\x11\n\ttransport\x18\x03 \x01(\r\x12\x13\n\x0bsource_port\x18\x04 \x01(\r\x12\x18\n\x10\x64\x65stination_port\x18\x05 \x01(\r"\xda\x01\n\x0c\x41\x64tDataPoint\x12\x11\n\tdevice_id\x18\x01 \x01(\x0c\x12\x11\n\tethertype\x18\x02 \x01(\r\x12\x30\n\nipv4_tuple\x18\x03 \x01(\x0b\x32\x1c.interfaces.adt.AdtIpv4Tuple\x12\x30\n\nipv6_tuple\x18\x04 \x01(\x0b\x32\x1c.interfaces.adt.AdtIpv6Tuple\x12*\n\x07kv_pair\x18\x05 \x03(\x0b\x32\x19.interfaces.adt.AdtKVPair\x12\x14\n\x0cnetwork_zone\x18\x06 \x01(\t";\n\x13\x41\x64tObservationPoint\x12\x0f\n\x07node_id\x18\x01 \x01(\t\x12\x13\n\x0blocation_id\x18\x02 \x01(\t"\x8f\x01\n\tAdtReport\x12>\n\x11observation_point\x18\x01 \x01(\x0b\x32#.interfaces.adt.AdtObservationPoint\x12*\n\x04\x64\x61ta\x18\x02 \x03(\x0b\x32\x1c.interfaces.adt.AdtDataPoint\x12\x16\n\x0ereported_at_ms\x18\x03 \x01(\x04*B\n\x0c\x41\x64tEnumAttrs\x12\x18\n\x14\x41\x44T_ATTR_UNSPECIFIED\x10\x00\x12\x18\n\x14\x41\x44T_ATTR_DHCPV6_DUID\x10\x01\x62\x06proto3'
)

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "adv_data_typing_pb2", globals())
if _descriptor._USE_C_DESCRIPTORS is False:
    DESCRIPTOR._options = None
    _ADTENUMATTRS._serialized_start = 983
    _ADTENUMATTRS._serialized_end = 1049
    _ADTATTRKEY._serialized_start = 41
    _ADTATTRKEY._serialized_end = 114
    _ADTATTRVALUE._serialized_start = 116
    _ADTATTRVALUE._serialized_end = 172
    _ADTKVPAIR._serialized_start = 174
    _ADTKVPAIR._serialized_end = 295
    _ADTIPV4TUPLE._serialized_start = 297
    _ADTIPV4TUPLE._serialized_end = 424
    _ADTIPV6TUPLE._serialized_start = 426
    _ADTIPV6TUPLE._serialized_end = 553
    _ADTDATAPOINT._serialized_start = 556
    _ADTDATAPOINT._serialized_end = 774
    _ADTOBSERVATIONPOINT._serialized_start = 776
    _ADTOBSERVATIONPOINT._serialized_end = 835
    _ADTREPORT._serialized_start = 838
    _ADTREPORT._serialized_end = 981
# @@protoc_insertion_point(module_scope)
