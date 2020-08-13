# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: message.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='message.proto',
  package='libpastiscomm',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\rmessage.proto\x12\rlibpastiscomm\"\xa0\x01\n\x0cInputSeedMsg\x12\x0c\n\x04seed\x18\x01 \x01(\x0c\x12\x32\n\x04type\x18\x02 \x01(\x0e\x32$.libpastiscomm.InputSeedMsg.SeedType\x12,\n\x06origin\x18\x03 \x01(\x0e\x32\x1c.libpastiscomm.FuzzingEngine\" \n\x08SeedType\x12\t\n\x05INPUT\x10\x00\x12\t\n\x05\x43RASH\x10\x01\"\xba\x03\n\x08StartMsg\x12\x17\n\x0f\x62inary_filename\x18\x01 \x01(\t\x12\x0e\n\x06\x62inary\x18\x02 \x01(\x0c\x12\x17\n\x0fklocwork_report\x18\x03 \x01(\t\x12,\n\x06\x65ngine\x18\x04 \x01(\x0e\x32\x1c.libpastiscomm.FuzzingEngine\x12\x33\n\texec_mode\x18\x05 \x01(\x0e\x32 .libpastiscomm.StartMsg.ExecMode\x12\x35\n\ncheck_mode\x18\x06 \x01(\x0e\x32!.libpastiscomm.StartMsg.CheckMode\x12;\n\rcoverage_mode\x18\x07 \x01(\x0e\x32$.libpastiscomm.StartMsg.CoverageMode\x12\x0c\n\x04\x61rgs\x18\x08 \x01(\t\"+\n\x08\x45xecMode\x12\x0f\n\x0bSINGLE_EXEC\x10\x00\x12\x0e\n\nPERSISTENT\x10\x01\"*\n\tCheckMode\x12\r\n\tCHECK_ALL\x10\x00\x12\x0e\n\nALERT_ONLY\x10\x01\".\n\x0c\x43overageMode\x12\t\n\x05\x42LOCK\x10\x00\x12\x08\n\x04PATH\x10\x01\x12\t\n\x05STATE\x10\x02\"\t\n\x07StopMsg\"\xd5\x01\n\x08HelloMsg\x12\x32\n\x0c\x61rchitecture\x18\x01 \x03(\x0e\x32\x1c.libpastiscomm.HelloMsg.Arch\x12\x0f\n\x07threads\x18\x02 \x01(\r\x12\x0e\n\x06memory\x18\x03 \x01(\r\x12-\n\x07\x65ngines\x18\x04 \x03(\x0e\x32\x1c.libpastiscomm.FuzzingEngine\x12\x10\n\x08versions\x18\x05 \x03(\t\"3\n\x04\x41rch\x12\x07\n\x03X86\x10\x00\x12\n\n\x06X86_64\x10\x01\x12\t\n\x05\x41RMV7\x10\x02\x12\x0b\n\x07\x41\x41RCH64\x10\x03\"\x8f\x01\n\x06LogMsg\x12\x0f\n\x07message\x18\x01 \x01(\t\x12-\n\x05level\x18\x02 \x01(\x0e\x32\x1e.libpastiscomm.LogMsg.LogLevel\"E\n\x08LogLevel\x12\t\n\x05\x44\x45\x42UG\x10\x00\x12\x08\n\x04INFO\x10\x01\x12\x0b\n\x07WARNING\x10\x02\x12\t\n\x05\x45RROR\x10\x03\x12\x0c\n\x08\x43RITICAL\x10\x04\"\x96\x02\n\x0cTelemetryMsg\x12#\n\x05state\x18\x01 \x01(\x0e\x32\x14.libpastiscomm.State\x12\x14\n\x0c\x65xec_per_sec\x18\x02 \x01(\r\x12\x12\n\ntotal_exec\x18\x03 \x01(\r\x12\r\n\x05\x63ycle\x18\x04 \x01(\r\x12\x12\n\niterations\x18\x05 \x01(\r\x12\x0f\n\x07timeout\x18\x06 \x01(\r\x12\x16\n\x0e\x63overage_block\x18\x07 \x01(\r\x12\x15\n\rcoverage_edge\x18\x08 \x01(\r\x12\x15\n\rcoverage_path\x18\t \x01(\r\x12\x17\n\x0flast_cov_update\x18\n \x01(\r\x12\x11\n\tcpu_usage\x18\x0b \x01(\r\x12\x11\n\tmem_usage\x18\x0c \x01(\r\"\x16\n\x14StopCoverageCriteria*\x1e\n\x05State\x12\x0b\n\x07RUNNING\x10\x00\x12\x08\n\x04IDLE\x10\x01*.\n\rFuzzingEngine\x12\r\n\tHONGGFUZZ\x10\x00\x12\x0e\n\nTRITONEXPL\x10\x01\x62\x06proto3'
)

_STATE = _descriptor.EnumDescriptor(
  name='State',
  full_name='libpastiscomm.State',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='RUNNING', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='IDLE', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=1318,
  serialized_end=1348,
)
_sym_db.RegisterEnumDescriptor(_STATE)

State = enum_type_wrapper.EnumTypeWrapper(_STATE)
_FUZZINGENGINE = _descriptor.EnumDescriptor(
  name='FuzzingEngine',
  full_name='libpastiscomm.FuzzingEngine',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='HONGGFUZZ', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='TRITONEXPL', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=1350,
  serialized_end=1396,
)
_sym_db.RegisterEnumDescriptor(_FUZZINGENGINE)

FuzzingEngine = enum_type_wrapper.EnumTypeWrapper(_FUZZINGENGINE)
RUNNING = 0
IDLE = 1
HONGGFUZZ = 0
TRITONEXPL = 1


_INPUTSEEDMSG_SEEDTYPE = _descriptor.EnumDescriptor(
  name='SeedType',
  full_name='libpastiscomm.InputSeedMsg.SeedType',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='INPUT', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='CRASH', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=161,
  serialized_end=193,
)
_sym_db.RegisterEnumDescriptor(_INPUTSEEDMSG_SEEDTYPE)

_STARTMSG_EXECMODE = _descriptor.EnumDescriptor(
  name='ExecMode',
  full_name='libpastiscomm.StartMsg.ExecMode',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='SINGLE_EXEC', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PERSISTENT', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=503,
  serialized_end=546,
)
_sym_db.RegisterEnumDescriptor(_STARTMSG_EXECMODE)

_STARTMSG_CHECKMODE = _descriptor.EnumDescriptor(
  name='CheckMode',
  full_name='libpastiscomm.StartMsg.CheckMode',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='CHECK_ALL', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='ALERT_ONLY', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=548,
  serialized_end=590,
)
_sym_db.RegisterEnumDescriptor(_STARTMSG_CHECKMODE)

_STARTMSG_COVERAGEMODE = _descriptor.EnumDescriptor(
  name='CoverageMode',
  full_name='libpastiscomm.StartMsg.CoverageMode',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='BLOCK', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PATH', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='STATE', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=592,
  serialized_end=638,
)
_sym_db.RegisterEnumDescriptor(_STARTMSG_COVERAGEMODE)

_HELLOMSG_ARCH = _descriptor.EnumDescriptor(
  name='Arch',
  full_name='libpastiscomm.HelloMsg.Arch',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='X86', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='X86_64', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='ARMV7', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='AARCH64', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=814,
  serialized_end=865,
)
_sym_db.RegisterEnumDescriptor(_HELLOMSG_ARCH)

_LOGMSG_LOGLEVEL = _descriptor.EnumDescriptor(
  name='LogLevel',
  full_name='libpastiscomm.LogMsg.LogLevel',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='DEBUG', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='INFO', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='WARNING', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='ERROR', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='CRITICAL', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=942,
  serialized_end=1011,
)
_sym_db.RegisterEnumDescriptor(_LOGMSG_LOGLEVEL)


_INPUTSEEDMSG = _descriptor.Descriptor(
  name='InputSeedMsg',
  full_name='libpastiscomm.InputSeedMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='seed', full_name='libpastiscomm.InputSeedMsg.seed', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='type', full_name='libpastiscomm.InputSeedMsg.type', index=1,
      number=2, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='origin', full_name='libpastiscomm.InputSeedMsg.origin', index=2,
      number=3, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _INPUTSEEDMSG_SEEDTYPE,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=33,
  serialized_end=193,
)


_STARTMSG = _descriptor.Descriptor(
  name='StartMsg',
  full_name='libpastiscomm.StartMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='binary_filename', full_name='libpastiscomm.StartMsg.binary_filename', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='binary', full_name='libpastiscomm.StartMsg.binary', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='klocwork_report', full_name='libpastiscomm.StartMsg.klocwork_report', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='engine', full_name='libpastiscomm.StartMsg.engine', index=3,
      number=4, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='exec_mode', full_name='libpastiscomm.StartMsg.exec_mode', index=4,
      number=5, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='check_mode', full_name='libpastiscomm.StartMsg.check_mode', index=5,
      number=6, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='coverage_mode', full_name='libpastiscomm.StartMsg.coverage_mode', index=6,
      number=7, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='args', full_name='libpastiscomm.StartMsg.args', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _STARTMSG_EXECMODE,
    _STARTMSG_CHECKMODE,
    _STARTMSG_COVERAGEMODE,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=196,
  serialized_end=638,
)


_STOPMSG = _descriptor.Descriptor(
  name='StopMsg',
  full_name='libpastiscomm.StopMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=640,
  serialized_end=649,
)


_HELLOMSG = _descriptor.Descriptor(
  name='HelloMsg',
  full_name='libpastiscomm.HelloMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='architecture', full_name='libpastiscomm.HelloMsg.architecture', index=0,
      number=1, type=14, cpp_type=8, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='threads', full_name='libpastiscomm.HelloMsg.threads', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='memory', full_name='libpastiscomm.HelloMsg.memory', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='engines', full_name='libpastiscomm.HelloMsg.engines', index=3,
      number=4, type=14, cpp_type=8, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='versions', full_name='libpastiscomm.HelloMsg.versions', index=4,
      number=5, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _HELLOMSG_ARCH,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=652,
  serialized_end=865,
)


_LOGMSG = _descriptor.Descriptor(
  name='LogMsg',
  full_name='libpastiscomm.LogMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='message', full_name='libpastiscomm.LogMsg.message', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='level', full_name='libpastiscomm.LogMsg.level', index=1,
      number=2, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _LOGMSG_LOGLEVEL,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=868,
  serialized_end=1011,
)


_TELEMETRYMSG = _descriptor.Descriptor(
  name='TelemetryMsg',
  full_name='libpastiscomm.TelemetryMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='state', full_name='libpastiscomm.TelemetryMsg.state', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='exec_per_sec', full_name='libpastiscomm.TelemetryMsg.exec_per_sec', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='total_exec', full_name='libpastiscomm.TelemetryMsg.total_exec', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='cycle', full_name='libpastiscomm.TelemetryMsg.cycle', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='iterations', full_name='libpastiscomm.TelemetryMsg.iterations', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='timeout', full_name='libpastiscomm.TelemetryMsg.timeout', index=5,
      number=6, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='coverage_block', full_name='libpastiscomm.TelemetryMsg.coverage_block', index=6,
      number=7, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='coverage_edge', full_name='libpastiscomm.TelemetryMsg.coverage_edge', index=7,
      number=8, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='coverage_path', full_name='libpastiscomm.TelemetryMsg.coverage_path', index=8,
      number=9, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='last_cov_update', full_name='libpastiscomm.TelemetryMsg.last_cov_update', index=9,
      number=10, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='cpu_usage', full_name='libpastiscomm.TelemetryMsg.cpu_usage', index=10,
      number=11, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='mem_usage', full_name='libpastiscomm.TelemetryMsg.mem_usage', index=11,
      number=12, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1014,
  serialized_end=1292,
)


_STOPCOVERAGECRITERIA = _descriptor.Descriptor(
  name='StopCoverageCriteria',
  full_name='libpastiscomm.StopCoverageCriteria',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1294,
  serialized_end=1316,
)

_INPUTSEEDMSG.fields_by_name['type'].enum_type = _INPUTSEEDMSG_SEEDTYPE
_INPUTSEEDMSG.fields_by_name['origin'].enum_type = _FUZZINGENGINE
_INPUTSEEDMSG_SEEDTYPE.containing_type = _INPUTSEEDMSG
_STARTMSG.fields_by_name['engine'].enum_type = _FUZZINGENGINE
_STARTMSG.fields_by_name['exec_mode'].enum_type = _STARTMSG_EXECMODE
_STARTMSG.fields_by_name['check_mode'].enum_type = _STARTMSG_CHECKMODE
_STARTMSG.fields_by_name['coverage_mode'].enum_type = _STARTMSG_COVERAGEMODE
_STARTMSG_EXECMODE.containing_type = _STARTMSG
_STARTMSG_CHECKMODE.containing_type = _STARTMSG
_STARTMSG_COVERAGEMODE.containing_type = _STARTMSG
_HELLOMSG.fields_by_name['architecture'].enum_type = _HELLOMSG_ARCH
_HELLOMSG.fields_by_name['engines'].enum_type = _FUZZINGENGINE
_HELLOMSG_ARCH.containing_type = _HELLOMSG
_LOGMSG.fields_by_name['level'].enum_type = _LOGMSG_LOGLEVEL
_LOGMSG_LOGLEVEL.containing_type = _LOGMSG
_TELEMETRYMSG.fields_by_name['state'].enum_type = _STATE
DESCRIPTOR.message_types_by_name['InputSeedMsg'] = _INPUTSEEDMSG
DESCRIPTOR.message_types_by_name['StartMsg'] = _STARTMSG
DESCRIPTOR.message_types_by_name['StopMsg'] = _STOPMSG
DESCRIPTOR.message_types_by_name['HelloMsg'] = _HELLOMSG
DESCRIPTOR.message_types_by_name['LogMsg'] = _LOGMSG
DESCRIPTOR.message_types_by_name['TelemetryMsg'] = _TELEMETRYMSG
DESCRIPTOR.message_types_by_name['StopCoverageCriteria'] = _STOPCOVERAGECRITERIA
DESCRIPTOR.enum_types_by_name['State'] = _STATE
DESCRIPTOR.enum_types_by_name['FuzzingEngine'] = _FUZZINGENGINE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

InputSeedMsg = _reflection.GeneratedProtocolMessageType('InputSeedMsg', (_message.Message,), {
  'DESCRIPTOR' : _INPUTSEEDMSG,
  '__module__' : 'message_pb2'
  # @@protoc_insertion_point(class_scope:libpastiscomm.InputSeedMsg)
  })
_sym_db.RegisterMessage(InputSeedMsg)

StartMsg = _reflection.GeneratedProtocolMessageType('StartMsg', (_message.Message,), {
  'DESCRIPTOR' : _STARTMSG,
  '__module__' : 'message_pb2'
  # @@protoc_insertion_point(class_scope:libpastiscomm.StartMsg)
  })
_sym_db.RegisterMessage(StartMsg)

StopMsg = _reflection.GeneratedProtocolMessageType('StopMsg', (_message.Message,), {
  'DESCRIPTOR' : _STOPMSG,
  '__module__' : 'message_pb2'
  # @@protoc_insertion_point(class_scope:libpastiscomm.StopMsg)
  })
_sym_db.RegisterMessage(StopMsg)

HelloMsg = _reflection.GeneratedProtocolMessageType('HelloMsg', (_message.Message,), {
  'DESCRIPTOR' : _HELLOMSG,
  '__module__' : 'message_pb2'
  # @@protoc_insertion_point(class_scope:libpastiscomm.HelloMsg)
  })
_sym_db.RegisterMessage(HelloMsg)

LogMsg = _reflection.GeneratedProtocolMessageType('LogMsg', (_message.Message,), {
  'DESCRIPTOR' : _LOGMSG,
  '__module__' : 'message_pb2'
  # @@protoc_insertion_point(class_scope:libpastiscomm.LogMsg)
  })
_sym_db.RegisterMessage(LogMsg)

TelemetryMsg = _reflection.GeneratedProtocolMessageType('TelemetryMsg', (_message.Message,), {
  'DESCRIPTOR' : _TELEMETRYMSG,
  '__module__' : 'message_pb2'
  # @@protoc_insertion_point(class_scope:libpastiscomm.TelemetryMsg)
  })
_sym_db.RegisterMessage(TelemetryMsg)

StopCoverageCriteria = _reflection.GeneratedProtocolMessageType('StopCoverageCriteria', (_message.Message,), {
  'DESCRIPTOR' : _STOPCOVERAGECRITERIA,
  '__module__' : 'message_pb2'
  # @@protoc_insertion_point(class_scope:libpastiscomm.StopCoverageCriteria)
  })
_sym_db.RegisterMessage(StopCoverageCriteria)


# @@protoc_insertion_point(module_scope)
