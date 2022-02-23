import json
from aenum import Enum, extend_enum
from pathlib import Path
from typing import Union
import base64

PathLike = Union[str, Path]


class State(Enum):
    RUNNING = 0
    IDLE = 1


class Platform(Enum):
    ANY = 0
    LINUX = 1
    WINDOWS = 2
    MACOS = 3
    ANDROID = 4
    IOS = 5


class SeedType(Enum):
    INPUT = 0
    CRASH = 1
    HANG = 2


class ExecMode(Enum):
    AUTO = 0
    SINGLE_EXEC = 1
    PERSISTENT = 2


class FuzzMode(Enum):
    AUTO = 0
    INSTRUMENTED = 1
    BINARY_ONLY = 2


class CheckMode(Enum):
    CHECK_ALL = 0
    ALERT_ONLY = 1
    ALERT_ONE = 2

class CoverageMode(str, Enum):
    AUTO = "auto"
    BLOCK = "block"
    EDGE = "edge"
    PATH = "path"
    STATE = "state"

    @classmethod
    def _missing_(cls, val) -> 'CoverageMode':
        """ Method used to dynmically creating an entry """
        enum_name = val.upper().replace(" ", "_")
        if enum_name in cls.__members__:
            return cls.__members__[enum_name]
        return extend_enum(cls, enum_name, val)


class SeedInjectLoc(Enum):
    STDIN = 0
    ARGV = 1


class Arch(Enum):
    X86 = 0
    X86_64 = 1
    ARMV7 = 2
    AARCH64 = 3


class LogLevel(Enum):
    DEBUG = 10
    INFO = 20
    WARNING = 2
    ERROR = 3
    CRITICAL = 4


class AlertData(object):
    def __init__(self, id: int, covered: bool, validated: bool, seed: bytes, address: int = 0):
        self.id = id
        self.covered = covered
        self.validated = validated
        self.seed = seed
        self.address = address


    @staticmethod
    def from_json(data: str) -> 'AlertData':
        data = json.loads(data)

        return AlertData(data['id'], data['covered'], data['validated'], base64.b64decode(data['seed']), data['address'])

    def to_json(self) -> str:
        return json.dumps({'id': self.id,
                           'covered': self.covered,
                           'validated': self.validated,
                           'seed': base64.b64encode(self.seed).decode(),
                           'address': self.address})


class FuzzingEngineInfo(object):
    def __init__(self, name: str, version: str, pymodule: str):
        self.name = name
        self.version = version
        self.pymodule = pymodule

    @staticmethod
    def from_pb(pb):
        return FuzzingEngineInfo(pb.name, pb.version, pb.pymodule)
