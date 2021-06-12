import json
from enum import Enum, IntEnum
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
    SINGLE_EXEC = 0
    PERSISTENT = 1


class CheckMode(Enum):
    CHECK_ALL = 0
    ALERT_ONLY = 1


class CoverageMode(IntEnum):
    BLOCK = 0
    EDGE = 1
    PATH = 2
    STATE = 3


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
    def __init__(self, id: int, covered: bool, validated: bool, seed: bytes):
        self.id = id
        self.covered = covered
        self.validated = validated
        self.seed = seed


    @staticmethod
    def from_json(data: str) -> 'AlertData':
        data = json.loads(data)

        return AlertData(data['id'], data['covered'], data['validated'], base64.b64decode(data['seed']))

    def to_json(self) -> str:
        return json.dumps({'id': self.id,
                           'covered': self.covered,
                           'validated': self.validated,
                           'seed': base64.b64encode(self.seed).decode()})


class FuzzingEngineInfo(object):
    def __init__(self, name: str, version: str, pymodule: str):
        self.name = name
        self.version = version
        self.pymodule = pymodule

    @staticmethod
    def from_pb(pb):
        return FuzzingEngineInfo(pb.name, pb.version, pb.pymodule)
