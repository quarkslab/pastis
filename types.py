import json
from enum import Enum, IntEnum
from pathlib import Path
from typing import Union
import base64

PathLike = Union[str, Path]

class State(Enum):
    RUNNING = 0
    IDLE = 1

class FuzzingEngine(Enum):
    HONGGFUZZ = 0
    TRITON = 1
    AFL = 2
    AFL_UNICORN = 3
    AFL_QEMU = 4 #Same as Triton

class SeedType(Enum):
    INPUT = 0
    CRASH = 1
    HANG = 2

class ExecMode(Enum):
    SINGLE_EXEC = 0
    HF_PERSISTENT = 1
    AFL_CMPLOG = 2

class CheckMode(Enum):
    CHECK_ALL = 0
    ALERT_ONLY = 1

class CoverageMode(IntEnum):
    BLOCK = 0
    EDGE = 1
    PATH = 2
    #STATE = 3

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
