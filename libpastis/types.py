from enum import Enum
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]


class State(Enum):
    RUNNING = 0
    IDLE = 1


class FuzzingEngine(Enum):
    HONGGFUZZ = 0
    TRITON = 1


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


class CoverageMode(Enum):
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
