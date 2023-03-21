import json
from aenum import Enum, extend_enum
from pathlib import Path
from typing import Union
import base64

PathLike = Union[str, Path]
#: Union of a string or Path object

class State(Enum):
    """
    Running type of a fuzzing engine. It
    can be either running or idle.
    """
    RUNNING = 0
    IDLE = 1


class Platform(Enum):
    """
    Enum representing the platform.
    """
    ANY = 0
    LINUX = 1
    WINDOWS = 2
    MACOS = 3
    ANDROID = 4
    IOS = 5


class SeedType(Enum):
    """
    Type of an input. They can be plain input,
    crash input or hanging input.
    """
    INPUT = 0
    CRASH = 1
    HANG = 2


class ExecMode(Enum):
    """
    Execution mode for fuzzing engine. With ``AUTO``
    the fuzzer will automatically select, ``SINGLE_EXEC``
    is the normal fuzzing mode where the process stops
    at each iteration while ``PERSISTENT`` indicate the
    fuzzer to run in persistent mode.
    """
    AUTO = 0
    SINGLE_EXEC = 1
    PERSISTENT = 2


class FuzzMode(Enum):
    """
    Fuzzing mode, indicates the fuzzer whether the target
    is instrumented or not.
    """
    AUTO = 0
    INSTRUMENTED = 1
    BINARY_ONLY = 2


class CheckMode(Enum):
    """
    CheckMode is used to indicates a fuzzer how to run depdending on
    the context. ``CHECK_ALL`` is the normal bug, vulnerability discovery
    mode. Then ``ALERT_ONLY`` indicates the fuzzer to focus on SAST alerts.
    Then ``ALERT_ONE`` indicates the fuzzer to focus on a single alert which
    id should be provided through the configuration file.
    """
    CHECK_ALL = 0
    ALERT_ONLY = 1
    ALERT_ONE = 2

class CoverageMode(str, Enum):
    """
    Coverage metrics to use. Some fuzzing engines do support multiple coverage
    metrics, thus the enum indicates the one to use.
    """
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
    """
    Indicates the location where to inject inputs. It can either be
    on STDIN or ARGV.
    """
    STDIN = 0
    ARGV = 1


class Arch(Enum):
    """
    Architecture representation
    """
    X86 = 0
    X86_64 = 1
    ARMV7 = 2
    AARCH64 = 3


class LogLevel(Enum):
    """
    Enum representing the Log level, for fuzzers to send message logs
    to the broker.
    """
    DEBUG = 10
    INFO = 20
    WARNING = 2
    ERROR = 3
    CRITICAL = 4


class AlertData(object):
    """
    AlertData is data message that can be sent from fuzzing agents to
    the broker to indicates that an alert has been covered or validated.
    """
    def __init__(self, id: int, covered: bool, validated: bool, seed: bytes, address: int = 0):
        self.id: int = id
        #: Id of the alert
        self.covered: bool = covered
        #: True if the alert has been covered
        self.validated: bool = validated
        #: True if the alert has been validated
        self.seed: bytes = seed
        #: Input that reached or validated the alert
        self.address: int = address
        #: memory address of the alert


    @staticmethod
    def from_json(data: str) -> 'AlertData':
        """
        Convert an AlertData in json to an instance.

        :param data: json serialized alert
        :return: AlertData object
        """
        data = json.loads(data)

        return AlertData(data['id'], data['covered'], data['validated'], base64.b64decode(data['seed']), data['address'])

    def to_json(self) -> str:
        """
        Serialize the alert to JSON.

        :return: json serialized alert
        """
        return json.dumps({'id': self.id,
                           'covered': self.covered,
                           'validated': self.validated,
                           'seed': base64.b64encode(self.seed).decode(),
                           'address': self.address})


class FuzzingEngineInfo(object):
    """
    Class to represent a fuzzing engine metadata.
    It contains its name, version and the Python module
    where to load the descriptor and configuration object.
    """
    def __init__(self, name: str, version: str, pymodule: str):
        self.name: str = name
        #: Name of the engine
        self.version = version
        #: Version of the engine
        self.pymodule = pymodule
        #: Name of the python module

    @staticmethod
    def from_pb(pb) -> 'FuzzingEngineInfo':
        """
        Parse a protobuf object into a FuzzingEngineInfo object.

        :param pb: protobuf object
        :return: object
        """
        return FuzzingEngineInfo(pb.name, pb.version, pb.pymodule)
