# builtin imports
from pathlib import Path
from typing import List, Union, Tuple, Optional



# Local imports
from libpastis.types import CoverageMode, ExecMode, FuzzMode


class EngineConfiguration(object):
    """
    Basic interface to represent an engine configuration file
    on broker side. All what addons have to provide are
    """
    # TODO: Making basic from_file, to_str (pour transmission
    # TODO: Plus tard description des champs en pydantic ou autre directement en dash

    @staticmethod
    def from_file(filepath: Path) -> 'EngineConfiguration':
        raise NotImplementedError

    @staticmethod
    def from_str(s: str) -> 'EngineConfiguration':
        raise NotImplementedError

    def to_str(self) -> str:
        raise NotImplementedError

    def get_coverage_mode(self) -> CoverageMode:
        """ Current coverage mode selected in the file """
        raise NotImplementedError



class FuzzingEngineDescriptor(object):

    NAME = "abstract-engine"
    SHORT_NAME = "AE"
    VERSION = "1.0"

    @staticmethod
    def accept_file(binary_file: Path) -> Tuple[bool, Optional[ExecMode], Optional[FuzzMode]]:
        raise NotImplementedError()

    @staticmethod
    def supported_coverage_strategies() -> List[CoverageMode]:
        raise NotImplementedError()

    @staticmethod
    def get_configuration_cls() -> EngineConfiguration:
        raise NotImplementedError()
