# builtin imports
from pathlib import Path
from typing import List, Union, Tuple, Optional



# Local imports
from libpastis.types import CoverageMode, ExecMode, FuzzMode


class EngineConfiguration(object):
    # TODO: Making basic from_file, to_str (pour transmission
    # TODO: Plus tard description des champs en pydantic ou autre directement en dash
    pass



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
    def configuration() -> EngineConfiguration:
        raise NotImplementedError()
