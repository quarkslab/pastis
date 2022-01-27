# built-in imports
from pathlib import Path
from typing import Union, Tuple, List, Optional

# third-party import
import lief

from libpastis import FuzzingEngineDescriptor, EngineConfiguration
from libpastis.types import ExecMode, CoverageMode, FuzzMode


class AFLPPEngineDescriptor(FuzzingEngineDescriptor):

    NAME = "AFLPP"
    SHORT_NAME = "AFLPP"
    VERSION = "0.3"  # Should be in sync with alfpp.__version__

    def __init__(self):
        pass

    @staticmethod
    def accept_file(binary_file: Path) -> Tuple[bool, Optional[ExecMode], Optional[FuzzMode]]:
        p = lief.parse(str(binary_file))
        if not p:
            return False, None, None

        # Search for HF instrumentation
        instrumented = False
        for f in p.functions:
            if "__sanitizer" in f.name:
                instrumented = True
                break
        if not instrumented:
            # NOTE This can be improve. We usually use PERSISTENT mode when
            # fuzzing a binary-only target because of performance reasons but
            # it can also be SINGLE_EXEC. Therefore, ExecMode would not be the
            # right place to add the BINARY_ONLY option (it was done this way
            # to keep things simple).
            return True, ExecMode.AUTO_EXEC, FuzzMode.BINARY_ONLY

        return True, ExecMode.AUTO_EXEC, FuzzMode.INSTRUMENTED

    @staticmethod
    def supported_coverage_strategies() -> List[CoverageMode]:
        return [CoverageMode.AUTO]

    @staticmethod
    def configuration() -> EngineConfiguration:
        raise NotImplementedError()
