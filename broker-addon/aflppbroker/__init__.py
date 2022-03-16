# built-in imports
from pathlib import Path
from typing import Union, Tuple, List, Optional, Type

# third-party import
import lief

from libpastis import FuzzingEngineDescriptor, EngineConfiguration
from libpastis.types import ExecMode, CoverageMode, FuzzMode


class AFLConfigurationInterface(EngineConfiguration):
    """
    Small wrapping function for AFL++ additional parameters
    """

    @staticmethod
    def new() -> 'EngineConfiguration':
        pass

    def __init__(self, args: List[str] = None):
        self._argvs = [] if args is None else args # Argument to send on the command line

    @staticmethod
    def from_file(filepath: Path) -> 'AFLConfigurationInterface':
        with open(filepath, "r") as f:
            return AFLConfigurationInterface(f.read().split())

    @staticmethod
    def from_str(s: str) -> 'AFLConfigurationInterface':
        return AFLConfigurationInterface(s.split())

    def to_str(self) -> str:
        return " ".join(self._argvs)

    def get_coverage_mode(self) -> CoverageMode:
        """ Current coverage mode selected in the file """
        raise CoverageMode.AUTO

    def set_target(self, target: int) -> None:
        # Note: Giving a target to Honggfuzz does not
        # do anything as Honggfuzz is not directed.
        pass


class AFLPPEngineDescriptor(FuzzingEngineDescriptor):

    NAME = "AFLPP"
    SHORT_NAME = "AFLPP"
    VERSION = "0.3"  # Should be in sync with alfpp.__version__

    config_class = AFLConfigurationInterface

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
            return True, ExecMode.AUTO, FuzzMode.BINARY_ONLY

        return True, ExecMode.AUTO, FuzzMode.INSTRUMENTED

    @staticmethod
    def supported_coverage_strategies() -> List[CoverageMode]:
        return [CoverageMode.AUTO]
