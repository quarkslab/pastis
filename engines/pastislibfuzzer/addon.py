# built-in imports
from pathlib import Path
from typing import Union, Tuple, List, Optional, Type

# third-party import
import lief

from libpastis import FuzzingEngineDescriptor, EngineConfiguration
from libpastis.types import ExecMode, CoverageMode, FuzzMode


class LibfuzzerConfigurationInterface(EngineConfiguration):
    """
    Small wrapping function for Libfuzzer additional parameters
    """

    def __init__(self, args: List[str]|None = None):
        self._argvs = [] if args is None else args # Argument to send on the command line

    @staticmethod
    def new() -> 'LibfuzzerConfigurationInterface':
        return LibfuzzerConfigurationInterface()

    @staticmethod
    def from_file(filepath: Path) -> 'LibfuzzerConfigurationInterface':
        with open(filepath, "r") as f:
            return LibfuzzerConfigurationInterface(f.read().split())

    @staticmethod
    def from_str(s: str) -> 'LibfuzzerConfigurationInterface':
        return LibfuzzerConfigurationInterface(s.split())

    def to_str(self) -> str:
        return " ".join(self._argvs)

    def get_coverage_mode(self) -> CoverageMode:
        """ Current coverage mode selected in the file """
        return CoverageMode.AUTO # type: ignore

    def set_target(self, target: int) -> None:
        # Note: Giving a target to Libfuzzer does not
        # do anything as Libfuzzer is not directed.
        pass


class LibfuzzerEngineDescriptor(FuzzingEngineDescriptor):

    NAME = "LIBFUZZER"
    SHORT_NAME = "LIBFUZZER"
    VERSION = "1.0.0"  # Should be in sync with libfuzzer.__version__

    config_class = LibfuzzerConfigurationInterface

    def __init__(self):
        pass

    @staticmethod
    def accept_file(binary_file: Path) -> Tuple[bool, Optional[ExecMode], Optional[FuzzMode]]:
        if str(binary_file).endswith(".cmplog"):
            return False, None, None

        p = lief.parse(str(binary_file))
        if not p:
            return False, None, None

        # Search for libfuzzer instrumentation
        instrumented = False

        for s in p.symbols:
            if "__afl_" in s.name or "hfuzz_" in s.name:
                return False, None, None  # Not a libfuzzer binary

        for f in p.functions:
            if "LLVMFuzzerTestOneInput" in f.name:
                instrumented = True
                break

        if not instrumented:
            # Libfuzzer do not support not instrumented binaries
            return False, None, None
        else:
            return True, ExecMode.AUTO, FuzzMode.INSTRUMENTED # type: ignore

    @staticmethod
    def supported_coverage_strategies() -> List[CoverageMode]:
        return [CoverageMode.AUTO] # type: ignore
