# built-in imports
from pathlib import Path
from typing import Union, Tuple, List, Optional
import json

# third-party import
import lief
from typing import Type

from libpastis import FuzzingEngineDescriptor, EngineConfiguration
from libpastis.types import ExecMode, CoverageMode, FuzzMode


class HonggfuzzConfigurationInterface(EngineConfiguration):
    def __init__(self, args: List[str] = None):
        self._argvs = [] if args is None else args # Argument to send on the command line

    @staticmethod
    def new() -> 'HonggfuzzConfigurationInterface':
        return HonggfuzzConfigurationInterface()

    @staticmethod
    def from_file(filepath: Path) -> 'HonggfuzzConfigurationInterface':
        with open(filepath, "r") as f:
            return HonggfuzzConfigurationInterface(f.read().split())

    @staticmethod
    def from_str(s: str) -> 'HonggfuzzConfigurationInterface':
        return HonggfuzzConfigurationInterface(s.split())

    def to_str(self) -> str:
        return " ".join(self._argvs)

    def get_coverage_mode(self) -> CoverageMode:
        """
        Current coverage mode selected in the file.
        Always EDGE for Honggfuzz
        """
        return CoverageMode.AUTO

    def set_target(self, target: int) -> None:
        # Note: Giving a target to Honggfuzz does not
        # do anything as Honggfuzz is not directed.
        pass


class HonggfuzzEngineDescriptor(FuzzingEngineDescriptor):

    NAME = "HONGGFUZZ"
    SHORT_NAME = "HF"
    VERSION = "1.0.0"  # Should be in sync with hfwrapper.__version__

    HF_PERSISTENT_SIG = b"\x01_LIBHFUZZ_PERSISTENT_BINARY_SIGNATURE_\x02\xFF"

    config_class = HonggfuzzConfigurationInterface

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
            if "hfuzz_" in f.name:
                instrumented = True
                break
        if not instrumented:
            return True, ExecMode.PERSISTENT, FuzzMode.BINARY_ONLY

        # Search for persistent magic
        exmode = ExecMode.SINGLE_EXEC  # by default single_exec
        sections = {x.name: x for x in p.sections}
        if '.rodata' in sections:
            rodata_content = bytearray(sections['.rodata'].content)
            if HonggfuzzEngineDescriptor.HF_PERSISTENT_SIG in rodata_content:
                exmode = ExecMode.PERSISTENT
        else:
            if 'HF_ITER' in (x.name for x in p.imported_functions):  # More dummy method
                exmode = ExecMode.PERSISTENT
        return True, exmode, FuzzMode.INSTRUMENTED

    @staticmethod
    def supported_coverage_strategies() -> List[CoverageMode]:
        return [CoverageMode.AUTO]
