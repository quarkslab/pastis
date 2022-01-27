# built-in imports
from pathlib import Path
from typing import Union, Tuple, List, Optional

# third-party import
import lief
from typing import Type

from libpastis import FuzzingEngineDescriptor, EngineConfiguration
from libpastis.types import ExecMode, CoverageMode, FuzzMode


class HonggfuzzConfiguration(EngineConfiguration):
    """
    Small wrapping function for AFL++ additional parameters
    """
    def __init__(self, data: str):
        """
        :param data: command line to provide AFL++ as-is
        """
        self.data = data

    @staticmethod
    def from_file(filepath: Path) -> 'HonggfuzzConfiguration':
        return HonggfuzzConfiguration(Path(filepath).read_text())

    @staticmethod
    def from_str(s: str) -> 'HonggfuzzConfiguration':
        return HonggfuzzConfiguration(s)

    def to_str(self) -> str:
        return self.data

    def get_coverage_mode(self) -> CoverageMode:
        """ Current coverage mode selected in the file """
        raise CoverageMode.AUTO


class HonggfuzzEngineDescriptor(FuzzingEngineDescriptor):

    NAME = "HONGGFUZZ"
    SHORT_NAME = "HF"
    VERSION = "0.3"  # Should be in sync with hfwrapper.__version__

    HF_PERSISTENT_SIG = b"\x01_LIBHFUZZ_PERSISTENT_BINARY_SIGNATURE_\x02\xFF"

    def __init__(self):
        pass

    @staticmethod
    def accept_file(binary_file: Path) -> Tuple[bool, Optional[ExecMode], Optional[FuzzMode]]:
        p = lief.parse(str(binary_file))
        if not p:
            return False, None, None

        # Search for HF instrumentation
        good = False
        for f in p.functions:
            if "__sanitizer" in f.name:
                good = True
                break
        if not good:
            return False, None, None

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
        return True, exmode, FuzzMode.INSTRUMENTED  # FIXME: Can honggfuzz work in binary_only?

    @staticmethod
    def supported_coverage_strategies() -> List[CoverageMode]:
        return [CoverageMode.AUTO]

    @staticmethod
    def get_configuration_cls() -> Type[EngineConfiguration]:
        return HonggfuzzConfiguration
