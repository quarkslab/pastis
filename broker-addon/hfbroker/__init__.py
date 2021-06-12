# built-in imports
from pathlib import Path
from typing import Union, Tuple, List, Optional

# third-party import
import lief

from libpastis import FuzzingEngineDescriptor, EngineConfiguration
from libpastis.types import ExecMode, CoverageMode



class HonggfuzzEngineDescriptor(FuzzingEngineDescriptor):

    NAME = "HONGGFUZZ"
    SHORT_NAME = "HF"
    VERSION = "0.3"  # Should be in sync with hfwrapper.__version__

    HF_PERSISTENT_SIG = b"\x01_LIBHFUZZ_PERSISTENT_BINARY_SIGNATURE_\x02\xFF"

    def __init__(self):
        pass

    @staticmethod
    def accept_file(binary_file: Path) -> Tuple[bool, Optional[ExecMode]]:
        p = lief.parse(str(binary_file))
        if not p:
            return False, None

        # Search for HF instrumentation
        good = False
        for f in p.functions:
            if "__sanitizer" in f.name:
                good = True
                break
        if not good:
            return False, None

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
        return True, exmode

    @staticmethod
    def supported_coverage_strategies() -> List[CoverageMode]:
        return [CoverageMode.EDGE]

    @staticmethod
    def configuration() -> EngineConfiguration:
        raise NotImplementedError()
