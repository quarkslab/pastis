# built-in imports
from pathlib import Path
from typing import Union, Tuple, List, Optional

# third-party import
import lief

from libpastis import FuzzingEngineDescriptor, EngineConfiguration
from libpastis.types import ExecMode, CoverageMode



class TritonEngineDescriptor(FuzzingEngineDescriptor):

    NAME = "TRITON"
    SHORT_NAME = "TT"
    VERSION = "0.3"

    FUNCTION_BLACKLIST_PREFIX = [
        "__sanitizer",  # all fuzzer related sanitizers
        "__gcov_"       # gcov functions
    ]

    IMPORT_BLACKLIST = [
        "HF_ITER"       # honggfuzz functions
    ]

    def __init__(self):
        pass

    @staticmethod
    def accept_file(binary_file: Path) -> Tuple[bool, Optional[ExecMode]]:
        p = lief.parse(str(binary_file))
        if not p:
            return False, None

        # Presumably good unless do find some instrumentation functions or imports
        for f in p.functions:
            for item in TritonEngineDescriptor.FUNCTION_BLACKLIST_PREFIX:
                if f.name.startswith(item):
                    return False, None

        for f in p.imported_functions:
            if f.name in TritonEngineDescriptor.IMPORT_BLACKLIST:
                return False, None

        return True, ExecMode.SINGLE_EXEC


    @staticmethod
    def supported_coverage_strategies() -> List[CoverageMode]:
        return list(CoverageMode)

    @staticmethod
    def configuration() -> EngineConfiguration:
        raise NotImplementedError()
