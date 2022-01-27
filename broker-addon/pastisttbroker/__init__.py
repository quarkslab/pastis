# built-in imports
from pathlib import Path
from typing import Union, Tuple, List, Optional
import json

# third-party import
import lief

from libpastis import FuzzingEngineDescriptor, EngineConfiguration
from libpastis.types import ExecMode, CoverageMode

# WARNING: This module is made in such a way that it does
# not directly depend on tritondse (to facilitate installation)
# coverage strategies thus have to be ported here !
TRITON_DSE_COVS = ['BLOCK', 'EDGE', 'PATH']


class TritonConfigurationInterface(EngineConfiguration):
    def __init__(self, data):
        self.data = data

    def from_file(self, filepath: Path) -> 'TritonConfigurationInterface':
        with open(filepath, "r") as f:
            json.load(f)

    def from_str(self, s: str) -> 'TritonConfigurationInterface':
        return json.laods(s)

    def to_str(self) -> str:
        json.dumps(self.data)

    def get_coverage_mode(self) -> CoverageMode:
        """ Current coverage mode selected in the file """

        raise NotImplementedError



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

    mapper = {"CODE": CoverageMode.BLOCK, "EDGE": CoverageMode.EDGE, "PATH": CoverageMode.PATH}

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
        return [TritonEngineDescriptor.mapper.get(st, CoverageMode(st.name)) for st in TRITON_DSE_COVS]

    @staticmethod
    def get_configuration_cls() -> EngineConfiguration:
        return TritonConfigurationInterface
