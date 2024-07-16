# built-in imports
from pathlib import Path
from typing import Union, Tuple, List, Optional
import json

# third-party import
import lief

from libpastis import FuzzingEngineDescriptor, EngineConfiguration
from libpastis.types import ExecMode, CoverageMode, FuzzMode

# WARNING: This module is made in such a way that it does
# not directly depend on tritondse (to facilitate installation)
# coverage strategies thus have to be ported here !
TRITON_DSE_COVS = ['BLOCK', 'EDGE', 'PATH']


class TritonConfigurationInterface(EngineConfiguration):
    def __init__(self, data):
        self.data = data

    @staticmethod
    def new() -> 'TritonConfigurationInterface':
        return TritonConfigurationInterface({})

    @staticmethod
    def from_file(filepath: Path) -> 'TritonConfigurationInterface':
        with open(filepath, "r") as f:
            return TritonConfigurationInterface(json.load(f))

    @staticmethod
    def from_str(s: str) -> 'TritonConfigurationInterface':
        return TritonConfigurationInterface(json.loads(s))

    def to_str(self) -> str:
        return json.dumps(self.data)

    def get_coverage_mode(self) -> CoverageMode:
        """ Current coverage mode selected in the file """
        v = self.data['coverage_strategy']
        return CoverageMode(v)

    def set_target(self, target: int) -> None:
        self.data['custom'] = {}
        self.data['custom']['target'] = target


class TritonEngineDescriptor(FuzzingEngineDescriptor):

    NAME = "TRITON"
    SHORT_NAME = "TT"
    VERSION = "1.0.0"

    FUNCTION_BLACKLIST_PREFIX = [
        "__sanitizer",  # all fuzzer related sanitizers
        "__gcov_",      # gcov functions
        "__asan_",
        "__afl_"
    ]

    SYMBOL_BLACKLIST_PREFIX = [
        "__sanitizer",  # all fuzzer related sanitizers
        "__gcov_",      # gcov functions
        "__asan_",
        "__afl_"
    ]

    IMPORT_BLACKLIST = [
        "HF_ITER"       # honggfuzz functions
    ]

    config_class = TritonConfigurationInterface

    def __init__(self):
        pass

    @staticmethod
    def accept_file(binary_file: Path) -> Tuple[bool, Optional[ExecMode], Optional[FuzzMode]]:
        p = lief.parse(str(binary_file))
        if not p:
            return False, None, None

        # Presumably good unless do find some instrumentation functions or imports
        for f in p.functions:
            for item in TritonEngineDescriptor.FUNCTION_BLACKLIST_PREFIX:
                if f.name.startswith(item):
                    return False, None, None

        for f in p.imported_functions:
            if f.name in TritonEngineDescriptor.IMPORT_BLACKLIST:
                return False, None, None

        for s in p.symbols:
            for item in TritonEngineDescriptor.SYMBOL_BLACKLIST_PREFIX:
                if s.name.startswith(item):
                    return False, None, None

        return True, ExecMode.SINGLE_EXEC, FuzzMode.BINARY_ONLY  # Only support single_exec, binary only (not instrumented)

    @staticmethod
    def supported_coverage_strategies() -> List[CoverageMode]:
        return [CoverageMode(st) for st in TRITON_DSE_COVS]
