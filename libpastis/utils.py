# builtin imports
from typing import Optional

# Third-party import
import psutil

# Local imports
from .types import FuzzingEngine, Arch


def do_engine_support_coverage_strategy(engine: FuzzingEngine) -> bool:
    """
    Utility function to check whether the fuzzing engine support
    different coverage strategy

    .. NOTE: Shall we return the list of supported strategies ?

    :param engine: engine to check
    :return: boolean if engine support variadic coverage strategies
    """
    return {FuzzingEngine.TRITON: True,
             FuzzingEngine.HONGGFUZZ: False}[engine]


def get_local_architecture() -> Optional[Arch]:
    mapping = {"i386": Arch.X86, "x86_64": Arch.X86_64, "armv7l": Arch.ARMV7, "aarch64": Arch.AARCH64}
    a = psutil.os.uname().machine
    # FIXME: Make sure psutil.os.uname().machine returns this string as architecture
    return mapping.get(a)
