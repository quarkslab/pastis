# builtin imports
import platform
from typing import Optional

# Third-party import
import psutil

# Local imports
from .types import FuzzingEngine, Arch, Platform


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
    # FIXME: Make sure platform.machine() returns this string for architectures
    return mapping.get(platform.machine())


def get_local_platform() -> Optional[Platform]:
    mapping = {"Linux": Platform.LINUX, "Windows": Platform.WINDOWS, "MacOS": Platform.MACOS, "iOS": Platform.IOS}
    # FIXME: Make sure platform.system() returns this string for other platforms
    return mapping.get(platform.system())
