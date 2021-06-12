# builtin imports
import platform
from typing import Optional

# Local imports
from .types import Arch, Platform


def get_local_architecture() -> Optional[Arch]:
    mapping = {"i386": Arch.X86, "x86_64": Arch.X86_64, "armv7l": Arch.ARMV7, "aarch64": Arch.AARCH64}
    # FIXME: Make sure platform.machine() returns this string for architectures
    return mapping.get(platform.machine())


def get_local_platform() -> Optional[Platform]:
    mapping = {"Linux": Platform.LINUX, "Windows": Platform.WINDOWS, "MacOS": Platform.MACOS, "iOS": Platform.IOS}
    # FIXME: Make sure platform.system() returns this string for other platforms
    return mapping.get(platform.system())
