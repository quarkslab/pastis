import platform

from tritondse.loaders import Program
from tritondse.types import Architecture, Platform


def is_compatible_with_local(program: Program) -> bool:
    """
    Checks whether the given program is compatible with the current architecture
    and platform.

    :param program: Program
    :return: True if the program can be run locally
    """
    arch_m = {
        "i386": Architecture.X86,
        "x86_64": Architecture.X86_64,
        "armv7l": Architecture.ARM32,
        "aarch64": Architecture.AARCH64
    }

    plfm_m = {
        "Linux": Platform.LINUX,
        "Windows": Platform.WINDOWS,
        "MacOS": Platform.MACOS,
        "iOS": Platform.IOS
    }

    local_arch, local_plfm = arch_m[platform.machine()], plfm_m[platform.system()]

    return program.architecture == local_arch and program.platform == local_plfm
