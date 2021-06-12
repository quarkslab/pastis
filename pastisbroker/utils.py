#built-in imports
import logging
from pathlib import Path
from typing import Optional, Tuple

# third-party imports
import lief

# local imports
from libpastis.types import Arch, FuzzingEngine, ExecMode, Platform


HF_PERSISTENT_SIG = b"\x01_LIBHFUZZ_PERSISTENT_BINARY_SIGNATURE_\x02\xFF"


def read_binary_infos(file: Path) -> Optional[Tuple[Platform, Arch, FuzzingEngine, ExecMode]]:
    p = lief.parse(str(file))
    if not p:
        return None
    if not isinstance(p, lief.ELF.Binary):
        logging.warning(f"binary {file} not supported (only ELF at the moment)")
        return None

    # Try to find intrinsic in program if so it is a good one!
    good = False
    honggfuzz = False
    for f in p.functions:
        name = f.name
        if '__klocwork' in name:
            good = True
        if '__sanitizer' in name:
            honggfuzz = True
    if not good:
        logging.debug(f"ignore binary: {file} (does not contain klocwork intrinsics)")
        return None

    # Try to find the Honggfuzz PERSISTENT magic in binary
    exmode = ExecMode.SINGLE_EXEC  # by default single_exec
    sections = {x.name: x for x in p.sections}
    if '.rodata' in sections:
        rodata_content = bytearray(sections['.rodata'].content)
        if HF_PERSISTENT_SIG in rodata_content:
            exmode = ExecMode.PERSISTENT
    else:
        if 'HF_ITER' in (x.name for x in p.imported_functions):  # More dummy method
            exmode = ExecMode.PERSISTENT

    # Determine the architecture of the binary
    mapping = {lief.ELF.ARCH.x86_64: Arch.X86_64,
               lief.ELF.ARCH.i386: Arch.X86,
               lief.ELF.ARCH.ARM: Arch.ARMV7,
               lief.ELF.ARCH.AARCH64: Arch.AARCH64}
    arch = mapping.get(p.header.machine_type)

    # Determine the platform from its format
    mapping_elf = {lief.EXE_FORMATS.ELF: Platform.LINUX,
                   lief.EXE_FORMATS.PE: Platform.WINDOWS,
                   lief.EXE_FORMATS.MACHO: Platform.MACOS}
    # FIXME: differentiating between ELF (Linux, Android ..) and MACHO (MacOS, iOS..)
    fmt = mapping_elf.get(p.format)

    if arch and fmt:
        engine = FuzzingEngine.HONGGFUZZ if honggfuzz else FuzzingEngine.TRITON
        return fmt, arch, engine, exmode
    else:
        return None
