#built-in imports
import logging
from pathlib import Path
from typing import Optional, Tuple
import importlib
import inspect

# third-party imports
import lief

# local imports
from libpastis.types import Arch, ExecMode, Platform
from libpastis.enginedesc import FuzzingEngineDescriptor


HF_PERSISTENT_SIG = b"\x01_LIBHFUZZ_PERSISTENT_BINARY_SIGNATURE_\x02\xFF"


def read_binary_infos(file: Path) -> Optional[Tuple[Platform, Arch]]:
    p = lief.parse(str(file))
    if not p:
        return None
    if not isinstance(p, lief.ELF.Binary):
        logging.warning(f"binary {file} not supported (only ELF at the moment)")
        return None

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
        return fmt, arch
    else:
        return None


def load_engine_descriptor(py_module: str) -> Optional[FuzzingEngineDescriptor]:
    try:
        mod = importlib.import_module(py_module)
        mems = inspect.getmembers(mod, lambda x: inspect.isclass(x) and issubclass(x, FuzzingEngineDescriptor) and x != FuzzingEngineDescriptor)
        if not mems:
            logging.error(f"can't find FuzzingEngineDescriptor in module {py_module}")
            return None
        else:
            if len(mems) > 1:
                logging.warning(f"module {py_module} contain multiple subclass of {FuzzingEngineDescriptor} (take first)")
            return mems[0][1]
    except ImportError:
        logging.error(f"cannot import py_module: {py_module}")
