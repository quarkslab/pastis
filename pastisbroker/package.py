#built-in imports
from pathlib import Path
import zipfile
import tempfile
import logging
from typing import Tuple, Optional

# third-party imports
import lief
from tritondse.qbinexportprogram import QBinExportProgram

# local imports
from libpastis.types import Arch, Platform


class BinaryPackage(object):
    def __init__(self, main_binary: Path):
        self._main_bin = Path(main_binary)
        self._qbinexport = None
        self._callgraph = None
        self.other_files = []

        self._package_file = None
        self._arch = None
        self._platform = None

    @property
    def executable_path(self) -> Path:
        return self._main_bin

    @property
    def name(self) -> str:
        return self._main_bin.name

    @property
    def qbinexport(self):
        return self._qbinexport

    def is_qbinexport(self) -> bool:
        return self._qbinexport is not None

    @property
    def arch(self) -> Arch:
        return self._arch

    @property
    def platform(self) -> Platform:
        return self._platform

    @staticmethod
    def auto(dir: Path, exe_name: str):
        bin_f = Path(dir) / exe_name
        if not bin_f.exists():
            raise FileNotFoundError(f"{exe_name}")
        data = BinaryPackage._read_binary_infos(bin_f)
        if not data:
            raise ValueError(f"{exe_name} format is not supported")
        p = BinaryPackage(bin_f)
        p._platform, p._arch = data
        qfile = bin_f.with_suffix(".QBinExport")
        if qfile.exists():
            p._qbinexport = QBinExportProgram(qfile, bin_f)
        cfile = bin_f.with_suffix(".gt")
        if cfile.exists():
            p._callgraph = cfile
        return p

    @staticmethod
    def load_directory(dir: Path, exe_name: str) -> 'BinaryPackage':
        """
        Create a BinaryPackage with all files it can find in the given
        directory.

        :param dir: Source directory
        :param exe_name: main executable in the directory
        :return: BinaryPackage
        """
        p = BinaryPackage.auto(dir, exe_name)
        for file in Path(dir).iterdir():
            if file not in [p._main_bin, p._callgraph, p._qbinexport]:
                p.other_files.append(file)

    def make_package(self) -> Path:
        if self._package_file is not None:
            if self._package_file.exists():
                return self._package_file
        # Recreate a package
        fname = tempfile.mktemp(suffix=".zip")
        zip = zipfile.ZipFile(fname, "w")
        zip.write(self._main_bin)
        if self._qbinexport:
            zip.write(self._qbinexport.export_file)
        if self._callgraph:
            zip.write(self._callgraph)
        for file in self.other_files:
            zip.write(file)
        zip.close()
        return Path(fname)

    @staticmethod
    def _read_binary_infos(file: Path) -> Optional[Tuple[Platform, Arch]]:
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
