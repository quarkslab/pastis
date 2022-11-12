# built-in imports
from pathlib import Path
import zipfile
import tempfile
import logging
from typing import Tuple, Optional, List

# third-party imports
import lief
import magic
import shutil
import stat

# local imports
from libpastis.types import Arch, Platform


class BinaryPackage(object):
    def __init__(self, main_binary: Path):
        self._main_bin = Path(main_binary)
        self._qbinexport = None
        self._callgraph = None
        self._cmplog = None
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
    def qbinexport(self) -> Path:
        return self._qbinexport

    @property
    def callgraph(self) -> Path:
        return self._callgraph

    @property
    def cmplog(self) -> Path:
        return self._cmplog

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
        bin_f.chmod(stat.S_IRWXU)  # make sur the binary executable
        data = BinaryPackage._read_binary_infos(bin_f)
        if not data:
            raise ValueError(f"{exe_name} format is not supported")
        p = BinaryPackage(bin_f)
        p._platform, p._arch = data

        # Search for a Quokka file
        qfile = Path(str(bin_f)+".Quokka")
        if qfile.exists():
            p._qbinexport = qfile

        # Search for a graph file (containing callgraph)
        cfile = Path(str(bin_f)+".gt")
        if cfile.exists():
            p._callgraph = cfile

        # Search for a cmplog file if any
        cfile = Path(str(bin_f)+".cmplog")
        if cfile.exists():
            p._cmplog = cfile

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
            if file not in [p._main_bin, p._callgraph, p._qbinexport, p._cmplog]:
                p.other_files.append(file)

    def make_package(self) -> Path:
        if self._package_file is not None:
            if self._package_file.exists():
                return self._package_file
        # Recreate a package
        fname = tempfile.mktemp(suffix=".zip")
        zip = zipfile.ZipFile(fname, "w")
        zip.write(self._main_bin, self._main_bin.name)
        if self._qbinexport:
            zip.write(self._qbinexport, self._qbinexport.name)
        if self._callgraph:
            zip.write(self._callgraph, self._callgraph.name)
        if self._cmplog:
            zip.write(self._cmplog, self._cmplog.name)
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

    @staticmethod
    def from_binary(name: str, binary: bytes, extract_dir: Path) -> 'BinaryPackage':
        """
        Convert the binary blob received as a BinaryPackage object. If its an archive,
        extract it and return the list of files. Files are extracted in /tmp. If
        directly an executable save it to a file and return its path. Also ensure
        the executable file is indeed executable in terms of permissions.

        :param name: name of executable, or executable name in archive
        :param binary: content
        :param extract_dir: Path: directory where files should be extracted
        :return: list of file paths

        :raise FileNotFoundError: if the mime type of the binary is not recognized
        """
        mime = magic.from_buffer(binary, mime=True)

        if mime in ['application/x-tar', 'application/zip']:
            map = {'application/x-tar': '.tar.gz', 'application/zip': '.zip'}
            tmp_file = Path(tempfile.mktemp(suffix=map[mime]))
            tmp_file.write_bytes(binary)          # write the archive in a file

            # Extract the archive in the right directory
            shutil.unpack_archive(tmp_file.as_posix(), extract_dir)  # unpack it in dst directory
            # Create the package object
            pkg = BinaryPackage.auto(extract_dir, name)
            for file in extract_dir.iterdir():
                if file not in [pkg.executable_path, pkg.callgraph, pkg.qbinexport]:
                    pkg.other_files.append(file)
            return pkg
        elif mime in ['application/x-pie-executable', 'application/x-dosexec', 'application/x-mach-binary', 'application/x-executable', 'application/x-sharedlib']:
            program_path = extract_dir / name
            program_path.write_bytes(binary)
            program_path.chmod(stat.S_IRWXU)  # set the binary executable
            return BinaryPackage(program_path)
        else:
            raise FileNotFoundError(f"mimetype not recognized {mime}")
