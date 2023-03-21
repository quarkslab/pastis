# built-in imports
from pathlib import Path
import zipfile
import tempfile
import logging
from typing import Tuple, Optional, Union

# third-party imports
import lief
import magic
import shutil
import stat

# local imports
from libpastis.types import Arch, Platform


class BinaryPackage(object):
    """
    Binary Package representing a given target to fuzz along with its shared
    libraries and additional files required (cmplog, dictionnary etc.).
    This object is received by fuzzing agents as part of the START message.
    """

    EXTENSION_BLACKLIST = ['.gt', '.Quokka', '.quokka', '.cmplog']
    #: specific extensions that will be ignored for the `other_files`

    def __init__(self, main_binary: Path):
        """
        :param main_binary: main executable file path
        """
        self._main_bin = Path(main_binary)
        self._quokka = None
        self._callgraph = None
        self._cmplog = None
        self._dictionary = None
        self.other_files = []
        #: list of additional files contained in this package

        self._package_file = None
        self._arch = None
        self._platform = None

    @property
    def executable_path(self) -> Path:
        """
        Path to the main executable file to fuzz.

        :return: filepath
        """
        return self._main_bin

    @property
    def name(self) -> str:
        """
        Name of the executable file

        :return: name as a string
        """
        return self._main_bin.name

    @property
    def quokka(self) -> Optional[Path]:
        """
        Path to the quokka file if provided.

        :return: path of the quokka file
        """
        return self._quokka

    @property
    def callgraph(self) -> Optional[Path]:
        """
        Path to the callgraph file if provided.

        :return: path of the quokka file
        """
        return self._callgraph

    @property
    def cmplog(self) -> Optional[Path]:
        """
        Path to the complog executable file if provided.

        :return: path to the complog file
        """
        return self._cmplog

    @property
    def dictionary(self) -> Optional[Path]:
        """
        Path the to dictionnary file if provided.

        :return: path to the dictionnary file
        """
        return self._dictionary

    def is_cmplog(self) -> bool:
        """
        Check if the package contains a cmplog file.

        :return: True if contains cmplog
        """
        return self._cmplog is not None

    def is_quokka(self) -> bool:
        """
        Check if the package contains a quokka file.

        :return: True if contains a quokka file
        """
        return self._quokka is not None

    def is_dictionary(self) -> bool:
        """
        Check if the package contains a dictionnary.

        :return: True if contains a dictionnary
        """
        return self._dictionary is not None

    def is_standalone(self) -> bool:
        """
        Indicates that this BinaryPackage only contains the program under test and no
        additional files such as a Quokka database or a cmplog instrumented binary.
        This is used in pastis-broker when sending the 'start' command to agents.
        """
        return not (self.is_quokka() or
                    self.is_cmplog() or
                    self.is_dictionary() or
                    bool(self.other_files))

    @property
    def arch(self) -> Arch:
        """
        Return the architecture of the binary package (main executable target).

        :return: architecture
        """
        return self._arch

    @property
    def platform(self) -> Platform:
        """
        Return the platform of the binary package (main exectuable target).

        :return: platform
        """
        return self._platform

    @staticmethod
    def auto(exe_file: Union[Path, str]) -> Optional['BinaryPackage']:
        """
        Take a file and try creating a BinaryPackage with it. The `exe_file` is
        the main executable file. From that the function will look for quokka,
        cmplog, dictionary files (in the same directory).

        :param exe_file: main target executable file
        :return: a binary package if `exe_file` if applicable
        """
        bin_f = Path(exe_file)

        # Exclude file if have one of the
        if bin_f.suffix in BinaryPackage.EXTENSION_BLACKLIST:
            return None

        # If do not exists
        if not bin_f.exists():
            return None

        # Make sure its an executable
        data = BinaryPackage._read_binary_infos(bin_f)
        if not data:
            return None

        bin_f.chmod(stat.S_IRWXU)  # make sure the binary is executable

        p = BinaryPackage(bin_f)
        p._platform, p._arch = data

        # Search for a Quokka file
        qfile1, qfile2 = Path(str(bin_f)+".Quokka"), Path(str(bin_f)+".quokka")
        if qfile1.exists():
            p._quokka = qfile1
        elif qfile2.exists():
            p._quokka = qfile2

        # Search for a graph file (containing callgraph)
        cfile = Path(str(bin_f)+".gt")
        if cfile.exists():
            p._callgraph = cfile

        # Search for a cmplog file if any
        cfile = Path(str(bin_f)+".cmplog")
        if cfile.exists():
            p._cmplog = cfile
            cfile.chmod(stat.S_IRWXU)  # make sure the cmplog binary is executable

        # Search for a dictionary file if any
        cfile = Path(str(bin_f)+".dict")
        if cfile.exists():
            p._dictionary = cfile

        return p

    @staticmethod
    def auto_directory(exe_file: Union[str, Path]) -> Optional['BinaryPackage']:
        """
        Create a BinaryPackage with all files it can find in the given
        directory. The difference with :py:meth:`BinaryPackage.auto` is
        that all additional files in the directory will be added to the
        package.

        :param exe_file: main executable in the directory
        :return: BinaryPackage if applicable
        """
        bin_f = Path(exe_file)

        p = BinaryPackage.auto(bin_f)

        if p is None:
            return None

        for file in bin_f.parent.iterdir():
            if file not in [p._main_bin, p._callgraph, p._quokka, p._cmplog, p._dictionary]:
                p.other_files.append(file)

    def make_package(self) -> Path:
        """
        Pack the BinaryPackage in a zip file.

        :return: Path to a .zip file containing the whole package
        """
        if self._package_file is not None:
            if self._package_file.exists():
                return self._package_file
        # Recreate a package
        fname = tempfile.mktemp(suffix=".zip")
        zip = zipfile.ZipFile(fname, "w")
        zip.write(self._main_bin, self._main_bin.name)
        if self._quokka:
            zip.write(self._quokka, self._quokka.name)
        if self._callgraph:
            zip.write(self._callgraph, self._callgraph.name)
        if self._cmplog:
            zip.write(self._cmplog, self._cmplog.name)
        if self._dictionary:
            zip.write(self._dictionary, self._dictionary.name)
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
            pkg = BinaryPackage.auto(Path(extract_dir) / name)
            if pkg is None:
                raise ValueError(f"Cannot create a BinaryPackage with {name}")
            for file in extract_dir.iterdir():
                if file not in [pkg.executable_path, pkg.callgraph, pkg.quokka, pkg.dictionary]:
                    pkg.other_files.append(file)
            return pkg
        elif mime in ['application/x-pie-executable', 'application/x-dosexec', 'application/x-mach-binary', 'application/x-executable', 'application/x-sharedlib']:
            program_path = extract_dir / name
            program_path.write_bytes(binary)
            program_path.chmod(stat.S_IRWXU)  # set the binary executable
            return BinaryPackage(program_path)
        else:
            raise FileNotFoundError(f"mimetype not recognized {mime}")
