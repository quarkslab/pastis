# built-in imports
from enum import Enum, auto
from pathlib import Path
from typing import Generator, Optional
import os
import subprocess
import logging
import re
from datetime import datetime

# third-party
from pastisbroker.workspace import Workspace, WorkspaceStatus
from libpastis.types import SeedInjectLoc, SeedType
from tritondse.trace import QBDITrace
from tritondse import CoverageStrategy


class ReplayType(Enum):
    qbdi = auto()
    llvm_profile = auto()


class Replayer(object):

    QBDI_REPLAY_DIR = "replays_qbdi"
    LLVMPROFILE_REPLAY_DIR = "replays_llvmprof"

    def __init__(self, program: Path, workspace: Path, type: ReplayType, injloc: SeedInjectLoc, stream: bool = False, *args):
        self.workspace = Workspace(workspace)
        self.type = type
        self.stream = stream
        self.program = Path(program)
        self._inject_loc = injloc
        self._args = list(args)

        # initiatialize directories
        self._init_directories()

        # set longjmp ENV var if applicable
        self._set_longjump_plt()

    def _init_directories(self):
        if not self.corpus_replay_dir.exists():
            self.corpus_replay_dir.mkdir()

    def _set_longjump_plt(self):
        try:
            proc = subprocess.Popen(['objdump', '-D', self.program.absolute()], stdout=subprocess.PIPE)
            out, err = proc.communicate()
            for line in out.split(b"\n"):
                if b"<longjmp@plt>:" in line:
                    addr = line.split()[0]
                    logging.info(f"lonjmp address found at: {addr}")
                    os.environ["TT_LONGJMP_ADDR"] = str(int(addr, 16))
        except:
            return 0

    @property
    def corpus_replay_dir(self) -> Path:
        if self.type == ReplayType.qbdi:
            return self.workspace.root / self.QBDI_REPLAY_DIR
        else:
            return self.workspace.root / self.LLVMPROFILE_REPLAY_DIR

    def iter(self) -> Generator[Path, None, None]:
        yield from self.workspace.iter_initial_corpus_directory()
        yield from self.workspace.iter_corpus_directory(SeedType.INPUT)

    def replay(self, input: Path) -> bool:
        if self.type == ReplayType.qbdi:
            return self._replay_qbdi(input)
        else:
            return self._replay_llvm_profile(input)

    def _replay_qbdi(self, input: Path) -> bool:
        out_file = self.corpus_replay_dir / (input.name + ".trace")
        args = self._args

        # If inject on argv try replacing the right argv
        if self._inject_loc == SeedInjectLoc.ARGV:
            if "@@" in args:
                idx = args.index("@@")
                args[idx] = str(input)

        return QBDITrace.run(CoverageStrategy.EDGE,
                             str(self.program.absolute()),
                             args=args,
                             output_path=str(out_file.absolute()),
                             stdin_file=input if self._inject_loc == SeedInjectLoc.STDIN else None,
                             cwd=self.program.parent)

    def _replay_llvm_profile(self, input: Path) -> bool:
        pass


    def start(self):
        # TODO: Start monitoring folders (and status file)
        pass

    @staticmethod
    def parse_filename(filename) -> Optional[tuple]:
        if re.match("^\d{4}-\d{2}-\d{2}", filename):  # start by the date
            date, time, elapsed, fuzzer_id, hash = filename.split("_")
            date = datetime.strptime(f"{date}_{time}", "%Y-%m-%d_%H:%M:%S")
            elapsed = datetime.strptime(elapsed, "%H:%M:%S.%f").time()
            hash = hash[:-4] if hash.endswith(".cov") else hash
            return date, elapsed, fuzzer_id, hash
        else:
            return None
