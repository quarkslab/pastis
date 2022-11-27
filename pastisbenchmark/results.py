# built-in imports
from abc import abstractmethod
from enum import Enum, auto
from pathlib import Path
from typing import Generator, Optional, Union, List, Dict, Tuple, Set
import os
import json
import subprocess
import logging
import re
from datetime import datetime, timedelta
from pydantic import BaseModel
import matplotlib.pyplot as plt

# third-party
from pastisbroker import BrokingMode
from pastisbroker.workspace import Workspace, WorkspaceStatus
from libpastis.types import SeedInjectLoc, SeedType
from tritondse.trace import QBDITrace
from tritondse import CoverageStrategy, GlobalCoverage, BranchSolvingStrategy
from tritondse.coverage import CovItem

# local imports
from pastisbenchmark.replayer import ReplayType

class InputCovDelta(BaseModel):
    time_elapsed: float        # Time elapsed when input generated
    input_name: str            # Input name
    fuzzer: str                # The fuzzer that found that input

    # The coverage of this one input (len(covered_items))
    coverage: int
    # Coverage found by this seed that was not previsouly hit (not in global_coverage)
    unique_coverage: Set[CovItem]
    # The total coverage of the fuzz campaign at this point
    total_coverage: int

    # Instruction coverage of that input
    coverage_insts: int
    # Total instruction coverage at this point
    total_coverage_insts: int
    # Instr
    unique_coverage_insts: Set[int]

    @property
    def new_coverage_count(self) -> int:
        return len(self.unique_coverage)

    @property
    def new_instruction_count(self) -> int:
        return len(self.unique_coverage_insts)

    def is_initial_input(self) -> bool:
        return self.fuzzer == "seeds"

    def is_triton_input(self) -> bool:
        return "TT" in self.fuzzer


class CampaignResult(object):

    SEED_FUZZER = "seeds"
    ALL_FUZZER = "all"

    QBDI_REPLAY_DIR = "replays_qbdi"
    LLVMPROFILE_REPLAY_DIR = "replays_llvmprof"
    REPLAYS_DELTA = "replays_delta"

    def __init__(self, workspace: Union[Path, str]):
        self.workspace = Workspace(Path(workspace))
        # Stat items
        self.fuzzers_items = {}     # fuzzer_name -> List[StatItem]
        self.fuzzers_coverage = {}  # fuzzer_name -> Coverage

        # Global branch coverage
        self.overall_coverage = GlobalCoverage(CoverageStrategy.EDGE, BranchSolvingStrategy.ALL_NOT_COVERED)

        # initialize directories
        self._init_directories()

        self.mode = self.load_broking_mode(self.workspace)

    @property
    def is_full_duplex(self) -> bool:
        return bool(self.mode == BrokingMode.FULL)

    @property
    def results(self):
        return self.fuzzers_items.items()

    def _init_directories(self):
        if not self.replay_delta_dir.exists():
            self.replay_delta_dir.mkdir()

    def _init_fuzzer_stats(self, fuzzer_name: str) -> None:
        if fuzzer_name in self.fuzzers_items:
            return None

        # consider seed inputs as common to all
        if self.SEED_FUZZER in self.fuzzers_items:
            cov = self.fuzzers_coverage[self.SEED_FUZZER].clone()
        else: # else create an empty coverage file
            cov = GlobalCoverage(CoverageStrategy.EDGE, BranchSolvingStrategy.ALL_NOT_COVERED)

        self.fuzzers_items[fuzzer_name] = []
        self.fuzzers_coverage[fuzzer_name] = cov

    @staticmethod
    def load_broking_mode(workspace: Workspace) -> BrokingMode:
        data = json.loads(workspace.config_file.read_text())
        return BrokingMode[data['broker_mode']]

    @property
    def replay_delta_dir(self) -> Path:
        return self.workspace.root / self.REPLAYS_DELTA

    def replay_ok(self) -> bool:
        return len(list(self.replay_delta_dir.iterdir())) != 0

    @staticmethod
    def parse_filename(filename) -> Optional[tuple]:
        ref = datetime.strptime("0:00:00.00", "%H:%M:%S.%f")
        if re.match("^\d{4}-\d{2}-\d{2}", filename):  # start by the date
            date, time, elapsed, fuzzer_id, hash = filename.split("_")
            date = datetime.strptime(f"{date}_{time}", "%Y-%m-%d_%H:%M:%S")
            elapsed = (datetime.strptime(elapsed, "%H:%M:%S.%f") - ref).total_seconds()
            hash = hash[:-4] if hash.endswith(".cov") else hash
            return date, elapsed, fuzzer_id, hash
        else:
            return None

    def _iter_sorted(self, path: Path):
        files = {None: []}
        for file in path.iterdir():
            res = self.parse_filename(file.name)
            if res is None:
                files[None].append(file)
            else:
                date, elapsed, fuzzer, hash = res
                if elapsed in files:
                    logging.warning(f"two files with same elapsed time: {files[elapsed]} | {file.name}")
                files[elapsed] = file

        # First yield initial seeds
        init_seeds = files.pop(None)
        yield from init_seeds

        # Then iterate file sorted by elapsed time
        for k in sorted(files):
            yield files[k]

    def load(self, type: ReplayType = ReplayType.qbdi) -> None:
        logging.info(f"load in {type.name} [mode:{self.mode.name}]")
        if len(list(self.replay_delta_dir.iterdir())) != 0:
            self.load_delta()
        elif type == ReplayType.qbdi:
            self.load_qbdi()
        elif type == ReplayType.llvm_profile:
            self.load_llvmprofile()
        else:
            assert False

    def load_qbdi(self) -> None:
        logging.info("load qbdi trace files")
        first = True
        for file in self._iter_sorted(self.workspace.root / self.QBDI_REPLAY_DIR):
            # parse name
            meta = self.parse_filename(file.name)

            # Get the fuzzer name (and coverage)
            if meta is None:
                fuzzer = self.SEED_FUZZER
            elif self.mode == BrokingMode.FULL:
                fuzzer = self.ALL_FUZZER
            elif self.mode == BrokingMode.NO_TRANSMIT:
                fuzzer = meta[2]
            else:
                assert False

            self._init_fuzzer_stats(fuzzer)
            fuzzer_coverage = self.fuzzers_coverage[fuzzer]

            cov = QBDITrace.from_file(file).coverage

            # if first adapt coverage strategy to the
            if first:
                fuzzer_coverage.strategy = cov.strategy
                first = False

            # Compute differences to know what has been covered
            new_items = fuzzer_coverage - cov
            new_instrs = cov.covered_instructions.keys() - fuzzer_coverage.covered_instructions.keys()

            # Update global coverage
            fuzzer_coverage.merge(cov)
            # Update the total coverage (all fuzzers all together)
            self.overall_coverage.merge(cov)

            # Create an InputCovDelta
            statitem = InputCovDelta(
                time_elapsed=0 if meta is None else meta[1],
                input_name=file.name,
                fuzzer=fuzzer,
                coverage=cov.unique_covitem_covered,  # number of items covered
                unique_coverage=new_items,
                total_coverage=fuzzer_coverage.unique_covitem_covered,  # total items covered
                coverage_insts=cov.unique_instruction_covered,
                total_coverage_insts=fuzzer_coverage.unique_instruction_covered,
                unique_coverage_insts=new_instrs

            )
            self.fuzzers_items[fuzzer].append(statitem)

            with open(self.replay_delta_dir / (file.name+".json"), 'w') as f:
                f.write(statitem.json())

    def load_llvmprofile(self) -> None:
        # TODO: to implement
        pass

    def load_delta(self) -> None:
        logging.info("load delta directory")
        for file in self._iter_sorted(self.replay_delta_dir):
            meta = self.parse_filename(file.name)

            # Get the fuzzer name (and coverage)
            if meta is None:
                fuzzer = self.SEED_FUZZER
            elif self.mode == BrokingMode.FULL:
                fuzzer = self.ALL_FUZZER
            elif self.mode == BrokingMode.NO_TRANSMIT:
                fuzzer = meta[2]
            else:
                assert False
            if fuzzer not in self.fuzzers_items:
                self.fuzzers_items[fuzzer] = []

            self.fuzzers_items[fuzzer].append(InputCovDelta.parse_file(file))

    def print_stats(self):
        for fuzzer, results in self.fuzzers_items.items():

            tot_inps = sum(len(x) for x in self.fuzzers_items.values())
            tot_edge = self.overall_coverage.unique_covitem_covered

            print("-----------------------")
            print(f"Fuzzer: {fuzzer}")
            cov = self.fuzzers_coverage[fuzzer]
            print(f"inputs: {len(results)}, {len(results)/tot_inps:.0%}")
            print(f"edges: {cov.unique_covitem_covered} {cov.unique_covitem_covered/tot_edge:.0%)}")
            print(f"instructions: {cov.unique_instruction_covered}")
            print("-----------------------")
            print(f"Total inputs: {tot_inps}")
            print(f"Total edges: {tot_edge}")
