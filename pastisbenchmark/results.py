# built-in imports
from abc import abstractmethod
from enum import Enum, auto
from pathlib import Path
from typing import Generator, Optional, Union, List, Dict, Tuple, Set
import os
import json
import sys
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
from tritondse import CoverageStrategy, GlobalCoverage, BranchSolvingStrategy, Config
from tritondse.coverage import CovItem

# local imports
from pastisbenchmark.replayer import ReplayType

class InputCovDelta(BaseModel):
    time_elapsed: float        # Time elapsed when input generated
    input_name: str            # Input name
    fuzzer: str                # The fuzzer that found that input

    # Trace generic info
    unique_items_covered_count: int            # The coverage of this one input (len(covered_items))
    unique_insts_covered_count: int            # Instruction coverage of that input

    # Local to the fuzzer
    fuzzer_new_items_covered: Set[CovItem]  # New items covered by THIS fuzzer
    fuzzer_coverage_sum: int            # Sum of covered items by THIS fuzzer at this point
    fuzzer_inst_coverage_sum: int       # Sum of unique instructions covered by THIS FUZZER at this point
    fuzzer_new_insts_covered: Set[int]  # Instr

    # Global accros all fuzzers of the campaign
    overall_new_items_covered: Set[CovItem]  # New items covered by this fuzzer agains ALL THE OTHERS
    overall_coverage_sum: int            # The total coverage of the fuzz campaign at this point
    overall_inst_coverage_sum: int       # Total instruction coverage at this point
    overall_new_insts_covered: Set[int]  # Instr


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
    CLIENT_STATS = "clients-stats.json"
    COVERAGE_DIR = "coverages"

    def __init__(self, workspace: Union[Path, str]):
        self.workspace = Workspace(Path(workspace))
        # Stat items
        self.fuzzers_items = {}     # fuzzer_name -> List[StatItem]
        self.fuzzers_coverage = {}  # fuzzer_name -> Coverage
        self.fuzzers_config = {}    # fuzzer_name -> Union[str, Config]
        self._load_fuzzer_configs()
        self._all_items = []

        # initialize directories
        self._init_directories()

        # Load fuzzers configuration

        self.mode = self.load_broking_mode(self.workspace)

    def _load_fuzzer_configs(self):
        f = self.workspace.root / self.CLIENT_STATS
        data = json.loads(f.read_text())
        for client in data:
            id = client['strid']
            conf = client['engine_args']
            if self.is_triton(id):
                self.fuzzers_config[id] = Config.from_json(conf)
            else:
                self.fuzzers_config[id] = conf

    def has_honggfuzz(self):
        for fuzz in self.fuzzers_items.keys():
            if "HF" in fuzz:
                return True
        return False

    @staticmethod
    def is_triton(fuzzer: str) -> bool:
        return "TT" in fuzzer

    @property
    def is_full_duplex(self) -> bool:
        return bool(self.mode == BrokingMode.FULL)

    @property
    def is_half_duplex(self) -> bool:
        return bool(self.mode == BrokingMode.NO_TRANSMIT)

    @property
    def slug_name(self) -> str:
        data = ["AFL" if any(("AFLPP" in x for x in self.fuzzers_config)) else "",
                "HF" if any(("HF" in x for x in self.fuzzers_config)) else "",
                "TT" if any(("TT" in x for x in self.fuzzers_config)) else ""]
        if self.is_full_duplex:
            return f"PASTIS[{'|'.join(x for x in data if x)}]"
        else:
            return f"U[{'|'.join(x for x in data if x)}]"

    @property
    def results(self):
        return self.fuzzers_items.items()

    @property
    def delta_items(self) -> Generator[InputCovDelta, None, None]:
        yield from self._all_items

    def _init_directories(self):
        if not self.replay_delta_dir.exists():
            self.replay_delta_dir.mkdir()

    def _init_fuzzer_coverage(self, fuzzer_name: str) -> None:
        if fuzzer_name in self.fuzzers_coverage:
            return None

        # consider seed inputs as common to all
        if self.SEED_FUZZER in self.fuzzers_coverage:
            cov = self.fuzzers_coverage[self.SEED_FUZZER].clone()
        else: # else create an empty coverage file
            cov = GlobalCoverage(CoverageStrategy.EDGE, BranchSolvingStrategy.ALL_NOT_COVERED)

        self.fuzzers_coverage[fuzzer_name] = cov

    @staticmethod
    def load_broking_mode(workspace: Workspace) -> BrokingMode:
        data = json.loads(workspace.config_file.read_text())
        return BrokingMode[data['broker_mode']]

    @property
    def replay_delta_dir(self) -> Path:
        return self.workspace.root / self.REPLAYS_DELTA

    def has_delta_files(self) -> bool:
        return len(list(self.replay_delta_dir.iterdir())) != 0

    def replay_ok(self) -> bool:
        return len(list(self.replay_delta_dir.iterdir())) != 0

    @staticmethod
    def parse_filename(filename) -> Optional[tuple]:
        ref = datetime.strptime("0:00:00.00", "%H:%M:%S.%f")
        if re.match("^\d{4}-\d{2}-\d{2}", filename):  # start by the date
            date, time, elapsed, fuzzer_id, hash = filename.split("_")
            date = datetime.strptime(f"{date}_{time}", "%Y-%m-%d_%H:%M:%S")
            spl = elapsed.split(":")
            if len(spl) == 4:
                elapsed = int(spl[0][:-1])*(3600*24)
                elapsed += (datetime.strptime(":".join(spl[1:]), "%H:%M:%S.%f") - ref).total_seconds()
            else:
                elapsed = (datetime.strptime(elapsed, "%H:%M:%S.%f") - ref).total_seconds()
            hash = hash.split(".")[0]
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
        if self.has_delta_files():
            items = self.load_delta_directory()
            self.load_delta(items)
            self.load_coverage()  # If delta, coverage files shall also be present
        elif type == ReplayType.qbdi:
            items = self.load_qbdi()
            self.load_delta(items)
            self.save_coverage()  # Once loaded save coverage files
        elif type == ReplayType.llvm_profile:
            self.load_llvmprofile()
        else:
            assert False

    def load_qbdi(self) -> List[Tuple[str, InputCovDelta]]:
        logging.info("load qbdi trace files")
        folder = self.workspace.root / self.QBDI_REPLAY_DIR
        total = sum(1 for _ in self._iter_sorted(folder))

        items = []

        # initialize a "all" fuzzer in all cases
        self._init_fuzzer_coverage(self.ALL_FUZZER)

        for i, file in enumerate(self._iter_sorted(folder)):
            # parse name
            print(f"[{i+1}/{total}] {file}\r", file=sys.stderr, end="")
            meta = self.parse_filename(file.name)

            # Get the fuzzer name (and coverage)
            if meta is None:
                fuzzer = self.SEED_FUZZER
            else:
                fuzzer = meta[2]

            self._init_fuzzer_coverage(fuzzer)

            cov = QBDITrace.from_file(file).coverage

            # Compute differences to know what has been covered
            if self.is_half_duplex:
                fuzzer_coverage = self.fuzzers_coverage[fuzzer]   # get the fuzzer coverage at this point
                local_new_items = cov - fuzzer_coverage
                local_new_instrs = cov.covered_instructions.keys() - fuzzer_coverage.covered_instructions.keys()
                fuzzer_coverage.merge(cov)   # Merge the new coverage
                cov_sum = fuzzer_coverage.unique_covitem_covered
                inst_sum = fuzzer_coverage.unique_instruction_covered
            else:  # FULL DUPLEX
                local_new_items, local_new_instrs, cov_sum, inst_sum = set(), set(), 0, 0


            # Update coverage and info OVERALL
            all_coverage = self.fuzzers_coverage[self.ALL_FUZZER]  # get the overall coverage
            overall_new_items = cov - all_coverage                 # compute new items
            overall_new_instrs = cov.covered_instructions.keys() - all_coverage.covered_instructions.keys()
            all_coverage.merge(cov)                                # Merge all of them (all fuzzers all together)


            # Create an InputCovDelta
            statitem = InputCovDelta(
                time_elapsed=0 if meta is None else meta[1],
                input_name=file.name,
                fuzzer=fuzzer,
                # Trace generic info
                unique_items_covered_count=cov.unique_covitem_covered,         # The coverage of this one input (len(covered_items))
                unique_insts_covered_count=cov.unique_instruction_covered, # Instruction coverage of that input
                # Local to the fuzzer
                fuzzer_new_items_covered=local_new_items, # New items covered by THIS fuzzer
                fuzzer_coverage_sum=cov_sum,              # Sum of covered items by THIS fuzzer at this point
                fuzzer_inst_coverage_sum=inst_sum,        # Sum of unique instructions covered by THIS FUZZER at this point
                fuzzer_new_insts_covered=local_new_instrs,# Instr
                # Global accros all fuzzers of the campaign
                overall_new_items_covered=overall_new_items,              # New items covered by this fuzzer agains ALL THE OTHERS
                overall_coverage_sum=all_coverage.unique_covitem_covered, # The total coverage of the fuzz campaign at this point
                overall_inst_coverage_sum=all_coverage.unique_instruction_covered, # Total instruction coverage at this point
                overall_new_insts_covered=overall_new_instrs
            )

            items.append((fuzzer, statitem))

            # Write the delta file
            with open(self.replay_delta_dir / (file.name+".json"), 'w') as f:
                f.write(statitem.json())
        return items

    def load_llvmprofile(self) -> None:
        # TODO: to implement
        pass

    def load_delta_directory(self) -> List[Tuple[str, InputCovDelta]]:
        logging.info("load delta directory")

        items = []

        for file in self._iter_sorted(self.replay_delta_dir):
            meta = self.parse_filename(file.name)

            # Get the fuzzer name (and coverage)
            if meta is None:
                fuzzer = self.SEED_FUZZER
            else:
                fuzzer = meta[2]

            delta = InputCovDelta.parse_file(file)
            items.append((fuzzer, delta))
        return items

    def load_delta(self, items: List[Tuple[str, InputCovDelta]]) -> None:
        self._all_items = [x[1] for x in items]
        self.fuzzers_items[self.SEED_FUZZER] = []
        self.fuzzers_items[self.ALL_FUZZER] = []

        for fuzzer, item in items:
            if fuzzer not in self.fuzzers_items:
                self.fuzzers_items[fuzzer] = []

            self.fuzzers_items[fuzzer].append(item)

            if fuzzer != self.SEED_FUZZER:  # Add in ALL, all that are not seed ones
                self.fuzzers_items[self.ALL_FUZZER].append(item)

    def save_coverage(self):
        cov_dir = self.workspace.root / self.COVERAGE_DIR
        if not cov_dir.exists():
            cov_dir.mkdir()

        for fuzzer_name, cov in self.fuzzers_coverage.items():
            covfile = cov_dir / (fuzzer_name + ".ttgcov")
            cov.to_file(covfile)

            if cov.covered_instructions:  # if we have instructions covered save file in Lightouse format
                covfile = cov_dir / (fuzzer_name + ".cov")
                with open(covfile, "w") as f:
                    f.write("\n".join(f"{x:#08x}" for x in cov.covered_instructions.keys()))
                    f.write("\n")

    def load_coverage(self):
        cov_dir = self.workspace.root / self.COVERAGE_DIR

        for fuzzer_name in self.fuzzers_items.keys():
            covfile = cov_dir / (fuzzer_name + ".ttgcov")
            if not covfile.exists():
                logging.error(f"can't find coverage of {fuzzer_name}")
            else:
                self.fuzzers_coverage[fuzzer_name] = GlobalCoverage.from_file(covfile)

    def print_stats(self):
        overall_coverage = self.fuzzers_coverage[self.ALL_FUZZER]
        for fuzzer, results in self.fuzzers_items.items():

            tot_inps = sum(len(x) for x in self.fuzzers_items.values())
            tot_edge = overall_coverage.unique_covitem_covered

            print("-----------------------")
            print(f"Fuzzer: {fuzzer}")
            cov = self.fuzzers_coverage[fuzzer]
            print(f"inputs: {len(results)}, {len(results)/tot_inps:.0%}")
            print(f"edges: {cov.unique_covitem_covered} {cov.unique_covitem_covered/tot_edge:.0%)}")
            print(f"instructions: {cov.unique_instruction_covered}")
            print("-----------------------")
            print(f"Total inputs: {tot_inps}")
            print(f"Total edges: {tot_edge}")
