from abc import ABC
import logging
from dataclasses import dataclass
from pathlib import Path
import os
import logging
import subprocess
import glob
import hashlib 
from enum import IntEnum
import json

# tritondse imports
from tritondse import GlobalCoverage, CoverageSingleRun, CoverageStrategy, BranchSolvingStrategy
from tritondse.trace import QBDITrace, TraceException

from libpastis.types import ReplayType
from pastisbroker.llvm_cov import ProfileCoverageFile, CovSummary, CovData, File, Function



class ReplayStatus(IntEnum):
    """
    Status of the replay
    """
    SUCCESS = 0         # The replay worked and coverage file properly produced
    FAIL_NO_COV = 1     # No coverage file produced by the replay
    FAIL_PARSE_COV = 2  # Failed to parse the coverage file
    FAIL_EXCEPTION = 3  # Crash or any other exception during the replay
    FAIL_TIMEOUT = 4    # Replay timed out



@dataclass
class CoverageUpdateDiff(object):
    """
    Represent the Coverage delta after running an input file.
    """
    # General data
    updated: bool     # Whether the coverage has been updated
    type: ReplayType  # Type of replay used to generate this diff
    
    # Summary of the diff (encode differences in coverage)
    summary: CovSummary

    input_file: str = "" # Input file that generated this diff

    # TODO: Detailed coverage data


    def to_json(self) -> str:
        """
        Convert the CoverageUpdateDiff to a JSON string.
        """
        return json.dumps({
            "updated": self.updated,
            "type": self.type.name,
            "summary": self.summary.to_dict(),
            "input_file": self.input_file
        })


class Coverage(ABC):
    """
    Abstract class represent current program coverage. It is meant to be
    subclassed by concrete coverage implementations such as QBDI or LLVM profile.
    It is meant to work as an accumulator of coverage so that it holds
    at all time the current coverage.
    """

    def add_coverage_file(self, cov_file: Path) -> CoverageUpdateDiff:
        """
        Add the file to the current coverage
        """
        raise NotImplementedError("should be subclassed")

    @staticmethod
    def run(program: Path,
            argvs: list[str],
            timeout: float,
            input_file: Path,
            coverage_file: Path,
            is_stdin: bool,
            cwd: Path | None = None,
            env: dict[str, str]|None = None) -> ReplayStatus:
        raise NotImplementedError("should be subclassed")


class QbdiCoverage(Coverage):
    STRATEGY = CoverageStrategy.EDGE

    def __init__(self, coverage_file: Path):
        # Keep coverage as a tritondse GlobalCoverage
        self.coverage_file = coverage_file  # Nothing done with it yet
        self.coverage = GlobalCoverage(self.STRATEGY, BranchSolvingStrategy.ALL_NOT_COVERED)

    def add_coverage_file(self, cov_file: Path) -> CoverageUpdateDiff:
        coverage: CoverageSingleRun = QBDITrace.from_file(cov_file).coverage

        bool_improved = self.coverage.improve_coverage(coverage)

        if bool_improved:
            # Get newly covered items (and put them in the stream queue
            new_items = coverage.difference(self.coverage)
        else:
            new_items = []

        # Update the global coverage
        self.coverage.merge(coverage)

        summary = CovSummary()
        # Set the count of new branches
        summary.branches.covered = len(new_items)

        return CoverageUpdateDiff(bool_improved,
                                  ReplayType.qbdi,
                                  summary)

    @staticmethod
    def run(program: Path,
            argvs: list[str],
            timeout: float,
            input_file: Path,
            coverage_file: Path,
            is_stdin: bool,
            cwd: Path | None = None,
            env: dict[str, str]|None = None) -> ReplayStatus:
        """
        Run program using QBDI as a tracer.
        """
        # note: if it input on argv the input_file should be already positioned
        #       at the right index on argv.
        try:
            res = QBDITrace.run(QbdiCoverage.STRATEGY,
                                 program,
                                 argvs,
                                 output_path=coverage_file,
                                 stdin_file=input_file if is_stdin else None,
                                 cwd=cwd,
                                 timeout=timeout,
                                 env=env)
            if res and coverage_file.exists():
                return ReplayStatus.SUCCESS
            else:
                return ReplayStatus.FAIL_NO_COV
        except TraceException:
            return ReplayStatus.FAIL_TIMEOUT


class LlvmProfileCoverage(Coverage):
    def __init__(self, coverage_binary: Path, coverage_file: Path):
        # Keep coverage as a tritondse GlobalCoverage
        self.coverage_binary = coverage_binary
        self.coverage: CovSummary = CovSummary()
        self.coverage_file = coverage_file

    @property
    def is_first_coverage(self) -> bool:
        return self.coverage.lines.covered == -1

    def add_coverage_file(self, cov_file: Path) -> CoverageUpdateDiff:
        dummy = CovSummary()
        # Merge the profraw with the current coverage (back in itself)
        if not LlvmProfileCoverage.merge_profdata(self.coverage_file, str(self.coverage_file), str(cov_file)):
            logging.error(f"Failed to merge profdata {cov_file} into {self.coverage_file}")
            return CoverageUpdateDiff(False, ReplayType.llvm_profile, dummy)

        # Export the coverage to JSON
        json_file = self.coverage_file.with_suffix(".json")
        if not LlvmProfileCoverage.export_profdata(self.coverage_file,
                                                   json_file,
                                                   self.coverage_binary,
                                                   summary_only=True):
            logging.error("Failed to export coverage to JSON")
            return CoverageUpdateDiff(False, ReplayType.llvm_profile, dummy)

        # Load the updated coverage JSON file
        new_coverage = CovSummary.from_json(json_file)
        
        # Check if the coverage has been updated
        if self.coverage.improve_coverage(new_coverage):
            # Compute the diff of every fields
            diff = new_coverage.diff(self.coverage)
            self.coverage = new_coverage  # Update the current coverage
            return CoverageUpdateDiff(True, ReplayType.llvm_profile, diff)
        else:
            # logging.debug("No coverage update found")
            return CoverageUpdateDiff(False, ReplayType.llvm_profile, dummy)
        

    @staticmethod
    def get_fuzz_env() -> dict[str, str]:
        symbolizer = os.environ.get('LLVM_SYMBOLIZER_PATH', "/usr/bin/llvm-symbolizer")
        fuzz_env = os.environ | {
            'UBSAN_SYMBOLIZER_PATH': symbolizer,
            "ASAN_OPTIONS": "detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1",
            'ASAN_SYMBOLIZER_PATH': symbolizer,
            'MSAN_SYMBOLIZER_PATH': symbolizer,
        }
        return fuzz_env

    @staticmethod
    def run(program: Path,
            argvs: list[str],
            timeout: float,
            input_file: Path,
            coverage_file: Path,
            is_stdin: bool,
            cwd: Path | None = None,
            env: dict[str, str]|None = None) -> ReplayStatus:

        # Configure environment variables
        dst_env: dict[str, str] = LlvmProfileCoverage.get_fuzz_env()
        if env is not None:
            dst_env.update(env)
        dst_env['LLVM_PROFILE_FILE'] = str(coverage_file.absolute())

        # Configure the way the input is introduced
        final_argv = argvs[:]
        if is_stdin:
            stdin_file = open(input_file, 'rb')
        else:
            stdin_file = None
            if not argvs:
                # logging.warning("Argv empty. Add input file as argument.")
                final_argv = [str(input_file.absolute())]
            else:
                try:
                    if any(input_file.name in arg for arg in argvs):
                        pass  # already provided (do nothing)
                    else:
                        idx = argvs.index("@@")
                        final_argv[idx] = str(input_file.absolute())
                except ValueError as e:
                    logging.error(f"No @@ in argvs. Cannot insert input file. {e}")
                    return ReplayStatus.FAIL_EXCEPTION

        command = [str(program)] + final_argv
        try:
            res = subprocess.run(command,
                                stdin=stdin_file,
                                env=dst_env,
                                timeout=timeout,
                                check=True,
                                cwd=cwd,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
            if coverage_file.exists():
                return ReplayStatus.SUCCESS
            else:
                return ReplayStatus.FAIL_NO_COV
        except subprocess.CalledProcessError as e:
            h = hashlib.md5(Path(input_file).read_bytes()).hexdigest()
            logging.warning(f"Replay {h} failed with error: {str(e)}")
            return ReplayStatus.FAIL_EXCEPTION
        except subprocess.TimeoutExpired:
            logging.warning(f"Timeout expired for command: {command}")
            return ReplayStatus.FAIL_TIMEOUT

    @staticmethod
    def merge_profdata(output_profdata: Path, *prof_files) -> bool:
        """
        Merge various .profraw or profdata into a single .profdata profile.

        :param output_profdata: Path where the output will be saved.
        :param profdata_file: Path to the input .profdata file.
        """
        command = ['llvm-profdata', 'merge',
                '-o',
                output_profdata,
        ]
        for prof_file in (Path(f) for f in list(prof_files)):
            if prof_file.is_dir():
                command.extend(glob.glob(f'{prof_file}/*.profraw'))
            elif prof_file.is_file():
                command.append(str(prof_file))
            else:
                pass  # Ignore if the file is a link or block
        res = subprocess.run(command,
                            check=True,
                            shell=False)
        return res.returncode == 0

    @staticmethod
    def export_profdata(profdata_file: Path,
                        output_file: Path,
                        binary: Path,
                        summary_only: bool=False,
                        file_filters: str = "") -> bool:
        """
        Exports the LLVM .profdata file to JSON.
        
        :param profdata_file: Path to the input .profdata file.
        :param output_file: Path where the output will be saved.
        :param binary: Path to the binary file.
        :param summary_only: If True, only the summary will be exported.
        :param file_filters: Optional filters for files to exclude from the export.
        """
        with open(output_file, 'w') as out_file:
            command = [
                'llvm-cov', 'export',
                '-instr-profile', str(profdata_file),
                '-format=text', # JSON
                f"--ignore-filename-regex='{file_filters}'" if file_filters else '',
                '-summary-only' if summary_only else '',
                str(binary)
            ]
            
            try:
                res = subprocess.run(command,
                                    stdout=out_file,
                                    check=True)
                if res.returncode != 0:
                    return False
                return True
            except subprocess.CalledProcessError as e:
                print(f"Error exporting coverage data: {e}")
                return False
