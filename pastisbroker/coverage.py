from abc import ABC
import logging
from dataclasses import dataclass
from pathlib import Path

# tritondse imports
from tritondse import GlobalCoverage, CoverageSingleRun, CoverageStrategy, BranchSolvingStrategy
from tritondse.trace import QBDITrace, TraceException




@dataclass
class CoverageUpdateDiff(object):
    updated: bool
    new_items: list[tuple[int, int]]
    


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
            env: dict[str, str]|None = None) -> bool:
        raise NotImplementedError("should be subclassed")


class QbdiCoverage(Coverage):
    STRATEGY = CoverageStrategy.EDGE

    def __init__(self):
        # Keep coverage as a tritondse GlobalCoverage
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

        return CoverageUpdateDiff(bool_improved, new_items)

    @staticmethod
    def run(program: Path,
            argvs: list[str],
            timeout: float,
            input_file: Path,
            coverage_file: Path,
            is_stdin: bool,
            cwd: Path | None = None,
            env: dict[str, str]|None = None) -> bool:
        """
        Run program using QBDI as a tracer.
        """
        # note: if it input on argv the input_file should be already positioned
        #       at the right index on argv.
        try:
            return QBDITrace.run(QbdiCoverage.STRATEGY,
                                 program,
                                 argvs,
                                 output_path=coverage_file,
                                 stdin_file=input_file if is_stdin else None,
                                 cwd=cwd,
                                 timeout=timeout,
                                 env=env)
        except TraceException:
            logging.info("trace exception !")
            return False  # TIMEOUT


class LlvmProfileCoverage(Coverage):
    pass
