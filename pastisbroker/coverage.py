import logging
from dataclasses import dataclass
from pathlib import Path

# tritondse imports
from tritondse import GlobalCoverage, CoverageSingleRun, CoverageStrategy, BranchSolvingStrategy
from tritondse.trace import QBDITrace, TraceException




@dataclass
class CoverageUpdateDiff(object):
    updated: bool
    new_items: list[int, int]



class Coverage(object):
    """
    Abstract class represent current program coverage.
    """

    def add_coverage_file(self, path: Path) -> CoverageUpdateDiff:
        """
        Add the file to the current coverage
        """
        raise NotImplementedError("should be suclassed")

    @staticmethod
    def run(program: str,
            argvs: list[str],
            cwd: str,
            timeout: float,
            input_file: str,
            cov_file: str,
            is_stdin: bool) -> bool:
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
    def run(program: str,
            argvs: list[str],
            cwd: str,
            timeout: float,
            input_file: str,
            cov_file: str,
            is_stdin: bool) -> bool:
        """
        Run program using QBDI as a tracer.
        """
        # note: if it input on argv the input_file should be already positioned
        #       at the right index on argv.
        try:
            return QBDITrace.run(QbdiCoverage.STRATEGY,
                                 program,
                                 argvs,
                                 output_path=cov_file,
                                 stdin_file=input_file if is_stdin else None,
                                 cwd=cwd,
                                 timeout=timeout)
        except TraceException:
            logging.info("trace exception !")
            return False  # TIMEOUT


class LlvmProfileCoverage(Coverage):
    pass
