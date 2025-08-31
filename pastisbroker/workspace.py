import json
from pathlib import Path
from typing import Iterator, Generator
import shutil
import stat
from enum import Enum, auto
import os
import logging

from libpastis.types import SeedType, PathLike
from libpastis import SASTReport


class WorkspaceStatus(Enum):
    NOT_STARTED = auto()
    RUNNING = auto()
    FINISHED = auto()


class Workspace(object):
    INPUT_DIR = "corpus"
    HANGS_DIR = "hangs"
    CRASH_DIR = "crashes"
    FILTERED_CORPUS_DIR = "filtered_corpus"
    LOG_DIR = "logs"
    BINS_DIR = "binaries"
    ALERTS_DIR = "alerts_data"
    SEED_DIR = "seeds"
    COVDIFF_DIR = "covdiffs"

    SAST_REPORT_COPY = "sast-report.bin"
    CSV_FILE = "results.csv"
    TELEMETRY_FILE = "telemetry.csv"
    CLIENTS_STATS = "clients-stats.json"
    LOG_FILE = "broker.log"
    STATUS_FILE = "STATUS"
    RUNTIME_CONFIG_FILE = "config.json"
    COVERAGE_HISTORY = "coverage-history.csv"
    COVERAGE_FILE = "coverage.cov"

    RAMDISK_DIR = "/mnt/ramdisk"


    def __init__(self, directory: Path, erase: bool = False):
        self.root = directory

        if erase:  # If want to erase the whole workspace
            shutil.rmtree(self.root)

        # Create the base directory structure
        if not self.root.exists():
            self.root.mkdir(parents=True, exist_ok=True)
        for s in [self.INPUT_DIR, self.CRASH_DIR, self.LOG_DIR,
                  self.HANGS_DIR, self.BINS_DIR, self.SEED_DIR,
                  self.FILTERED_CORPUS_DIR, self.COVDIFF_DIR]:
            p = self.root / s
            if not p.exists():
                p.mkdir()

        # If no status file is found create one
        status_file = Path(self.root / self.STATUS_FILE)
        self._status = WorkspaceStatus.NOT_STARTED
        if not status_file.exists():
            status_file.write_text(self._status.name)
        else:
            self._status = WorkspaceStatus[status_file.read_text()]
        
        # Detect if a mounted ramdisk is available
        p = Path(self.RAMDISK_DIR)
        if p.exists() and p.is_dir() and os.access(p, os.W_OK):
            logging.info(f"Ramdisk directory detected. Use it {p} for temporary files")
            self.tmp_dir = p
        else:
            self.tmp_dir = Path("/tmp")

    def initialize_runtime(self, binaries_dir: PathLike, params: dict):
        # First copy binary files in workspace if different directories
        if self.root / self.BINS_DIR != binaries_dir:
            shutil.copytree(binaries_dir, self.root / self.BINS_DIR, dirs_exist_ok=True)
        # Save runtime configuration
        config = self.root / self.RUNTIME_CONFIG_FILE
        config.write_text(json.dumps(params))

    def iter_corpus_directory(self, typ: SeedType) -> Generator[Path, None, None]:
        dir_map = {SeedType.INPUT: self.INPUT_DIR, SeedType.CRASH: self.CRASH_DIR, SeedType.HANG: self.HANGS_DIR}
        dir = self.root / dir_map[typ]
        for file in dir.iterdir():
            yield file

    def iter_initial_corpus_directory(self) -> Generator[Path, None, None]:
        for file in (self.root / self.SEED_DIR).iterdir():
            yield file

    def count_corpus_directory(self, typ: SeedType) -> int:
        return sum(1 for _ in self.iter_corpus_directory(typ))

    @property
    def status(self) -> WorkspaceStatus:
        return self._status

    @status.setter
    def status(self, value: WorkspaceStatus) -> None:
        self._status = value
        Path(self.root / self.STATUS_FILE).write_text(value.name)

    @property
    def telemetry_file(self) -> Path:
        return self.root / self.TELEMETRY_FILE

    @property
    def clients_stat_file(self) -> Path:
        return self.root / self.CLIENTS_STATS

    @property
    def sast_report_file(self) -> Path:
        return self.root / self.SAST_REPORT_COPY

    @property
    def csv_result_file(self) -> Path:
        return self.root / self.CSV_FILE

    @property
    def log_directory(self) -> Path:
        return self.root / self.LOG_DIR

    @property
    def broker_log_file(self) -> Path:
        return self.root / self.LOG_FILE

    @property
    def config_file(self) -> Path:
        return self.root / self.RUNTIME_CONFIG_FILE

    @property
    def coverage_history(self) -> Path:
        return self.root / self.COVERAGE_HISTORY

    @property
    def coverage_file(self) -> Path:
        return self.root / self.COVERAGE_FILE

    def add_binary(self, binary_path: Path) -> Path:
        """
        Add a binary in the workspace directory structure.

        :param binary_path: Path of the executable to copy
        :return: the final executable file path
        """
        dst_file = self.root / self.BINS_DIR / binary_path.name
        if dst_file.absolute() != binary_path.absolute():  # If not already in the workspace copy them in workspace
            dst_file.write_bytes(binary_path.read_bytes())
            dst_file.chmod(stat.S_IRWXU)  # Change target mode to execute.
        return dst_file

    def add_binary_data(self, name: str, content: bytes) -> Path:
        """
        Add a binary in the workspace directory structure.

        :param name: Name of the executable file
        :param content: Content of the executable
        :return: the final executable file path
        """
        dst_file = self.root / self.BINS_DIR / name
        dst_file.write_bytes(content)
        dst_file.chmod(stat.S_IRWXU)  # Change target mode to execute.
        return dst_file

    def add_sast_report(self, report: SASTReport) -> Path:
        f = self.root / self.SAST_REPORT_COPY
        report.write(f)
        return f

    @property
    def binaries(self) -> Generator[Path, None, None]:
        for file in (self.root / self.BINS_DIR).iterdir():
            yield file

    def initialize_alert_corpus(self, report: SASTReport) -> None:
        """ Create a directory for each alert where to store coverage / vuln corpus """
        p = self.root / self.ALERTS_DIR
        p.mkdir(exist_ok=True)
        for alert in report.iter_alerts():
            a_dir = p / str(alert.id)
            a_dir.mkdir(exist_ok=True)

    def save_alert_seed(self, id: int, name: str, data: bytes) -> None:
        p = ((self.root / self.ALERTS_DIR) / str(id)) / name
        p.write_bytes(data)

    def save_seed_file(self, typ: SeedType, file: Path, initial: bool = False) -> None:
        dir_map = {SeedType.INPUT: self.INPUT_DIR, SeedType.CRASH: self.CRASH_DIR, SeedType.HANG: self.HANGS_DIR}
        if initial:
            out = self.root / self.SEED_DIR / file.name
        else:
            out = self.root / dir_map[typ] / file.name
        if str(file) != str(out):
            shutil.copy(str(file), str(out))

    def save_seed(self, typ: SeedType, name: str, data: bytes) -> None:
        dir_map = {SeedType.INPUT: self.INPUT_DIR, SeedType.CRASH: self.CRASH_DIR, SeedType.HANG: self.HANGS_DIR}
        out = self.root / dir_map[typ] / name
        out.write_bytes(data)

    def save_filtered_seed(self, name: str, data: bytes) -> None:
        """
        Save a seed at the given location.

        :param name: Name of the seed file
        :param data: Data of the seed
        :return: Path to the saved seed file
        """
        out_file = self.root / self.FILTERED_CORPUS_DIR / name
        out_file.write_bytes(data)

    def save_coverage_diff(self, name: str, data: bytes|str) -> None:
        """
        Save a coverage diff file.

        :param name: Name of the coverage diff file
        :param data: Data of the coverage diff
        :return: Path to the saved coverage diff file
        """
        out_file = self.root / self.COVDIFF_DIR / name
        if isinstance(data, str):
            out_file.write_text(data)
        else:
            out_file.write_bytes(data)
