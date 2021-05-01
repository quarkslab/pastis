from pathlib import Path
from typing import Iterator, Generator
import shutil
import stat

from libpastis.types import SeedType, PathLike
from klocwork import KlocworkReport


class Workspace(object):
    INPUT_DIR = "corpus"
    HANGS_DIR = "hangs"
    CRASH_DIR = "crashes"
    LOG_DIR = "logs"
    BINS_DIR = "binaries"
    ALERTS_DIR = "alerts_data"

    KL_REPORT_COPY = "klreport.json"
    CSV_FILE = "results.csv"
    TELEMETRY_FILE = "telemetry.csv"
    CLIENTS_STATS = "clients-stats.json"
    LOG_FILE = "broker.log"

    def __init__(self, directory: Path, erase: bool = False):
        self.root = directory

        if erase:  # If want to erase the whole workspace
            shutil.rmtree(self.root)

        # Create the base directory structure
        if not self.root.exists():
            self.root.mkdir()
        for s in [self.INPUT_DIR, self.CRASH_DIR, self.LOG_DIR, self.HANGS_DIR, self.BINS_DIR]:
            p = self.root / s
            if not p.exists():
                p.mkdir()

    def iter_corpus_directory(self, typ: SeedType) -> Generator[Path, None, None]:
        dir_map = {SeedType.INPUT: self.INPUT_DIR, SeedType.CRASH: self.CRASH_DIR, SeedType.HANG: self.HANGS_DIR}
        dir = self.root / dir_map[typ]
        for file in dir.iterdir():
            yield file

    @property
    def telemetry_file(self) -> Path:
        return self.root / self.TELEMETRY_FILE

    @property
    def clients_stat_file(self) -> Path:
        return self.root / self.CLIENTS_STATS

    @property
    def klocwork_report_file(self) -> Path:
        return self.root / self.KL_REPORT_COPY

    @property
    def csv_result_file(self) -> Path:
        return self.root / self.CSV_FILE

    @property
    def log_directory(self) -> Path:
        return self.root / self.LOG_DIR

    @property
    def broker_log_file(self) -> Path:
        return self.root / self.LOG_FILE

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

    @property
    def binaries(self) -> Generator[Path, None, None]:
        for file in (self.root / self.BINS_DIR).iterdir():
            yield file

    def initialize_alert_corpus(self, report: KlocworkReport) -> None:
        """ Create a directory for each alert where to store coverage / vuln corpus """
        p = self.root / self.ALERTS_DIR
        p.mkdir(exist_ok=True)
        for alert in report.counted_alerts:
            a_dir = p / str(alert.id)
            a_dir.mkdir(exist_ok=True)

    def save_alert_seed(self, id: int, name: str, data: bytes) -> None:
        p = ((self.root / self.ALERTS_DIR) / str(id)) / name
        p.write_bytes(data)

    def save_seed_file(self, typ: SeedType, file: Path) -> None:
        dir_map = {SeedType.INPUT: self.INPUT_DIR, SeedType.CRASH: self.CRASH_DIR, SeedType.HANG: self.HANGS_DIR}
        out = self.root / dir_map[typ] / file.name
        shutil.copy(str(file), str(out))

    def save_seed(self, typ: SeedType, name: str, data: bytes) -> None:
        dir_map = {SeedType.INPUT: self.INPUT_DIR, SeedType.CRASH: self.CRASH_DIR, SeedType.HANG: self.HANGS_DIR}
        out = self.root / dir_map[typ] / name
        out.write_bytes(data)
