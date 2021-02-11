# Built-in imports
from typing import Tuple, List, Dict
from pathlib import Path
import logging
import time
import inspect

# Third-party imports
from libpastis.types import FuzzingEngine, Arch, LogLevel, ExecMode, CheckMode, CoverageMode, SeedType


class PastisClient(object):
    """
    Utility class holding all information related to
    a client connected to the broker.
    """

    def __init__(self, id: int, netid: bytes, log_dir: Path, engines: List[Tuple[FuzzingEngine, str]], arch: Arch, cpus: int, memory: int, hostname: str):
        self.id = id
        self.netid = netid
        self.engines = engines
        self.arch = arch
        self.cpus = cpus
        self.memory = memory
        self.hostname = hostname

        self.logger = logging.getLogger(f"client-{id}")
        self._configure_logging(log_dir)

        # Runtime properties
        self._running = False
        self._engine = None
        self._coverage_mode = None
        self._exec_mode = None
        self._check_mode = None
        self._seeds_received = set()  # Seed sent to the client
        self._seeds_submitted = set()  # Seed submitted by the client

        # Runtime telemetry stats
        self.exec_per_sec = None
        self.total_exec = None
        self.cycle = None
        self.timeout = None
        self.coverage_block = None
        self.coverage_edge = None
        self.coverage_path = None
        self.last_cov_update = None

        # seed stats
        self.input_submitted_count = 0
        self.crash_submitted_count = 0
        self.timeout_submitted_count = 0
        self.seed_first = 0

        # klocwork parameters
        self.alert_covered = set()
        self.alert_covered_first = 0
        self.alert_validated = set()
        self.alert_validated_first = 0

        # time series
        self._timeline_seeds = []  # List[Tuple[float, int, typ]]  # history of submission
        # self._timeline_coverage = []

    def _configure_logging(self, log_dir):
        hldr = logging.FileHandler(log_dir/f"client-{self.id}")
        hldr.setLevel(logging.DEBUG)
        hldr.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s]: %(message)s"))
        self.logger.addHandler(hldr)

    def reconfigure_logger(self, colorid: int):
        self.logger.name = f"\033[7m\033[{colorid}m[{self.strid}]\033[0m"

    @property
    def strid(self):
        return f"CLI-{self.id}{self._engine_short()}"

    def _engine_short(self):
        if self._engine:
            return {FuzzingEngine.HONGGFUZZ: "-HF", FuzzingEngine.TRITON: "-TT"}[self._engine]
        else:
            return ""

    def is_new_seed(self, seed: bytes) -> bool:
        """
        Return true if the seed has never been sent to a client

        :param seed: seed bytes
        :return: True if never sent to client
        """
        return seed not in self._seeds_received and seed not in self._seeds_submitted

    def add_peer_seed(self, seed: bytes) -> None:
        self._seeds_received.add(seed)

    def add_own_seed(self, seed: bytes) -> None:
        self._seeds_submitted.add(seed)

    def is_running(self) -> bool:
        return self._running

    def is_idle(self) -> bool:
        return not self._running

    def log(self, level: LogLevel, message: str):
        # Get the function in the logger (warning, debug, info) and call it with message
        getattr(self.logger, level.name.lower())(message)

    @property
    def engine(self):
        return self._engine

    @property
    def coverage_mode(self):
        return self._coverage_mode

    @property
    def exec_mode(self):
        return self._exec_mode

    @property
    def check_mode(self):
        return self._check_mode

    def set_stopped(self):
        """ Flush runtime data (keep stats) """
        self._running = False
        self._engine = None
        self._coverage_mode = None
        self._exec_mode = None
        self._check_mode = None

    def set_running(self, engine: FuzzingEngine, covmode: CoverageMode, exmode: ExecMode, ckmode: CheckMode):
        self._running = True
        self._engine = engine
        self._coverage_mode = covmode
        self._exec_mode = exmode
        self._check_mode = ckmode

    def is_supported_engine(self, engine: FuzzingEngine) -> bool:
        for e, v in self.engines:
            if e == engine:
                return True
        return False

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "strid": self.strid,
            "engines": [x[0].name for x in self.engines],
            "arch": self.arch.name,
            "cpus": self.cpus,
            "memory": self.memory,
            "hostname": self.hostname,
            "engine": self._engine.name,
            "coverage_mode": self._coverage_mode.name,
            "exec_mode": self._exec_mode.name,
            "check_mode": self._check_mode.name,
            "seed_received_count": len(self._seeds_received),
            "exec_per_sec": self.exec_per_sec,
            "total_exec": self.total_exec,
            "cycle": self.cycle,
            "timeout": self.timeout,
            "coverage_block": self.coverage_block,
            "coverage_edge": self.coverage_edge,
            "coverage_path": self.coverage_path,
            "last_cov_update": self.last_cov_update,
            "input_submitted_count": self.input_submitted_count,
            "crash_submitted_count": self.crash_submitted_count,
            "timeout_submitted_count": self.timeout_submitted_count,
            "seed_first": self.seed_first,
            "alert_covered": list(self.alert_covered),
            "alert_covered_first": self.alert_covered_first,
            "alert_validated": self.alert_validated,
            "alert_validated_first": self.alert_validated_first,
        }

    def add_covered_alert(self, a_id: int, cov: bool, cov_first: bool, val: bool, val_first: bool):
        if cov:
            self.alert_covered.add(a_id)
        if cov_first:
            self.alert_covered_first += 1
        if val:
            self.alert_validated.add(a_id)
        if val_first:
            self.alert_validated_first += 1
