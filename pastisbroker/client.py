# Built-in imports
from typing import Tuple, List
from pathlib import Path
import logging

# Third-party imports
from libpastis.types import FuzzingEngine, Arch, LogLevel, ExecMode, CheckMode, CoverageMode


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
        self._seeds_received = set()

        # Runtime stats
        self.exec_per_sec = None
        self.total_exec = None
        self.cycle = None
        self.timeout = None
        self.coverage_block = None
        self.coverage_edge = None
        self.coverage_path = None
        self.last_cov_update = None

        # Stats properties
        self.seed_submitted_count = 0
        self.seed_first = 0
        self.defaut_count = 0
        self.defaut_first = 0
        self.vuln_count = 0
        self.vuln_first = 0

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
        return seed not in self._seeds_received

    def add_seed(self, seed: bytes) -> None:
        self._seeds_received.add(seed)

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
