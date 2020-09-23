# Built-in imports
from typing import Tuple
from pathlib import Path
import logging

# Third-party imports
from libpastis.types import FuzzingEngine, Arch


class PastisClient(object):
    """
    Utility class holding all information related to
    a client connected to the broker.
    """

    def __init__(self, id: int, netid: bytes, log_dir: Path, engines: Tuple[FuzzingEngine, str], arch: Arch, cpus: int, memory: int):
        self.id = id
        self.netid = netid
        self.engines = engines
        self.arch = arch
        self.cpus = cpus
        self.memory = memory

        self.logger = logging.getLogger(f"client-{id}")
        self._configure_logging(log_dir)

        # Runtime properties
        self._running = False
        self._engine = None
        self._seeds_received = set()

    def _configure_logging(self, log_dir):
        hldr = logging.FileHandler(log_dir/f"client-{id}")
        hldr.setLevel(logging.DEBUG)
        hldr.setFormatter("%(asctime) - %(levelname)s %(name)s - %(message)s")
        self.logger.addHandler(hldr)

    @property
    def strid(self):
        return f"Cli-{self.id}{self._engine()}"

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
