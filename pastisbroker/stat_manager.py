# Built-in imports
import time

# Third-party importq
from libpastis.types import SeedType

# Local imports
from pastisbroker.client import PastisClient


class StatManager(object):
    """
    Keeps temporal statistics to plot them.
    """
    def __init__(self):
        self.cli_coverage = {}  # Client -> List[]
        self.cli_inputs = {}    # Client -> Tuple[new_seed, total_seed]
        self.cli_crashs = {}
        self.cli_hangs = {}

    def update_seed_stat(self, client: PastisClient, typ: SeedType, new: bool) -> None:
        t = time.localtime()
        info = {SeedType.INPUT: self.cli_inputs, SeedType.CRASH: self.cli_crashs, SeedType.HANG: self.cli_hangs}[typ]
        if client not in info:
            info[client.netid] = ([], [])
        data = info[client.netid]
        # Update total submitted seeds and update stats
        client.seed_submitted_count += 1
        data[1].append((t, client.seed_submitted_count))

        if new:
            client.seed_first += 1
            data[0].append((t, client.seed_first))

    def set_exec_per_sec(self, client: PastisClient, exec_per_sec: int = None):
        if exec_per_sec:
            client.exec_per_sec = exec_per_sec  # instantaneous value does not keep history

    def set_total_exec(self, client: PastisClient, total_exec: int = None):
        if total_exec:
            client.total_exec = total_exec  # instantaneous value does not keep history

    def set_cycle(self, client: PastisClient, cycle: int = None):
        if cycle:
            client.cycle = cycle  # instantaneous value does not keep history

    def set_timeout(self, client: PastisClient, timeout: int = None):
        if timeout:
            client.timeout = timeout  # instantaneous value does not keep history

    def _set_coverage(self, client: PastisClient, coverage: int = None):
        t = time.localtime()
        client.coverage_block = coverage
        if client.netid not in self.cli_coverage:
            self.cli_coverage[client.netid] = []
        self.cli_coverage[client.netid].append((t, coverage))

    def set_coverage_block(self, client: PastisClient, coverage: int = None):
        self._set_coverage(client, coverage)

    def set_coverage_edge(self, client: PastisClient, coverage: int = None):
        self._set_coverage(client, coverage)

    def set_coverage_path(self, client: PastisClient, coverage: int = None):
        self._set_coverage(client, coverage)

    @staticmethod
    def set_last_coverage_update(client: PastisClient, last_up: int = None):
        if last_up:
            client.last_cov_update = last_up  # instantaneous value does not keep history

