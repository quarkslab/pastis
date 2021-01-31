# Built-in imports
import time
from pathlib import Path
import csv
import json
from typing import List

# Third-party importq
from libpastis.types import SeedType

# Local imports
from pastisbroker.client import PastisClient


class StatManager(object):
    """
    Keeps temporal statistics to plot them.
    """
    def __init__(self, log_dir: Path):
        self.cli_coverage = {}  # Client -> List[Tuple[float, int]]     # Coverage overtime for each clients
        self.cli_inputs = {}    # Client -> Tuple[List[Tuple[float, int]], List[Tuple[float, int]] # new_seed, all_seeds
        self.cli_crashs = {}
        self.cli_hangs = {}
        self._workspace = log_dir

        # Configure CSV writer that will write stats
        names = ['date', 'id', 'exec_per_sec', 'total_exec', 'cycle', 'timeout', 'block', 'edge', 'path', 'last_cov_update']
        self._tel_file = open(log_dir/"telemetry.csv", "w")
        self.writer = csv.DictWriter(self._tel_file, fieldnames=names)
        self.writer.writeheader()


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
        if exec_per_sec is not None:
            client.exec_per_sec = exec_per_sec  # instantaneous value does not keep history

    def set_total_exec(self, client: PastisClient, total_exec: int = None):
        if total_exec is not None:
            client.total_exec = total_exec  # instantaneous value does not keep history

    def set_cycle(self, client: PastisClient, cycle: int = None):
        if cycle is not None:
            client.cycle = cycle  # instantaneous value does not keep history

    def set_timeout(self, client: PastisClient, timeout: int = None):
        if timeout is not None:
            client.timeout = timeout  # instantaneous value does not keep history

    def _add_coverage_chart(self, client: PastisClient, coverage: int = None):
        t = time.localtime()
        if client.netid not in self.cli_coverage:
            self.cli_coverage[client.netid] = []
        self.cli_coverage[client.netid].append((t, coverage))

    def set_coverage_block(self, client: PastisClient, coverage: int = None):
        if coverage is not None:
            client.coverage_block = coverage
            self._add_coverage_chart(client, coverage)

    def set_coverage_edge(self, client: PastisClient, coverage: int = None):
        if coverage is not None:
            client.coverage_edge = coverage
            self._add_coverage_chart(client, coverage)

    def set_coverage_path(self, client: PastisClient, coverage: int = None):
        if coverage is not None:
            client.coverage_path = coverage
            self._add_coverage_chart(client, coverage)

    @staticmethod
    def set_last_coverage_update(client: PastisClient, last_up: int = None):
        if last_up is not None:
            client.last_cov_update = last_up  # instantaneous value does not keep history

    def update_telemetry_client(self, client: PastisClient):
        self.writer.writerow({
            'date': time.time(),
            'id': client.strid,
            'exec_per_sec': client.exec_per_sec,
            'total_exec': client.total_exec,
            'cycle': client.cycle,
            'timeout': client.timeout,
            'block': client.coverage_block,
            'edge': client.coverage_edge,
            'path': client.coverage_path,
            'last_cov_update': client.last_cov_update
        })


    def post_execution(self, clients: List[PastisClient]) -> None:
        """
        Called at the end of the execution. Export
        :return: None
        """
        self._tel_file.flush()  # Flush the csv if it has not been

        for cli in clients:
            print(cli.to_dict())

        with open(self._workspace/"clients-stats.json", "w") as f:
            json.dump([cli.to_dict() for cli in clients], f, indent=2)
