# built-in imports
import logging
from typing import Tuple, Generator
from pathlib import Path
from time import gmtime, strftime
from hashlib import md5

# Third-party imports
from libpastis import BrokerAgent
from libpastis.types import SeedType, FuzzingEngine, LogLevel, Arch
from klocwork import KlocworkReport

# Local imports
from .client import PastisClient


class PastisBroker(BrokerAgent):

    INPUT_DIR = "corpus"
    HANGS_DIR = "hangs"
    CRASH_DIR = "crashes"
    LOG_DIR = "logs"

    KL_MAGIC = "KL-METADATA"

    def __init__(self, workspace, kl_report, binaries_dir):
        super(PastisBroker, self).__init__()
        self.workspace = Path(workspace)
        self._init_workspace()

        # Initialize availables binaries
        self.programs = {}  # Tuple[(Arch, Fuzzer, ExecMode)] -> Path
        self._find_binary_workspace()

        # Klocwork informations
        self.kl_report = KlocworkReport(kl_report)
        if not self.kl_report.has_binding():
            logging.warning(f"the klocwork report {kl_report} does not contain bindings")

        # Client infos
        self.clients = {}   # bytes -> Client
        self._cur_id = 0

        # Runtime infos
        self._running = False
        self._seed_pool = {}  # Seed bytes -> (SeedType, origin)

    @property
    def running(self) -> bool:
        return self._running

    def iter_other_clients(self, client: PastisClient) -> Generator[PastisClient, None, None]:
        """
        Generator of all clients but the one given in parameter

        :param client: PastisClient client to ignore
        :return: Generator of PastisClient object
        """
        for c in self.clients.values():
            if c.netid != client.netid:
                yield c

    def new_uid(self) -> int:
        """
        Generate a new unique id for a client (int)

        :return: int, unique (in an execution)
        """
        v = self._cur_id
        self._cur_id += 1
        return v

    def _register_all(self):
        self.register_seed_callback(self.seed_received)
        self.register_hello_callback(self.hello_received)
        self.register_log_callback(self.log_received)
        self.register_telemetry_callback(self.telemetry_received)
        self.register_stop_coverage_callback(self.stop_coverage_received)

    def seed_received(self, cli_id: bytes, typ: SeedType, seed: bytes, origin: FuzzingEngine):
        cli = self.clients[cli_id]

        # Show log message and save seed to file
        if seed not in self._seed_pool:
            logging.info(f"[{cli.strid}] [SEED] [{origin.name}] {seed.hex()} ({typ.name})")
            self.write_seed(typ, cli, seed) # Write seed to file
            self._seed_pool[seed] = (typ, origin)  # Save it in the local pool

        # Iterate on all clients and send it to whomever never received it
        for c in self.iter_other_clients(cli):
            if c.is_new_seed(seed):
                self.send_seed(c.netid, typ, seed, origin)  # send the seed to the client
                c.add_seed(seed)  # Add it in its list of seed

    def write_seed(self, typ: SeedType, from_cli: PastisClient, seed: bytes):
        time = strftime("%Y-%m-%d_%H:%M:%S", gmtime())
        fname = f"{time}_{from_cli.strid}_{md5(seed).hexdigest()}.cov"
        p = self.workspace / self._seed_typ_to_dir(typ) / fname
        p.write_bytes(seed)

    def hello_received(self, cli_id: bytes, engines: Tuple[FuzzingEngine, str], arch: Arch, cpus: int, memory: int):
        uid = self.new_uid()
        client = PastisClient(uid, cli_id, self.workspace/self.LOG_DIR, engines, arch, cpus, memory)
        logging.info(f"[{client.strid}] [HELLO] Arch:{arch.name} engines:{[x[0].name for x in engines]} (cpu:{cpus}, mem:{memory})")
        self.clients[client.netid] = client

        # A client is coming in the middle of a session
        if self.running:
            # TODO: Send him the start message immediately (balancing engines etc..)
            # TODO: Send him all seeds that have already transited here
            pass

    def log_received(self, cli_id: bytes, level: LogLevel, message: str):
        logging.info(f"[{cli_id.hex()}] [LOG] [{level.name}] {message}")
        # TODO: To implement
        # TODO: Implementer le *magic* pour recevoir les infos de defaut, vulns

    def telemetry_received(self, cli_id: bytes, *args):
        # state: State = None, exec_per_sec: int = None, total_exec: int = None,
        # cycle: int = None, timeout: int = None, coverage_block: int = None, coverage_edge: int = None,
        # coverage_path: int = None, last_cov_update: int = None):
        logging.info(f"[{cli_id.hex()}] [TELEMETRY] [{args}")

    def stop_coverage_received(self, cli_id: bytes):
        logging.info(f"[{cli_id.hex()}] [STOP_COVERAGE]")
        # TODO: To implement

    def start_client(self, client: PastisClient):
        # TODO: Find the appropriate binary for the client
        # Send him the start message
        pass

    def run(self):
        # TOOD: Set the start timer
        # TODO: Send the start message to all clients already connected
        pass

    def _find_binary_workspace(self):
        # TODO: iterate all files parse them with lief and
        # TODO: fill programs
        pass

    def _init_workspace(self):
        """ Create the directory for inputs, crashes and logs"""
        for s in [self.INPUT_DIR, self.CRASH_DIR, self.LOG_DIR, self.HANGS_DIR]:
            p = self.workspace / s
            if not p.exists():
                p.mkdir()

    def _seed_typ_to_dir(self, typ: SeedType):
        return {SeedType.INPUT: self.INPUT_DIR,
                SeedType.CRASH: self.CRASH_DIR,
                SeedType.HANG: self.HANGS_DIR}[typ]
