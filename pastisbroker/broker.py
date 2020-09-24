# built-in imports
import logging
from typing import Tuple, Generator, List
from pathlib import Path
import time
from hashlib import md5
from enum import Enum
from collections import Counter

# Third-party imports
from libpastis import BrokerAgent, do_engine_support_coverage_strategy
from libpastis.types import SeedType, FuzzingEngine, LogLevel, Arch, State, SeedInjectLoc, CheckMode, CoverageMode, ExecMode
from klocwork import KlocworkReport
import lief

# Local imports
from .client import PastisClient
from .stat_manager import StatManager


class BrokingMode(Enum):
    FULL = 1              # Transmit all seeds to all peers
    NO_TRANSMIT = 2       # Does not transmit seed to peers (for comparing perfs of tools against each other)
    COVERAGE_ORDERED = 3  # Transmit a seed to a peer if they have the same notion of coverage


class PastisBroker(BrokerAgent):

    INPUT_DIR = "corpus"
    HANGS_DIR = "hangs"
    CRASH_DIR = "crashes"
    LOG_DIR = "logs"

    KL_MAGIC = "KL-METADATA"

    def __init__(self, workspace, kl_report, binaries_dir, broker_mode: BrokingMode, check_mode: CheckMode = CheckMode.CHECK_ALL, p_argv: List[str] = []):
        super(PastisBroker, self).__init__()
        self.workspace = Path(workspace)
        self._init_workspace()

        # Init internal state
        self.mode = broker_mode
        self.ck_mode = check_mode
        self.inject = SeedInjectLoc.STDIN  # At the moment injection location is hardcoded
        self.argv = p_argv
        self.engines_args = {x: "" for x in FuzzingEngine}

        # Initialize availables binaries
        self.programs = {}  # Tuple[(Arch, Fuzzer, ExecMode)] -> Path
        self._find_binary_workspace(binaries_dir)

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
        self._start_time = None
        self._stop = False

        # Create the stat manager
        self.statmanager = StatManager()

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
        is_new = seed not in self._seed_pool
        self.statmanager.update_seed_stat(cli, typ, is_new)

        # Show log message and save seed to file
        if is_new:
            logging.info(f"[{cli.strid}] [SEED] [{origin.name}] {seed.hex()} ({typ.name})")
            self.write_seed(typ, cli, seed) # Write seed to file
            self._seed_pool[seed] = (typ, origin)  # Save it in the local pool

        # Iterate on all clients and send it to whomever never received it
        if self.mode == BrokingMode.FULL:
            for c in self.iter_other_clients(cli):
                if c.is_new_seed(seed):
                    self.send_seed(c.netid, typ, seed, origin)  # send the seed to the client
                    c.add_seed(seed)  # Add it in its list of seed
        # TODO: implementing BrokingMode.COVERAGE_ORDERED

    def write_seed(self, typ: SeedType, from_cli: PastisClient, seed: bytes):
        t = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())
        fname = f"{t}_{from_cli.strid}_{md5(seed).hexdigest()}.cov"
        p = self.workspace / self._seed_typ_to_dir(typ) / fname
        p.write_bytes(seed)

    def hello_received(self, cli_id: bytes, engines: Tuple[FuzzingEngine, str], arch: Arch, cpus: int, memory: int):
        uid = self.new_uid()
        client = PastisClient(uid, cli_id, self.workspace/self.LOG_DIR, engines, arch, cpus, memory)
        logging.info(f"[{client.strid}] [HELLO] Arch:{arch.name} engines:{[x[0].name for x in engines]} (cpu:{cpus}, mem:{memory})")
        self.clients[client.netid] = client

        if self.running: # A client is coming in the middle of a session
            self.start_client(client)
            # Iterate all the seed pool and send it to the client
            if self.mode == BrokingMode.FULL:
                for seed, (typ, orig) in self._seed_pool.items():
                    self.send_seed(client.netid, typ, seed, orig)  # necessarily a new seed
                    client.add_seed(seed)  # Add it in its list of seed
                # TODO: Implementing BrokingMode.COVERAGE_ORDERED

    def log_received(self, cli_id: bytes, level: LogLevel, message: str):
        client = self.clients[cli_id]
        logging.info(f"[{client.strid}] [LOG] [{level.name}] {message}")
        client.log(level, message)
        if message.startswith(self.KL_MAGIC):
            pass # TODO: Retrieving info about the defaut, vulns (covered / validated)

    def telemetry_received(self, cli_id: bytes,
        state: State = None, exec_per_sec: int = None, total_exec: int = None,
        cycle: int = None, timeout: int = None, coverage_block: int = None, coverage_edge: int = None,
        coverage_path: int = None, last_cov_update: int = None):
        client = self.clients[cli_id]
        # NOTE: ignore state (shall we do something of it?)
        args = [('-' if not x else x) for x in [exec_per_sec, total_exec, cycle, timeout, coverage_block, coverage_edge, coverage_path, last_cov_update]]
        client.log(LogLevel.INFO, "exec/s:{} tot_exec:{} cycle:{} To:{} CovB:{} CovE:{} CovP:{} last_up:{}".format(args))

        # Update all stats in the stat manager (for later UI update)
        self.statmanager.set_exec_per_sec(client, exec_per_sec)
        self.statmanager.set_total_exec(client, total_exec)
        self.statmanager.set_cycle(client, cycle)
        self.statmanager.set_timeout(client, timeout)
        self.statmanager.set_coverage_block(client, coverage_block)
        self.statmanager.set_coverage_edge(client, coverage_edge)
        self.statmanager.set_coverage_path(client, coverage_path)
        self.statmanager.set_las_coverage_update(client, last_cov_update)
        # NOTE: Send an update signal for future UI ?

    def stop_coverage_received(self, cli_id: bytes):
        client = self.clients[cli_id]
        logging.info(f"[{client.strid}] [STOP_COVERAGE]")
        for c in self.iter_other_clients(client):
            c.set_stopped()
            self.send_stop(c.netid)

    def start_client(self, client: PastisClient):
        program = None  # The program yet to be selected
        engine = None
        exmode = ExecMode.SINGLE_EXEC
        engines = Counter({e: 0 for e in FuzzingEngine})
        engines.update(c.engine for c in self.clients.values() if c.is_running())  # Count instances of each engine running
        for eng, _ in engines.most_common()[::-1]:
            # If the engine is not supported by the client continue
            if not client.is_supported_engine(eng):
                continue

            # Try finding a suitable binary for the current engine and the client arch
            program = self.programs.get((client.arch, eng, ExecMode.PERSISTENT))
            if program:
                exmode = ExecMode.PERSISTENT  # a program was found in persistent mode
            else:
                program = self.programs.get((client.arch, eng, ExecMode.SINGLE_EXEC))
            if not program:  # If still no program was found continue iterating engines
                continue

            # Valid engine and suitable program found
            engine = eng

            # Now that program have been found select coverage strategy
            if do_engine_support_coverage_strategy(engine):
                covs = Counter({c: 0 for c in CoverageMode})
                # Count how many times each coverage strategies have been launched
                covs.update(x.coverage_mode for x in self.clients.values() if x.is_running() and x.engine == engine)
                # Revert dictionnary to have freq -> [covmodes]
                d = {v: [] for v in covs.values()}
                for cov, count in covs.items():
                    d[count].append(cov)
                # pick in-order BLOCK < EDGE < PATH among the least frequently launched modes
                covmode = sorted(d[min(d)])[0]
            else:
                covmode = None

            # If got here a suitable program has been found just break loop
            break

        if engine is None or program is None:
            logging.critical(f"No suitable engine or program was found for client {client.strid} {client.engines}")
            return

        # Update internal client info and send him the message
        client.set_running(engine, covmode, exmode, self.ck_mode)
        self.send_start(client.netid,
                        program,
                        self.argv,
                        exmode,
                        self.ck_mode,
                        covmode,
                        engine,
                        self.engines_args[engine],
                        self.inject,
                        self.kl_report.to_json())

    def run(self):
        self._start_time = time.localtime()

        # Send the start message to all clients
        for c in self.clients.values():
            if not c.is_running():
                self.start_client(c)

        # Start infinite loop
        while True:
            time.sleep(0.1)
            if self._stop:
                logging.info("broker terminate")
                break

    def _find_binary_workspace(self, binaries_dir) -> None:
        """
        Iterate the whole directory to find suitables binaries in the
        various architecture, and compiled for the various engines.

        :param binaries_dir: directory containing the various binaries
        :return: None
        """
        d = Path(binaries_dir)
        for file in d.iterdir():
            if file.is_file():
                p = lief.parse(str(file))
                if not p:
                    continue
                if not isinstance(p, lief.ELF.Binary):
                    logging.warning(f"binary {file} not supported (only ELF at the moment)")
                    continue

                good = False
                honggfuzz = False
                exmode = ExecMode.SINGLE_EXEC
                for f in p.functions:
                    name = f.name
                    if '__klocwork' in name:
                        good = True
                    if '__sanitizer' in name:
                        honggfuzz = True
                if not good:
                    logging.info(f"ignore binary: {file} (does not contain klocwork intrinsics)")
                    continue
                if 'HF_ITER' in (x.name for x in p.imported_functions):
                    exmode = ExecMode.PERSISTENT
                mapping = {lief.ELF.ARCH.x86_64: Arch.X86_64,
                           lief.ELF.ARCH.i386: Arch.X86,
                           lief.ELF.ARCH.ARM: Arch.ARMV7,
                           lief.ELF.ARCH.AARCH64: Arch.AARCH64}
                arch = mapping.get(p.header.machine_type)
                if arch:
                    engine = FuzzingEngine.HONGGFUZZ if honggfuzz else FuzzingEngine.TRITON
                    tup = (arch, engine, exmode)
                    if tup in self.programs:
                        logging.warning(f"binary with same properties {tup} already detected, drop: {file}")
                    else:
                        self.programs[tup] = file
                        logging.info(f"new binary detected [{arch}, {engine}, {exmode}]: {file}")

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

    def set_engine_args(self, engine: FuzzingEngine, args: str):
        if self.engines_args[engine]:
            logging.warning(f"arguments where already set for engine {engine.name}")
        self.engines_args[engine] = args
