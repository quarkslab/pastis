# built-in imports
import logging
from typing import Tuple, Generator, List, Optional
from pathlib import Path
import time
from hashlib import md5
from enum import Enum
from collections import Counter
import datetime
import random
import json

# Third-party imports
from libpastis import BrokerAgent, FuzzingEngineDescriptor, EngineConfiguration
from libpastis.types import SeedType, FuzzingEngineInfo, LogLevel, Arch, State, SeedInjectLoc, CheckMode, CoverageMode, \
                            ExecMode, AlertData, PathLike, Platform, FuzzMode
from klocwork import KlocworkReport
import lief

# Local imports
from pastisbroker.client import PastisClient
from pastisbroker.stat_manager import StatManager
from pastisbroker.workspace import Workspace
from pastisbroker.utils import read_binary_infos, load_engine_descriptor

lief.logging.disable()


class BrokingMode(Enum):
    FULL = 1              # Transmit all seeds to all peers
    NO_TRANSMIT = 2       # Does not transmit seed to peers (for comparing perfs of tools against each other)
    COVERAGE_ORDERED = 3  # Transmit a seed to a peer if they have the same notion of coverage


COLORS = [32, 33, 34, 35, 36, 37, 39, 91, 93, 94, 95, 96]


class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



class PastisBroker(BrokerAgent):

    def __init__(self, workspace: PathLike, binaries_dir: PathLike, broker_mode: BrokingMode, check_mode: CheckMode = CheckMode.CHECK_ALL, kl_report: PathLike = None, p_argv: List[str] = []):
        super(PastisBroker, self).__init__()
        self.workspace = Workspace(Path(workspace))
        self._configure_logging()

        # Register all agent callbacks
        self._register_all()

        # Init internal state
        self.broker_mode = broker_mode
        self.ck_mode = check_mode
        self.inject = SeedInjectLoc.STDIN  # At the moment injection location is hardcoded
        self.argv = p_argv
        self.engines_args = {}
        self.engines = {}  # name->FuzzingEngineDescriptor

        # Initialize availables binaries
        self.programs = {}  # Tuple[(Arch, Fuzzer, ExecMode)] -> Path
        self._find_binaries(binaries_dir)

        # Klocwork informations
        self.kl_report = None
        if kl_report:
            self.initialize_klocwork_report(kl_report)

        # Client infos
        self.clients = {}   # bytes -> Client
        self._cur_id = 0

        # Runtime infos
        self._running = False
        self._seed_pool = {}  # Seed bytes -> SeedType
        self._init_seed_pool = {}  # Used for NO_TRANSMIT mode
        self._start_time = None
        self._stop = False

        # Load the workspace seeds
        self._load_workspace()

        # Create the stat manager
        self.statmanager = StatManager(self.workspace)

    def load_engine_addon(self, py_module: str) -> bool:
        desc = load_engine_descriptor(py_module)
        if desc is not None:
            self.engines[desc.NAME] = desc
            self.engines_args[desc.NAME] = []
            return True
        else:
            return False

    def initialize_klocwork_report(self, report: PathLike):
        self.kl_report = KlocworkReport(report)
        if not self.kl_report.has_binding():
            logging.warning(f"the klocwork report {report} does not contain bindings (auto-bind it)")
            self.kl_report.auto_bind()
        self.workspace.add_klocwork_report(self.kl_report)
        self.workspace.initialize_alert_corpus(self.kl_report)

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
        self.register_data_callback(self.data_received)

    def get_client(self, cli_id: bytes) -> Optional[PastisClient]:
        cli = self.clients.get(cli_id)
        if not cli:
            logging.warning(f"client '{cli_id}' unknown (send stop)")
            self.send_stop(cli_id)
        return cli

    def seed_received(self, cli_id: bytes, typ: SeedType, seed: bytes):
        cli = self.get_client(cli_id)
        if not cli:
            return
        is_new = seed not in self._seed_pool
        h = md5(seed).hexdigest()

        # Show log message and save seed to file
        if is_new:
            self.statmanager.update_seed_stat(cli, typ)  # Add info only if new
            cli.log(LogLevel.INFO, f"new seed {h} [{self._colored_seed_type(typ)}]")
            cli.add_own_seed(seed)  # Add seed in client's seed
            self.write_seed(typ, cli, seed) # Write seed to file
            self._seed_pool[seed] = typ  # Save it in the local pool
        else:
            logging.warning(f"receive duplicate seed {h} by {cli.strid}")

        # Iterate on all clients and send it to whomever never received it
        if self.broker_mode == BrokingMode.FULL:
            for c in self.iter_other_clients(cli):
                if c.is_new_seed(seed):
                    self.send_seed(c.netid, typ, seed)  # send the seed to the client
                    c.add_peer_seed(seed)  # Add it in its list of seed
        # TODO: implementing BrokingMode.COVERAGE_ORDERED

    def add_seed_file(self, file: PathLike, initial: bool = False) -> None:
        p = Path(file)
        logging.info(f"Add seed {p.name} in pool")
        # Save seed in the workspace
        self.workspace.save_seed_file(SeedType.INPUT, p)

        seed = p.read_bytes()
        self._seed_pool[seed] = SeedType.INPUT
        if initial:
            self._init_seed_pool[seed] = SeedType.INPUT

    def write_seed(self, typ: SeedType, from_cli: PastisClient, seed: bytes):
        t = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())
        elapsed = str(datetime.timedelta(seconds=time.time() - self._start_time)).replace(" day, ", "d:").replace(" days, ", "d:")
        fname = f"{t}_{elapsed}_{from_cli.strid}_{md5(seed).hexdigest()}.cov"
        self.workspace.save_seed(typ, fname, seed)

    def hello_received(self, cli_id: bytes, engines: List[FuzzingEngineInfo], arch: Arch, cpus: int, memory: int, hostname: str, platform: Platform):
        uid = self.new_uid()
        client = PastisClient(uid, cli_id, engines, arch, cpus, memory, hostname, platform)
        logging.info(f"[{client.strid}] [HELLO] Name:{hostname} Arch:{arch.name} engines:{[x.name for x in engines]} (cpu:{cpus}, mem:{memory})")
        self.clients[client.netid] = client

        # Load engines if they are not (lazy loading)
        for eng in engines:
            if eng not in self.engines:
                self.load_engine_addon(eng.pymodule)

        if self.running: # A client is coming in the middle of a session
            self.start_client_and_send_corpus(client)

    def _transmit_pool(self, client, pool) -> None:
        for seed, typ in pool.items():
            self.send_seed(client.netid, typ, seed)  # necessarily a new seed
            client.add_peer_seed(seed)  # Add it in its list of seed

    def log_received(self, cli_id: bytes, level: LogLevel, message: str):
        client = self.get_client(cli_id)
        if not client:
            return
        #logging.info(f"[{client.strid}] [LOG] [{level.name}] {message}")
        client.log(level, message)

    def telemetry_received(self, cli_id: bytes,
        state: State = None, exec_per_sec: int = None, total_exec: int = None,
        cycle: int = None, timeout: int = None, coverage_block: int = None, coverage_edge: int = None,
        coverage_path: int = None, last_cov_update: int = None):
        client = self.get_client(cli_id)
        if not client:
            return
        # NOTE: ignore state (shall we do something of it?)
        args = [('-' if not x else x) for x in [exec_per_sec, total_exec, cycle, timeout, coverage_block, coverage_edge, coverage_path, last_cov_update]]
        client.log(LogLevel.INFO, "exec/s:{} tot_exec:{} cycle:{} To:{} CovB:{} CovE:{} CovP:{} last_up:{}".format(*args))

        # Update all stats in the stat manager (for later UI update)
        self.statmanager.set_exec_per_sec(client, exec_per_sec)
        self.statmanager.set_total_exec(client, total_exec)
        self.statmanager.set_cycle(client, cycle)
        self.statmanager.set_timeout(client, timeout)
        self.statmanager.set_coverage_block(client, coverage_block)
        self.statmanager.set_coverage_edge(client, coverage_edge)
        self.statmanager.set_coverage_path(client, coverage_path)
        self.statmanager.set_last_coverage_update(client, last_cov_update)
        self.statmanager.update_telemetry_client(client)
        # NOTE: Send an update signal for future UI ?

    def stop_coverage_received(self, cli_id: bytes):
        client = self.get_client(cli_id)
        if not client:
            return
        logging.info(f"[{client.strid}] [STOP_COVERAGE]")
        for c in self.iter_other_clients(client):
            c.set_stopped()
            self.send_stop(c.netid)

    def data_received(self,  cli_id: bytes, data: str):
        client = self.get_client(cli_id)
        if not client:
            return
        first_cov, first_val = False, False

        if not self.kl_report:
            logging.warning("Data received while no Klocwork report is loaded (drop data)")
            return

        alert_data = AlertData.from_json(data)
        if self.kl_report.has_binding():
            alert = self.kl_report.get_alert(binding_id=alert_data.id)
        else:
            alert = self.kl_report.get_alert(kid=alert_data.id)

        if not alert.covered and alert_data.covered:
            logging.info(f"[{client.strid}] First to cover {alert}")
            alert.covered = alert_data.covered
            self.kl_report.write_csv(self.workspace.csv_result_file)  # Update CSV to keep it updated
            first_cov = True

        if not alert.validated and alert_data.validated:
            logging.info(f"[{client.strid}] First to validate {alert}")
            alert.validated = alert_data.validated
            self.kl_report.write_csv(self.workspace.csv_result_file)  # Update CSV to keep it updated
            first_val = True

        # Update clients of and stats
        client.add_covered_alert(alert.id, alert.covered, first_cov, alert.validated, first_val)

        # Save systematically the AlertData received
        self._save_alert_seed(client, alert_data)  # Also save seed in separate folder

        if first_cov or first_val:
            d, v = self.kl_report.get_stats()
            logging.info(f"Klocwork results updated: defaults: [cov:{d.checked}/{d.total}] vulns: [check:{v.checked}/{v.total}]")

        # If all alerts are validated send a stop to everyone
        if self.kl_report.all_alerts_validated():
            self.stop_broker()

    def stop_broker(self):
        for client in self.clients.values():
            logging.info(f"Send stop to {client.strid}")
            self.send_stop(client.netid)
        self._stop = True

        # Call the statmanager to wrap-up values
        self.statmanager.post_execution(list(self.clients.values()), self.workspace)

        if self.kl_report:  # If a klocwork report was loaded
            # Write the final CSV in the workspace
            self.kl_report.write_csv(self.workspace.csv_result_file)
            # And also re-write the Klocwork report (that also contains resutls)
            self.kl_report.write(self.workspace.klocwork_report_file)

    def start_client_and_send_corpus(self, client: PastisClient) -> None:
        self.start_client(client)
        # Iterate all the seed pool and send it to the client
        if self.broker_mode == BrokingMode.FULL:
            self._transmit_pool(client, self._seed_pool)
            # TODO: Implementing BrokingMode.COVERAGE_ORDERED
        elif self.broker_mode == BrokingMode.NO_TRANSMIT:
            self._transmit_pool(client, self._init_seed_pool)

    def start_client(self, client: PastisClient):
        program = None  # The program yet to be selected
        engine = None
        exmode = ExecMode.SINGLE_EXEC
        fuzzmode = FuzzMode.INSTRUMENTED
        engine_args = ""
        engines = Counter({e: 0 for e in self.engines})
        engines.update(c.engine.NAME for c in self.clients.values() if c.is_running())  # Count instances of each engine running
        for eng, _ in engines.most_common()[::-1]:
            eng_desc = self.engines[eng]
            # If the engine is not supported by the client continue
            if not client.is_supported_engine(eng_desc):
                continue

            # Try finding a suitable binary for the current engine and the client arch
            programs = self.programs.get((client.platform, client.arch))
            program = None
            exmode = None
            fuzzmod = FuzzMode.AUTO
            for p in programs:
                res, xmod, fmod = eng_desc.accept_file(p)  # Iterate all files on that engine descriptor to check it accept it
                if res:
                    if exmode:
                        if exmode == ExecMode.SINGLE_EXEC and xmod == ExecMode.PERSISTENT:  # persistent supersede single_exec
                            program, exmode, fuzzmod = p, xmod, fmod
                        else:
                            if fuzzmod == FuzzMode.BINARY_ONLY and fmod == FuzzMode.INSTRUMENTED:  # instrumented supersede binary only
                                program, exmode, fuzzmod = p, xmod, fmod
                            else:
                                pass  # Program is suitable but we already had found a PERSISTENT one
                    else:
                        program, exmode, fuzzmod = p, xmod, fmod  # first suitable program found

            if not program:  # If still no program was found continue iterating engines
                continue

            # Valid engine and suitable program found
            engine = eng_desc

            # Find a configuration to use for that engine
            engine_args = self._find_configuration(engine)
            covmode = self._find_coverage_mode(engine, engine_args)

            # If got here a suitable program has been found just break loop
            break

        if engine is None or program is None:
            logging.critical(f"No suitable engine or program was found for client {client.strid} {client.engines}")
            return

        # Update internal client info and send him the message
        logging.info(f"send start client {client.id}: {program.name} [{engine.NAME}, {covmode.name}, {fuzzmod.name}, {exmode.name}]")
        client.set_running(engine, covmode, exmode, self.ck_mode)
        client.configure_logger(self.workspace.log_directory, random.choice(COLORS))  # Assign custom color client
        self.send_start(client.netid,
                        program,
                        self.argv,
                        exmode,
                        fuzzmod,
                        self.ck_mode,
                        covmode,
                        FuzzingEngineInfo(engine.NAME, engine.VERSION, ""),
                        engine_args,
                        self.inject,
                        self.kl_report.to_json() if self.kl_report else "")

    def _find_configuration(self, engine: FuzzingEngineDescriptor) -> str:
        """
        Find a coverage mode for the engine. It will iterate all configuration
        available or automatically balance de configuration if there is multiple of
        them
        :param engine:
        :return:
        """
        confs = self.engines_args[engine.NAME]
        if confs:
            if len(confs) == 1:
                return confs[0]
            else:
                conf = confs.pop(0)
                confs.append(conf)  # Rotate the configuration
                return conf
        else:
            return ""

    def _find_coverage_mode(self, engine: FuzzingEngineDescriptor, conf: str) -> CoverageMode:

        # Now that program have been found select coverage strategy
        if len(engine.supported_coverage_strategies()) > 1:

            if conf:
                data = json.loads(conf)  # FIXME: dirty as it assume we knows the format and the key
                if "coverage_strategy" in data:
                    mapper = {"CODE_COVERAGE": CoverageMode.BLOCK, "EDGE_COVERAGE": CoverageMode.EDGE, "PATH_COVERAGE": CoverageMode.PATH}
                    return mapper[data["coverage_strategy"]]  # Return the CoverageMode of the config file

            else:  # Auto-balance the CoverageMode
                covs = Counter({c: 0 for c in CoverageMode})
                # Count how many times each coverage strategies have been launched
                covs.update(x.coverage_mode for x in self.clients.values() if x.is_running() and x.engine == engine)
                if sum(covs.values()) == 0:  # No configuration has been triggered yet launch in edge
                    return CoverageMode.EDGE
                # Revert dictionnary to have freq -> [covmodes]
                d = {v: [] for v in covs.values()}
                for cov, count in covs.items():
                    d[count].append(cov)
                # pick in-order BLOCK < EDGE < PATH among the least frequently launched modes
                return sorted(d[min(d)])[0]

        else:
            return CoverageMode.BLOCK  # Dummy value (for honggfuzz)


    def start(self, running: bool=True):
        super(PastisBroker, self).start()  # Start the listening thread
        self._start_time = time.time()
        self._running = running
        logging.info("start broking")

        # Send the start message to all clients
        if self._running:  # If we want to run now (cmdline mode)
            for c in self.clients.values():
                if not c.is_running():
                    self.start_client(c)

    def run(self):
        self.start()

        # Start infinite loop
        try:
            while True:
                time.sleep(0.1)
                if self._stop:
                    logging.info("broker terminate")
                    break
        except KeyboardInterrupt:
            logging.info("stop required (Ctrl+C)")
        self.stop_broker()

    def _find_binaries(self, binaries_dir) -> None:
        """
        Iterate the whole directory to find suitables binaries in the
        various architecture, and compiled for the various engines.

        :param binaries_dir: directory containing the various binaries
        :return: None
        """
        d = Path(binaries_dir)
        for file in d.iterdir():
            if file.is_file():
                data = read_binary_infos(file)
                if data is None:
                    continue

                platform, arch = data
                logging.info(f"new binary detected [{platform.name}, {arch.name}]: {file}")

                # Copy binary in workspace
                dst_file = self.workspace.add_binary(file)

                # Add it in the internal structure
                data2 = (Platform.ANY, arch)
                if data not in self.programs:
                    self.programs[data] = []
                if data2 not in self.programs:
                    self.programs[data2] = []
                self.programs[data].append(dst_file)
                self.programs[data2].append(dst_file)  # Also add an entry for any platform

    def _load_workspace(self):
        """ Load all the seeds in the workspace"""
        for typ in SeedType:  # iter seed types: input, crash, hang..
            for file in self.workspace.iter_corpus_directory(typ):
                logging.debug(f"Load seed in pool: {file.name}")
                content = file.read_bytes()
                self._seed_pool[content] = typ
        # TODO: Also dumping the current state to a file in case
        # TODO: of exit. And being able to reload it. (not to resend all seeds to clients)

    def add_engine_configuration(self, engine: str, args: str):
        if engine in self.engines_args:
            self.engines_args[engine].append(args)
        else:
            logging.error(f"can't find engine {engine} (shall preload it to add a configuration)")

    def _configure_logging(self):
        hldr = logging.FileHandler(self.workspace.broker_log_file)
        hldr.setLevel(logging.root.level)
        hldr.setFormatter(logging.Formatter("%(asctime)s [%(name)s] [%(levelname)s]: %(message)s"))
        logging.root.addHandler(hldr)

    def _colored_seed_type(self, typ: SeedType) -> str:
        mapper = {SeedType.INPUT: Bcolors.OKBLUE,
                  SeedType.HANG: Bcolors.WARNING,
                  SeedType.CRASH: Bcolors.FAIL}
        return mapper[typ]+typ.name+Bcolors.ENDC

    def _save_alert_seed(self, from_cli: PastisClient, alert: AlertData):
        t = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())
        elapsed = str(datetime.timedelta(seconds=time.time()-self._start_time)).replace(" day, ", "d:").replace(" days, ", "d:")
        fname = f"{t}_{elapsed}_{from_cli.strid}_{md5(alert.seed).hexdigest()}-{'CRASH' if alert.validated else 'COVERAGE'}.cov"
        logging.debug(f"Save alert  [{alert.id}] file: {fname}")
        self.workspace.save_alert_seed(alert.id, fname, alert.seed)
