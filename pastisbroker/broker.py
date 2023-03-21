# built-in imports
import logging
from typing import Generator, List, Optional, Union
from pathlib import Path
import time
from hashlib import md5
from enum import Enum
from collections import Counter
import datetime
import random

# Third-party imports
import psutil
from libpastis import BrokerAgent, FuzzingEngineDescriptor, EngineConfiguration, BinaryPackage, SASTReport
from libpastis.types import SeedType, FuzzingEngineInfo, LogLevel, Arch, State, SeedInjectLoc, CheckMode, CoverageMode, \
                            ExecMode, AlertData, PathLike, Platform, FuzzMode
import lief
from tritondse import QuokkaProgram

# Local imports
from pastisbroker.client import PastisClient
from pastisbroker.stat_manager import StatManager
from pastisbroker.workspace import Workspace, WorkspaceStatus
from pastisbroker.utils import load_engine_descriptor


lief.logging.disable()


class BrokingMode(Enum):
    FULL = 1              # Transmit all seeds to all peers
    NO_TRANSMIT = 2       # Does not transmit seed to peers (for comparing perfs of tools against each other)


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

    def __init__(self, workspace: PathLike,
                 binaries_dir: PathLike,
                 broker_mode: BrokingMode,
                 check_mode: CheckMode = CheckMode.CHECK_ALL,
                 inject_loc: SeedInjectLoc = SeedInjectLoc.STDIN,
                 sast_report: PathLike = None,
                 p_argv: List[str] = None,
                 memory_threshold: int = 85):
        super(PastisBroker, self).__init__()

        # Initialize workspace
        self.workspace = Workspace(Path(workspace))
        params = {"binaries_dir": str(Path(binaries_dir).absolute()),
                  "broker_mode": broker_mode.name,
                  "check_mode": check_mode.name,
                  "inject_loc": inject_loc.name,
                  "argvs": p_argv}
        self.workspace.initialize_runtime(binaries_dir, params)

        self._configure_logging()

        # Register all agent callbacks
        self._register_all()

        # Init internal state
        self.broker_mode = broker_mode
        self.ck_mode = check_mode
        self.inject = inject_loc
        self.argv = [] if p_argv is None else p_argv
        self.engines_args = {}
        self.engines = {}  # name->FuzzingEngineDescriptor

        # for slicing mode (otherwise not used)
        self._slicing_ongoing = {}  # Program -> {Addr -> [cli]}

        # Initialize availables binaries
        self.programs = {}  # Tuple[(Arch, Fuzzer, ExecMode)] -> Path
        self._find_binaries(binaries_dir)

        # Klocwork informations
        self.sast_report = None
        if sast_report:
            self.initialize_sast_report(sast_report)

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

        # Watchdog to monitor RAM usage
        self.watchdog = None
        self._threshold = memory_threshold # percent

    def load_engine_addon(self, py_module: str) -> bool:
        desc = load_engine_descriptor(py_module)
        if desc is not None:
            self.engines[desc.NAME] = desc
            self.engines_args[desc.NAME] = []
            return True
        else:
            return False

    def initialize_sast_report(self, report: PathLike):
        self.sast_report = SASTReport.from_file(report)
        self.workspace.add_sast_report(self.sast_report)
        self.workspace.initialize_alert_corpus(self.sast_report)

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

    def kick_client(self, cli_id: bytes) -> None:
        cli = self.clients.pop(cli_id)  # pop it from client list
        logging.info(f"kick client: {cli.strid}")
        self.send_stop(cli_id)

    def seed_received(self, cli_id: bytes, typ: SeedType, seed: bytes):
        cli = self.get_client(cli_id)
        if not cli:
            return
        is_new = seed not in self._seed_pool
        h = md5(seed).hexdigest()

        # Show log message and save seed to file
        self.statmanager.update_seed_stat(cli, typ)  # Add info only if new
        cli.log(LogLevel.INFO, f"seed {h} [{self._colored_seed_type(typ)}][{self._colored_seed_newness(is_new)}]")
        cli.add_own_seed(seed)  # Add seed in client's seed
        self.write_seed(typ, cli, seed) # Write seed to file

        if is_new:
            self._seed_pool[seed] = typ  # Save it in the local pool
        else:
            pass
            # logging.warning(f"receive duplicate seed {h} by {cli.strid}")

        # Iterate on all clients and send it to whomever never received it
        if self.broker_mode == BrokingMode.FULL:
            for c in self.iter_other_clients(cli):
                if c.is_new_seed(seed):
                    self.send_seed(c.netid, typ, seed)  # send the seed to the client
                    c.add_peer_seed(seed)  # Add it in its list of seed

    def add_seed_file(self, file: PathLike, initial: bool = False) -> None:
        p = Path(file)
        logging.info(f"Add seed {p.name} in pool")
        # Save seed in the workspace
        self.workspace.save_seed_file(SeedType.INPUT, p, initial)

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
            if eng.name not in self.engines:
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
        client.log(level, message)

    def telemetry_received(self, cli_id: bytes,
                           _: State = None, exec_per_sec: int = None, total_exec: int = None,
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

        if self.ck_mode == CheckMode.ALERT_ONE:  # Start it on another target
            addr = client.target
            s = "validated " if client.target_validated else "is stuck for "
            logging.info(f"[{client.strid}] [STOP_COVERAGE] client {s} 0x{addr:x} address (launch another target)")
            clis = self._slicing_ongoing[client.package_name].pop(addr)  # pop the address definitely
            self.relaunch_clients(clis)  # relaunch all clients on a new target
        else:
            logging.info(f"[{client.strid}] [STOP_COVERAGE]: restart client")
            self.relaunch_clients([client])  # restart the client

    def data_received(self,  cli_id: bytes, data: str):
        client = self.get_client(cli_id)
        if not client:
            return
        first_cov, first_val = False, False

        if not self.sast_report:
            logging.warning("Data received while no SAST report is loaded (drop data)")
            return

        alert_data = AlertData.from_json(data)
        alert = self.sast_report.alerts[alert_data.id]

        if not alert.validated and alert_data.validated:
            logging.info(f"[{client.strid}] First to validate {alert}")
            alert.validated = alert_data.validated
            self.sast_report.write_csv(self.workspace.csv_result_file)  # Update CSV to keep it updated
            first_val = True

            if self.ck_mode == CheckMode.ALERT_ONE:
                client.target_validated = True
                # Note: Do not relaunch the client now, wait for him to send stop_coverage

        # Need to be after validated because alert.covered = True (will also set validated)
        if not alert.covered and alert_data.covered:
            logging.info(f"[{client.strid}] First to cover {alert}")
            alert.covered = alert_data.covered
            self.sast_report.write_csv(self.workspace.csv_result_file)  # Update CSV to keep it updated
            first_cov = True

        # Update clients of and stats
        client.add_covered_alert(alert.id, alert.covered, first_cov, alert.validated, first_val)

        # Save systematically the AlertData received
        self._save_alert_seed(client, alert_data)  # Also save seed in separate folder

        if first_cov or first_val:
            cov, val, tot = self.sast_report.get_stats()
            logging.info(f"SAST results updated: defaults: [covered:{cov}/{tot}] [validated:{val}/{tot}]")

        # If all alerts are validated send a stop to everyone
        if self.sast_report.all_alerts_validated():
            self.stop_broker()

    def relaunch_clients(self, clients):
        for cli in clients:
            logging.info(
                f"Launch client {cli.strid} as its targeting an address that has just been validated")
            self.start_client_and_send_corpus(cli)

    def stop_broker(self):
        for client in self.clients.values():
            logging.info(f"Send stop to {client.strid}")
            self.send_stop(client.netid)
        self._stop = True

        # Call the statmanager to wrap-up values
        self.statmanager.post_execution(list(self.clients.values()), self.workspace)

        if self.sast_report:  # If a SAST report was loaded
            # Write the final CSV in the workspace
            self.sast_report.write_csv(self.workspace.csv_result_file)
            # And also re-write the Klocwork report (that also contains resutls)
            self.sast_report.write(self.workspace.sast_report_file)

    def start_client_and_send_corpus(self, client: PastisClient) -> None:
        self.start_client(client)
        # Iterate all the seed pool and send it to the client
        if self.broker_mode == BrokingMode.FULL:
            self._transmit_pool(client, self._seed_pool)
        elif self.broker_mode == BrokingMode.NO_TRANSMIT:
            self._transmit_pool(client, self._init_seed_pool)

    def start_client(self, client: PastisClient):
        engine = None
        exmode = ExecMode.SINGLE_EXEC
        fuzzmode = FuzzMode.INSTRUMENTED
        engine_args = None
        package = covmode = fuzzmod = None
        engines = Counter({e: 0 for e in self.engines})
        engines.update(c.engine.NAME for c in self.clients.values() if c.is_running())  # Count instances of each engine running
        for eng, _ in engines.most_common()[::-1]:
            eng_desc = self.engines[eng]
            # If the engine is not supported by the client continue
            if not client.is_supported_engine(eng_desc):
                continue

            # Try finding a suitable binary for the current engine and the client arch
            programs: List[BinaryPackage] = self.programs.get((client.platform, client.arch))
            package = None
            exmode = None
            fuzzmod = FuzzMode.AUTO
            for p in programs:
                res, xmod, fmod = eng_desc.accept_file(p.executable_path)  # Iterate all files on that engine descriptor to check it accept it
                if res:
                    if exmode:
                        if exmode == ExecMode.SINGLE_EXEC and xmod == ExecMode.PERSISTENT:  # persistent supersede single_exec
                            package, exmode, fuzzmod = p, xmod, fmod
                        else:
                            if fuzzmod == FuzzMode.BINARY_ONLY and fmod == FuzzMode.INSTRUMENTED:  # instrumented supersede binary only
                                package, exmode, fuzzmod = p, xmod, fmod
                            else:
                                pass  # Program is suitable but we already had found a PERSISTENT one
                    else:
                        package, exmode, fuzzmod = p, xmod, fmod  # first suitable program found

            if not package:  # If still no program was found continue iterating engines
                continue

            # Valid engine and suitable program found
            engine = eng_desc

            # Find a configuration to use for that engine
            engine_args = self._find_configuration(engine)
            covmode = self._find_coverage_mode(engine, engine_args)

            # If got here a suitable program has been found just break loop
            break

        if engine is None or package is None:
            logging.critical(f"No suitable engine or program was found for client {client.strid} {client.engines}")
            return

        if self.ck_mode == CheckMode.ALERT_ONE:
            if package.is_quokka():
                targets = self._slicing_ongoing[package.name]
                sorted_targets = sorted(targets, key=lambda k: len(targets[k]), reverse=False)  # sort alert addresses by number of client instances working on it
                if sorted_targets:
                    addr = sorted_targets[0]
                    targets[addr].append(client)
                    client.target = addr   # keep the target on which the client is working on
                    client.target_validated = False
                    # Now twist the config to transmit it to the client
                    engine_args = engine.config_class.new() if engine_args is None else engine_args
                    engine_args.set_target(addr)
                    logging.info(f"will start client {client.strid} to target 0x{addr:x}")
                else:
                    logging.error(f"No alert target for binary package {package.name}")
            else:
                logging.error(f"In mode {self.ck_mode} but the binary package is not a QBinExport")
                return


        # Update internal client info and send him the message
        engine_args_str = engine_args.to_str() if engine_args else ""
        logging.info(f"send start client {client.id}: {package.name} [{engine.NAME}, {covmode.name}, {fuzzmod.name}, {exmode.name}]")
        client.set_running(package.name, engine, covmode, exmode, self.ck_mode, engine_args_str)
        client.configure_logger(self.workspace.log_directory, random.choice(COLORS))  # Assign custom color client

        self.send_start(client.netid,
                        package.name,
                        package.executable_path if package.is_standalone() else package.make_package(),
                        self.argv,
                        exmode,
                        fuzzmod,
                        self.ck_mode,
                        covmode,
                        FuzzingEngineInfo(engine.NAME, engine.VERSION, ""),
                        engine_args_str,
                        self.inject,
                        self.sast_report.to_json() if self.sast_report else b"")


    def _find_configuration(self, engine: FuzzingEngineDescriptor) -> Optional[EngineConfiguration]:
        """
        Find a configuration for the engine. It will iterate all configuration
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
            return None

    def _find_coverage_mode(self, engine: FuzzingEngineDescriptor, conf: Union[EngineConfiguration]) -> CoverageMode:

        # Get coverage modes supported by the engine
        supported_mods = engine.supported_coverage_strategies()

        # Now that program have been found select coverage strategy
        if len(supported_mods) > 1:

            if conf:  # In the case we wanted to launch engines with specific configuration
                return conf.get_coverage_mode()    # return the appropriate coverage mode in that configuration

            else:
                # auto-balance the CoverageMode instances
                covs = Counter({c: 0 for c in supported_mods})
                # Count how many times each coverage strategies have been launched
                covs.update(x.coverage_mode for x in self.clients.values() if x.is_running() and x.engine == engine)

                if sum(covs.values()) == 0:  # No configuration has been triggered yet
                    if CoverageMode.EDGE in supported_mods:  # launch preferably edge first
                        return CoverageMode.EDGE
                    else:
                        return supported_mods[0]  # Return first supported mode

                reverted = {v: k for k, v in covs.items()}  # Revert dictionnary to have freq -> covmodes
                return reverted[min(reverted)]  # Select mode if least instances

        else:
            return supported_mods[0]

    def start(self, running: bool = True):
        super(PastisBroker, self).start()  # Start the listening thread
        self._start_time = time.time()
        self._running = running
        self.workspace.status = WorkspaceStatus.RUNNING
        logging.info("start broking")

        # Send the start message to all clients
        if self._running:  # If we want to run now (cmdline mode)
            for c in self.clients.values():
                if not c.is_running():
                    self.start_client(c)

    def run(self, timeout: int = None):
        self.start()
        last_t = time.time()

        # Start infinite loop
        try:
            while True:
                time.sleep(1)
                t = time.time()

                # Check if the campaign have to be stopped
                if timeout is not None:
                    if t > (self._start_time + timeout):
                        logging.info("Campaign timeout reached, stop campaign.")
                        self._stop = True

                if t > (last_t + 60):  # only check every minute
                    last_t = t
                    if not self._check_memory_usage():
                        # The machine starts being overloaded
                        # For security kill triton instance
                        for cli in list(self.clients.values()):
                            if cli.engine.SHORT_NAME == "TT":  # is triton
                                self.kick_client(cli.netid)

                if self._stop:
                    logging.info("broker terminate")
                    break
        except KeyboardInterrupt:
            logging.info("stop required (Ctrl+C)")
        self.workspace.status = WorkspaceStatus.FINISHED
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
                try:
                    pkg = BinaryPackage.auto(file)  # try creating a package
                except ValueError:  # if not an executable
                    continue

                if pkg is None:
                    continue

                # Check that we can find a Quokka file associated otherwise reject it
                if self.ck_mode == CheckMode.ALERT_ONE:
                    if pkg.is_quokka():
                        try:
                            # Instanciate the Quokka Program and monkey patch object
                            quokka_prog = QuokkaProgram(pkg.quokka, pkg.executable_path)
                            f = quokka_prog.get_function("__sast_alert_placeholder")
                            self._slicing_ongoing[file.name] = {x: [] for x in quokka_prog.get_caller_instructions(f)}
                        except ValueError:
                            logging.warning(f"can't find placeholder file in {file.name}, thus ignores it.")
                            continue
                    else:
                        logging.warning(f"{file.name} executable found but no QBinExport file associated (ignores it)")
                        continue

                logging.info(f"new binary detected [{pkg.platform.name}, {pkg.arch.name}]: {file}")

                # Add it in the internal structure
                data = (pkg.platform, pkg.arch)
                data2 = (Platform.ANY, pkg.arch)
                if data not in self.programs:
                    self.programs[data] = []
                if data2 not in self.programs:
                    self.programs[data2] = []
                self.programs[data].append(pkg)
                self.programs[data2].append(pkg)  # Also add an entry for any platform

    def _load_workspace(self):
        """ Load all the seeds in the workspace"""
        for typ in list(SeedType):  # iter seed types: input, crash, hang..
            for file in self.workspace.iter_corpus_directory(typ):
                logging.debug(f"Load seed in pool: {file.name}")
                content = file.read_bytes()
                self._seed_pool[content] = typ
        # TODO: Also dumping the current state to a file in case
        # TODO: of exit. And being able to reload it. (not to resend all seeds to clients)

    def add_engine_configuration(self, name: str, config_file: PathLike):
        if name in self.engines_args:
            engine = self.engines[name]
            conf = engine.config_class.from_file(config_file)
            self.engines_args[name].append(conf)
        else:
            logging.error(f"can't find engine {name} (shall preload it to add a configuration)")

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

    def _colored_seed_newness(self, is_new: bool) -> str:
        col, text = {True: (Bcolors.OKGREEN, "NEW"),
                     False: (Bcolors.WARNING, "DUP")}[is_new]
        return col+text+Bcolors.ENDC

    def _save_alert_seed(self, from_cli: PastisClient, alert: AlertData):
        t = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())
        elapsed = str(datetime.timedelta(seconds=time.time()-self._start_time)).replace(" day, ", "d:").replace(" days, ", "d:")
        fname = f"{t}_{elapsed}_{from_cli.strid}_{md5(alert.seed).hexdigest()}-{'CRASH' if alert.validated else 'COVERAGE'}.cov"
        logging.debug(f"Save alert  [{alert.id}] file: {fname}")
        self.workspace.save_alert_seed(alert.id, fname, alert.seed)

    def _check_memory_usage(self) -> bool:
        mem = psutil.virtual_memory()
        logging.info(f"RAM usage: {mem.percent:.2f}%")
        if mem.percent >= self._threshold:
            logging.warning(f"Threshold reached: {mem.percent}%")
            return False
        return True
