# built-in imports
import json
import logging
import threading
import time
import os
from queue import Queue
from hashlib import md5
from pathlib import Path
from typing import List, Optional, Union

import pastistritondse

from pastistritondse.alert import AlertValidator
from pastistritondse.replayer import Replayer
from pastistritondse.utils import is_compatible_with_local

# third-party imports

# pastis & tritondse imports
from tritondse.callbacks import ProbeInterface
from tritondse.config import Config
from tritondse.coverage import CoverageSingleRun, CoverageStrategy
from tritondse.loaders import CleLoader, Program, QuokkaProgram
from tritondse.process_state import ProcessState
from tritondse.sanitizers import FormatStringSanitizer, NullDerefSanitizer, UAFSanitizer
from tritondse.seed import CompositeData, Seed, SeedFormat, SeedStatus
from tritondse.seed_scheduler import FreshSeedPrioritizerWorklist, WorklistAddressToSet
from tritondse.symbolic_executor import SymbolicExecutor
from tritondse.symbolic_explorator import ExplorationStatus, SymbolicExplorator
from tritondse.types import Addr, AstNode, Edge, SymExType
from tritondse.workspace import Workspace

from libpastis import BinaryPackage, ClientAgent, SASTReport
from libpastis.types import AlertData, CheckMode, CoverageMode, ExecMode, FuzzMode, FuzzingEngineInfo, LogLevel, \
    SeedInjectLoc, SeedType


class TritonDSEDriver(object):

    INPUT_FILE_NAME = "input_file"
    STAT_FILE = "tritondse-stats.json"

    DEFAULT_WS_PATH = "/tmp/tritondse_workspace"

    def __init__(self, agent: ClientAgent):

        # Internal objects
        self._agent = agent

        self._workspace = None

        # Parameters received through start_received
        self._check_mode = None
        self._report = None
        self._seed_inj = None

        self.__setup_agent()

        # Runtime data
        self._seed_recvs = set()            # Seeds received from the broker.
        self._seed_recvs_queue = Queue()    # Seeds received from the broker that are pending to process (that is,
                                            # to be directly added to the DSE or replayed and added).
        # ---

        self._config = None
        self._dse = None
        self._last_alert_id = None
        self._last_alert_id_pc = None       # Last ID previous program counter.
        self._probes = []
        self._program = None
        self._program_slice = None
        self._seeds_sent_count = 0          # Number of seed sent to the broker.
        self._stop = False
        self._tracing_enabled = False

        # Local attributes for telemetry
        self._crash_count = 0
        self._cur_cov_count = 0
        self._last_cov_update = 0
        self._seeds_merged = 0              # Number of seeds merged into the coverage after replaying them.
        self._seeds_rejected = 0            # Number of seeds discarded after replaying them.
        self._timeout_count = 0

        # Timing stats
        self._start_time = 0
        self._replay_time_acc = 0

        # Misc
        self._replayer = None
        self._alert_validator = None
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()

    def stop(self):
        if self._dse:
            self._dse.stop_exploration()

            self.__save_stats()

        self._stop = True

    def reset(self):
        """ Reset the current DSE to be able to restart from fresh settings """
        self._check_mode = None
        self._report = None
        self._seed_inj = None

        self._seed_recvs = set()

        self._config = None
        self._dse = None
        self._last_alert_id = None
        self._last_alert_id_pc = None
        self._program = None
        self._program_slice = None
        self._seeds_sent_count = 0
        self._stop = False
        self._tracing_enabled = False

        # local attributes for telemetry
        self._crash_count = 0
        self._cur_cov_count = 0
        self._last_cov_update = 0
        self._seeds_merged = 0
        self._seeds_rejected = 0
        self._timeout_count = 0

        # Timing stats
        self._replay_time_acc = 0
        self._start_time = 0

        logging.info("DSE Ready")

    @property
    def started(self):
        return self._dse is not None

    def add_initial_seed(self, file: Union[str, Path]):
        p = Path(file)
        logging.info(f"Add initial seed {p.name}")
        self.__add_seed(p.read_bytes())

    def add_probe(self, probe: ProbeInterface):
        self._probes.append(probe)

    def init_agent(self, remote: str = "localhost", port: int = 5555):
        self._agent.register_start_callback(self.start_received)
        self._agent.connect(remote, port)
        self._agent.start()
        self._agent.send_hello([FuzzingEngineInfo("TRITON", pastistritondse.__version__, "pastistritondse.addon")])

    def run(self, online: bool = True, debug_pp: bool = False):
        if online:
            self.__run_online(debug_pp=debug_pp)
        else:
            self.__run_offline(debug_pp=debug_pp)

    def __run_online(self, debug_pp: bool = False):
        def cb_debug(se: SymbolicExecutor, _: ProcessState):
            se.debug_pp = True

        # Run while we are not instructed to stop
        while not self._stop:
            self.reset()

            # Just wait until the broker says let's go
            while self._dse is None:
                time.sleep(0.10)

            if debug_pp:
                self._dse.callback_manager.register_pre_execution_callback(cb_debug)

            if not self.__run_one_online():
                break

        self._agent.stop()

    def __run_one_online(self):
        # Run while we are not instructed to stop
        while not self._stop:
            self.__wait_seed_event()

            self._start_time = time.time()

            status = self._dse.explore()

            self.__save_stats()

            if status == ExplorationStatus.STOPPED:             # If the exploration stopped just return.
                logging.info("Exploration stopped")
                return False                                    # This will cause the agent to stop.
            elif status == ExplorationStatus.TERMINATED:
                self._agent.send_stop_coverage_criteria()       # This will make the broker to relaunch all clients.
                return True                                     # Reset and wait for further instruction from the broker.
            elif status == ExplorationStatus.IDLE:              # No more seeds available.
                if self._check_mode == CheckMode.ALERT_ONE:
                    self._agent.send_stop_coverage_criteria()   # Warn the broker we explored the whole search space and
                                                                # did not validate the target.
                                                                # This will make the broker to relaunch all clients.
                    return True                                 # Make ourselves ready to receive a new one.
                else:                                           # Wait for seeds from peers.
                    logging.info("Exploration idle (worklist empty)")
                    self._agent.send_log(LogLevel.INFO, "exploration idle (worklist empty)")
            else:
                logging.error(f"Explorator not meant to be in state: {status}")
                return False                                    # This will cause the agent to stop.

    def __run_offline(self, debug_pp: bool = False):
        def cb_debug(se: SymbolicExecutor, _: ProcessState):
            se.debug_pp = True

        if not self._stop:
            # Just wait until the broker says let's go
            while self._dse is None:
                time.sleep(0.10)

            if debug_pp:
                self._dse.callback_manager.register_pre_execution_callback(cb_debug)

            self.__wait_seed_event()

            self._start_time = time.time()

            self._dse.explore()

            self.__save_stats()

        self._agent.stop()

    def __setup_agent(self):
        # Register callbacks.
        self._agent.register_seed_callback(self.__seed_received_cb)
        self._agent.register_stop_callback(self.__stop_received_cb)

    def __wait_seed_event(self):
        logging.info("Waiting to receive seeds")
        while not self._dse.seeds_manager.seeds_available() and not self._stop:
            self.__try_process_seed_queue()
            time.sleep(0.5)

    def __try_process_seed_queue(self):
        while not self._seed_recvs_queue.empty() and not self._stop:
            seed = self._seed_recvs_queue.get()
            self.__process_seed_received(seed)

    def dual_log(self, level: LogLevel, message: str) -> None:
        """
        Helper function to log message both in the local log system and also
        to the broker.

        :param level: LogLevel message type
        :param message: string message to log
        :return: None
        """
        log_level_mapper = {
            LogLevel.DEBUG: "debug",
            LogLevel.INFO: "info",
            LogLevel.CRITICAL: "critical",
            LogLevel.WARNING: "warning",
            LogLevel.ERROR: "error"
        }
        log_fn = getattr(logging, log_level_mapper[level])
        log_fn(message)

        self._agent.send_log(level, message)

    # ---
    # ClientAgent Callbacks
    # ---

    def start_received(self,
                       fname: str,
                       binary: bytes,
                       engine: FuzzingEngineInfo,
                       exmode: ExecMode,
                       fuzzmode: FuzzMode,
                       chkmode: CheckMode,
                       covmode: CoverageMode,
                       seed_inj: SeedInjectLoc,
                       engine_args: str,
                       argv: List[str],
                       envp: list[str],
                       sast_report: str = None):
        """
        This function is called when the broker says to start the fuzzing session. Here, we receive all information
        about the program to fuzz and the configuration.

        :param fname: The name of the binary to explore
        :param binary: The content of the binary to explore
        :param engine: The kind of fuzzing engine (should be Triton for this script)
        :param exmode: The mode of the exploration
        :param fuzzmode: The fuzzing mode (instrumented or binary only)
        :param chkmode: The mode of vulnerability check
        :param covmode: The mode of coverage
        :param seed_inj: The location where to inject input
        :param engine_args: The engine arguments
        :param argv: The program arguments
        :param envp: The environment variables
        :param sast_report: The SAST report
        :return: None
        """
        logging.info(f"[START] bin:{fname} engine:{engine.name} exmode:{exmode.name} covmod:{covmode.name} "
                     f"seedloc:{seed_inj.name} chk:{chkmode.name}")

        if self._dse is not None:
            self.dual_log(LogLevel.CRITICAL, "Instance already started!")
            return

        if engine.name != "TRITON":
            logging.error(f"Wrong fuzzing engine received {engine.name} while I am Triton")
            self.dual_log(LogLevel.ERROR, f"Invalid fuzzing engine received {engine.name} can't do anything")
            return

        if engine.version != pastistritondse.__version__:
            logging.error(f"Wrong fuzzing engine version {engine.version} received")
            self.dual_log(LogLevel.ERROR, f"Invalid fuzzing engine version {engine.version} do nothing")
            return

        self._seed_inj = seed_inj
        self._check_mode = chkmode

        self.__initialize_config(fname, argv, engine_args, seed_inj, covmode)

        self.__initialize_workspace()

        # Retrieve package out of the binary received.
        try:
            pkg = BinaryPackage.from_binary(fname, binary, self._workspace.get_binary_directory())
        except FileNotFoundError:
            self.dual_log(LogLevel.ERROR, "Invalid package data")
            return

        self._program = self.__initialize_program(pkg)

        if self._program is None:
            self.dual_log(LogLevel.CRITICAL, f"LIEF was not able to parse the binary file {fname}")
            return

        # if env variables provided add them to the global env
        for env_var in envp:
            if '=' in env_var:
                key, value = env_var.split('=', 1)
                os.environ[key] = value
            else:
                logging.warning(f"Invalid environment variable format: {env_var}")

        if sast_report:
            logging.info("Loading SAST report")
            self._report = SASTReport.from_json(sast_report)
            logging.info(f"SAST report alerts: {len(list(self._report.iter_alerts()))}")

        # Initialize the dynamic symbolic executor.
        try:
            self._dse = self.__initialize_dse(chkmode, self._workspace, self._probes)
        except Exception as e:
            self.dual_log(LogLevel.CRITICAL, f"Unexpected error while initializing the DSE: {e}")
            return

    def __seed_received_cb(self, typ: SeedType, seed: bytes):
        """
        This function is called when we receive a seed from the broker.

        :param typ: The type of the seed
        :param seed: The sequence of bytes representing the seed
        :return: None
        """
        self.__add_seed(seed)

    def __stop_received_cb(self):
        """
        This function is called when the broker says stop. (Called from the agent thread)
        """
        logging.info(f"[STOP]")

        self.stop()

    # ---
    # DSE Initialization
    # ---

    def __initialize_dse(self, chkmode: CheckMode, workspace: Workspace, probes: List[ProbeInterface]):
        self.__instantiate_argv(self._seed_inj)

        # Enable local tracing if the binary is compatible with local architecture
        self._tracing_enabled = is_compatible_with_local(self._program)
        logging.info(f"Local arch and program arch matching: {self._tracing_enabled}")

        if self._tracing_enabled:
            self._replayer = Replayer(self._program, self._config, self._seed_inj)

        self._alert_validator = AlertValidator()

        # Set seed scheduler based on whether tracing is enabled.
        if self._tracing_enabled:
            seed_scheduler_class = WorklistAddressToSet
        else:
            seed_scheduler_class = FreshSeedPrioritizerWorklist

        dse = SymbolicExplorator(self._config, self._program, workspace=workspace,
                                 seed_scheduler_class=seed_scheduler_class)

        # Register common callbacks.
        dse.callback_manager.register_new_input_callback(self.__send_input_seed_cb)
        dse.callback_manager.register_post_execution_callback(self.__post_execution_cb)
        dse.callback_manager.register_exploration_step_callback(self.__send_telemetry_cb)

        # Register user-provided probes.
        for probe in probes:
            dse.callback_manager.register_probe(probe)

        # Set up the dse instance according to the check mode parameter.
        if chkmode == CheckMode.CHECK_ALL:
            dse.callback_manager.register_probe(UAFSanitizer())
            dse.callback_manager.register_probe(NullDerefSanitizer())
            dse.callback_manager.register_probe(FormatStringSanitizer())
            # dse.callback_manager.register_probe(IntegerOverflowSanitizer())
            # TODO Buffer overflow
        elif chkmode == CheckMode.ALERT_ONLY:
            # TODO: Refactor out into a probe (IntrinsicsProbe).
            dse.callback_manager.register_function_callback('__sast_alert_placeholder', self.__intrinsic_cb)
        elif chkmode == CheckMode.ALERT_ONE:  # targeted approach
            self.__setup_slice_mode(chkmode, dse)

        return dse

    def __setup_slice_mode(self, chkmode, dse):
        if not isinstance(self._program, QuokkaProgram):
            logging.error(f"Targeted mode [{chkmode.name}] requires a Quokka program")
            raise Exception(f"Targeted mode [{chkmode.name}] requires a Quokka program")

        # Retrieve the target address to reach, and set the callback.
        target_addr = self._config.custom['target']
        dse.callback_manager.register_post_addr_callback(target_addr, self.__intrinsic_cb)

        # NOTE Target address must be the starting address of a basic block.
        slice_from = self._program.find_function_addr('main')
        slice_to = target_addr

        if slice_from and slice_to:
            # Find the functions that correspond to the from and to addresses.
            slice_from_fn = self._program.find_function_from_addr(slice_from)
            slice_to_fn = self._program.find_function_from_addr(slice_to)
            logging.info(f"Launching exploration in targeted mode on: 0x{target_addr:08x} in {slice_to_fn.name}")

            if slice_from_fn and slice_to_fn:
                # NOTE Generate call graph with backedges so when we do the
                #      slice it also includes functions that are called in
                #      the path from the source to the destination of the
                #      slice.
                call_graph = self._program.get_call_graph(backedge_on_ret=True)

                logging.info(f'Slicing program from {slice_from:#x} ({slice_from_fn.name}) to {slice_to:#x} ({slice_to_fn.name})')

                self._program_slice = QuokkaProgram.get_slice(call_graph, slice_from_fn.start, slice_to_fn.start)

                logging.info(f'Call graph (full): #nodes: {len(call_graph.nodes)}, #edges: {len(call_graph.edges)}')
                logging.info(f'Call graph (sliced): #nodes: {len(self._program_slice.nodes)}, #edges: {len(self._program_slice.edges)}')

                dse.callback_manager.register_on_solving_callback(self.__on_solving_cb)
            else:
                logging.warning(f'Invalid source or target function, skipping slicing!')
        else:
            logging.warning(f'Invalid source or target addresses, skipping slicing!')

    def __initialize_program(self, package: BinaryPackage):
        if package.is_quokka():
            logging.info(f"Load QuokkaProgram: {package.quokka.name}")
            program = QuokkaProgram(package.quokka, package.executable_path)
        else:
            logging.info(f"Load Program: {package.executable_path.name} [{self._seed_inj.name}]")
            program = Program(package.executable_path)

            # Make sure the program is compatible with the local platform
            if is_compatible_with_local(program):
                program = CleLoader(package.executable_path)

        return program

    def __initialize_workspace(self):
        workspace_path = self._config.workspace

        # If a workspace is given keep it, otherwise generate a new unique one.
        if not workspace_path:
            workspace_path = self.DEFAULT_WS_PATH + f"/{int(time.time())}"

            logging.info(f"Configure workspace to be: {workspace_path}")

        # Create the workspace object in advance (to directly save the binary inside)
        self._workspace = Workspace(workspace_path)
        self._workspace.initialize(flush=False)

    def __initialize_config(self, program_name: str, program_argv: List[str], config_json: str, seed_inj: SeedInjectLoc, covmode: CoverageMode):
        # Load or create configuration.
        if config_json:
            logging.info(f"Loading existing configuration")
            self._config = Config.from_json(config_json)
        else:
            logging.info(f"Creating empty configuration")

            # Set seed format according to the injection location.
            seed_format = SeedFormat.COMPOSITE if seed_inj == SeedInjectLoc.ARGV else SeedFormat.RAW

            # Create empty configuration and assign default settings.
            self._config = Config(program_argv=[f"./{program_name}"] + program_argv,
                                  seed_format=seed_format)

        self.__check_and_fix_seed_format(seed_inj)

        # Update the coverage strategy in the current config (it overrides the config file one)
        try:
            self._config.coverage_strategy = CoverageStrategy(covmode.value)  # Names are meant to match.
        except Exception as e:
            logging.critical(f"Invalid covmode (not supported by TritonDSE): {e}")

    def __check_and_fix_seed_format(self, seed_inj: SeedInjectLoc) -> None:
        # Actions taken depending on seed format and injection method:
        # | Config    | Inject | Action |
        #   RAW         STDIN    None
        #   COMPOSITE   STDIN    None (seed needs 'stdin' in files)
        #   RAW         ARGV     Fix (switch to COMPOSITE to be able to inject on argv (and convert seeds on the fly))
        #   COMPOSITE   ARGV     None (seed needs 'input_file' in files)
        if seed_inj == SeedInjectLoc.STDIN:
            if self._config.is_format_raw():
                # Nothing to do.
                pass
            else:  # self._config.is_format_composite()
                logging.warning("Injecting on STDIN but seed format is COMPOSITE")
        else:  # SeedInjectLoc.ARGV
            if self._config.is_format_raw():
                logging.warning("Injection is ARGV thus switch config seed format to COMPOSITE")
                self._config.seed_format = SeedFormat.COMPOSITE
            else:  # self._config.is_format_composite()
                if "@@" not in self._config.program_argv:
                    logging.warning("Injection is ARGV but there is no injection marker (@@)")

    def __instantiate_argv(self, seed_inj: SeedInjectLoc):
        if seed_inj == SeedInjectLoc.ARGV:
            if "@@" in self._config.program_argv:
                idx = self._config.program_argv.index("@@")
                self._config.program_argv[idx] = self.INPUT_FILE_NAME
            else:
                logging.warning(f"Seed inject location {self._seed_inj.name} but no '@@' found in argv (will likely not work!)")

    # ---
    # SymbolicExecutor Callbacks
    # ---

    def __post_execution_cb(self, se: SymbolicExecutor, pstate: ProcessState):
        """
        This function is called after each execution. In this function we verify
        the ABV_GENERAL alert when a crash occurred during the last execution.

        :param se: The current symbolic executor
        :param pstate: The current process state of the execution
        :return: None
        """
        # Process seed
        if se.seed.status == SeedStatus.NEW:
            logging.warning(f"Seed is not meant to be NEW in post execution: {se.seed.status.name}")
        elif se.seed.status in [SeedStatus.CRASH, SeedStatus.HANG]:
            # The status changed, send it back again.
            self.__send_seed(se.seed)
        else:
            # If se.seed.status in [SeedStatus.FAIL, SeedStatus.OK_DONE], do
            # not send it back again.
            pass

        # Update some stats
        if se.seed.status == SeedStatus.CRASH:
            self._crash_count += 1
        elif se.seed.status == SeedStatus.HANG:
            self._timeout_count += 1

        # Handle CRASH and ABV_GENERAL
        if se.seed.status == SeedStatus.CRASH and self._last_alert_id:
            alert = self._report.get_alert(self._last_alert_id)
            if alert.type == "ABV_GENERAL":
                logging.info(f'A crash occurred with an ABV_GENERAL encountered just before.')
                self.dual_log(LogLevel.INFO, f"Alert [{alert.id}] in {alert.file}:{alert.line}: {alert.type} validation [SUCCESS]")
                alert.validated = True
                self.__send_alert_data(alert, se.seed, self._last_alert_id_pc)

        # Print stats
        if self._report:
            cov, va, tot = self._report.get_stats()
            logging.info(f"SAST stats: defaults: [covered:{cov}/{tot}] [validated:{va}/{tot}]")

        # Process enqueued seeds
        self.__try_process_seed_queue()

    def __send_telemetry_cb(self, dse: SymbolicExplorator):
        """
        Callback called after each execution to send telemetry to the broker

        :param dse: SymbolicExplorator
        :return: None
        """
        new_count = dse.coverage.unique_covitem_covered

        if new_count != self._cur_cov_count:        # Coverage has been updated
            self._cur_cov_count = new_count         # Update count
            self._last_cov_update = time.time()     # Update last coverage update to be now

        if dse.coverage.strategy == CoverageStrategy.PREFIXED_EDGE:
            new_count = len(set(x[1] for x in dse.coverage.covered_items.keys()))  # For prefixed-edge only count edge

        self._agent.send_telemetry(exec_per_sec=int(dse.execution_count / (time.time() - dse.ts)),
                                   total_exec=dse.execution_count,
                                   timeout=self._timeout_count,
                                   coverage_block=dse.coverage.unique_instruction_covered,
                                   coverage_edge=new_count if dse.coverage in [CoverageStrategy.EDGE, CoverageStrategy.PREFIXED_EDGE] else 0,
                                   coverage_path=new_count if dse.coverage.strategy == CoverageStrategy.PATH else 0,
                                   last_cov_update=int(self._last_cov_update))

    def __on_solving_cb(self, se: SymbolicExplorator, pstate: ProcessState, edge: Edge, typ: SymExType,
                        astnode: AstNode, astnode_list: List[AstNode]) -> bool:
        # Only consider conditional and dynamic jumps.
        if typ in [SymExType.SYMBOLIC_READ, SymExType.SYMBOLIC_WRITE]:
            return True

        # Unpack edge.
        src, dst = edge

        # Find the function which holds the basic block of the destination.
        dst_fn = self._program.find_function_from_addr(dst)
        if dst_fn is None:
            logging.warning("Solving edge ({src:#x} -> {dst:#x}) not in a function")
            return True
        else:
            if dst_fn.start in self._program_slice:
                return True
            else:
                logging.info(f"Slicer: reject edge ({src:#x} -> {dst:#x} ({dst_fn.name}) not in slice!")
                return False

    def __send_input_seed_cb(self, se: SymbolicExecutor, pstate: ProcessState, seed: Seed):
        self.__send_seed(seed)

    def __intrinsic_cb(self, se: SymbolicExecutor, pstate: ProcessState, addr: Addr):
        """
        This function is called when an intrinsic call occurs in order to verify
        defaults and vulnerabilities.

        :param se: The current symbolic executor
        :param pstate: The current process state of the execution
        :param addr: The instruction address of the intrinsic call
        :return: None
        """
        alert_id = pstate.get_argument_value(0)

        self._last_alert_id = alert_id
        self._last_alert_id_pc = se.previous_pc

        def status_changed(a, cov, vld):
            return a.covered != cov or a.validated != vld

        if self._report:
            # Retrieve the SASTAlert object from the report
            try:
                alert = self._report.get_alert(alert_id)
                cov, vld = alert.covered, alert.validated
            except IndexError:
                logging.warning(f"Intrinsic id {alert_id} not found in report (ignored)")
                return

            if not alert.covered:
                self.dual_log(LogLevel.INFO, f"Alert [{alert.id}] in {alert.file}:{alert.line}: {alert.type} covered !")
                alert.covered = True  # that might also set validated to true!

            if not alert.validated:  # If of type VULNERABILITY and not yet validated
                res = self._alert_validator.validate(alert.code, se, pstate, addr)
                if res:
                    alert.validated = True
                    self.dual_log(LogLevel.INFO, f"Alert [{alert.id}] in {alert.file}:{alert.line}: {alert.type} validation [SUCCESS]")
                    if se.seed.is_status_set():
                        logging.warning(f"Status already set ({se.seed.status}) for seed {se.seed.hash} (override with CRASH)")
                    se.seed.status = SeedStatus.CRASH  # Mark the seed as crash, as it validates an alert
                else:
                    logging.info(f"Alert [{alert.id}] in {alert.file}:{alert.line}: validation [FAIL]")

            if status_changed(alert, cov, vld):  # If either coverage or validation were improved print stats
                # Send updates to the broker
                self.__send_alert_data(alert, se.seed, se.previous_pc)
                cov, vals, tot = self._report.get_stats()
                logging.info(f"SAST stats: defaults: [covered:{cov}/{tot}] [validated:{vals}/{tot}]")

                if self._report.all_alerts_validated() or (self._check_mode == CheckMode.ALERT_ONE and alert.validated):
                    self.__do_stop_all_alerts_validated()

        else:  # Kind of autonomous mode. Try to check it even it is not bound to a report
            # Retrieve alert type from parameters
            alert_type = se.pstate.get_string_argument(1)
            try:
                if self._alert_validator.validate(alert_type, se, pstate, addr):
                    logging.info(f"Alert {alert_id} of type {alert_type} [VALIDATED]")
                else:
                    logging.info(f"Alert {alert_id} of type {alert_type} [NOT VALIDATED]")
            except KeyError:
                logging.error(f"Alert type {alert_type} not recognized")

    def __do_stop_all_alerts_validated(self) -> None:
        """
        Function called if all alerts have been covered and validated. All data are meant to
        have been transmitted to the broker, but writes down locally the CSV anyway
        :return: None
        """
        logging.info("All defaults and vulnerability have been covered !")

        # Write the final CSV in the workspace directory
        out_file = self._dse.workspace.get_metadata_file_path("klocwork_coverage_results.csv")
        self._report.write_csv(out_file)

        # Stop the dse exploration
        self._dse.terminate_exploration()

    def __save_stats(self):
        stat_file = self._workspace.get_metadata_file_path(self.STAT_FILE)
        data = {
            "total_time": time.time() - self._start_time,
            "emulation_time": self._dse.total_emulation_time,  # Note: includes replay time but not solving
            "solving_time": self._dse.seeds_manager.total_solving_time,
            "replay_time": self._replay_time_acc,
            "seed_accepted": self._seeds_merged,
            "seed_rejected": self._seeds_rejected,
            "seed_received": self._seeds_merged + self._seeds_rejected
        }
        stat_file.write_text(json.dumps(data))

    # ---
    # Auxiliary methods
    # ---

    def __seed_hash(self, seed: Seed) -> str:
        if seed.is_composite():
            if self.INPUT_FILE_NAME in seed.content.files:
                content = seed.content.files[self.INPUT_FILE_NAME]
            elif "stdin" in seed.content.files:
                content = seed.content.files["stdin"]
            else:
                raise NameError("Can't find main payload in the seed")
        else:
            content = seed.content

        return md5(content).hexdigest()

    def __from_raw_seed(self, raw_seed: bytes) -> Seed:
        """
        Convert a raw seed (sequence of bytes) into a seed whose type is
        consistent with the configuration's seed format.
        """
        seed = Seed.from_bytes(raw_seed)

        if not seed.is_raw():
            raise Exception("A raw seed was expected")

        if self._config.is_format_composite():
            logging.debug("Converting RAW seed to COMPOSITE")
            if self._seed_inj == SeedInjectLoc.ARGV:
                return Seed(CompositeData(files={self.INPUT_FILE_NAME: seed.content}))
            else:   # SeedInjectLoc.STDIN
                return Seed(CompositeData(files={"stdin": seed.content}))
        else:   # _config.is_raw()
            if self._seed_inj == SeedInjectLoc.ARGV:
                raise Exception("Invalid combination of seed injection and seed format")
            else:   # SeedInjectLoc.STDIN
                return seed

    def __to_raw_seed(self, seed: Seed) -> bytes:
        """
        Convert a seed (RAW or COMPOSITE) into a raw seed (sequence of bytes).
        """
        if self._seed_inj == SeedInjectLoc.ARGV:
            return seed.content.files[self.INPUT_FILE_NAME] if seed.is_composite() else seed.bytes()

        if self._seed_inj == SeedInjectLoc.STDIN:
            return seed.content.files["stdin"] if seed.is_composite() else seed.bytes()

    def __process_seed_received(self, seed: Seed) -> None:
        """
        This function is called when we receive a seed from the broker.

        :param seed: The seed
        :return: None
        """
        logging.info(f"Process seed received {self.__seed_hash(seed)} (pool: {self._seed_recvs_queue.qsize()})")

        try:
            if not self._tracing_enabled:
                # Accept all seeds.
                self._dse.add_input_seed(seed)
            else:
                # Try running the seed to know whether to keep it. Note that the
                # seed is re-run regardless of its status.
                coverage = self.__replay_seed(seed)

                self.__process_seed_coverage(coverage, seed, SeedType.INPUT)
        except AttributeError as e:
            # NOTE If reset() is call during the execution of this function,
            #      self.dse will be set to None and an AttributeError will occur.
            logging.warning(f"Receiving seeds while the DSE is not instantiated {e}")

        seed_receive_count = len(self._seed_recvs)
        seed_merge_rate = (self._seeds_merged / seed_receive_count) * 100
        seed_reject_rate = (self._seeds_rejected / seed_receive_count) * 100
        seed_processed = self._seeds_merged + self._seeds_rejected
        seed_pending = seed_receive_count - seed_processed
        seed_pending_rate = (seed_pending / seed_receive_count) * 100

        logging.info(f"Seeds received: {seed_receive_count} | "
                     f"merged {self._seeds_merged} [{seed_merge_rate:.2f}%] "
                     f"rejected {self._seeds_rejected} [{seed_reject_rate:.2f}%] "
                     f"pending {seed_pending} [{seed_pending_rate:.2f}%]")

    def __replay_seed(self, seed: Seed) -> Optional[CoverageSingleRun]:
        coverage, replay_time = self._replayer.run(self.__to_raw_seed(seed))

        # Save time spent replaying inputs.
        self._replay_time_acc += replay_time

        logging.info(f'Replay time for seed {self.__seed_hash(seed)}: {replay_time:.02f}s')

        return coverage

    def __process_seed_coverage(self, coverage: Optional[CoverageSingleRun], seed: Seed, typ: SeedType) -> None:
        if not coverage:
            logging.warning(f"Coverage not found after replaying: {self.__seed_hash(seed)} [{typ.name}] (add it anyway)")

            # Add the seed anyway, if it was not possible to re-run the seed.
            # TODO Set seed.coverage_objectives as "empty" (use ellipsis
            # object). Modify WorklistAddressToSet to support it.
            self._dse.add_input_seed(seed)

            self._seeds_merged += 1
        else:
            # Check whether the seed improves the current coverage.
            if self._dse.coverage.improve_coverage(coverage):
                logging.info(f"Seed added {self.__seed_hash(seed)} [{typ.name}] (coverage merged)")

                self._dse.coverage.merge(coverage)
                self._dse.seeds_manager.worklist.update_worklist(coverage)

                seed.coverage_objectives = self._dse.coverage.new_items_to_cover(coverage)

                self._dse.add_input_seed(seed)

                self._seeds_merged += 1
            else:
                logging.info(f"Seed rejected {self.__seed_hash(seed)} [{typ.name}] (NOT merging coverage)")

                self._seeds_rejected += 1

    def __add_seed(self, raw_seed: bytes):
        seed = self.__from_raw_seed(raw_seed)
        seed_hash = self.__seed_hash(seed)

        if seed_hash in self._seed_recvs:
            logging.warning(f"Receiving already known seed: {self.__seed_hash(seed)} (dropped)")
            return

        # Remember seeds received, so we do not send them back to the broker.
        self._seed_recvs.add(seed_hash)

        # Enqueue seed to be process (either add it directly to the dse or
        # replay it).
        self._seed_recvs_queue.put(seed)

        logging.info(f"Seed received {self.__seed_hash(seed)} (pool: {self._seed_recvs_queue.qsize()})")

    def __send_seed(self, seed: Seed) -> None:
        status_mapper = {
            SeedStatus.CRASH: SeedType.CRASH,
            SeedStatus.FAIL: SeedType.HANG,
            SeedStatus.HANG: SeedType.HANG,
            SeedStatus.NEW: SeedType.INPUT,
            SeedStatus.OK_DONE: SeedType.INPUT,
        }

        seed_hash = self.__seed_hash(seed)

        # Do not send back a seed that already came from the broker.
        if seed_hash not in self._seed_recvs:
            if seed.status == SeedStatus.NEW:
                logging.info(f"Sending new seed: {self.__seed_hash(seed)} [{self._seeds_sent_count}]")

                # Only count new seeds.
                self._seeds_sent_count += 1

            self._agent.send_seed(status_mapper[seed.status], self.__to_raw_seed(seed))

    def __send_alert_data(self, alert, seed, address):
        self._agent.send_alert_data(AlertData(alert.id, alert.covered, alert.validated, seed.content, address))
