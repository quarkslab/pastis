# built-in imports
from typing import List, Tuple
import os
import time
import logging
from hashlib import md5
from pathlib import Path
import threading
import platform
import json
import queue

# third-party imports
from triton               import MemoryAccess, CPUSIZE

# Pastis & triton imports
import pastisdse
from tritondse            import Config, Program, CleLoader, CoverageStrategy, SymbolicExplorator, \
                                 SymbolicExecutor, ProcessState, ExplorationStatus, SeedStatus, ProbeInterface, \
                                 Workspace, Seed, CompositeData, SeedFormat, QuokkaProgram
from tritondse.sanitizers import FormatStringSanitizer, NullDerefSanitizer, UAFSanitizer, IntegerOverflowSanitizer, mk_new_crashing_seed
from tritondse.types      import Addr, Edge, SymExType, Architecture, Platform
from libpastis import ClientAgent, BinaryPackage, SASTReport
from libpastis.types      import SeedType, FuzzingEngineInfo, ExecMode, CoverageMode, SeedInjectLoc, CheckMode, LogLevel, AlertData, FuzzMode
from tritondse.trace      import QBDITrace, TraceException
from tritondse.worklist import FreshSeedPrioritizerWorklist, WorklistAddressToSet

def to_h(seed: Seed) -> str:
    if seed.is_composite():
        if PastisDSE.INPUT_FILE_NAME in seed.content.files:
            return md5(seed.content.files[PastisDSE.INPUT_FILE_NAME]).hexdigest()
        elif "stdin" in seed.content.files:
            return md5(seed.content.files["stdin"]).hexdigest()
        else:
            raise NameError("can't find main payload in Seed")
    else:
        return md5(seed.content).hexdigest()


class PastisDSE(object):

    INPUT_FILE_NAME = "input_file"
    STAT_FILE = "pastidse-stats.json"

    RAMDISK = "/mnt/ramdisk"
    TMP_SEED = "seed.seed"
    TMP_TRACE = "result.trace"

    def __init__(self, agent: ClientAgent):
        self.agent = agent
        self._init_callbacks()  # register callbacks on the given agent

        self.config = Config()
        self.config.workspace = ""  # Reset workspace so that it will computed in start_received
        self.dse        = None
        self.program    = None
        self._stop      = False
        self.sast_report= None
        self._last_id = None
        self._last_id_pc = None
        self._seed_received = set()
        self._probes = []
        self._chkmode = None
        self._seedloc = None
        self._program_slice = None
        self._tracing_enabled = False

        # local attributes for telemetry
        self.nb_to, self.nb_crash = 0, 0
        self._cur_cov_count = 0
        self._last_cov_update = time.time()
        self._seed_queue = queue.Queue()
        self._sending_count = 0
        self.seeds_merged = 0
        self.seeds_rejected = 0

        # Timing stats
        self._start_time = 0
        self._replay_acc = 0

        self.replay_trace_file, self.replay_seed_file = self._initialize_tmp_files()

    def _initialize_tmp_files(self) -> Tuple[Path, Path]:
        ramdisk = Path(self.RAMDISK)
        pid = os.getpid()
        if ramdisk.exists():  # there is a ramdisk available
            dir = ramdisk / f"triton_{pid}"
            dir.mkdir()
            logging.info(f"tmp directory set to: {dir}")
            return dir / self.TMP_TRACE, dir / self.TMP_SEED
        else:
            logging.info(f"tmp directory set to: /tmp")
            return Path(f"/tmp/triton_{pid}.trace"), Path("/tmp/triton_{pid}.seed")

    def add_probe(self, probe: ProbeInterface):
        self._probes.append(probe)

    def _init_callbacks(self):
        self.agent.register_seed_callback(self.seed_received)
        self.agent.register_stop_callback(self.stop_received)

    def init_agent(self, remote: str = "localhost", port: int = 5555):
        self.agent.register_start_callback(self.start_received) # register start because launched manually
        self.agent.connect(remote, port)
        self.agent.start()
        self.agent.send_hello([FuzzingEngineInfo("TRITON", pastisdse.__version__, "pastisttbroker")])

    def start(self):
        self._th = threading.Thread(target=self.run, daemon=True)
        self._th.start()

    def reset(self):
        """ Reset the current DSE to be able to restart from fresh settings """
        self.dse = None  # remove DSE object
        self.config = Config()
        self.config.workspace = ""  # Reset workspace so that it will computed in start_received
        self._last_id_pc = None
        self._last_id = None
        self.sast_report = None
        self._program_slice = None
        self._seed_received = set()
        self.program = None
        self._stop = False
        self._chkmode = None
        self._seedloc = None
        self.nb_to, self.nb_crash = 0, 0
        self._cur_cov_count = 0
        self._last_cov_update = time.time()
        self._tracing_enabled = False
        self._sending_count = 0
        self.seeds_merged = 0
        self.seeds_rejected = 0
        self._start_time = 0
        self._replay_acc = 0
        logging.info("DSE Ready")

    def run(self, online: bool, debug_pp: bool=False):

        # Run while we are not instructed to stop
        while not self._stop:

            if online:  # in offline start_received, seed_received will already have been called
                self.reset()

            # Just wait until the broker says let's go
            while self.dse is None:
                time.sleep(0.10)

            if debug_pp:
                def cb_debug(se, _):
                    se.debug_pp = True
                self.dse.callback_manager.register_pre_execution_callback(cb_debug)

            if not self.run_one(online):
                break

        self.agent.stop()

    def run_one(self, online: bool):
        # Run while we are not instructed to stop
        while not self._stop:

            # wait for seed event
            self._wait_seed_event()
            self._start_time = time.time()

            st = self.dse.explore()

            if not online:
                return False  # in offline whatever the status we stop

            else: # ONLINE
                if st == ExplorationStatus.STOPPED:  # if the exploration stopped just return
                    logging.info("exploration stopped")
                    return False
                elif st == ExplorationStatus.TERMINATED:
                    self.agent.send_stop_coverage_criteria()
                    return True  # Reset and wait for further instruction from the broker
                elif st == ExplorationStatus.IDLE:  # no seed
                    if self._chkmode == CheckMode.ALERT_ONE:
                        self.agent.send_stop_coverage_criteria()  # Warn: the broker we explored the whole search space and did not validated the target
                        return True                               # Make ourself ready to receive a new one
                    else: # wait for seed of peers
                        logging.info("exploration idle (worklist empty)")
                        self.agent.send_log(LogLevel.INFO, "exploration idle (worklist empty)")
                else:
                    logging.error(f"explorator not meant to be in state: {st}")
                    return False

            # Finished an exploration batch
            self.save_stats()  # Save stats

    def _wait_seed_event(self):
        logging.info("wait to receive seeds")
        while not self.dse.seeds_manager.seeds_available() and not self._stop:
            self.try_process_seed_queue()
            time.sleep(0.5)


    def cb_post_execution(self, se: SymbolicExecutor, state: ProcessState):
        """
        This function is called after each execution. In this function we verify
        the ABV_GENERAL alert when a crash occurred during the last execution.

        :param se: The current symbolic executor
        :param state: The current processus state of the execution
        :return: None
        """
        # Send seed that have been executed
        mapper = {SeedStatus.OK_DONE: SeedType.INPUT, SeedStatus.CRASH: SeedType.CRASH, SeedStatus.HANG: SeedType.HANG}
        seed = se.seed
        if seed.status == SeedStatus.NEW:
            logging.warning(f"seed is not meant to be NEW in post execution current:{seed.status.name}")
        elif seed.status in [SeedStatus.CRASH, SeedStatus.HANG]:  # The stats is new send it back again
            if seed not in self._seed_received:  # Do not send back a seed that already came from broker
                self.agent.send_seed(mapper[seed.status], seed.content.files[self.INPUT_FILE_NAME] if seed.is_composite() else seed.content)
        else:  # INPUT
            pass  # Do not send it back again

        # Update some stats
        if se.seed.status == SeedStatus.CRASH:
            self.nb_crash += 1
        elif se.seed.status == SeedStatus.HANG:
            self.nb_to += 1

        # Handle CRASH and ABV_GENERAL
        if se.seed.status == SeedStatus.CRASH and self._last_id:
            alert = self.sast_report.get_alert(self._last_id)
            if alert.type == "ABV_GENERAL":
                logging.info(f'A crash occured with an ABV_GENERAL encountered just before.')
                self.dual_log(LogLevel.INFO, f"Alert [{alert.id}] in {alert.file}:{alert.line}: {alert.type} validation [SUCCESS]")
                alert.validated = True
                self.agent.send_alert_data(AlertData(alert.id, alert.covered, alert.validated, se.seed.content, self._last_id_pc))

        # Process all the seed received
        self.try_process_seed_queue()

        # Print stats
        if self.sast_report:
            cov, va, tot = self.sast_report.get_stats()
            logging.info(f"SAST stats: defaults: [covered:{cov}/{tot}] [validated:{va}/{tot}]")

    def try_process_seed_queue(self):

        while not self._seed_queue.empty() and not self._stop:
            seed, typ = self._seed_queue.get()
            self._process_seed_received(typ, seed)

    def cb_telemetry(self, dse: SymbolicExplorator):
        """
        Callback called after each execution to send telemetry to the broker

        :param dse: SymbolicExplorator
        :return: None
        """
        new_count = dse.coverage.unique_covitem_covered

        if new_count != self._cur_cov_count:         # Coverage has been updated
            self._cur_cov_count = new_count          # update count
            self._last_cov_update = time.time()  # update last coverage update to be now

        if dse.coverage.strategy == CoverageStrategy.PREFIXED_EDGE:
            new_count = len(set(x[1] for x in dse.coverage.covered_items.keys()))  # For prefixed-edge only count edge

        self.agent.send_telemetry(exec_per_sec=int(dse.execution_count / (time.time()-dse.ts)),
                                  total_exec=dse.execution_count,
                                  timeout=self.nb_to,
                                  coverage_block=dse.coverage.unique_instruction_covered,
                                  coverage_edge=new_count if dse.coverage in [CoverageStrategy.EDGE, CoverageStrategy.PREFIXED_EDGE] else 0,
                                  coverage_path=new_count if dse.coverage.strategy == CoverageStrategy.PATH else 0,
                                  last_cov_update=int(self._last_cov_update))

    def cb_on_solving(self, dse: SymbolicExplorator, pstate: ProcessState, edge: Edge, typ: SymExType) -> bool:
        # Only consider conditional and dynamic jumps.
        if typ in [SymExType.SYMBOLIC_READ, SymExType.SYMBOLIC_WRITE]:
            return True

        # Unpack edge.
        src, dst = edge

        # Find the function which holds the basic block of the destination.
        dst_fn = self.program.find_function_from_addr(dst)
        if dst_fn is None:
            logging.warning("Solving edge ({src:#x} -> {dst:#x}) not in a function")
            return True
        else:
            if dst_fn.start in self._program_slice:
                return True
            else:
                logging.info(
                    f"Slicer: reject edge ({src:#x} -> {dst:#x} ({dst_fn.name}) not in slice!")
                return False

    def start_received(self, fname: str, binary: bytes, engine: FuzzingEngineInfo, exmode: ExecMode, fuzzmode: FuzzMode, chkmode: CheckMode,
                       covmode: CoverageMode, seed_inj: SeedInjectLoc, engine_args: str, argv: List[str], sast_report: str=None):
        """
        This function is called when the broker says to start the fuzzing session. Here, we receive all information about
        the program to fuzz and the configuration.

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
        :param sast_report: The SAST report
        :return: None
        """
        logging.info(f"[BROKER] [START] bin:{fname} engine:{engine.name} exmode:{exmode.name} cov:{covmode.name} chk:{chkmode.name}")

        if self.dse is not None:
            logging.warning("DSE already instanciated (override it)")

        if engine.version != pastisdse.__version__:
            logging.error(f"Pastis-DSE mismatch with one from the server {engine.version} (local: {pastisdse.__version__})")
            return

        self._seedloc = seed_inj

        # ------- Create the TritonDSE configuration file ---------
        if engine_args:
            self.config = Config.from_json(engine_args)
        else:
            self.config = Config()  # Empty configuration
            # Use argv ONLY if no configuration provided
            self.config.program_argv = [f"./{fname}"]
            if argv:
                self.config.program_argv.extend(argv) # Preprend the binary to argv

        """
        Actions taken depending on seed format & co:
        Config    |  Inject  |  Result
        RAW          STDIN      /
        COMPOSITE    STDIN      / (but need 'stdin' in files)
        RAW          ARGV       change to COMPOSITE to be able to inject on argv (and convert seeds on the fly)
        COMPOSITE    ARGV       / (but need 'input_file' in files)
        """
        if seed_inj == SeedInjectLoc.ARGV:  # Make sure we inject input on argv
            if self.config.is_format_raw():
                logging.warning("injection is ARGV thus switch config seed format to COMPOSITE")
                self.config.seed_format = SeedFormat.COMPOSITE
            if "@@" in self.config.program_argv:
                idx = self.config.program_argv.index("@@")
                self.config.program_argv[idx] = self.INPUT_FILE_NAME
            else:
                logging.warning(f"seed inject {self._seedloc.name} but no '@@' found in argv (will likely not work!)")
        else:  # SeedInjectLoc.STDIN
            if engine_args:
                if self.config.is_format_composite():
                    self.dual_log(LogLevel.WARNING, "injecting on STDIN but seed format is COMPOSITE")
            else:  # no config was provided just override
                self.config.seed_format = SeedFormat.RAW
            pass  # nothing to do ?
        # ----------------------------------------------------------

        # If a workspace is given keep it other generate new unique one
        if not self.config.workspace:
            ws = f"/tmp/triton_workspace/{int(time.time())}"
            logging.info(f"Configure workspace to be: {ws}")
            self.config.workspace = ws

        # Create the workspace object in advance (to directly save the binary inside
        workspace = Workspace(self.config.workspace)
        workspace.initialize(flush=False)

        try:
            pkg = BinaryPackage.from_binary(fname, binary, workspace.get_binary_directory())
        except FileNotFoundError:
            logging.error("Invalid package data")
            return

        if pkg.is_quokka():
            logging.info(f"load QuokkaProgram: {pkg.quokka.name}")
            self.program = QuokkaProgram(pkg.quokka, pkg.executable_path)
        else:
            logging.info(f"load Program: {pkg.executable_path.name} [{self._seedloc.name}]")
            program = Program(pkg.executable_path)

            # Make sure the Program is compatible with the local platform
            if self.is_compatible_with_local(program):
                self.program = CleLoader(pkg.executable_path)
            else:
                self.program = program

        if self.program is None:
            self.dual_log(LogLevel.CRITICAL, f"LIEF was not able to parse the binary file {fname}")
            self.agent.stop()
            return

        # Enable local tracing if the binary is compatible with local architecture
        self._tracing_enabled = self.is_compatible_with_local(self.program)
        logging.info(f"Local arch and program arch matching: {self._tracing_enabled}")

        # Update the coverage strategy in the current config (it overrides the config file one)
        try:
            self.config.coverage_strategy = CoverageStrategy(covmode.value)  # names are meant to match
        except Exception as e:
            logging.info(f"Invalid covmode. Not supported by the tritondse library {e}")
            self.agent.stop()
            return

        if sast_report:
            self.sast_report = SASTReport.from_json(sast_report)
            logging.info(f"SAST report loaded: alerts:{len(list(self.sast_report.iter_alerts()))}")

        # Set seed scheduler based on whether tracing is enabled.
        if self._tracing_enabled:
            seed_scheduler_class = WorklistAddressToSet
        else:
            seed_scheduler_class = FreshSeedPrioritizerWorklist

        dse = SymbolicExplorator(self.config, self.program, workspace=workspace, seed_scheduler_class=seed_scheduler_class)

        # Register common callbacks
        dse.callback_manager.register_new_input_callback(self.send_seed_to_broker) # must be the second cb
        dse.callback_manager.register_post_execution_callback(self.cb_post_execution)
        dse.callback_manager.register_exploration_step_callback(self.cb_telemetry)

        for probe in self._probes:
            dse.callback_manager.register_probe(probe)

        # Save check mode
        self._chkmode = chkmode

        if chkmode == CheckMode.CHECK_ALL:
           dse.callback_manager.register_probe(UAFSanitizer())
           dse.callback_manager.register_probe(NullDerefSanitizer())
           dse.callback_manager.register_probe(FormatStringSanitizer())
           #dse.callback_manager.register_probe(IntegerOverflowSanitizer())
           # TODO Buffer overflow

        elif chkmode == CheckMode.ALERT_ONLY:
           dse.callback_manager.register_function_callback('__sast_alert_placeholder', self.intrinsic_callback)

        elif chkmode == CheckMode.ALERT_ONE:  # targeted approach
            if not isinstance(self.program, QuokkaProgram):
                logging.error(f"Targeted mode [{chkmode.name}] requires a Quokka program")
                self.agent.stop()
                return

            target_addr = self.config.custom['target']  # retrieve the target address to reach
            dse.callback_manager.register_post_addr_callback(target_addr, self.intrinsic_callback)

            # NOTE Target address must be the starting address of a basic block.
            slice_from = self.program.find_function_addr('main')
            slice_to = target_addr

            if slice_from and slice_to:
                # Find the functions that correspond to the from and to addresses.
                slice_from_fn = self.program.find_function_from_addr(slice_from)
                slice_to_fn = self.program.find_function_from_addr(slice_to)
                logging.info(f"launching exploration in targeted mode on: 0x{target_addr:08x} in {slice_to_fn.name}")

                if slice_from_fn and slice_to_fn:
                    # NOTE Generate call graph with backedges so when we do the
                    #      slice it also includes functions that are called in
                    #      the path from the source to the destination of the
                    #      slice.
                    call_graph = self.program.get_call_graph(backedge_on_ret=True)

                    logging.info(f'Slicing program from {slice_from:#x} ({slice_from_fn.name}) to {slice_to:#x} ({slice_to_fn.name})')

                    self._program_slice = QuokkaProgram.get_slice(call_graph, slice_from_fn.start, slice_to_fn.start)

                    logging.info(f'Call graph (full): #nodes: {len(call_graph.nodes)}, #edges: {len(call_graph.edges)}')
                    logging.info(f'Call graph (sliced): #nodes: {len(self._program_slice.nodes)}, #edges: {len(self._program_slice.edges)}')

                    dse.callback_manager.register_on_solving_callback(self.cb_on_solving)
                else:
                    logging.warning(f'Invalid source or target function, skipping slicing!')
            else:
                logging.warning(f'Invalid source or target addresses, skipping slicing!')

        # will trigger the dse to start has another thread is waiting for self.dse to be not None
        self.dse = dse

    def _get_seed(self, raw_seed: bytes) -> Seed:
        # Convert seed to CompositeData
        seed = Seed.from_bytes(raw_seed)

        if self.config.is_format_composite() and seed.is_raw() and self._seedloc == SeedInjectLoc.ARGV:
            logging.debug("convert raw seed to composite")
            return Seed(CompositeData(files={self.INPUT_FILE_NAME: seed.content}))

        elif self.config.is_format_composite() and seed.is_raw() and self._seedloc == SeedInjectLoc.STDIN:
            logging.warning("Seed is RAW but format is COMPOSITE with injection on STDIN")
            return Seed(CompositeData(files={"stdin": seed.content}))

        else:
            return seed

    def seed_received(self, typ: SeedType, seed: bytes):
        """
        This function is called when we receive a seed from the broker.

        :param typ: The type of the seed
        :param seed: The seed
        :return: None
        """
        seed = self._get_seed(seed)

        if seed in self._seed_received:
            logging.warning(f"receiving seed already known: {to_h(seed)} (dropped)")
            return
        else:
            self._seed_queue.put((seed, typ))
            logging.info(f"seed received {to_h(seed)} (pool: {self._seed_queue.qsize()})")


    def _process_seed_received(self, typ: SeedType, seed: Seed):
        """
        This function is called when we receive a seed from the broker.

        :param typ: The type of the seed
        :param seed: The seed
        :return: None
        """
        try:
            if not self._tracing_enabled:
                # Accept all seeds
                self.dse.add_input_seed(seed)

            else:  # Try running the seed to know whether to keep it
                # NOTE: re-run the seed regardless of its status
                coverage = None
                logging.info(f"process seed received {to_h(seed)} (pool: {self._seed_queue.qsize()})")

                data = seed.content.files[self.INPUT_FILE_NAME] if seed.is_composite() else seed.bytes()
                self.replay_seed_file.write_bytes(data)
                # Adjust injection location before calling QBDITrace
                if self._seedloc == SeedInjectLoc.STDIN:
                    stdin_file = str(self.replay_seed_file)
                    argv = self.config.program_argv
                else:  # SeedInjectLoc.ARGV
                    stdin_file = None
                    try:
                        # Replace 'input_file' in argv with the temporary file name created
                        argv = self.config.program_argv[:]
                        idx = argv.index(self.INPUT_FILE_NAME)
                        argv[idx] = str(self.replay_seed_file)
                    except ValueError:
                        logging.error(f"seed injection {self._seedloc.name} but can't find 'input_file' on program argv")
                        return

                try:
                    # Run the seed and determine whether it improves our current coverage.
                    t0 = time.time()
                    if QBDITrace.run(self.config.coverage_strategy,
                                          str(self.program.path.resolve()),
                                          argv[1:] if len(argv) > 1 else [],
                                          output_path=str(self.replay_trace_file),
                                          stdin_file=stdin_file,
                                          cwd=Path(self.program.path).parent,
                                          timeout=60):
                        coverage = QBDITrace.from_file(str(self.replay_trace_file)).coverage
                    else:
                        logging.warning("Cannot load the coverage file generated (maybe had crashed?)")
                        coverage = None
                    self._replay_acc += time.time() - t0  # Save time spent replaying inputs
                except FileNotFoundError:
                    logging.warning("Cannot load the coverage file generated (maybe had crashed?)")
                except TraceException:
                    logging.warning('There was an error while trying to re-run the seed')

                if not coverage:
                    logging.warning(f"coverage not found after replaying: {to_h(seed)} [{typ.name}] (add it anyway)")
                    # Add the seed anyway, if it was not possible to re-run the seed.
                    # TODO Set seed.coverage_objectives as "empty" (use ellipsis
                    # object). Modify WorklistAddressToSet to support it.
                    self.seeds_merged += 1
                    self.dse.add_input_seed(seed)
                else:
                    # Check whether the seed improves the current coverage.
                    if self.dse.coverage.improve_coverage(coverage):
                        logging.info(f"seed added {to_h(seed)} [{typ.name}] (coverage merged)")
                        self.seeds_merged += 1
                        self.dse.coverage.merge(coverage)
                        self.dse.seeds_manager.worklist.update_worklist(coverage)

                        seed.coverage_objectives = self.dse.coverage.new_items_to_cover(coverage)
                        self.dse.add_input_seed(seed)
                    else:
                        logging.info(f"seed archived {to_h(seed)} [{typ.name}] (NOT merging coverage)")
                        self.seeds_rejected += 1
                        #self.dse.seeds_manager.archive_seed(seed)
                        # logging.info(f"seed archived {seed.hash} [{typ.name}]")

            self._seed_received.add(seed)  # Remember seed received not to send them back
        except FileNotFoundError as e:
            # NOTE If reset() is call during the execution of this function,
            #      self.dse will be set to None and an AttributeError will occur.
            logging.warning(f"receiving seeds while the DSE is not instantiated {e}")

        rcv = len(self._seed_received)
        logging.info(f"seeds recv: {rcv} | merged {self.seeds_merged} [{(self.seeds_merged/rcv) * 100:.2f}%]"
                     f" rejected {self.seeds_rejected} [{(self.seeds_rejected/rcv) * 100:.2f}%]")

    def stop_received(self):
        """
        This function is called when the broker says stop. (Called from the agent thread)
        """
        logging.info(f"[BROKER] [STOP]")

        if self.dse:
            self.dse.stop_exploration()

            self.save_stats()  # Save stats

        self._stop = True
        # self.agent.stop()  # Can't call it here as this function executed from within agent thread

    def save_stats(self):
        stat_file = self.dse.workspace.get_metadata_file_path(self.STAT_FILE)
        data = {
            "total_time": time.time() - self._start_time,
            "emulation_time": self.dse.total_emulation_time,  # Note: includes replay time but not solving
            "solving_time": self.dse.seeds_manager.total_solving_time,
            "replay_time": self._replay_acc,
            "seed_accepted": self.seeds_merged,
            "seed_rejected": self.seeds_rejected,
            "seed_received": self.seeds_merged + self.seeds_rejected
        }
        stat_file.write_text(json.dumps(data))

    def dual_log(self, level: LogLevel, message: str) -> None:
        """
        Helper function to log message both in the local log system and also
        to the broker.

        :param level: LogLevel message type
        :param message: string message to log
        :return: None
        """
        mapper = {LogLevel.DEBUG: "debug",
                  LogLevel.INFO: "info",
                  LogLevel.CRITICAL: "critical",
                  LogLevel.WARNING: "warning",
                  LogLevel.ERROR: "error"}
        log_f = getattr(logging, mapper[level])
        log_f(message)
        self.agent.send_log(level, message)

    def send_seed_to_broker(self, se: SymbolicExecutor, state: ProcessState, seed: Seed):
        if seed not in self._seed_received:  # Do not send back a seed that already came from broker
            self._sending_count += 1
            logging.info(f"Sending new: {to_h(seed)} [{self._sending_count}]")
            bytes = seed.content.files[self.INPUT_FILE_NAME] if seed.is_composite() else seed.content
            self.agent.send_seed(SeedType.INPUT, bytes)

    def intrinsic_callback(self, se: SymbolicExecutor, state: ProcessState, addr: Addr):
        """
        This function is called when an intrinsic call occurs in order to verify
        defaults and vulnerabilities.

        :param se: The current symbolic executor
        :param state: The current processus state of the execution
        :param addr: The instruction address of the intrinsic call
        :return: None
        """
        alert_id = state.get_argument_value(0)
        self._last_id = alert_id
        self._last_id_pc = se.previous_pc

        def status_changed(a, cov, vld):
            return a.covered != cov or a.validated != vld

        if self.sast_report:
            # Retrieve the SASTAlert object from the report
            try:
                alert = self.sast_report.get_alert(alert_id)
                cov, vld = alert.covered, alert.validated
            except IndexError:
                logging.warning(f"Intrinsic id {alert_id} not found in report (ignored)")
                return

            if not alert.covered:
                self.dual_log(LogLevel.INFO, f"Alert [{alert.id}] in {alert.file}:{alert.line}: {alert.type} covered !")
                alert.covered = True  # that might also set validated to true!

            if not alert.validated:  # If of type VULNERABILITY and not yet validated
                res = self.check_alert_dispatcher(alert.code, se, state, addr)
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
                self.agent.send_alert_data(AlertData(alert.id, alert.covered, alert.validated, se.seed.content, se.previous_pc))
                cov, vals, tot = self.sast_report.get_stats()
                logging.info(f"SAST stats: defaults: [covered:{cov}/{tot}] [validated:{vals}/{tot}]")

                if self.sast_report.all_alerts_validated() or (self._chkmode == CheckMode.ALERT_ONE and alert.validated):
                    self._do_stop_all_alerts_validated()

        else:  # Kind of autonomous mode. Try to check it even it is not bound to a report
            # Retrieve alert type from parameters
            alert_type = se.pstate.get_string_argument(1)
            try:
                if self.check_alert_dispatcher(alert_type, se, state, addr):
                    logging.info(f"Alert {alert_id} of type {alert_type} [VALIDATED]")
                else:
                    logging.info(f"Alert {alert_id} of type {alert_type} [NOT VALIDATED]")
            except KeyError:
                logging.error(f"Alert type {alert_type} not recognized")


    def check_alert_dispatcher(self, type: str, se: SymbolicExecutor, state: ProcessState, addr: Addr) -> bool:
        """
        This function is called by intrinsic_callback in order to verify defaults
        and vulnerabilities.

        :param type: Type of the alert as a string
        :param se: The current symbolic executor
        :param state: The current processus state of the execution
        :param addr: The instruction address of the intrinsic call
        :return: True if a vulnerability has been verified
        """
        # BUFFER_OVERFLOW related alerts
        if type == "SV_STRBO_UNBOUND_COPY":
            size = se.pstate.get_argument_value(2)
            ptr = se.pstate.get_argument_value(3)

            # Runtime check
            if len(se.pstate.get_memory_string(ptr)) >= size:
                # FIXME: Do we have to define the seed as CRASH even if there is no crash?
                # FIXME: Maybe we have to define a new TAG like BUG or VULN or whatever
                return True

            # Symbolic check
            actx = se.pstate.actx
            predicate = [se.pstate.tt_ctx.getPathPredicate()]

            # For each memory cell, try to proof that they can be different from \0
            for i in range(size + 1): # +1 in order to proof that we can at least do an off-by-one
                cell = se.pstate.tt_ctx.getMemoryAst(MemoryAccess(ptr + i, CPUSIZE.BYTE))
                predicate.append(cell != 0)

            # FIXME: Maybe we can generate models until unsat in order to find the bigger string

            model = se.pstate.tt_ctx.getModel(actx.land(predicate))
            if model:
                crash_seed = mk_new_crashing_seed(se, model)
                se.workspace.save_seed(crash_seed)
                logging.info(f'Model found for a seed which may lead to a crash ({crash_seed.filename})')
                return True

            return False

        ######################################################################

        # BUFFER_OVERFLOW related alerts
        elif type == "SV_STRBO_BOUND_COPY_OVERFLOW":
            dst_size = se.pstate.get_argument_value(2)
            ptr_inpt = se.pstate.get_argument_value(3)
            max_size = se.pstate.get_argument_value(4)

            # Runtime check
            if max_size >= dst_size and len(se.pstate.get_memory_string(ptr_inpt)) >= dst_size:
                # FIXME: Do we have to define the seed as CRASH even if there is no crash?
                # FIXME: Maybe we have to define a new TAG like BUG or VULN or whatever
                return True

            # Symbolic check
            actx = se.pstate.actx
            max_size_s = se.pstate.get_argument_symbolic(4).getAst()
            predicate = [se.pstate.tt_ctx.getPathPredicate(), max_size_s >= dst_size]

            # For each memory cell, try to proof that they can be different from \0
            for i in range(dst_size + 1): # +1 in order to proof that we can at least do an off-by-one
                cell = se.pstate.tt_ctx.getMemoryAst(MemoryAccess(ptr_inpt + i, CPUSIZE.BYTE))
                predicate.append(cell != 0)

            # FIXME: Maybe we can generate models until unsat in order to find the bigger string

            model = se.pstate.tt_ctx.getModel(actx.land(predicate))
            if model:
                crash_seed = mk_new_crashing_seed(se, model)
                se.workspace.save_seed(crash_seed)
                logging.info(f'Model found for a seed which may lead to a crash ({crash_seed.filename})')
                return True

            return False

        ######################################################################

        # BUFFER_OVERFLOW related alerts
        elif type == "ABV_GENERAL":
            logging.warning(f'ABV_GENERAL encounter but can not check the issue. This issue will be handle if the program will crash.')
            return False

        ######################################################################

        # All INTEGER_OVERFLOW related alerts
        elif type == "NUM_OVERFLOW":
            return IntegerOverflowSanitizer.check(se, state, state.current_instruction)

        ######################################################################

        # All USE_AFTER_FREE related alerts
        elif type in ["UFM_DEREF_MIGHT", "UFM_FFM_MUST", "UFM_FFM_MIGHT"]:
            ptr = se.pstate.get_argument_value(2)
            return UAFSanitizer.check(se, state, ptr, f'UAF detected at {ptr:#x}')

        ######################################################################

        # All FORMAT_STRING related alerts
        elif type in ["SV_TAINTED_FMTSTR", "SV_FMTSTR_GENERIC"]:
            ptr = se.pstate.get_argument_value(2)
            return FormatStringSanitizer.check(se, state, addr, ptr)

        ######################################################################

        # All INVALID_MEMORY related alerts
        # FIXME: NPD_CHECK_MIGHT and NPD_CONST_CALL are not supported by klocwork-alert-inserter
        elif type in ["NPD_FUNC_MUST", "NPD_FUNC_MIGHT", "NPD_CHECK_MIGHT", "NPD_CONST_CALL"]:
            ptr = se.pstate.get_argument_value(2)
            return NullDerefSanitizer.check(se, state, ptr, f'Invalid memory access at {ptr:#x}')

        ######################################################################

        elif type == "MISRA_ETYPE_CATEGORY_DIFFERENT_2012":
            expr = se.pstate.get_argument_symbolic(2).getAst()

            # Runtime check
            if expr.isSigned():
                # FIXME: Do we have to define the seed as CRASH even if there is no crash?
                # FIXME: Maybe we have to define a new TAG like BUG or VULN or whatever
                return True

            # Symbolic check
            actx = se.pstate.tt_ctx.getAstContext()
            size = expr.getBitvectorSize() - 1
            predicate = [se.pstate.tt_ctx.getPathPredicate(), actx.extract(size - 1, size - 1, expr) == 1]

            model = se.pstate.tt_ctx.getModel(actx.land(predicate))
            if model:
                crash_seed = mk_new_crashing_seed(se, model)
                se.workspace.save_seed(crash_seed)
                logging.info(f'Model found for a seed which may lead to a crash ({crash_seed.filename})')
                return True
            return False

        else:
            logging.error(f"Unsupported alert kind {type}")


    def _do_stop_all_alerts_validated(self) -> None:
        """
        Function called if all alerts have been covered and validated. All data are meant to
        have been transmitted to the broker, but writes down locally the CSV anyway
        :return: None
        """
        logging.info("All defaults and vulnerability have been covered !")

        # Write the final CSV in the workspace directory
        out_file = self.dse.workspace.get_metadata_file_path("klocwork_coverage_results.csv")
        self.sast_report.write_csv(out_file)

        # Stop the dse exploration
        self.dse.terminate_exploration()


    def is_compatible_with_local(self, program: Program) -> bool:
        """
        Checks whether the given program is compatible with the current architecture
        and platform.

        :param program: Program
        :return: True if the program can be run locally
        """
        arch_m = {"i386": Architecture.X86, "x86_64": Architecture.X86_64, "armv7l": Architecture.ARM32, "aarch64": Architecture.AARCH64}
        plfm_m = {"Linux": Platform.LINUX, "Windows": Platform.WINDOWS, "MacOS": Platform.MACOS, "iOS": Platform.IOS}
        local_arch, local_plfm = arch_m[platform.machine()], plfm_m[platform.system()]
        return program.architecture == local_arch and program.platform == local_plfm
