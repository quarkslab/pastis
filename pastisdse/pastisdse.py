# built-in imports
from typing  import List, Tuple
from hashlib import md5
import time
import logging
import tempfile
from pathlib import Path
import threading

# third-party imports
import magic
import shutil

# Pastis & triton imports
import pastisdse
from triton               import MemoryAccess, CPUSIZE
from tritondse            import TRITON_VERSION, Config, Program, CoverageStrategy, SymbolicExplorator, SymbolicExecutor, ProcessState, ExplorationStatus, SeedStatus, ProbeInterface
from tritondse.sanitizers import FormatStringSanitizer, NullDerefSanitizer, UAFSanitizer, IntegerOverflowSanitizer, mk_new_crashing_seed
from tritondse.types      import Addr, Input
from tritondse.qbinexportprogram import QBinExportProgram
from libpastis.agent      import ClientAgent
from libpastis.types      import SeedType, FuzzingEngineInfo, ExecMode, CoverageMode, SeedInjectLoc, CheckMode, LogLevel, State, AlertData, FuzzMode
from klocwork             import KlocworkReport, KlocworkAlertType, PastisVulnKind


class PastisDSE(object):

    def __init__(self, agent: ClientAgent):
        self.agent = agent
        self._init_callbacks()  # register callbacks on the given agent

        self.config     = Config(debug=False)
        self.config.workspace = ""  # Reset workspace so that it will computed in start_received
        self.dse        = None
        self.program    = None
        self._stop      = False
        self.klreport   = None
        self._last_kid  = None
        self._seed_wait = False
        self._seed_received = set()
        self._probes = []
        self._chkmode = None

        # local attributes for telemetry
        self.nb_to, self.nb_crash = 0, 0
        self._cur_cov_count = 0
        self._last_cov_update = time.time()

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


    def run(self, wait_idle=True):
        """
        This function does the exploration while a stop is received
        from the broker.
        """
        # Just wait until the broker says let's go
        while self.dse is None:
            time.sleep(0.10)

        # Run while we are not instructed to stop
        while not self._stop:
            st = self.dse.explore()
            if st == ExplorationStatus.STOPPED:  # if the exploration stopped just return
                break
            elif st == ExplorationStatus.IDLE:
                if wait_idle:  # if we want to wait for seeds just wait to receive one
                    logging.info("exploration idle (worklist empty)")
                    self.agent.send_log(LogLevel.INFO, "exploration idle (worklist empty)")
                    self._wait_seed_event()
                else:
                    break  # Just break and exit
            else:
                logging.error(f"explorator not meant to be in state: {st}")
                break

        # Exited loop because received stop (from broker)
        self.agent.stop()


    def _wait_seed_event(self):
        self._seed_wait = True
        while self._seed_wait and not self._stop:
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
        else:
            if seed.content not in self._seed_received:  # Do not send back a seed that already came from broker
                self.agent.send_seed(mapper[seed.status], seed.content)

        # Update some stats
        if se.seed.status == SeedStatus.CRASH:
            self.nb_crash += 1
        elif se.seed.status == SeedStatus.HANG:
            self.nb_to += 1

        # Handle CRASH and ABV_GENERAL
        if se.seed.status == SeedStatus.CRASH and self._last_kid:
            alert = self.klreport.get_alert(binding_id=self._last_kid)
            if alert.code == KlocworkAlertType.ABV_GENERAL:
                logging.info(f'A crash occured with an ABV_GENERAL encountered just before.')
                self.dual_log(LogLevel.INFO, f"Alert [{alert.id}] in {alert.file}:{alert.line}: {alert.code.name} validation [SUCCESS]")
                alert.validated = True
                self.agent.send_alert_data(AlertData(alert.id, alert.covered, alert.validated, se.seed.content))

        # Print stats
        if self.klreport:
            d, v = self.klreport.get_stats()
            logging.info(f"Klocwork stats: defaults: [cov:{d.checked}/{d.total}] vulns: [check:{v.checked}/{v.total}]")

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

    def get_files(self, name: str, binary: bytes) -> List[Path]:
        """
        Analyse the binary blob received. If its an archive, extract it and return
        the list of files. Files are extracted in /tmp. If directly an executable
        save it to a file and return its path.

        :param name: name of executable, or executable name in archive
        :param binary: content
        :return: list of file paths
        """
        mime = magic.from_buffer(binary, mime=True)

        tmp_dir = Path(tempfile.mkdtemp())

        if mime in ['application/x-tar', 'application/zip']:
            map = {'application/x-tar': '.tar.gz', 'application/zip': '.zip'}
            tmp_file = Path(tempfile.mktemp(suffix=map[mime]))
            tmp_file.write_bytes(binary)          # write the archive in a file
            shutil.unpack_archive(tmp_file.as_posix(), tmp_dir)  # unpack it in dst directory
            return list(tmp_dir.iterdir())
        elif mime in ['application/x-pie-executable', 'application/x-dosexec', 'application/x-mach-binary', 'application/x-executable', 'application/x-sharedlib']:
            program_path = tmp_dir / name
            program_path.write_bytes(binary)
            return [program_path]
        else:
            logging.error(f"mimetype not recognized {mime}")
            return []

    def start_received(self, fname: str, binary: bytes, engine: FuzzingEngineInfo, exmode: ExecMode, fuzzmode: FuzzMode, chkmode: CheckMode,
                       covmode: CoverageMode, seed_inj: SeedInjectLoc, engine_args: str, argv: List[str], kl_report: str=None):
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
        :param kl_report: The Klocwork report
        :return: None
        """
        logging.info(f"[BROKER] [START] bin:{fname} engine:{engine.name} exmode:{exmode.name} cov:{covmode.name} chk:{chkmode.name}")

        if engine.version != pastisdse.__version__:
            logging.error(f"Pastis-DSE mismatch with one from the server {engine.version} (local: {pastisdse.__version__})")
            return

        # Parse triton specific parameters and update conf if needed
        if engine_args:
            self.config = Config.from_json(engine_args)
            logging.root.level = logging.DEBUG if self.config.debug else logging.INFO  # dynamically change level

        # If a workspace is given keep it other generate new unique one
        if not self.config.workspace:
            ws = f"/tmp/triton_workspace/{int(time.time())}"
            logging.info(f"Configure workspace to be: {ws}")
            self.config.workspace = ws

        # Retrieve one or multiple files out of the binary data
        files = self.get_files(fname, binary)
        if not files:
            logging.error(f"unrecognized file type for {fname}")
            return

        f_path = [x for x in files if x.name == fname][0]

        qbexp_path = f_path.with_suffix(".QBinExport")
        if qbexp_path in files:
            logging.info(f"load QBinExportProgram: {qbexp_path.name}")
            self.program = QBinExportProgram(qbexp_path, f_path)
        else:
            logging.info(f"load Program: {f_path.name}")
            self.program = Program(f_path)

        if self.program is None:
            self.dual_log(LogLevel.CRITICAL, f"LIEF was not able to parse the binary file {fname}")
            self.agent.stop()
            return

        # Update the coverage strategy in the current config (it overrides the config file one)
        try:
            self.config.coverage_strategy = CoverageStrategy(covmode.value)  # names are meant to match
        except Exception as e:
            logging.info(f"Invalid covmode. Not supported by the tritondse library {e}")
            self.agent.stop()
            return

        if seed_inj == SeedInjectLoc.STDIN:
            self.config.symbolize_stdin = True
        else:
            logging.info(f"Invalid seed_inj. Not supported by the tritondse library")
            self.agent.stop()
            return

        if kl_report:
            self.klreport = KlocworkReport.from_json(kl_report)
            if not self.klreport.has_binding():
                logging.info("Klocwork report not binded (bind it automatically)")
                self.klreport.auto_bind()
            logging.info(f"Klocwork report loaded: counted alerts:{len(list(self.klreport.counted_alerts))} (total:{len(self.klreport.alerts)})")

        if argv: # Override config
            self.config.program_argv = [str(self.program.path)]  # Set current binary
            self.config.program_argv.extend(argv)

        dse = SymbolicExplorator(self.config, self.program)

        # Copy all files extracted in workspace
        for file in [x for x in files if x != self.program.path]:  # Copy all files but the binary (which has already been moved)
            dse.workspace.save_file(file.name, file.read_bytes())

        # Register common callbacks
        # dse.callback_manager.register_new_input_callback(self.send_seed_to_broker) # must be the second cb
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
           dse.callback_manager.register_function_callback('__klocwork_alert_placeholder', self.intrinsic_callback)

        elif chkmode == CheckMode.ALERT_ONE:  # targeted approach
            if not isinstance(self.program, QBinExportProgram):
                logging.error(f"Targeted mode [{chkmode.name}] requires a QBinExport program")
                self.agent.stop()
                return

            target_addr = self.config.custom['target']  # retrieve the target address to reach
            dse.callback_manager.register_post_addr_callback(target_addr, self.intrinsic_callback)

            logging.info(f"launching exploration in targeted mode on: 0x{target_addr:08x}")

            # TODO: Initializing the slice and anything needed !


        # will trigger the dse to start has another thread is waiting for self.dse to be not None
        self.dse = dse

    def seed_received(self, typ: SeedType, seed: bytes):
        """
        This function is called when we receive a seed from the broker.

        :param typ: The type of the seed
        :param seed: The seed
        :param origin: The origin of the mutation (Triton or HF)
        :return: None
        """
        if seed in self._seed_received:
            logging.warning(f"receiving seed already known: {md5(seed).hexdigest()} (dropped)")
            return

        logging.info(f"seed received {md5(seed).hexdigest()} [{typ.name}]")

        self._seed_received.add(seed)  # Remember seed received not to send them back

        # TODO: Handle INPUT, CRASH ou HANGS
        if self.dse:
            self.dse.add_input_seed(seed)
        else:
            logging.warning("receiving seeds while the DSE is not instanciated")
        self._seed_wait = False  # Unlock the run() thread if it was waiting for a seed


    def stop_received(self):
        """
        This function is called when the broker says stop. (Called from the agent thread)
        """
        logging.info(f"[BROKER] [STOP]")
        self.stop()


    def stop(self):
        if self.dse:
            self.dse.stop_exploration()
        self._stop = True
        # self.agent.stop()  # Can't call it here as this function executed from within agent thread


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


    # def send_seed_to_broker(self, se: SymbolicExecutor, state: ProcessState, seed: Input):
    #     self.agent.send_seed(SeedType.INPUT, bytes(seed), FuzzingEngine.TRITON)
    #     return


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
        self._last_kid = alert_id
        covered, validated = False, False
        if self.klreport:
            # Retrieve the KlocworkAlert object from the report
            try:
                alert = self.klreport.get_alert(binding_id=alert_id)
            except IndexError:
                logging.warning(f"Intrinsic id {alert_id} not binded in report (ignored)")
                return

            if not alert.covered:
                self.dual_log(LogLevel.INFO, f"Alert [{alert.id}] in {alert.file}:{alert.line}: {alert.code.name} covered ! ({alert.kind.name})")
                alert.covered = True
                covered = True

            if alert.kind == PastisVulnKind.VULNERABILITY and not alert.validated:  # If of type VULNERABILITY and not yet validated
                res = self.check_alert_dispatcher(alert.code, se, state, addr)
                if res:
                    alert.validated = True
                    self.dual_log(LogLevel.INFO, f"Alert [{alert.id}] in {alert.file}:{alert.line}: {alert.code.name} validation [SUCCESS]")
                    validated = True
                    if se.seed.is_status_set():
                        logging.warning(f"Status already set ({se.seed.status}) for seed {se.seed.hash} (override with CRASH)")
                    se.seed.status = SeedStatus.CRASH  # Mark the seed as crash, as it validates an alert
                else:
                    logging.info(f"Alert [{alert.id}] in {alert.file}:{alert.line}: validation [FAIL]")

            if covered or validated:  # If either coverage or validation were improved print stats
                # Send updates to the broker
                self.agent.send_alert_data(AlertData(alert.id, alert.covered, validated, se.seed.content))
                d, v = self.klreport.get_stats()
                logging.info(f"Klocwork stats: defaults: [cov:{d.checked}/{d.total}] vulns: [check:{v.checked}/{v.total}]")

            if self.klreport.all_alerts_validated() or (self._chkmode == CheckMode.ALERT_ONE and alert.validated):
                self._all_alerts_validated()

        else:  # Kind of autonomous mode. Try to check it even it is not bound to a report
            # Retrieve alert type from parameters
            alert_kind = se.pstate.get_string_argument(1)
            try:
                kind = KlocworkAlertType[alert_kind]
                if self.check_alert_dispatcher(kind, se, state, addr):
                    logging.info(f"Alert {alert_id} of type {kind.name} [VALIDATED]")
                else:
                    logging.info(f"Alert {alert_id} of type {kind.name} [NOT VALIDATED]")
            except KeyError:
                logging.error(f"Alert kind {alert_kind} not recognized")


    def check_alert_dispatcher(self, type: KlocworkAlertType, se: SymbolicExecutor, state: ProcessState, addr: Addr) -> bool:
        """
        This function is called by intrinsic_callback in order to verify defaults
        and vulnerabilities.

        :param se: The current symbolic executor
        :param state: The current processus state of the execution
        :param addr: The instruction address of the intrinsic call
        :return: True if a vulnerability has been verified
        """
        # BUFFER_OVERFLOW related alerts
        if type == KlocworkAlertType.SV_STRBO_UNBOUND_COPY:
            size = se.pstate.get_argument_value(2)
            ptr  = se.pstate.get_argument_value(3)

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
        elif type == KlocworkAlertType.SV_STRBO_BOUND_COPY_OVERFLOW:
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
        elif type == KlocworkAlertType.ABV_GENERAL:
            logging.warning(f'ABV_GENERAL encounter but can not check the issue. This issue will be handle if the program will crash.')
            return False

        ######################################################################

        # All INTEGER_OVERFLOW related alerts
        elif type == KlocworkAlertType.NUM_OVERFLOW:
            return IntegerOverflowSanitizer.check(se, state, state.current_instruction)

        ######################################################################

        # All USE_AFTER_FREE related alerts
        elif type in [KlocworkAlertType.UFM_DEREF_MIGHT, KlocworkAlertType.UFM_FFM_MUST, KlocworkAlertType.UFM_FFM_MIGHT]:
            ptr = se.pstate.get_argument_value(2)
            return UAFSanitizer.check(se, state, ptr, f'UAF detected at {ptr:#x}')

        ######################################################################

        # All FORMAT_STRING related alerts
        elif type in [KlocworkAlertType.SV_TAINTED_FMTSTR, KlocworkAlertType.SV_FMTSTR_GENERIC]:
            ptr = se.pstate.get_argument_value(2)
            return FormatStringSanitizer.check(se, state, addr, ptr)

        ######################################################################

        # All INVALID_MEMORY related alerts
        # FIXME: NPD_CHECK_MIGHT and NPD_CONST_CALL are not supported by klocwork-alert-inserter
        elif type in [KlocworkAlertType.NPD_FUNC_MUST, KlocworkAlertType.NPD_FUNC_MIGHT, KlocworkAlertType.NPD_CHECK_MIGHT, KlocworkAlertType.NPD_CONST_CALL]:
            ptr = se.pstate.get_argument_value(2)
            return NullDerefSanitizer.check(se, state, ptr, f'Invalid memory access at {ptr:#x}')

        ######################################################################

        elif type == KlocworkAlertType.MISRA_ETYPE_CATEGORY_DIFFERENT_2012:
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


    def _all_alerts_validated(self) -> None:
        """
        Function called if all alerts have been covered and validated. All data are meant to
        have been transmitted to the broker, but writes down locally the CSV anyway
        :return: None
        """
        logging.info("All defaults and vulnerability have been covered !")
        self.agent.send_stop_coverage_criteria()  # FIXME: Not sure anymore it makes sense ?

        # Write the final CSV in the workspace directory
        out_file = self.dse.workspace.get_metadata_file_path("klocwork_coverage_results.csv")
        self.klreport.write_csv(out_file)

        # Stop the dse exploration
        self.dse.stop_exploration()
