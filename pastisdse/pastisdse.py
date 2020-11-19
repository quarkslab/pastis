# built-in imports
from typing  import List
from hashlib import md5
import time
import logging
import tempfile
from pathlib import Path

# third-party imports
from scapy.all          import Ether, IP, TCP, UDP, ICMP
from scapy.contrib.igmp import IGMP

# Pastis & triton imports
from triton               import MemoryAccess, CPUSIZE
from tritondse            import TRITON_VERSION, Config, Program, CoverageStrategy, SymbolicExplorator, SymbolicExecutor, ProcessState, ExplorationStatus, SeedStatus
from tritondse.sanitizers import FormatStringSanitizer, NullDerefSanitizer, UAFSanitizer, IntegerOverflowSanitizer, mk_new_crashing_seed
from tritondse.types      import Addr, Input
from libpastis.agent      import ClientAgent
from libpastis.types      import SeedType, FuzzingEngine, ExecMode, CoverageMode, SeedInjectLoc, CheckMode, LogLevel, State, AlertData
from klocwork             import KlocworkReport, KlocworkAlertType, PastisVulnKind


class PastisDSE(object):

    def __init__(self, agent: ClientAgent):
        self.agent = agent
        self._init_callbacks()  # register callbacks on the given agent

        self.config     = Config(debug=False)
        self.dse        = None
        self.program    = None
        self.stop       = False
        self.klreport   = None
        self._last_kid  = None
        self._seed_lock = False
        self._seed_received = set()


    def _init_callbacks(self):
        self.agent.register_start_callback(self.start_received)
        self.agent.register_seed_callback(self.seed_received)
        self.agent.register_stop_callback(self.stop_received)


    def init_agent(self, remote: str = "localhost", port: int = 5555):
        self.agent.connect(remote, port)
        self.agent.start()
        self.agent.send_hello([(FuzzingEngine.TRITON, TRITON_VERSION)])


    def run(self, wait_idle=True):
        # Just wait until the broker says let's go
        while self.dse is None:
            time.sleep(0.10)

        # Run while we are not instructed to stop
        while not self.stop:
            st = self.dse.explore()
            if st == ExplorationStatus.STOPPED:  # if the exploration stopped just return
                break
            elif st == ExplorationStatus.IDLE:
                if wait_idle:  # if we want to wait for seeds just wait to receive one
                    logging.info("exploration idle (worklist empty)")
                    self.agent.send_log(LogLevel.INFO, "exploration idle (worklist empty)")
                    self.wait_seed_event()
                else:
                    break  # Just break and exit
            else:
                logging.error(f"explorator not meant to be in state: {st}")
                break


    def cb_post_execution(self, se: SymbolicExecutor, state: ProcessState):

        # Send seed that have been executed
        mapper = {SeedStatus.OK_DONE: SeedType.INPUT, SeedStatus.CRASH: SeedType.CRASH, SeedStatus.HANG: SeedType.HANG}
        seed = se.seed
        if seed.status == SeedStatus.NEW:
            logging.warning(f"seed is not meant to be NEW in post execution current:{seed.status.name}")
        else:
            if seed.content not in self._seed_received:  # Do not send back a seed that already came from broker
                self.agent.send_seed(mapper[seed.status], seed.content, origin=FuzzingEngine.TRITON)

        # Handle CRASH and ABV_GENERAL
        if se.seed.status == SeedStatus.CRASH and self._last_kid:
            alert = self.klreport.get_alert(binding_id=self._last_kid)
            if alert.code == KlocworkAlertType.ABV_GENERAL:
                logging.info(f'A crash occured with an ABV_GENERAL encountered just before.')
                self.dual_log(LogLevel.INFO, f"Alert [{alert.id}] in {alert.file}:{alert.line}: {alert.code.name} validation [SUCCESS]")
                alert.validated = True
                self.agent.send_alert_data(AlertData(alert.id, alert.covered, alert.validated, se.seed.content))

        # Print stats
        d, v = self.klreport.get_stats()
        logging.info(f"Klocwork stats: defaults: [cov:{d.checked}/{d.total}] vulns: [check:{v.checked}/{v.total}]")


    def wait_seed_event(self):
        self._seed_lock = True
        while self._seed_lock:
            time.sleep(0.5)


    def start_received(self, fname: str, binary: bytes, engine: FuzzingEngine, exmode: ExecMode, chkmode: CheckMode,
                       covmode: CoverageMode, seed_inj: SeedInjectLoc, engine_args: str, argv: List[str], kl_report: str=None):
        logging.info(f"[BROKER] [START] bin:{fname} engine:{engine.name} exmode:{exmode.name} cov:{covmode.name} chk:{chkmode.name}")

        # Parse triton specific parameters and update conf if needed
        if engine_args:
            self.config = Config.from_json(engine_args)
            logging.root.level = logging.DEBUG if self.config.debug else logging.INFO  # dynamically change level

        # Write the binary in a temporary file
        tmp_dir = tempfile.mkdtemp()
        program_path = Path(tmp_dir) / fname
        with open(program_path, 'wb') as f:
            f.write(binary)

        self.program = Program(str(program_path))
        if self.program is None:
            self.dual_log(LogLevel.CRITICAL, f"LIEF was not able to parse the binary file {fname}")
            self.agent.stop()
            return

        # Update the coverage strategy in the current config (it overrides the config file one)
        if covmode == CoverageMode.BLOCK:
            self.config.coverage_strategy = CoverageStrategy.CODE_COVERAGE
        elif covmode == CoverageMode.EDGE:
            self.config.coverage_strategy = CoverageStrategy.EDGE_COVERAGE
        elif covmode == CoverageMode.PATH:
            self.config.coverage_strategy = CoverageStrategy.PATH_COVERAGE
        else:
            logging.info(f"Invalid covmode. Not supported by the tritondse library")
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
            bd = 'OK' if self.klreport.has_binding() else 'KO'
            logging.info(f"Klocwork report loaded [binded:{bd}]: counted alerts:{len(list(self.klreport.counted_alerts))} (total:{len(self.klreport.alerts)}")

        if argv: # Override config
            self.config.program_argv = [str(program_path)]  # Set current binary
            self.config.program_argv.extend(argv)

        self.dse = SymbolicExplorator(self.config, self.program)

        # Register common callbacks
        #self.dse.callback_manager.register_new_input_callback(self.checksum_callback)   # must be the first cb
        # self.dse.callback_manager.register_new_input_callback(self.send_seed_to_broker) # must be the second cb
        self.dse.callback_manager.register_post_execution_callback(self.cb_post_execution)
        #self.dse.callback_manager.register_post_instuction_callback(self.trace_debug)

        if chkmode == CheckMode.CHECK_ALL:
           self.dse.callback_manager.register_probe_callback(UAFSanitizer())
           self.dse.callback_manager.register_probe_callback(NullDerefSanitizer())
           self.dse.callback_manager.register_probe_callback(FormatStringSanitizer())
           self.dse.callback_manager.register_probe_callback(IntegerOverflowSanitizer())
           # TODO Buffer overflow

        elif chkmode == CheckMode.ALERT_ONLY:
           self.dse.callback_manager.register_function_callback('__klocwork_alert_placeholder', self.intrinsic_callback)

    def trace_debug(self, se: SymbolicExecutor, state: ProcessState, instruction: 'Instruction'):
        print("[tid:%d] %#x: %s" %(instruction.getThreadId(), instruction.getAddress(), instruction.getDisassembly()))


    def seed_received(self, typ: SeedType, seed: bytes, origin: FuzzingEngine):
        if seed in self._seed_received:
            logging.warning(f"receiving seed already known: {md5(seed).hexdigest()} (dropped)")
            return

        logging.info(f"seed received from:{origin.name} {md5(seed).hexdigest()} [{typ.name}]")

        self._seed_received.add(seed)  # Remember seed received not to send them back

        # TODO: Handle INPUT, CRASH ou HANGS
        if self.dse:
            self.dse.add_input_seed(seed)
        else:
            logging.warning("receiving seeds while the DSE is not instanciated")
        self._seed_lock = False  # Unlock the run() thread if it was waiting for a seed


    def stop_received(self):
        logging.info(f"[BROKER] [STOP]")
        if self.dse:
            self.dse.stop_exploration()
        self.stop = True
        self.agent.stop()


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


    def checksum_callback(self, se: SymbolicExecutor, state: ProcessState, new_input_generated: Input):
        """
        This callback is called each time a model is returned by the SMT solver. In this function
        we compute the checksum of the packets using scapy.
        """
        base = 0
        pkt_len = 600
        for i in range(int(len(new_input_generated) / pkt_len)): # number of packet with our initial seed
            pkt_raw = new_input_generated[base:base+pkt_len]
            eth_pkt = Ether(pkt_raw)
            # Remove the checksum generated by the solver
            for proto in [IP, TCP, UDP, IGMP, ICMP]:
                if proto in eth_pkt:
                    del eth_pkt[proto].chksum
            # Rebuild the Ethernet packet with scapy in order to recompute the checksum
            eth_pkt.build()
            # Rewrite the seed with the appropriate checksum
            count = 0
            for b in raw(eth_pkt):
                new_input_generated[base+count] = b
                count += 1
            base += pkt_len # the size of a packet in our fuzzing_driver
        return new_input_generated


    # def send_seed_to_broker(self, se: SymbolicExecutor, state: ProcessState, seed: Input):
    #     self.agent.send_seed(SeedType.INPUT, bytes(seed), FuzzingEngine.TRITON)
    #     return


    def intrinsic_callback(self, se: SymbolicExecutor, state: ProcessState, addr: Addr):
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
                else:
                    logging.info(f"Alert [{alert.id}] in {alert.file}:{alert.line}: validation [FAIL]")

            if covered or validated:  # If either coverage or validation were improved print stats
                # Send updates to the broker
                self.agent.send_alert_data(AlertData(alert.id, alert.covered, validated, se.seed.content))
                d, v = self.klreport.get_stats()
                logging.info(f"Klocwork stats: defaults: [cov:{d.checked}/{d.total}] vulns: [check:{v.checked}/{v.total}]")

            if self.klreport.all_alerts_validated():
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
            return NullDerefSanitizer.check(se, state, MemoryAccess(ptr, CPUSIZE.BYTE), f'Invalid memory access at {ptr:#x}')

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
