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
from tritondse            import TRITON_VERSION, Config, Program, CoverageStrategy, SymbolicExplorator, SymbolicExecutor, ProcessState, ExplorationStatus
from tritondse.sanitizers import FormatStringSanitizer, NullDerefSanitizer, UAFSanitizer, IntegerOverflowSanitizer, mk_new_crashing_seed
from tritondse.types      import Addr, Input
from libpastis.agent      import ClientAgent
from libpastis.types      import SeedType, FuzzingEngine, ExecMode, CoverageMode, SeedInjectLoc, CheckMode, LogLevel, State
from klocwork             import KlocworkReport, KlocworkAlertType, PastisVulnKind


class PastisDSE(object):

    KL_MAGIC = "KL-METADATA"

    def __init__(self, agent: ClientAgent):
        self.agent = agent
        self._init_callbacks()  # register callbacks on the given agent

        self.config  = Config(debug=False)
        self.dse     = None
        self.program = None
        self.stop    = False
        self._seed_lock = False
        self.klreport = None

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
        self.dse.callback_manager.register_new_input_callback(self.send_seed_to_broker) # must be the second cb
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
        logging.info(f"[BROKER] [SEED RCV] [{origin.name}] {md5(seed).hexdigest()} ({typ})")
        # TODO: Handle whether the seed is already known or not
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


    def send_seed_to_broker(self, se: SymbolicExecutor, state: ProcessState, seed: Input):
        self.agent.send_seed(SeedType.INPUT, bytes(seed), FuzzingEngine.TRITON)
        return


    def intrinsic_callback(self, se: SymbolicExecutor, state: ProcessState, addr: Addr):
        alert_id = state.tt_ctx.getConcreteRegisterValue(se.abi.get_arg_register(0))
        res_improved = False
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
                res_improved = True

            if alert.kind == PastisVulnKind.VULNERABILITY and not alert.validated:  # If of type VULNERABILITY and not yet validated
                res = self.check_alert_dispatcher(alert.code, se, state, addr)
                if res:
                    alert.validated = True
                    self.dual_log(LogLevel.INFO, f"Alert [{alert.id}] in {alert.file}:{alert.line}: {alert.code.name} validation [SUCCESS]")
                    res_improved = True
                else:
                    logging.info(f"Alert [{alert.id}] in {alert.file}:{alert.line}: validation [FAIL]")

            if res_improved:  # If either coverage or validation were improved print stats
                d, v = self.klreport.get_stats()
                logging.info(f"Klocwork stats: defaults: [cov:{d.checked}/{d.total}] vulns: [check:{v.checked}/{v.total}]")

            if self.klreport.all_alerts_validated():
                self._all_alerts_validated()

        else:  # Kind of autonomous mode. Try to check it even it is not bound to a report
            # Retrieve alert type from parameters
            arg1  = se.pstate.tt_ctx.getConcreteRegisterValue(se.abi.get_arg_register(1))
            alert_kind = se.abi.get_memory_string(arg1)
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
            size = se.pstate.tt_ctx.getConcreteRegisterValue(se.abi.get_arg_register(2))
            ptr = se.pstate.tt_ctx.getRegisterAst(se.abi.get_arg_register(3))

            # Runtime check
            if len(se.abi.get_memory_string(ptr)) >= size:
                # FIXME: Do we have to define the seed as CRASH even if there is no crash?
                return True

            # Symbolic check
            actx = se.pstate.tt_ctx.getAstContext()
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
                logging.warning(f'Model found for a seed which may lead to a crash ({crash_seed.filename})')
                return True

            return False

        ######################################################################

        # BUFFER_OVERFLOW related alerts
        elif type == KlocworkAlertType.SV_STRBO_BOUND_COPY_OVERFLOW:
            pass

        ######################################################################

        # BUFFER_OVERFLOW related alerts
        # FIXME: Il faut modifier le rapport et le klocwork-alert-inserter.
        # Le prototype doit être intrinseque(id, type, sizeof(buff), index)
        elif type == KlocworkAlertType.ABV_GENERAL:
            size = se.pstate.tt_ctx.getConcreteRegisterValue(se.abi.get_arg_register(2))
            index = se.pstate.tt_ctx.getRegisterAst(se.abi.get_arg_register(3))

            # Runtime check
            if index.evaluate() >= size:
                # FIXME: Do we have to define the seed as CRASH even if there is no crash?
                return True

            # Symbolic check
            actx = se.pstate.tt_ctx.getAstContext()
            predicate = se.pstate.tt_ctx.getPathPredicate()
            model = se.pstate.tt_ctx.getModel(actx.land([predicate, index >= size]))
            if model:
                crash_seed = mk_new_crashing_seed(se, model)
                se.workspace.save_seed(crash_seed)
                logging.warning(f'Model found for a seed which may lead to a crash ({crash_seed.filename})')
                return True

            return False

        ######################################################################

        # All INTEGER_OVERFLOW related alerts
        elif type == KlocworkAlertType.NUM_OVERFLOW:
            return IntegerOverflowSanitizer.check(se, state, state.current_instruction)

        ######################################################################

        # All USE_AFTER_FREE related alerts
        elif type in [KlocworkAlertType.UFM_DEREF_MIGHT, KlocworkAlertType.UFM_FFM_MUST, KlocworkAlertType.UFM_DEREF_MIGHT]:
            ptr = se.pstate.tt_ctx.getConcreteRegisterValue(se.abi.get_arg_register(2))
            return UAFSanitizer.check(se, state, ptr, f'UAF detected at {ptr:#x}')

        ######################################################################

        # All FORMAT_STRING related alerts
        elif type in [KlocworkAlertType.SV_TAINTED_FMTSTR, KlocworkAlertType.SV_FMTSTR_GENERIC]:
            ptr = se.pstate.tt_ctx.getConcreteRegisterValue(se.abi.get_arg_register(2))
            return FormatStringSanitizer.check(se, state, addr, ptr)

        ######################################################################

        # All INVALID_MEMORY related alerts
        # FIXME: NPD_CHECK_MIGHT and NPD_CONST_CALL are not supported by klocwork-alert-inserter
        elif type in [KlocworkAlertType.NPD_FUNC_MUST, locworkAlertType.NPD_FUNC_MIGHT, KlocworkAlertType.NPD_CHECK_MIGHT, KlocworkAlertType.NPD_CONST_CALL]:
            ptr = se.pstate.tt_ctx.getConcreteRegisterValue(se.abi.get_arg_register(2))
            return NullDerefSanitizer.check(se, state, MemoryAccess(ptr, CPUSIZE.BYTE), f'Invalid memory access at {ptr:#x}')

        ######################################################################

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
