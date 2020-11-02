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

from tritondse          import TRITON_VERSION, Config, Program, CoverageStrategy, SymbolicExplorator, SymbolicExecutor, \
                               ProcessState, ExplorationStatus
from tritondse.types    import Addr, Input
from libpastis.agent    import ClientAgent
from libpastis.types    import SeedType, FuzzingEngine, ExecMode, CoverageMode, SeedInjectLoc, CheckMode, LogLevel, State


class PastisDSE(object):

    def __init__(self, agent: ClientAgent):
        self.agent = agent
        self._init_callbacks()  # register callbacks on the given agent

        self.config  = Config(debug=False)
        self.dse     = None
        self.program = None
        self.stop    = False
        self._seed_lock = False


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
            self.config = Config.from_str(engine_args)

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

        if argv: # Override config
            self.config.program_argv = [str(program_path)]  # Set current binary
            self.config.program_argv.extend(argv)

        self.dse = SymbolicExplorator(self.config, self.program)

        # Register common callbacks
        #self.dse.callback_manager.register_new_input_callback(self.checksum_callback)   # must be the first cb
        self.dse.callback_manager.register_new_input_callback(self.send_seed_to_broker) # must be the second cb

        if chkmode == CheckMode.CHECK_ALL:
            pass
           # self.dse.callback_manager.register_probe_callback(UAFSanitizer())
           # self.dse.callback_manager.register_probe_callback(NullDerefSanitizer())
           # self.dse.callback_manager.register_probe_callback(FormatStringSanitizer())
           # self.dse.callback_manager.register_probe_callback(IntegerOverflowSanitizer())
           # # TODO Buffer overflow
        elif chkmode == CheckMode.ALERT_ONLY:
           self.dse.callback_manager.register_function_callback('__klocwork_alert_placeholder', self.intrinsic_callback)


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
        logging.info(f"[INTRINSIC] id {alert_id} triggered")
        with open('./id', 'a+') as f:
            f.write(f'{alert_id}\n')
        return

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
