# built-in imports
from typing  import List
from hashlib import md5
import time
import logging

# third-party imports
from scapy.all          import Ether, IP, TCP, UDP, ICMP
from scapy.contrib.igmp import IGMP

from tritondse          import TRITON_VERSION, Config, Program, CoverageStrategy, SeedFile, SymbolicExplorator, \
                               SymbolicExecutor, Seed, ProcessState
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

        # Default config
        self.config.execution_timeout    = 120   # 2 minutes
        self.config.smt_timeout          = 5000  # 5 seconds
        self.config.smt_queries_limit    = 400
        self.config.thread_scheduling    = 300
        self.config.time_inc_coefficient = 0.00001


    def _init_callbacks(self):
        self.agent.register_start_callback(self.start_received)
        self.agent.register_seed_callback(self.seed_received)
        self.agent.register_stop_callback(self.stop_received)


    def init_agent(self, remote: str = "localhost", port: int = 5555):
        self.agent.connect(remote, port)
        self.agent.start()
        self.agent.send_hello([(FuzzingEngine.TRITON, TRITON_VERSION)])


    def run(self):
        # Just wait until the broker says let's go
        while self.dse is None:
            time.sleep(0.10)

        # When the start_received callback is triggered, the dse should be
        # initialized. So, let's start the exploration
        while not self.stop and not self.dse.stop:
            self.dse.explore()
            time.sleep(0.5)


    def start_received(self, fname: str, binary: bytes, engine: FuzzingEngine, exmode: ExecMode, chkmode: CheckMode,
                       covmode: CoverageMode, seed_inj: SeedInjectLoc, engine_args: str, argv: List[str], kl_report: str=None):
        logging.info(f"[BROKER] [START] bin:{fname} engine:{engine.name} exmode:{exmode.name} cov:{covmode.name} chk:{chkmode.name}")

        with open('/tmp/' + fname, 'wb+') as f:
            f.write(binary)
        try:
            self.program = Program('/tmp/' + fname)
        except FileNotFoundError as e:
            print(e)
            self.agent.stop()
            return

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

        self.config.program_argv.append(b'/tmp/' + fname.encode('utf-8'))
        for arg in argv:
            self.config.program_argv.append(arg.encode('utf-8'))

        self.dse = SymbolicExplorator(self.config, self.program)
        #self.dse.callback_manager.register_new_input_callback(self.checksum_callback)   # must be the first cb
        self.dse.callback_manager.register_new_input_callback(self.send_seed_to_broker) # must be the second cb
        self.dse.callback_manager.register_function_callback('__klocwork_alert_placeholder', self.intrinsic_callback)
        #self.dse.callback_manager.register_post_instuction_callback(self.trace_debug)

        #if chkmode == CheckMode.CHECK_ALL:
        #    self.dse.callback_manager.register_probe_callback(UAFSanitizer())
        #    self.dse.callback_manager.register_probe_callback(NullDerefSanitizer())
        #    self.dse.callback_manager.register_probe_callback(FormatStringSanitizer())
        #    self.dse.callback_manager.register_probe_callback(IntegerOverflowSanitizer())
        #    # TODO Buffer overflow
        #elif chkmode == CheckMode.ALERT_ONLY:
        #    self.dse.callback_manager.register_function_callback('__klocwork_alert_placeholder', self.intrinsic_callback)

    def trace_debug(self, se: SymbolicExecutor, state: ProcessState, instruction: 'Instruction'):
        print("[tid:%d] %#x: %s" %(instruction.getThreadId(), instruction.getAddress(), instruction.getDisassembly()))


    def seed_received(self, typ: SeedType, seed: bytes, origin: FuzzingEngine):
        logging.info(f"[BROKER] [SEED RCV] [{origin.name}] {md5(seed).hexdigest()} ({typ})")
        # TODO: Handle whether the seed is already known or not
        # TODO: Handle INPUT, CRASH ou HANGS
        if self.dse:
            self.dse.seeds_manager.add_seed(Seed(seed))


    def stop_received(self):
        logging.info(f"[BROKER] [STOP]")
        if self.dse:
            self.dse.stop = True
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
