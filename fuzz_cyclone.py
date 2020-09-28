#!/usr/bin/env python3

import sys
import logging
import time

from tritondse          import *
from libpastis.agent    import ClientAgent
from libpastis.types    import SeedType, FuzzingEngine, ExecMode, CoverageMode, SeedInjectLoc, CheckMode, LogLevel, State
from scapy.all          import Ether, IP, TCP, UDP, ICMP
from scapy.contrib.igmp import IGMP
from typing             import List



class PastisDSE(object):

    def __init__(self, agent: ClientAgent):
        self.agent   = agent
        self.config  = Config(debug=False)
        self.dse     = None
        self.program = None

        # Default config
        self.config.execution_timeout    = 0     # unlimited
        self.config.smt_timeout          = 5000  # 5 seconds
        self.config.smt_queries_limit    = 0
        self.config.thread_scheduling    = 300
        self.config.time_inc_coefficient = 0.00001
        self.config.execution_timeout    = 240


    def run(self):
        self.agent.connect()
        self.agent.register_start_callback(self.start_received)
        self.agent.register_seed_callback(self.seed_received)
        self.agent.register_stop_callback(self.stop_received)
        self.agent.start()
        self.agent.send_hello([(FuzzingEngine.TRITON, "v0.9")])

        # Just wait until the broker says let's go
        while self.dse is None:
            time.sleep(0.10)

        # When the start_received callback is triggered, the dse should be
        # initialized. So, let's start the exploration
        self.dse.explore()


    def start_received(self, fname: str, binary: bytes, engine: FuzzingEngine, exmode: ExecMode, chkmode: CheckMode,
                       covmode: CoverageMode, seed_inj: SeedInjectLoc, engine_args: str, argv: List[str], kl_report: str=None):
        logging.info(f"[START] bin:{fname} engine:{engine.name} exmode:{exmode.name} cov:{covmode.name} chk:{chkmode.name}")

        if engine != FuzzingEngine.TRITON:
            logging.info(f"Invalid engine for this instance")
            self.agent.stop()
            return

        # TODO ExecMode
        # TODO ALERT_ONLY

        # TODO: Maybe we can update the tritondse to take as Program input a sequence of bytes
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

        # FIXME: Maybe (argv) returning bytes could be avoid this step
        self.config.program_argv.append(b'/tmp/' + fname.encode('utf-8'))
        for arg in argv:
            self.config.program_argv.append(arg.encode('utf-8'))

        init_seed = SeedFile('../programme_etalon_final/micro_http_server/misc/frame.seed')
        self.dse = SymbolicExplorator(self.config, self.program, init_seed)
        self.dse.callback_manager.register_new_input_callback(self.checksum_callback)
        #self.dse.callback_manager.register_probe_callback(UAFSanitizer())
        #self.dse.callback_manager.register_probe_callback(NullDerefSanitizer())
        #self.dse.callback_manager.register_probe_callback(FormatStringSanitizer())
        #self.dse.callback_manager.register_probe_callback(IntegerOverflowSanitizer())


    def seed_received(self, typ: SeedType, seed: bytes, origin: FuzzingEngine):
        logging.info(f"[SEED] [{origin.name}] {seed.hex()} ({typ})")
        if self.dse:
            self.dse.seeds_manager.add_seed(Seed(seed))


    def stop_received(self):
        logging.info(f"[STOP]")
        if self.dse:
            self.dse.stop = True
        self.agent.stop()


    # FIXME: failed to deepcopy when it's not static
    @staticmethod
    def checksum_callback(se: SymbolicExecutor, state: ProcessState, new_input_generated: Input):
        """
        This callback is called each time a model is returned by the SMT solver. In this function
        we compute the checksum of the packets using scapy.
        """
        global agent # FIXME
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
        # FIXME: self.agent
        agent.send_seed(SeedType.INPUT, bytes(new_input_generated), FuzzingEngine.TRITON)
        return new_input_generated

agent = ClientAgent()
pastis = PastisDSE(agent)
pastis.run()
