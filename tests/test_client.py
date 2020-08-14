#!/usr/bin/env python3
import random
import time
import logging
from typing import List

from libpastis.agent import ClientAgent
from libpastis.types import SeedType, FuzzingEngine, ExecMode, CoverageMode, SeedInjectLoc, CheckMode, LogLevel, State

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")


def start_received(fname: str, binary: bytes, engine: FuzzingEngine, exmode: ExecMode, chkmode: CheckMode,
                   covmode: CoverageMode, seed_inj: SeedInjectLoc, engine_args: str, argv: List[str], kl_report: str=None):
    logging.info(f"[START] bin:{fname} engine:{engine.name} exmode:{exmode.name} cov:{covmode.name} chk:{chkmode.name}")


def seed_received(typ: SeedType, seed: bytes, origin: FuzzingEngine):
    logging.info(f"[SEED] [{origin.name}] {seed.hex()} ({typ})")


def stop_received():
    logging.info(f"[STOP]")


if __name__ == "__main__":
    agent = ClientAgent()
    agent.connect()

    agent.register_start_callback(start_received)
    agent.register_seed_callback(seed_received)
    agent.register_stop_callback(stop_received)

    agent.start()

    while True:
        #  Do some 'work'
        time.sleep(2)

        v = random.randint(0, 3)
        if v == 0:
            seed = bytes(random.getrandbits(8) for _ in range(16))
            agent.send_seed(SeedType.INPUT, seed, FuzzingEngine.HONGGFUZZ)
        elif v == 1:
            level = random.choice(list(LogLevel))
            agent.send_log(level, f"Message: {random.randint(0, 100)}")
            # can also call agent.debug(), agent.warning() ..
        elif v == 2:
            r1, r2, r3 = [random.randint(0, 100) for _ in range(3)]
            agent.send_telemetry(State.RUNNING, exec_per_sec=r1, total_exec=r2, timeout=r3)
        elif v == 3:
            agent.send_stop_coverage_criteria()
