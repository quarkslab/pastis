#!/usr/bin/env python3
import random
import time
import logging
from typing import List

from libpastis.agent import ClientAgent
from libpastis.types import SeedType, FuzzingEngine, ExecMode, CoverageMode, SeedInjectLoc, CheckMode

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
        v = random.randint(0, 5)
        time.sleep(v)

        seed = bytes(random.getrandbits(8) for _ in range(16))

        agent.send_seed(SeedType.INPUT, seed, FuzzingEngine.HONGGFUZZ)
        print("seed sent")
