#!/usr/bin/env python3
import logging
from typing import Tuple
import sys
from pathlib import Path

import inotify.adapters

from libpastis.agent import BrokerAgent
from libpastis.types import SeedType, FuzzingEngine, LogLevel, Arch, State

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")

clients = set()


def seed_received(cli_id: bytes, typ: SeedType, seed: bytes, origin: FuzzingEngine):
    logging.info(f"[{cli_id.hex()}] [SEED] [{origin.name}] {seed.hex()} ({typ.name})")


def hello_received(cli_id: bytes, engines: Tuple[FuzzingEngine, str], arch: Arch, cpus: int, memory: int):
    global clients
    if cli_id not in clients:
        logging.info(f"[broker] new client: {cli_id.hex()}")
        clients.add(cli_id)
    logging.info(f"[{cli_id.hex()}] [HELLO] Arch:{arch.name} engines:{[x[0].name for x in engines]} (cpu:{cpus}, mem:{memory})")


def log_received(cli_id: bytes, level: LogLevel, message: str):
    logging.info(f"[{cli_id.hex()}] [LOG] [{level.name}] {message}")


def telemetry_received(cli_id: bytes, *args):
    logging.info(f"[{cli_id.hex()}] [TELEMETRY] [{args}")


def stop_coverage_received(cli_id: bytes):
    logging.info(f"[{cli_id.hex()}] [STOP_COVERAGE]")


if __name__ == "__main__":

    agent = BrokerAgent()
    agent.bind()

    agent.register_seed_callback(seed_received)
    agent.register_hello_callback(hello_received)
    agent.register_log_callback(log_received)
    agent.register_telemetry_callback(telemetry_received)
    agent.register_stop_coverage_callback(stop_coverage_received)

    agent.start()

    # Now start listening on a seed folder given in parameter
    # and send them to all clients that have at least sent
    # once a message

    i = inotify.adapters.Inotify()

    i.add_watch(sys.argv[1])

    for event in i.event_gen():
        if event is not None:
            (header, type_names, watch_path, filename) = event

            if 'IN_CLOSE_WRITE' in type_names:
                file = Path(watch_path) / filename
                bts = file.read_bytes()
                print(f"send: {filename}")
                for cli in clients:
                    agent.send_seed(cli, SeedType.INPUT, bts, FuzzingEngine.HONGGFUZZ)

'''
PYTHONPATH=. python3  ./tests/broker_fw_honggfuzz_seed.py /tmp/toto 
'''