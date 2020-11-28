#!/usr/bin/env python3
import logging
from typing import Tuple


from libpastis.agent import BrokerAgent
from libpastis.types import SeedType, FuzzingEngine, LogLevel, Arch, State

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")


def seed_received(cli_id: bytes, typ: SeedType, seed: bytes):
    global agent
    logging.info(f"[{cli_id.hex()}] [SEED] {seed.hex()} ({typ.name})")
    agent.send_seed(cli_id, typ, seed[::-1])


def hello_received(cli_id: bytes, engines: Tuple[FuzzingEngine, str], arch: Arch, cpus: int, memory: int):
    logging.info(f"[{cli_id.hex()}] [HELLO] Arch:{arch.name} engines:{[x[0].name for x in engines]} (cpu:{cpus}, mem:{memory})")


def log_received(cli_id: bytes, level: LogLevel, message: str):
    logging.info(f"[{cli_id.hex()}] [LOG] [{level.name}] {message}")


def telemetry_received(cli_id: bytes, *args):
    # state: State = None, exec_per_sec: int = None, total_exec: int = None,
    # cycle: int = None, timeout: int = None, coverage_block: int = None, coverage_edge: int = None,
    # coverage_path: int = None, last_cov_update: int = None):
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

    agent.run()
