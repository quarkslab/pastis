#! /usr/bin/env python3

import logging

from typing import Tuple

from libpastis.agent import BrokerAgent
from libpastis.types import Arch
from libpastis.types import CheckMode
from libpastis.types import CoverageMode
from libpastis.types import ExecMode
from libpastis.types import FuzzingEngine
from libpastis.types import LogLevel
from libpastis.types import SeedInjectLoc
from libpastis.types import SeedType
from libpastis.types import State


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")


def seed_received(cli_id: bytes, typ: SeedType, seed: bytes, origin: FuzzingEngine):
    logging.info(f"[{cli_id.hex()}] [SEED] [{origin.name}] {seed.hex()} ({typ.name})")


def hello_received(cli_id: bytes, engines: Tuple[FuzzingEngine, str], arch: Arch, cpus: int, memory: int):
    global agent

    logging.info(f"[{cli_id.hex()}] [HELLO] Arch:{arch.name} engines:{[x[0].name for x in engines]} (cpu:{cpus}, mem:{memory})")

    target = '../../programme_etalon_final/micro_http_server/micro_http_server_hf_fuzz_single_without_vuln'
    target_arguments = 'wlp0s20f3 5c:80:b6:96:d7:3c 192.168.43.127 255.255.255.0 192.168.43.255'

    agent.send_start(cli_id, target, target_arguments.split(' '),
        ExecMode.SINGLE_EXEC, CheckMode.CHECK_ALL, CoverageMode.BLOCK,
        FuzzingEngine.HONGGFUZZ, "", SeedInjectLoc.STDIN, "")


def log_received(cli_id: bytes, level: LogLevel, message: str):
    logging.info(f"[{cli_id.hex()}] [LOG] [{level.name}] {message}")


def telemetry_received(cli_id: bytes, *args):
    logging.info(f"[{cli_id.hex()}] [TELEMETRY] [{args}")


def stop_coverage_received(cli_id: bytes):
    logging.info(f"[{cli_id.hex()}] [STOP_COVERAGE]")


if __name__ == "__main__":
    agent = BrokerAgent()

    agent.bind()

    agent.register_hello_callback(hello_received)
    agent.register_log_callback(log_received)
    agent.register_seed_callback(seed_received)
    agent.register_stop_coverage_callback(stop_coverage_received)
    agent.register_telemetry_callback(telemetry_received)

    agent.run()

    # TODO: Where seeds to clients are sent?
