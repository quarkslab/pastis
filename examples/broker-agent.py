#! /usr/bin/env python3

import argparse
import logging
import pathlib

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


# Global variables.
agent = None
target = None
target_arguments = None


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")


def init_arg_parser():
    description = "Honggfuzz explorer."

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description)

    parser.add_argument("--target", required=True,
                        type=pathlib.Path, help="Target path")

    parser.add_argument("--target-arguments",
                        type=str, help="Target arguments")

    return parser


def seed_received(cli_id: bytes, typ: SeedType, seed: bytes, origin: FuzzingEngine):
    logging.info(f"[{cli_id.hex()}] [SEED] [{origin.name}] {seed.hex()} ({typ.name})")


def hello_received(cli_id: bytes, engines: Tuple[FuzzingEngine, str], arch: Arch, cpus: int, memory: int):
    global agent, target, target_arguments

    logging.info(f"[{cli_id.hex()}] [HELLO] Arch:{arch.name} engines:{[x[0].name for x in engines]} (cpu:{cpus}, mem:{memory})")

    agent.send_start(cli_id, target, target_arguments.split(' '),
        ExecMode.SINGLE_EXEC, CheckMode.CHECK_ALL, CoverageMode.BLOCK,
        FuzzingEngine.HONGGFUZZ, "", SeedInjectLoc.STDIN, "")


def log_received(cli_id: bytes, level: LogLevel, message: str):
    logging.info(f"[{cli_id.hex()}] [LOG] [{level.name}] {message}")


def telemetry_received(cli_id: bytes, *args):
    logging.info(f"[{cli_id.hex()}] [TELEMETRY] [{args}")


def stop_coverage_received(cli_id: bytes):
    logging.info(f"[{cli_id.hex()}] [STOP_COVERAGE]")


def main(args):
    global agent, target, target_arguments

    agent = BrokerAgent()

    agent.bind()

    agent.register_hello_callback(hello_received)
    agent.register_log_callback(log_received)
    agent.register_seed_callback(seed_received)
    agent.register_stop_coverage_callback(stop_coverage_received)
    agent.register_telemetry_callback(telemetry_received)

    try:
        logging.info(f'Starting broker agent...')

        logging.debug(f'Target: {args.target}')
        logging.debug(f'Target arguments: {args.target_arguments}')

        target = args.target
        target_arguments = args.target_arguments

        agent.run()
    except KeyboardInterrupt:
        print("[!] CTRL+C detected! Aborting...")

        logging.info(f'Stopping broker agent...')
        agent.stop()


if __name__ == "__main__":
    main(init_arg_parser().parse_args())
