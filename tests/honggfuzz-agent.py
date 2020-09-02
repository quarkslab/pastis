#! /usr/bin/env python3

import hfwrapper
import inotify.adapters
import logging
import os
import pathlib
import random
import stat
import threading
import time

from typing import List

from libpastis.agent import ClientAgent
from libpastis.agent import FileAgent
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


HFUZZ_CONFIG = {
    'HFUZZ_PATH': pathlib.Path('/mnt/hdd/workspace/missions/pastis/repositories/honggfuzz'),
    'HFUZZ_VERSION': '2.1',
    'HFUZZ_WS': pathlib.Path('/tmp/hfuzz-workspace'),
}


class Honggfuzz():

    def __init__(self):
        self.__job_id = None

        self.__job_manager = hfwrapper.HonggfuzzJobManager(HFUZZ_CONFIG['HFUZZ_PATH'] / 'honggfuzz', HFUZZ_CONFIG['HFUZZ_WS'])

        self.__inotify = inotify.adapters.Inotify()
        self.__coverage_monitor = None
        self.__crashes_monitor = None
        self.__stats_monitor = None

        self.__terminate = False

        self.__target_path = None
        self.__coverage_path = None
        self.__crashes_path = None
        self.__stats_path = None

    def start(self, binary, argv):
        # Make sure to create the workspace.
        HFUZZ_CONFIG['HFUZZ_WS'].mkdir(parents=True, exist_ok=True)

        # Write target to disk.
        target_path = HFUZZ_CONFIG['HFUZZ_WS'] / f'target-{self.__generate_id()}.bin'

        target_path.write_bytes(binary)

        # Change target mode to execute.
        target_path.chmod(stat.S_IRWXU)

        # Prepare target arguments.
        target_arguments = ' '.join(argv)

        # Start fuzzing job.
        self.__job_id = self.__job_manager.start(target_path.absolute(), target_arguments)

        # Set workspace paths.
        self.__coverage_path = pathlib.Path(HFUZZ_CONFIG['HFUZZ_WS'] / f'{self.__job_id}' / 'outputs' / 'coverage')
        self.__crashes_path = pathlib.Path(HFUZZ_CONFIG['HFUZZ_WS'] / f'{self.__job_id}' / 'outputs' / 'crashes')
        self.__stats_path = pathlib.Path(HFUZZ_CONFIG['HFUZZ_WS'] / f'{self.__job_id}' / 'stats')

        # Set termination flag.
        self.__terminate = False

        # Start coverage monitor.
        self.__coverage_monitor = threading.Thread(target=self.__monitor_coverage, daemon=True)
        self.__coverage_monitor.start()

        # Start crashes monitor.
        self.__crashes_monitor = threading.Thread(target=self.__monitor_crashes, daemon=True)
        self.__crashes_monitor.start()

        # Start stats monitor.
        self.__stats_monitor = threading.Thread(target=self.__monitor_stats, daemon=True)
        self.__stats_monitor.start()

    def stop(self):
        self.__job_manager.stop(self.__job_id)

        self.__terminate = True

        self.__inotify.remove_watch(str(self.__coverage_path))
        self.__coverage_monitor.join()

        self.__inotify.remove_watch(str(self.__crashes_path))
        self.__crashes_monitor.join()

        self.__inotify.remove_watch(str(self.__stats_path))
        self.__stats_monitor.join()

    def add_seed(self, seed):
        # TODO: Implement.
        pass

    def __generate_id(self):
        return int(time.time())

    def __monitor_coverage(self):
        global agent

        self.__inotify.add_watch(str(self.__coverage_path))

        for event in self.__inotify.event_gen():
            if self.__terminate:
                break

            if event is not None:
                (header, type_names, watch_path, filename) = event

                if 'IN_CLOSE_WRITE' in type_names:
                    logging.debug(f'[SEED] Sending new seed: {filename}')

                    file = pathlib.Path(watch_path) / filename
                    bts = file.read_bytes()

                    agent.send_seed(SeedType.INPUT, bts, FuzzingEngine.HONGGFUZZ)

    def __monitor_crashes(self):
        global agent

        self.__inotify.add_watch(str(self.__crashes_path))

        for event in self.__inotify.event_gen():
            if self.__terminate:
                break

            if event is not None:
                (header, type_names, watch_path, filename) = event

                if 'IN_CLOSE_WRITE' in type_names:
                    logging.debug(f'[SEED] Sending new crash: {filename}')

                    file = pathlib.Path(watch_path) / filename
                    bts = file.read_bytes()

                    agent.send_seed(SeedType.CRASH, bts, FuzzingEngine.HONGGFUZZ)

    def __monitor_stats(self):
        global agent

        self.__inotify.add_watch(str(self.__stats_path))

        for event in self.__inotify.event_gen():
            if self.__terminate:
                break

            if event is not None:
                (header, type_names, watch_path, filename) = event

                if 'IN_MODIFY' in type_names:
                    logging.debug(f'[TELEMETRY] Stats file updated: {filename}')

                    file = pathlib.Path(watch_path) / filename

                    stats = ''
                    # TODO: Lock file before reading it.
                    with open(file, 'r') as stats_file:
                        try:
                            stats = stats_file.readlines()[-1]
                        except:
                            logging.error(f'Error reading stats file!')

                    if not stats or stats.startswith("#"):
                        continue

                    # unix_time, thread_no, mutations, crashes, unique_crashes, hangs, current (i,b,hw,ed,ip,cmp), total (i,b,hw,ed,ip,cmp)
                    try:
                        mutations = int(stats[2])
                        hangs = int(stats[5])

                        agent.send_telemetry(state=State.RUNNING, total_exec=mutations, timeout=hangs)
                    except:
                            logging.error(f'Error parsing stats!')


def start_received(fname: str, binary: bytes, engine: FuzzingEngine, exmode: ExecMode, chkmode: CheckMode,
                   covmode: CoverageMode, seed_inj: SeedInjectLoc, engine_args: str, argv: List[str], kl_report: str=None):
    global hfuzz

    logging.info(f"[START] bin:{fname} engine:{engine.name} exmode:{exmode.name} cov:{covmode.name} chk:{chkmode.name}")

    hfuzz.start(binary, argv)


def seed_received(typ: SeedType, seed: bytes, origin: FuzzingEngine):
    global hfuzz

    logging.info(f"[SEED] [{origin.name}] {seed.hex()} ({typ})")

    hfuzz.add_seed(seed)


def stop_received():
    global hfuzz

    logging.info(f"[STOP]")

    hfuzz.stop()


if __name__ == "__main__":
    hfuzz = Honggfuzz()

    agent = ClientAgent()

    agent.connect()

    agent.register_seed_callback(seed_received)
    agent.register_start_callback(start_received)
    agent.register_stop_callback(stop_received)

    agent.start()

    # Send initial HELLO message.
    agent.send_hello([(FuzzingEngine.HONGGFUZZ, HFUZZ_CONFIG['HFUZZ_VERSION'])], Arch.X86_64)

    try:
        # Send Alive message.
        while True:
            agent.send_log(LogLevel.DEBUG, f"Alive: {int(time.time())}")

            time.sleep(2)
    except KeyboardInterrupt:
        print("[!] CTRL+C detected! Aborting...")

    # TODO: Make sure every honggfuzz instance has been stopped before exiting.
    hfuzz.stop()

    agent.send_stop_coverage_criteria()
