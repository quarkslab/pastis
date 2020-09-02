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

    def start(self, binary, argv):
        # Write target to disk.
        target = HFUZZ_CONFIG['HFUZZ_WS'] / f'target-{self.__generate_id()}.bin'

        target.write_bytes(binary)

        # Change target mode to execute.
        target.chmod(stat.S_IRWXU)

        # Prepare target arguments.
        target_arguments = ' '.join(argv)

        # Start fuzzing job.
        self.__job_id = self.__job_manager.start(target.absolute(), target_arguments)

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

        coverage_path = pathlib.Path(HFUZZ_CONFIG['HFUZZ_WS'] / f'{self.__job_id}' / 'outputs' / 'coverage')
        self.__inotify.remove_watch(str(coverage_path))
        self.__coverage_monitor.join()

        crashes_path = pathlib.Path(HFUZZ_CONFIG['HFUZZ_WS'] / f'{self.__job_id}' / 'outputs' / 'crashes')
        self.__inotify.remove_watch(str(crashes_path))
        self.__crashes_monitor.join()

        stats_path = pathlib.Path(HFUZZ_CONFIG['HFUZZ_WS'] / f'{self.__job_id}' / 'stats')
        self.__inotify.remove_watch(str(stats_path))
        self.__stats_monitor.join()

    def add_seed(self, seed):
        # TODO: Implement.
        pass

    def __generate_id(self):
        return int(time.time())

    def __monitor_coverage(self):
        global agent

        coverage_path = pathlib.Path(HFUZZ_CONFIG['HFUZZ_WS'] / f'{self.__job_id}' / 'outputs' / 'coverage')

        self.__inotify.add_watch(str(coverage_path))

        for event in self.__inotify.event_gen():
            if self.__terminate:
                break

            if event is not None:
                (header, type_names, watch_path, filename) = event

                if 'IN_CLOSE_WRITE' in type_names:
                    file = pathlib.Path(watch_path) / filename
                    bts = file.read_bytes()
                    print(f"send seed: {filename}")

                    agent.send_seed(SeedType.INPUT, bts, FuzzingEngine.HONGGFUZZ)

    def __monitor_crashes(self):
        global agent

        crashes_path = pathlib.Path(HFUZZ_CONFIG['HFUZZ_WS'] / f'{self.__job_id}' / 'outputs' / 'crashes')

        self.__inotify.add_watch(str(crashes_path))

        for event in self.__inotify.event_gen():
            if self.__terminate:
                break

            if event is not None:
                (header, type_names, watch_path, filename) = event

                if 'IN_CLOSE_WRITE' in type_names:
                    file = pathlib.Path(watch_path) / filename
                    bts = file.read_bytes()
                    print(f"send crash: {filename}")

                    agent.send_seed(SeedType.CRASH, bts, FuzzingEngine.HONGGFUZZ)

    def __monitor_stats(self):
        global agent

        stats_path = pathlib.Path(HFUZZ_CONFIG['HFUZZ_WS'] / f'{self.__job_id}' / 'stats')

        self.__inotify.add_watch(str(stats_path))

        for event in self.__inotify.event_gen():
            if self.__terminate:
                break

            if event is not None:
                (header, type_names, watch_path, filename) = event

                if 'IN_MODIFY' in type_names:
                    file = pathlib.Path(watch_path) / filename
                    print(f"modified file: {filename}")
                    try:
                        with open(str(file), 'r', encoding='latin1') as stats_file:
                            lines = stats_file.readlines()
                            # print(f"lines: {lines}")
                            last = lines[-1]

                            if last.startswith("#"):
                                continue

                            print(f"last: {last}")

        # def send_telemetry(self, state: State = None, exec_per_sec: int = None, total_exec: int = None, cycle: int = None,
        #                    timeout: int = None, coverage_block: int = None, coverage_edge: int = None,
        #                    coverage_path: int = None, last_cov_update: int = None):

                            # unix_time, thread_no, mutations, crashes, unique_crashes, hangs, current (i,b,hw,ed,ip,cmp), total (i,b,hw,ed,ip,cmp)
                            mutations = int(last[2])
                            hangs = int(last[5])

                            agent.send_telemetry(state=State.RUNNING, total_exec=mutations, timeout=hangs)
                    except:
                        print(f'Error opening stats file!')


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
