#!/usr/bin/env python3
import json
import time
import logging
import tempfile
import os
import subprocess
from typing import Generator
from pathlib import Path
import queue
import csv
from dataclasses import dataclass
from threading import Thread
from multiprocessing import Queue, Manager
from multiprocessing.pool import Pool

from libpastis.types import SeedType, SeedInjectLoc

# tritondse imports
from tritondse import GlobalCoverage, CoverageSingleRun, CoverageStrategy, BranchSolvingStrategy
from tritondse.trace import QBDITrace, TraceException

from pastisbroker.utils import Bcolors, mk_color


@dataclass
class ClientInput:
    content: bytes          # Content of the input
    log_time: str           # Time the log has been generated
    recv_time: str          # Time the input has been received
    elapsed: str            # Elapsed time since the begining
    hash: str               # Input hash
    path: str               # Input file path
    seed_status: SeedType   # Status of the seed
    fuzzer_id: bytes        # Fuzzer ID
    fuzzer_name: str        # Fuzzer name
    broker_status: str      # Status in: DUPLICATE, DROPPED, GRANTED
    replay_status: str      # Status in: OK, TRACE_EXCEPTION, FAIL
    replay_time: float      # Time taken for the replay
    new_coverage: list[tuple[int, int]]  # New items covered


class CoverageManager(object):

    ARGV_PLACEHOLDER = "@@"
    STRATEGY = CoverageStrategy.EDGE

    def __init__(self, pool_size: int, replay_timeout: int, filter: bool, program: str, args: list[str], inj_loc: SeedInjectLoc, stream_file: str = ""):
        # Base info for replay
        self.pool_size = pool_size
        self.replay_timeout = replay_timeout
        self.filter_enabled = filter
        self.program = str(program)
        self.args = args
        self.inj_loc = inj_loc

        # Coverage and messaging attributes
        self._coverage = GlobalCoverage(self.STRATEGY, BranchSolvingStrategy.ALL_NOT_COVERED)
        self._manager = Manager()
        self.input_queue = self._manager.Queue()
        self.cov_queue = self._manager.Queue()
        self.granted_queue = self._manager.Queue()

        # Pool of workers
        self.pool = Pool(self.pool_size)
        self._running = False
        self.cov_worker = Thread(name="[coverage_worker]", target=self.coverage_worker)

        # stats
        self.seeds_accepted, self.seeds_submitted = 0, 0
        self.cli_stats = {}

        # Streaming
        if stream_file:
            self.stream_file = open(stream_file, "a")
            self.csv = csv.writer(self.stream_file)
        else:
            self.stream_file, self.csv = None, None


    def start(self) -> None:
        """
        Start all the workers
        """
        # First start the coverage worker
        self._running = True
        self.cov_worker.start()
        logging.info("Starting coverage manager")

        for work_id in range(self.pool_size):
            self.pool.apply_async(self.worker, (self.input_queue, self.cov_queue, self.program, self.args, self.inj_loc, self.replay_timeout))

    def stop(self) -> None:
        self._running = False
        self.cov_worker.join()
        self.pool.terminate()

    def push_input(self, cli_input: ClientInput) -> None:
        """ Push the input in the """
        cli_input.log_time = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())
        # logging.info(f"push input {str(cli_input)[:50]}")

        # Update stats
        self.seeds_submitted += 1
        if cli_input.fuzzer_id in self.cli_stats:
            self.cli_stats[cli_input.fuzzer_id][0] += 1
        else:
            self.cli_stats[cli_input.fuzzer_id] = [1, 0]

        self.input_queue.put(cli_input)

    def iter_granted_inputs(self) -> Generator[ClientInput, None, None]:
        try:
            while True:
                yield self.granted_queue.get_nowait()
        except queue.Empty:
            pass

    @staticmethod
    def worker_sleep(q, n) -> None:
        """
        worker thread that unstack inputs and replay them.
        """
        time.sleep(n)
        q.put_nowait(n)
        return n

    def add_item_coverage_stream(self, item: ClientInput) -> None:
        if self.stream_file:  # Stream enabled
            self.csv.writerow([
                item.log_time,
                item.recv_time,
                item.elapsed,
                item.hash,
                item.path,
                item.seed_status.name,
                item.fuzzer_name,
                item.broker_status,
                item.replay_status,
                f"{item.replay_time:.2f}",
                item.new_coverage
            ])
            self.stream_file.flush()

    def coverage_worker(self):
        while self._running:
            try:
                item, cov_file = self.cov_queue.get(timeout=0.5)
                # logging.info("Coverage worker fetch item")
                new_items = []
                try:
                    coverage: CoverageSingleRun = QBDITrace.from_file(cov_file).coverage
                    if self._coverage.improve_coverage(coverage):
                        self.cli_stats[item.fuzzer_id][1] += 1  # input accepted
                        self.seeds_accepted += 1

                        # Get newly covered items (and put them in the stream queue

                        new_items = coverage.difference(self._coverage)

                        item.new_coverage = list(new_items)

                        # logging.info(f"seed {item.hash}  ({item.fuzzer_name}) [replay:{}][status:{}] ({len(new_items)} new edges)")

                        # Update the global coverage
                        self._coverage.merge(coverage)

                        if item.fuzzer_name != "INITIAL":  # if not initial corpus and granted
                            self.granted_queue.put(item)

                    else:
                        item.broker_status = "DROPPED" if self.filter_enabled else "GRANTED"
                        # logging.info(f"seed {item.hash} ({item.seed_status.name}) of {item.fuzzer_name} rejected (do not improve coverage)")

                    # Remove the coverage file
                    os.unlink(cov_file)

                except json.JSONDecodeError:
                    item.replay_status = "FAIL_PARSE_COV"
                    os.unlink(cov_file)
                    self.seeds_accepted += 1
                    if item.fuzzer_name != "INITIAL":  # if not initial corpus add it
                        self.granted_queue.put(item)

                except FileNotFoundError:
                    # Grant input
                    self.seeds_accepted += 1
                    if item.fuzzer_name != "INITIAL":  # if not initial corpus add it
                        self.granted_queue.put(item)

                logging.info(f"seed {item.hash} ({item.fuzzer_name}) [replay:{self.mk_rpl_status(item.replay_status)}][{self.mk_broker_status(item.broker_status, bool(new_items))}][{int(item.replay_time):}s] ({len(new_items)} new edges) (pool:{self.input_queue.qsize()})")
                # Regardless if it was a success or not log it
                self.add_item_coverage_stream(item)
            except queue.Empty:
                pass
            except KeyboardInterrupt:
                self._running = False
                logging.info("coverage worker stop")
                break

    @staticmethod
    def mk_rpl_status(status: str) -> str:
        if status == "SUCCESS":
            return mk_color(status, Bcolors.OKGREEN)
        else:
            return mk_color(status, Bcolors.FAIL)


    @staticmethod
    def mk_broker_status(status: str, new_items: bool) -> str:
        if status == "GRANTED":
            return mk_color(status, Bcolors.OKGREEN if new_items else Bcolors.WARNING)
        elif status == "DROPPED":
            return mk_color(status, Bcolors.WARNING)
        else:
            return mk_color(status, Bcolors.FAIL)

    @staticmethod
    def worker(input_queue: Queue, cov_queue: Queue, program: str, argv: list[str], seed_inj: SeedInjectLoc, timeout) -> None:
        """
        worker thread that unstack inputs and replay them.
        """
        tmpfile = Path(tempfile.mktemp(suffix=f"{os.getpid()}.input"))
        pid = os.getpid()
        try:
            while True:
                item: ClientInput = input_queue.get()
                # logging.debug(f"Worker {os.getpid()} fetch: {str(item)[:50]}")
                # Write inputs in our tempfile
                tmpfile.write_bytes(item.content)

                # Create to coverage file
                cov_file = tempfile.mktemp(f"_{item.hash}.cov")

                # Adjust injection location before calling QBDITrace
                cur_argv = argv[:]
                if seed_inj == SeedInjectLoc.ARGV:  # Try to replace the placeholder with filename
                    try:
                        # Replace 'input_file' in argv with the temporary file name created
                        idx = cur_argv.index(CoverageManager.ARGV_PLACEHOLDER)
                        cur_argv[idx] = str(tmpfile)
                    except ValueError as e:
                        logging.error(f"seed injection {seed_inj.name} but can't find '@@' on program argv: {argv}: {e}")
                        continue

                t0 = time.time()
                try:
                    # Run the seed
                    if QBDITrace.run(CoverageManager.STRATEGY,
                                     program,
                                     cur_argv,  # argv[1:] if len(argv) > 1 else [],
                                     output_path=str(cov_file),
                                     stdin_file=str(tmpfile) if seed_inj == SeedInjectLoc.STDIN else None,
                                     cwd=Path(program).parent,
                                     timeout=timeout):
                        item.replay_status = "SUCCESS"
                        # logging.info(f"[worker-{pid}] replaying {item.hash} sucessful")
                    else:
                        item.replay_status = "FAIL_NO_COV"
                        # logging.warning("Cannot load the coverage file generated (maybe had crashed?)")
                except TraceException:
                    item.replay_status = "FAIL_TIMEOUT"
                    # logging.warning('Timeout hit, while trying to re-run the seed')
                item.replay_time = time.time() - t0
                # Add it to the coverage queue (even if it failed
                cov_queue.put((item, cov_file))
        except KeyboardInterrupt:
            pass
            # logging.info(f"replay worker {os.getpid()}, stops (keyboard interrupt)")
