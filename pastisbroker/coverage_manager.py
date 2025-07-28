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

from libpastis.types import SeedType, SeedInjectLoc, ReplayType

from pastisbroker.coverage import QbdiCoverage, LlvmProfileCoverage, CoverageUpdateDiff
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
    # FIXME: check if keep it like this


class CoverageManager(object):

    ARGV_PLACEHOLDER = "@@"

    def __init__(self,
                 global_coverage: Path,
                 pool_size: int,
                 replay_timeout: int,
                 filter: bool,
                 program: Path,
                 replay_type: ReplayType,
                 args: list[str],
                 inj_loc: SeedInjectLoc,
                 stream_file: str = "",
                 env: dict[str, str] | None = None):
        # Base info for replay
        self.pool_size = pool_size
        self.replay_timeout = replay_timeout
        self.filter_enabled = filter
        self.replay_type = replay_type
        self.program = program
        self.args = args
        self.inj_loc = inj_loc
        self.env = env if env is not None else {}

        # Coverage and messaging attributes
        if replay_type == ReplayType.qbdi:
            self._coverage = QbdiCoverage(global_coverage)
        elif replay_type == ReplayType.llvm_profile:
            self._coverage = LlvmProfileCoverage(program, global_coverage)
        else:
            assert False

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
            self.pool.apply_async(self.replay_worker, (self.input_queue, self.cov_queue, self.program, self.args, self.inj_loc, self.replay_timeout, self.replay_type, self.env))

    def stop(self) -> None:
        self._running = False
        self.cov_worker.join()
        self.pool.terminate()

    def push_input(self, cli_input: ClientInput) -> None:
        """
        Push the clent input in the pending queue of inputs to re-run
        to determine whether it should be kept or not.
        """
        cli_input.log_time = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())
        # logging.info(f"push input {str(cli_input)[:50]}")

        # Update stats
        self.seeds_submitted += 1
        if cli_input.fuzzer_id in self.cli_stats:
            self.cli_stats[cli_input.fuzzer_id][0] += 1
        else:
            self.cli_stats[cli_input.fuzzer_id] = [1, 0]

        self.input_queue.put(cli_input)

    def push_input_synchronous(self, cli_input: ClientInput) -> None:
        self.push_input(cli_input)
        self.replay_one_input_in_queue(self.input_queue, # type: ignore
                                       self.cov_queue, # type: ignore
                                       self.program,
                                       self.args,
                                       self.inj_loc,
                                       self.replay_timeout,
                                       self.replay_type,
                                       Path("/tmp/toto.txt"),
                                       os.getpid(),
                                       self.env)
        self.read_one_coverage_in_queue()   


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
            assert self.csv is not None, "CSV writer not initialized"
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
        """
        Solo thread that receive coverage/trace files updates the coverage
        and determine the outcome for that input. 
        """
        while self._running:
            try:
                self.read_one_coverage_in_queue()
            except KeyboardInterrupt:
                self._running = False
                logging.info("coverage worker stop")
                break
            except Exception as e:
                logging.exception(f"Exception in coverage worker {e}")
                self._running = False
                break

    def read_one_coverage_in_queue(self):
        try:
            item, cov_file = self.cov_queue.get(timeout=0.5)
            if not cov_file.exists():
                raise FileNotFoundError(f"Coverage file {cov_file} does not exist")
            # logging.info("Coverage worker fetch item")
            _print_new_items = []
            try:
                covdiff: CoverageUpdateDiff = self._coverage.add_coverage_file(cov_file)
                if covdiff.updated:
                    self.cli_stats[item.fuzzer_id][1] += 1  # input accepted

                    item.new_coverage = list(covdiff.new_items)
                    _print_new_items = item.new_coverage

                    self.grant_input(item)

                else:
                    item.broker_status = "DROPPED" if self.filter_enabled else "GRANTED"
                    # logging.info(f"seed {item.hash} ({item.seed_status.name}) of {item.fuzzer_name} rejected (do not improve coverage)")

                # Remove the coverage file
                os.unlink(cov_file)

            except json.JSONDecodeError:
                item.replay_status = "FAIL_PARSE_COV"
                os.unlink(cov_file)
                self.grant_input(item)

            except FileNotFoundError:
                # self.grant_input(item)  # Grant input
                # If not coverage file generated, just drop input
                item.broker_status = "DROPPED"
                logging.warning(f"Coverage file {cov_file} does not exist")

            logging.info(f"seed {item.hash} ({item.fuzzer_name})"
                         f"[replay:{self.mk_rpl_status(item.replay_status)}]"
                         f"[{self.mk_broker_status(item.broker_status, bool(_print_new_items))}]"
                         f"[{int(item.replay_time):}s] ({len(_print_new_items)} new edges)"
                         f" (pool: inp={self.input_queue.qsize()}, cov={self.cov_queue.qsize()})")
            # Regardless if it was a success or not log it
            self.add_item_coverage_stream(item)
        except queue.Empty:
            pass


    def grant_input(self, item: ClientInput) -> None:
        """
        Add the input to the granted_queue if
        filtering is activated and the input is not
        part of the initial.
        """
        self.seeds_accepted += 1
        if self.filter_enabled:  # if not enabled do not need to put it in granted input (just logging)
            if item.fuzzer_name != "INITIAL":  # if not initial corpus add it
                self.granted_queue.put(item)

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
    def replay_worker(input_queue: Queue,
                      cov_queue: Queue,
                      program: Path,
                      argv: list[str],
                      seed_inj: SeedInjectLoc,
                      timeout,
                      replay_type: ReplayType,
                      env: dict[str, str]) -> None:
        """
        worker thread that unstack inputs and replay them (in parrallel)
        """
        tmpfile = Path(tempfile.mktemp(suffix=f"{os.getpid()}.input"))
        pid = os.getpid()
        Path(f"/tmp/replay_worker-{pid}").write_text("into !")
        
        try:
            while True:
                CoverageManager.replay_one_input_in_queue(input_queue, cov_queue, program, argv, seed_inj, timeout, replay_type, tmpfile, pid, env)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logging.exception(f"Exception in replay worker {e}")
            # logging.info(f"replay worker {os.getpid()}, stops (keyboard interrupt)")

    @staticmethod
    def replay_one_input_in_queue(input_queue: Queue,
                                  cov_queue: Queue,
                                  program: Path,
                                  argv: list[str],
                                  seed_inj: SeedInjectLoc,
                                  timeout: int,
                                  replay_type: ReplayType,
                                  tmpfile: Path,
                                  pid: int,
                                  env: dict[str, str]):
        item: ClientInput = input_queue.get()
        # logging.debug(f"Worker {os.getpid()} fetch: {str(item)[:50]}")
        # Write inputs in our tempfile
        tmpfile.write_bytes(item.content)

        # Create to coverage file
        cov_file = Path(tempfile.mktemp(f"_{item.hash}.cov"))

        # Adjust injection location before calling QBDITrace
        cur_argv = argv[:]
        if seed_inj == SeedInjectLoc.ARGV:  # Try to replace the placeholder with filename
            try:
                # Replace 'input_file' in argv with the temporary file name created
                idx = cur_argv.index(CoverageManager.ARGV_PLACEHOLDER)
                cur_argv[idx] = str(tmpfile)
            except ValueError as e:
                logging.error(f"seed injection {seed_inj.name} but can't find '@@' on program argv: {argv}: {e}")
                return

        t0 = time.time()

        cwd = program.parent
        is_stdin = bool(seed_inj == SeedInjectLoc.STDIN)
        
        # Run the seed
        logging.info(f"[replay-worker] running input into trace {cov_file}")
        Runner = QbdiCoverage if replay_type == ReplayType.qbdi else LlvmProfileCoverage
        if Runner.run(program,
                      cur_argv,
                      timeout,
                      tmpfile,
                      cov_file,
                      is_stdin,
                      cwd,
                      env):
            item.replay_status = "SUCCESS"
            logging.info(f"[worker-{pid}] replaying {item.hash} sucessful")
        else:
            item.replay_status = "FAIL_NO_COV"
            logging.warning("Cannot load the coverage file generated (maybe had crashed?)")
        
        item.replay_time = time.time() - t0
        # Add it to the coverage queue (even if it failed
        cov_queue.put((item, cov_file))
