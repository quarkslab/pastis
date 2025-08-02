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
from hashlib import md5
from enum import IntEnum

from libpastis.types import SeedType, SeedInjectLoc, ReplayType

from pastisbroker.coverage import QbdiCoverage, LlvmProfileCoverage, CoverageUpdateDiff, ReplayStatus
from pastisbroker.utils import Bcolors, mk_color
from pastisbroker.workspace import Workspace



class BrokerStatus(IntEnum):
    """
    Status of the broker
    """
    UNSET = 0
    GRANTED = 1
    DROPPED = 2
    # DUPLICATE = 3


@dataclass
class ClientInput:
    content: bytes          # Content of the input
    log_time: str           # Time the log has been generated
    recv_time: str          # Time the input has been received
    elapsed: str            # Elapsed time since the begining
    hash: str               # Input hash
    filename: str           # Input file path
    seed_status: SeedType   # Status of the seed
    fuzzer_id: bytes        # Fuzzer ID
    fuzzer_name: str        # Fuzzer name
    broker_status: BrokerStatus # Status in: DUPLICATE, DROPPED, GRANTED
    replay_status: ReplayStatus # Status in: OK, TRACE_EXCEPTION, FAIL
    replay_time: float      # Time taken for the replay
    new_coverage: list[tuple[int, int]]  # New items covered
    # FIXME: check if keep it like this

    def is_initial_input(self) -> bool:
        """
        Check if the input is part of the initial corpus
        """
        return self.fuzzer_name == "INITIAL"

    @staticmethod
    def unpack_name(fname: str) -> tuple[str, str, str, str]:
        """
        Unpack the name of the input file to retrieve the time, elapsed,
        client id and hash.
        """
        sp = fname.split("_")
        if len(sp) != 5:
            raise ValueError(f"Invalid input filename format: {fname}")
        date, time_rcv, elapsed, client_id, hash = sp
        hash = hash.split(".")[0]  # Remove the extension
        return f"{date}_{time_rcv}", elapsed, client_id, hash
    
    @staticmethod
    def make(fname: str,
             seed: bytes,
             typ: SeedType,
             netid: bytes) -> 'ClientInput':
        log_time = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())
        date, elapsed, client_id, hash = ClientInput.unpack_name(fname)
        return ClientInput(seed, log_time, date, elapsed, hash, fname, typ, netid,
                           client_id, BrokerStatus.UNSET, ReplayStatus.FAIL_EXCEPTION, -1, [])
        
    @staticmethod
    def make_initial(fname: str, seed: bytes) -> 'ClientInput':
        return ClientInput.make(fname, seed, SeedType.INPUT, b"INITIAL")


@dataclass
class CoverageConfig:
    enabled: bool = False
    filter_inputs: bool = False
    replay_thread: int = 1
    replay_timeout: int = 60
    replay_binary: Path = Path("")
    replay_type: ReplayType = ReplayType.qbdi



class CoverageManager(object):

    ARGV_PLACEHOLDER = "@@"

    def __init__(self,
                 workspace: Workspace,
                 config: CoverageConfig,
                 args: list[str],
                 inj_loc: SeedInjectLoc,
                 env: dict[str, str] | None = None):
        
        # Base info for replay
        self.workspace = workspace
        self.config = config
        self.args = args
        self.inj_loc = inj_loc
        self.env = env if env is not None else {}

        # Coverage and messaging attributes
        if self.config.replay_type == ReplayType.qbdi:
            self._coverage = QbdiCoverage(workspace.coverage_file)
        elif self.config.replay_type == ReplayType.llvm_profile:
            self._coverage = LlvmProfileCoverage(config.replay_binary.absolute(), workspace.coverage_file)
        else:
            assert False

        self._manager = Manager()
        self.input_queue = self._manager.Queue()   # Incoming inputs to replay
        self.cov_queue = self._manager.Queue()     # Coverage queue filled after replay
        self.granted_queue = self._manager.Queue() # Queue of granted inputs
        self._pending_inputs = 0  # Count of inputs not yet fully processed

        # Pool of workers
        self.pool = Pool(self.config.replay_thread)
        self._running = False
        self.cov_worker = Thread(name="[coverage_worker]", target=self.coverage_worker)

        # stats
        self.seeds_accepted, self.seeds_submitted = 0, 0
        self.cli_stats = {}

        # If coverage enabled open CSV log file
        if self.config.enabled:
            self.cov_history = open(self.workspace.coverage_history, "a")
            self.csv = csv.writer(self.cov_history)
        else:
            self.cov_history, self.csv = None, None

        # Then start threads
        self.start()

    def has_pending_inputs(self) -> bool:
        """
        Return the number of pending inputs to be processed
        """
        return self._pending_inputs != 0

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    @property
    def filtering(self) -> bool:
        return self.config.filter_inputs

    def start(self) -> None:
        """
        Start all the workers
        """
        # First start the coverage worker
        self._running = True
        self.cov_worker.start()
        logging.info("Starting coverage manager")

        for work_id in range(self.config.replay_thread):
            self.pool.apply_async(self.replay_worker, (self.input_queue, self.cov_queue, self.config.replay_binary,
                                                       self.args, self.inj_loc, self.config.replay_timeout,
                                                       self.config.replay_type, self.env))

    def stop(self) -> None:
        if self._running:  # Only join if it was started
            self._running = False
            self.cov_worker.join()
            self.pool.terminate()

    def push_input(self, cli_input: ClientInput) -> None:
        """
        Push the clent input in the pending queue of inputs to re-run
        to determine whether it should be kept or not.
        """
        # Update submission stats
        self.seeds_submitted += 1
        if cli_input.fuzzer_id in self.cli_stats:
            self.cli_stats[cli_input.fuzzer_id][0] += 1
        else:
            self.cli_stats[cli_input.fuzzer_id] = [1, 0]

        # If coverage enabled replay it.
        if self.enabled:
            self._pending_inputs += 1
            self.input_queue.put(cli_input)
        else:
            # WARNING: In this case we do not gather coverage..
            self.grant_input(cli_input)

    def push_input_synchronous(self, cli_input: ClientInput) -> None:
        self.push_input(cli_input)
        self.replay_one_input_in_queue(self.input_queue, # type: ignore
                                       self.cov_queue, # type: ignore
                                       self.config.replay_binary,
                                       self.args,
                                       self.inj_loc,
                                       self.config.replay_timeout,
                                       self.config.replay_type,
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
        if self.enabled:  # Coverage enabled
            assert self.csv is not None, "CSV writer not initialized"
            assert self.cov_history is not None, "Coverage history file not initialized"
            self.csv.writerow([
                item.log_time,
                item.recv_time,
                item.elapsed,
                item.hash,
                item.filename,
                item.seed_status.name,
                item.fuzzer_name,
                item.broker_status.name,
                item.replay_status.name,
                f"{item.replay_time:.2f}",
                len(item.new_coverage)
            ])
            self.cov_history.flush()

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
        """
        | Replay   | New Cov   | Filter   | Status  |
        |----------|-----------|----------|---------|
        | OK       | Yes       | Yes      | OK      |
        | OK       | Yes       | No       | OK      |
        | OK       | No        | Yes      | Dropped |
        | OK       | No        | No       | OK      |
        | Fail     | -         | Yes      | Dropped |
        | Fail     | -         | No       | OK      |
        |----------|-----------|----------|---------|
        """
        _print_new_items = []
        new_cov = False

        try:
            item, cov_file = self.cov_queue.get(timeout=0.5)

            match item.replay_status:
                case ReplayStatus.SUCCESS:
                    # Try loading the coverage file
                    try:
                        covdiff: CoverageUpdateDiff = self._coverage.add_coverage_file(cov_file)
                        # Successfully loaded the coverage file
                        if covdiff.updated:
                            self.cli_stats[item.fuzzer_id][1] += 1  # input accepted

                            item.new_coverage = list(covdiff.new_items)

                            new_cov = True  # for printing
                            _print_new_items = item.new_coverage

                            item.broker_status = BrokerStatus.GRANTED
                        else:
                            item.broker_status = BrokerStatus.DROPPED if self.filtering else BrokerStatus.GRANTED

                    except json.JSONDecodeError:  # Failed to parse coverage file
                        item.replay_status = ReplayStatus.FAIL_PARSE_COV
                        item.broker_status = BrokerStatus.DROPPED if self.filtering else BrokerStatus.GRANTED
                    finally:
                        os.unlink(cov_file)  # either way remove the coverage file
                
                case _: # FAIL_NO_COV, FAIL_TIMEOUT, FAIL_EXCEPTION
                    item.broker_status = BrokerStatus.DROPPED if self.filtering else BrokerStatus.GRANTED                  

            # At this point the broker_status is "final"
            if item.broker_status == BrokerStatus.GRANTED:
                self.grant_input(item)

            # Performed in ALL cases!
            self._pending_inputs -= 1  # Decrease the pending inputs count regardless of the outcome

            logging.info(f"seed {item.hash} ({item.fuzzer_name})"
                         f"[replay:{self.mk_rpl_status(item.replay_status)},"
                         f"cov:{self.mk_color_bool(new_cov, soft=True)} => "
                         f"{self.mk_broker_status(item.broker_status)}]"
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
        self.granted_queue.put(item)

    @staticmethod
    def mk_rpl_status(status: ReplayStatus) -> str:
        if status == ReplayStatus.SUCCESS:
            return mk_color("OK", Bcolors.OKGREEN)
        else:
            return mk_color(status.name, Bcolors.FAIL)

    @staticmethod
    def mk_color_bool(bool_val: bool, soft: bool = False) -> str:
        if bool_val:
            return mk_color("YES", Bcolors.OKGREEN)
        else:
            return mk_color("NO", Bcolors.WARNING if soft else Bcolors.FAIL)

    @staticmethod
    def mk_broker_status(status: BrokerStatus) -> str:
        if status == BrokerStatus.GRANTED:
            return mk_color(status.name, Bcolors.OKGREEN)
        elif status == BrokerStatus.DROPPED:
            return mk_color(status.name, Bcolors.FAIL)
        else:
            return mk_color(status.name, Bcolors.WARNING)

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

        # Run the given input on the coverage program
        status = Runner.run(program,
                      cur_argv,
                      timeout,
                      tmpfile,
                      cov_file,
                      is_stdin,
                      cwd,
                      env)
        
        if status == ReplayStatus.SUCCESS:
            logging.info(f"[worker-{pid}] replaying {item.hash} sucessful")
        else:
            logging.warning(f"[worker-{pid}] replay fail: {status.name.lower()}")
        item.replay_status = status
        item.replay_time = time.time() - t0
        # Add it to the coverage queue (even if it failed
        cov_queue.put((item, cov_file))
