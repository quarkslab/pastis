# builtin imports
import hashlib
import logging
import threading
import time
import os

from pathlib import Path
from typing import List, Union, Set, Type

# Third party imports
from libpastis import ClientAgent, BinaryPackage, SASTReport
from libpastis.types import CheckMode, CoverageMode, ExecMode, FuzzingEngineInfo, SeedInjectLoc, SeedType, State, \
                            LogLevel, AlertData, FuzzMode


# Local imports
import pastislibfuzzer
from pastislibfuzzer.replay import Replay
from pastislibfuzzer.libfuzzer import LibfuzzerProcess, LibfuzzerState
from pastislibfuzzer.workspace import Workspace


# Inotify logs are very talkative, set them to ERROR
for logger in (logging.getLogger(x) for x in ["watchdog.observers.inotify_buffer", 'watchdog.observers', "watchdog"]):
    logger.setLevel(logging.ERROR)


class LibfuzzerDriver:

    RESTART_WINDOW = 30 # 240  # seconds

    def __init__(self, agent: ClientAgent, telemetry_frequency: int = 60):

        # Internal objects
        self._agent = agent
        self.workspace = Workspace()
        self.libfuzzer = LibfuzzerProcess()

        # Parameters received through start_received
        self.__exec_mode = None   # SINGLE_RUN, PERSISTENT
        self.__check_mode = None  # CHECK_ALL, ALERT_ONLY
        self.__seed_inj = None    # STDIN or ARGV
        self.__report = None      # Klocwork report if supported

        # Target data
        self.__package = None
        self.__target_args = None  # Kept for replay

        self.__setup_agent()

        # Configure hookds on workspace
        self.workspace.add_creation_hook(self.workspace.input_dir, self.__send_seed)
        self.workspace.add_creation_hook(self.workspace.crash_dir, self.__send_crash)
        # self.workspace.add_file_modification_hook(self.workspace.stats_file, self.__send_telemetry)

        # Telemetry frequency
        self._tel_frequency = telemetry_frequency
        self._tel_last = time.time()

        # Runtime data
        self._tot_seeds = 0
        self._seed_recvs: Set[str] = set()  # Seed received to make sure NOT to send them back
        self._input_recvs_count = 0  # keep a counter of received inputs
        self._last_start = 0  # Last time we started libfuzzer
        
        # Variables for replay
        self._replay_thread = None
        self._queue_to_send = []
        self._started = False

    @staticmethod
    def hash_seed(seed: bytes) -> str:
        return hashlib.md5(seed).hexdigest()

    def start(self,
              package: BinaryPackage,
              argv: List[str],
              exmode: ExecMode,
              fuzzmode: FuzzMode,
              seed_inj: SeedInjectLoc,
              engine_args: str,
              envp: list[str],
              threads: int,
              exec_timeout: int):
        # Write target to disk.
        self.__package = package
        self.__target_args = argv

        self.workspace.start()  # Start looking at directories

        logging.info(f"Start process (injectloc: {seed_inj.name})") # type: ignore
        self.libfuzzer.start(str(package.executable_path.absolute()),
                         argv,
                         self.workspace,
                         exmode,
                         fuzzmode,
                         seed_inj == SeedInjectLoc.STDIN,
                         engine_args,
                         envp,
                         str(package.cmplog.absolute()) if package.cmplog else None,
                         str(package.dictionary.absolute()) if package.dictionary else None,
                         threads,
                         exec_timeout)
        self._started = True
        self._last_start = time.time()

        # Start the replay worker (note that the queue might already have started to be filled by agent thread)
        self._replay_thread = threading.Thread(target=self.replay_worker, daemon=True)
        self._replay_thread.start()

    def stop(self):
        match self.libfuzzer.status:
            case LibfuzzerState.IDLE:
                logging.info("cannot stop, Libfuzzer has never started")
            case LibfuzzerState.RUNNING:
                logging.info("Stopping Libfuzzer")
                self.libfuzzer.stop()
            case LibfuzzerState.RESTARTING:
                logging.info("Libfuzzer is restarting, waiting for it to be relaunched to stop it")
                while self.libfuzzer.status != LibfuzzerState.RUNNING:
                    time.sleep(0.1)  # Wait for the fuzzer to be restarted
                self.libfuzzer.stop()
            case LibfuzzerState.TERMINATED:
                logging.info("Libfuzzer is already terminated, nothing to do")
        
        self.workspace.stop()
        self._started = False  # should stop the replay thread

    def replay_worker(self):
        while True:
            if not self._started:
                break  # Break when the fuzzer stops
            if self._queue_to_send:
                filename, res = self._queue_to_send.pop(0)
                if not self.__check_seed_alert(filename, is_crash=res):
                    break
            time.sleep(0.05)

    @property
    def started(self):
        return self._started

    def init_agent(self, remote: str = "localhost", port: int = 5555):
        self._agent.register_start_callback(self.start_received)  # Register start because launched manually (not by pastisd)
        self._agent.connect(remote, port)
        self._agent.start()
        # Send initial HELLO message, whick will make the Broker send the START message.
        self._agent.send_hello([FuzzingEngineInfo("LIBFUZZER", pastislibfuzzer.__version__, "pastislibfuzzer.addon")])

    def run(self):
        self.libfuzzer.wait()

    def __setup_agent(self):
        # Register callbacks.
        self._agent.register_seed_callback(self.__seed_received)
        self._agent.register_stop_callback(self.__stop_received)

    def __send_seed(self, filename: Path):
        self.__send(filename, SeedType.INPUT) # type: ignore
        self.__send_periodic_telemetry()

    def __send_crash(self, filename: Path):
        self.__send(filename, SeedType.CRASH) # type: ignore

    def __send(self, filename: Path, typ: SeedType):
        self._tot_seeds += 1
        file = Path(filename)
        raw = file.read_bytes()
        h = self.hash_seed(raw)
        logging.debug(f'[{typ.name}] Sending new: {h} [{self._tot_seeds}]') # type: ignore
        if h not in self._seed_recvs:
            self._agent.send_seed(typ, raw)
        else:
            logging.info("seed (previously sent) do not send it back")
        self._queue_to_send.append((filename, True if typ == SeedType.CRASH else False))

    def __check_seed_alert(self, filename: Path, is_crash: bool) -> bool:
        p = Path(filename)
        # Only rerun the seed if in alert only mode and a SAST report was provided
        if self.__check_mode == CheckMode.ALERT_ONLY and self.__report:

            # Rerun the program with the seed
            assert self.__package is not None and self.__target_args is not None
            run = Replay.run(str(self.__package.executable_path.absolute()), self.__target_args, stdin_file=filename, timeout=5, cwd=str(self.workspace.target_dir))

             # Iterate all covered alerts
            for id in run.alert_covered:
                alert = self.__report.alerts[id]
                if not alert.covered:
                    alert.covered = True
                    logging.info(f"New alert covered {alert} [{alert.id}]")
                    self._agent.send_alert_data(AlertData(alert.id, alert.covered, False, p.read_bytes()))

            # Check if the target has crashed and if so tell the broker which one
            if run.has_crashed() or run.is_asan_without_crash():  # Also consider ASAN warning as detection
                if not run.crashing_id:
                    self.dual_log(LogLevel.WARNING, f"Crash on {filename.name} but can't link it to a Klocwork alert (maybe bonus !)") # type: ignore
                else:
                    alert = self.__report.alerts[run.crashing_id]
                    if not alert.validated:
                        alert.validated = True
                        bugt, aline = run.asan_info()
                        self.dual_log(LogLevel.INFO, f"AFLPP new alert validated {alert} [{alert.id}] ({aline})  (asan no crash: {run.is_asan_without_crash()})") # type: ignore
                        self._agent.send_alert_data(AlertData(alert.id, alert.covered, alert.validated, p.read_bytes()))
            else:
                if is_crash:
                    self.dual_log(LogLevel.WARNING, f"crash not reproducible by rerunning seed: {filename.name}") # type: ignore

            if run.has_hanged():  # AFLPP does not stores 'hangs' it will have been sent as corpus or crash
                self.dual_log(LogLevel.WARNING, f"Seed {filename} was hanging in replay") # type: ignore
        return True

    @staticmethod
    def __read_last_lines(filename: Path, line_num: int = 3) -> list[str]:
        """
        Read the last `lines` lines of a file.
        """
        with open(filename, 'r') as f:
            end_pos = f.seek(0, os.SEEK_END)
            off = f.seek(max(end_pos - 300, 0), os.SEEK_SET)
            chunk = f.read(end_pos - off)
            lines = chunk.splitlines()[1:]
            return lines[-line_num:]
    
    def __send_periodic_telemetry(self):
        filename = self.workspace.stats_file

        now = time.time()
        if now < (self._tel_last + self._tel_frequency):
            return
        self._tel_last = now

        logging.debug(f'[TELEMETRY] Stats file updated: {filename}')

        # Read the last 3 lines of the stats file
        lines = self.__read_last_lines(filename, 10)

        for line in lines[::-1]: # read lines from the end, take the first that matches
            
            if "cov:" in line:  # We are on a good line
                items = line.split()

                state = State.RUNNING
                coverage, oom, to, crash, execs = 0, 0, 0, 0, 0
                try:
                    if idx := items.index("cov:"):
                        coverage = int(items[idx + 1])
                    if idx := items.index("exec/s:"):
                        execs = int(items[idx + 1])
                    if "oom/timeout/crash:" in items:
                        oom, to, crash = items[items.index("oom/timeout/crash:") + 1].split("/")

                    self._agent.send_telemetry(state=state, # type: ignore
                                                exec_per_sec=execs,
                                                timeout=int(to),
                                                coverage_edge=coverage)
                    return
                except ValueError as e:
                    logging.error(f"Error parsing stats file: {filename} ({e})")

        # if reach here it means that the stats file is not well formatted
        logging.warning(f'Error retrieving stats!')

    def start_received(self,
                       fname: str,
                       binary: bytes,
                       engine: FuzzingEngineInfo,
                       exmode: ExecMode,
                       fuzzmode: FuzzMode,
                       chkmode: CheckMode,
                       cov: CoverageMode,
                       seed_inj: SeedInjectLoc,
                       engine_args: str,
                       argv: List[str],
                       envp: list[str],
                       sast_report: str|None,
                       threads: int,
                       exec_timeout: int):
        logging.info(f"[START] bin:{fname} engine:{engine.name} exmode:{exmode.name} seedloc:{seed_inj.name} chk:{chkmode.name}") # type: ignore
        if self.started:
            self._agent.send_log(LogLevel.CRITICAL, "Instance already started!") # type: ignore
            return

        if engine.name != "LIBFUZZER":
            logging.error(f"Wrong fuzzing engine received {engine.name} while I am LibFuzzer")
            self._agent.send_log(LogLevel.ERROR, f"Invalid fuzzing engine received {engine.name} can't do anything") # type: ignore
            return
        if engine.version != pastislibfuzzer.__version__:
            logging.error(f"Wrong fuzzing engine version {engine.version} received")
            self._agent.send_log(LogLevel.ERROR, f"Invalid fuzzing engine version {engine.version} do nothing") # type: ignore
            return

        # Retrieve package out of the binary received
        try:
            package = BinaryPackage.from_binary(fname, binary, self.workspace.target_dir)
        except FileNotFoundError:
            logging.error("Invalid package received")
            return
        except ValueError:
            logging.error("Invalid package received")
            return

        if sast_report:
            logging.info("Loading SAST report")
            self.__report = SASTReport.from_json(sast_report)

        self.__check_mode = chkmode  # CHECK_ALL, ALERT_ONLY

        self.start(package, argv, exmode, fuzzmode, seed_inj, engine_args, envp, threads, exec_timeout)

    def __seed_received(self, typ: SeedType, seed: bytes):
        h = self.hash_seed(seed)
        logging.info(f"[SEED] received  {h} ({typ.name})") # type: ignore
        self._seed_recvs.add(h)  # save hash as being received
        self._input_recvs_count += 1

        seed_path = self.workspace.input_dir / f"seed-{h}"
        seed_path.write_bytes(seed)

        # Checks to potentially restart libfuzzer
        now = time.time()
        if self.libfuzzer.status == LibfuzzerState.RUNNING:  # don't do anything if already RESTARTING
            if now > (self._last_start + self.RESTART_WINDOW) and self._input_recvs_count > 0:  # 4 minutes
                logging.info(f"Restarting libfuzzer")
                self.libfuzzer.restart()
                self._last_start = now
                self._input_recvs_count = 0

    def __stop_received(self):
        logging.info(f"[STOP]")

        self.stop()

    def dual_log(self, level: LogLevel, message: str) -> None:
        """
        Helper function to log message both in the local log system and also
        to the broker.

        :param level: LogLevel message type
        :param message: string message to log
        :return: None
        """
        mapper = {LogLevel.DEBUG: "debug",
                  LogLevel.INFO: "info",
                  LogLevel.CRITICAL: "critical",
                  LogLevel.WARNING: "warning",
                  LogLevel.ERROR: "error"}
        log_f = getattr(logging, mapper[level]) # type: ignore
        log_f(message)
        self._agent.send_log(level, message)

    def add_initial_seed(self, file: Path):
        logging.info(f"add initial seed {file.name}")
        self._seed_recvs
        # Write seed to disk.
        seed_path = self.workspace.input_dir / file.name
        seed_path.write_bytes(file.read_bytes())
