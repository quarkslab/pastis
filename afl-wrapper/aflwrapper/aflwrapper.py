# builtin imports
import inotify.adapters
import logging
import os
from pathlib import Path
import signal
import stat
import subprocess
import threading
import time
import hashlib
import re
from typing import Callable, List, Dict, Union

# Third party imports
from libpastis import FileAgent, ClientAgent
from libpastis.types import Arch, CheckMode, CoverageMode, ExecMode, FuzzingEngine, SeedInjectLoc, SeedType, State, \
                            PathLike, LogLevel, AlertData
try:  # Make the klocwork support optional
    from klocwork import KlocworkReport
    KLOCWORK_SUPPORTED = True
except ImportError:
    KLOCWORK_SUPPORTED = False

# Local imports
from aflwrapper.replay import Replay


class AFLNotFound(Exception):
    """ Issue raised on """
    pass


def check_afl_path() -> None:
    return os.environ.get('AFL_PATH') is not None


class ManagedProcess:
    def __init__(self):
        self.__process = None

    @property
    def instanciated(self):
        return self.__process is not None

    def start(self, command: str, workspace: str = '.'):
        logging.debug(f'Starting process...')
        logging.debug(f'\tCommand: {command}')
        logging.debug(f'\tWorkspace: {workspace}')

        # Remove empty strings when converting the command to a list.
        command = list(filter(None, command.split(' ')))

        # Create a new fuzzer process and set it apart into a new process group.
        self.__process = subprocess.Popen(command, cwd=str(workspace),
                                            preexec_fn=os.setsid,
                                            stdout=subprocess.PIPE,
                                            stdin=subprocess.PIPE,
                                            stderr=subprocess.PIPE
                                        )

        logging.debug(f'Process pid: {self.__process.pid}')

    def stop(self):
        if self.__process:
            logging.debug(f'Stopping process with pid: {self.__process.pid}')
            os.killpg(os.getpgid(self.__process.pid), signal.SIGTERM)
        else:
            logging.debug(f"AFL process seem's already killed")

    def wait(self):
        while not self.instanciated:
            time.sleep(0.1)
        self.__process.wait()


class AFLProcess:
    def __init__(self, path: PathLike):
        self.__path = Path(path) / "afl-fuzz"
        self.__process = ManagedProcess()

        if not self.__path.exists():
            raise Exception('Invalid AFL path!')

    def start(self, target: str, target_arguments: str, target_workspace: Dict, exmode: ExecMode, seed_inj: SeedInjectLoc, engine_args: str):
        # Build target command line.
        target_cmdline = f"{target} {target_arguments}"

        # Build fuzzer arguments.
        # NOTE: Assuming the target receives inputs from stdin.
        afl_arguments = ' '.join([
            re.sub(r"\s", " ", engine_args),  # Any arguments coming right from the broker (remove \r\n)
            "-M main", # Master MODE, seed distribution is ensured by the broker
            f"-o {target_workspace['root']}",
            f"-F {target_workspace['dynamic-inputs']}",
        ])

        # Build fuzzer command line
        os.environ.putenv("AFL_NO_UI", "1")
        os.environ.putenv("AFL_QUIET", "1")
        os.environ.putenv("AFL_IMPORT_FIRST", "1")
        os.environ.putenv("AFL_SKIP_CPUFREQ", "1")

        #os.environ.putenv("AFL_AUTORESUME", "1")

        afl_cmdline = f'{self.__path} {afl_arguments} -- {target_cmdline}'

        logging.info(f"Run AFL with: {afl_cmdline}")

        # Start fuzzer.
        self.__process.start(afl_cmdline, target_workspace['root'])

    def stop(self):
        self.__process.stop()

    def wait(self):
        self.__process.wait()


class DirectoryEventWatcher:

    def __init__(self, path: Path, event_type: str, callback: Callable):
        self.__path = path
        self.__event_type = event_type
        self.__callback = callback
        self.__inotify = inotify.adapters.Inotify()
        self.__thread = None
        self.__terminate = False

    def start(self):
        self.__terminate = False

        self.__thread = threading.Thread(target=self.__handler, daemon=True)
        self.__thread.start()

    def stop(self):
        self.__terminate = True
        self.__thread.join()

    def try_add_watch(self):
        while (1):
            try:
                self.__inotify.add_watch(str(self.__path))
            except inotify.calls.InotifyError:
                time.sleep(1)
                continue
            break

    def try_rm_watch(self):
        while (1):
            try:
                self.__inotify.remove_watch(str(self.__path))
            except inotify.calls.InotifyError:
                time.sleep(1)
                continue
            break

    def __handler(self):
        self.try_add_watch()
        logging.debug(f"Added EventWatcher to {self.__path}")
        for event in self.__inotify.event_gen():
            if self.__terminate:
                break

            if event is not None:
                (header, type_names, watch_path, filename) = event

                # Since AFL cleans up folders upon start-up, we might need to reset the EventWatchers
                # TODO There's a high probability of missing the first few seeds
                if 'IN_DELETE_SELF' in type_names:
                    self.try_rm_watch()
                    self.try_add_watch()

                elif self.__event_type in type_names:
                    self.__callback(Path(watch_path) / filename)
        self.try_rm_watch()


class AFL:
    def __init__(self, agent: ClientAgent):
        self._agent = agent

        # Parameters received through start_received
        self.__exec_mode = None   # SINGLE_RUN, PERSISTENT
        self.__check_mode = None  # CHECK_ALL, ALERT_ONLY
        self.__seed_inj = None    # STDIN or ARGV
        self.__report = None      # Klocwork report if supported

        # File watcher threads
        self.__coverage_watcher = None
        self.__crashes_watcher = None
        self.__stats_watcher = None

        self.__afl_path = os.environ.get('AFL_PATH')
        if self.__afl_path is None:
            raise AFLNotFound()
        self.__afl_version = '3.10'
        self.__afl_workspace = Path(os.environ.get('AFL_WS', '/dev/shm/afl'))
        self.__afl_process = AFLProcess(self.__afl_path)

        self.__target_id = self.__generate_id()
        self.__target_path = None
        self.__target_args = None  # Kept for replay
        self.__target_workspace = None
        self.__setup_target_workspace()

        self.__setup_agent()

        self._tel_counter = 0

        # Runtime data
        self._tot_seeds = 0

        # Variables for replay
        self._replay_thread = None
        self._queue_to_send = []
        self._started = False

    def start(self, bin_name: str, binary: bytes, argv: List[str], exmode: ExecMode, seed_inj: SeedInjectLoc, engine_args: str):
        # Write target to disk.
        self.__target_path = self.__target_workspace['target'] / bin_name
        self.__target_path.write_bytes(binary)
        self.__target_path.chmod(stat.S_IRWXU)  # Change target mode to execute.
        self.__target_args = argv

        self.__setup_watchers()
        self.__start_watchers()

        logging.info("Start process")
        self.__afl_process.start(self.__target_path.absolute(), " ".join(argv), self.__target_workspace, exmode, seed_inj, engine_args)
        self._started = True

        # Start the replay worker (note that the queue might already have started to be filled by agent thread)
        self._replay_thread = threading.Thread(target=self.replay_worker, daemon=True)
        self._replay_thread.start()


    def stop(self):
        self.__afl_process.stop()
        self.__stop_watchers()
        self._started = False  # should stop the replay thread

    def replay_worker(self):
        while True:
            if not self._started:
                break  # Break when the fuzzer stops
            if self._queue_to_send:
                filename, res = self._queue_to_send.pop(0)
                self.__check_seed_alert(filename, is_crash=res)
            time.sleep(0.05)

    @property
    def started(self):
        return self._started

    def add_seed(self, seed: bytes):
        # Write seed to disk.
        seed_path = self.__target_workspace['dynamic-inputs'] / f'seed-{self.__generate_id()}'
        seed_path.write_bytes(seed)

    def init_agent(self, remote: str = "localhost", port: int = 5555):
        self._agent.register_start_callback(self.start_received)  # Register start because launched manually (not by pastisd)
        self._agent.connect(remote, port)
        self._agent.start()
        # Send initial HELLO message, whick will make the Broker send the START message.
        self._agent.send_hello([(FuzzingEngine.AFL, self.__afl_version)])

    def run(self):
        self.__afl_process.wait()

    def __setup_target_workspace(self):
        target_root_workspace = self.__afl_workspace / f'{self.__target_id}'

        # Make sure there's no directory for the job id.
        if target_root_workspace.exists():
            raise Exception('Target workspace already exists.')

        self.__target_workspace = {
            'root' : target_root_workspace,
            'main': target_root_workspace / 'main',
            'target': target_root_workspace / 'main' / 'target',
            'inputs': target_root_workspace / 'main'/ 'inputs',
            'dynamic-inputs': target_root_workspace / 'main'/  'sync',
            'outputs': target_root_workspace / 'main',
            'coverage': target_root_workspace / 'main' / 'queue',
            'crashes': target_root_workspace / 'main' / 'crashes',
            'stats': target_root_workspace / 'main' / 'fuzzer_stats',
        }

        for name, path in self.__target_workspace.items():
            if not path.exists() and name != 'stats':
                path.mkdir(parents=True)

    def __setup_agent(self):
        # Register callbacks.
        self._agent.register_seed_callback(self.__seed_received)
        self._agent.register_stop_callback(self.__stop_received)

    def __setup_watchers(self):
        self.__coverage_watcher = DirectoryEventWatcher(self.__target_workspace['coverage'], 'IN_CLOSE_WRITE', self.__send_seed)
        self.__crashes_watcher = DirectoryEventWatcher(self.__target_workspace['crashes'], 'IN_CLOSE_WRITE', self.__send_crash)
        self.__stats_watcher = DirectoryEventWatcher(self.__target_workspace['stats'], 'IN_MODIFY', self.__send_telemetry)
        # Inotify logs are very talkative, set them to ERROR
        for logger in (logging.getLogger(x) for x in ["inotify.adapters", "inotify", "inotify.calls"]):
            logger.setLevel(logging.WARNING)

    def __start_watchers(self):
        self.__coverage_watcher.start()
        self.__crashes_watcher.start()
        self.__stats_watcher.start()

    def __stop_watchers(self):
        self.__coverage_watcher.stop()
        self.__crashes_watcher.stop()
        self.__stats_watcher.stop()

    @staticmethod
    def __generate_id():
        return int(time.time())

    def __send_seed(self, filename: Path):
        self._tot_seeds += 1
        file = Path(filename)
        logging.info(f'[SEED] Sending new seed: {file.name} [{self._tot_seeds}]')
        self._agent.send_seed(SeedType.INPUT, file.read_bytes())
        self._queue_to_send.append((filename, False))

    def __send_crash(self, filename: Path):
        self._tot_seeds += 1
        file = Path(filename)
        logging.info(f'[CRASH] Sending new crash: {file.name} [{self._tot_seeds}]')
        self._agent.send_seed(SeedType.CRASH, file.read_bytes())
        self._queue_to_send.append((filename, True))

    def __check_seed_alert(self, filename: Path, is_crash: bool):
        p = Path(filename)
        #logging.debug(f"Start replaying {filename}")
        # Only rerun the seed if in alert only mode and a klocwork report was provided
        if self.__check_mode == CheckMode.ALERT_ONLY and self.__report:

            # Rerun the program with the seed
            run = Replay.run(self.__target_path.absolute(), self.__target_args, stdin_file=filename, timeout=5, cwd=str(self.__target_workspace['target']))

            # Iterate all covered alerts
            for id in run.alert_covered:
                alert = self.__report.get_alert(binding_id=id)
                if not alert.covered:
                    alert.covered = True
                    logging.info(f"New alert covered {alert} [{alert.id}]")
                    self._agent.send_alert_data(AlertData(alert.id, alert.covered, False, p.read_bytes()))

            # Check if the target has crashed and if so tell the broker which one
            if run.has_crashed() or run.is_asan_without_crash():  # Also consider ASAN warning as detection
                if not run.crashing_id:
                    self.dual_log(LogLevel.WARNING, f"Crash on {filename.name} but can't link it to a Klocwork alert (maybe bonus !)")
                else:
                    alert = self.__report.get_alert(binding_id=run.crashing_id)
                    if not alert.validated:
                        alert.validated = True
                        bugt, aline = run.asan_info()
                        self.dual_log(LogLevel.INFO, f"AFL new alert validated {alert} [{alert.id}] ({aline})  (asan no crash: {run.is_asan_without_crash()})")
                        self._agent.send_alert_data(AlertData(alert.id, alert.covered, alert.validated, p.read_bytes()))
            else:
                if is_crash:
                    self.dual_log(LogLevel.WARNING, f"crash not reproducible by rerunning seed: {filename.name}")

            if run.has_hanged():  # Honggfuzz does not stores 'hangs' it will have been sent as corpus or crash
                self.dual_log(LogLevel.WARNING, f"Seed {filename} was hanging in replay")


    def __send_telemetry(self, filename: Path):
        self._tel_counter += 1
        if (self._tel_counter % 2) != 0:
            return

        logging.debug(f'[TELEMETRY] Stats file updated: {filename}')
        with open(filename, 'r') as stats_file:
            #try:
                stats = stats_file.readlines()

                if not stats:
                    return

                for line in stats:
                    line_ = line[:-1].replace(' ', '').split(':')

                    if line_[0] == 'execs_done':
                        total_exec = int(line_[1])
                    elif line_[0] == 'last_path':
                        last_cov_update = int(line_[1])
                    elif line_[0] == 'execs_per_sec':
                        exec_per_sec = int(float(line_[1]))
                    elif line_[0] == 'edges_found':             # aka hangs.
                        edges = int(line_[1])
                    elif line_[0] == 'unique_hangs':
                        timeout = int(line_[1])
                    elif line_[0] == 'unique_crashes':
                        crashes = int(line_[1])
                    elif line_[0] == 'cycles_done':
                        cycles = int(line_[1])
                    elif line_[0] == 'paths_total':
                        paths = int(line_[1])
                    else:
                        continue

                # Stats format:
                #   unix_time, last_cov_update, total_exec, exec_per_sec,
                #   crashes, unique_crashes, hangs, edge_cov, block_cov
                # NOTE: `cycle` and `coverage_path` does not apply for Honggfuzz.
                self._agent.send_telemetry(state=State.RUNNING, exec_per_sec=exec_per_sec,
                                            total_exec=total_exec, timeout=timeout,
                                            coverage_edge=edges,
                                            coverage_path=paths,
                                            last_cov_update=last_cov_update,
                                            cycle=cycles)
            #except:
            #    logging.error(f'Error retrieving stats!')

    def start_received(self, fname: str, binary: bytes, engine: FuzzingEngine,
                        exmode: ExecMode, chkmode: CheckMode, _: CoverageMode,
                        seed_inj: SeedInjectLoc, engine_args: str,
                        argv: List[str], kl_report: str = None):
        logging.info(f"[START] bin:{fname} engine:{engine.name} exmode:{exmode.name} seedloc:{seed_inj.name} chk:{chkmode.name}")
        if self.started:
            self._agent.send_log(LogLevel.CRITICAL, "Instance already started!")
            return

        if engine not in [FuzzingEngine.AFL, FuzzingEngine.AFL_UNICORN, FuzzingEngine.AFL_QEMU]:
            logging.error(f"Wrong fuzzing engine received {engine} while I am AFL")
            self._agent.send_log(LogLevel.ERROR, "Invalid fuzzing engine received {engine} can't do anything")
            return

        if kl_report:
            if KLOCWORK_SUPPORTED:
                logging.info("Loading klocwork report")
                self.__report = KlocworkReport.from_json(kl_report)
                if not self.__report.has_binding():
                    logging.info("Report not binded (auto_bind it)")
                    self.__report.auto_bind()
            else:
                self.dual_log(LogLevel.ERROR, "Klocwork report provided while Klocwork not supported by host")

        self.__check_mode = chkmode  # CHECK_ALL, ALERT_ONLY

        self.start(fname, binary, argv, exmode, seed_inj, engine_args)

    def __seed_received(self, typ: SeedType, seed: bytes):
        logging.info(f"[SEED] received  {hashlib.md5(seed).hexdigest()} ({typ.name})")
        self.add_seed(seed)

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
        log_f = getattr(logging, mapper[level])
        log_f(message)
        self._agent.send_log(level, message)

    def add_initial_seed(self, file: Union[str, Path]):
        p = Path(file)
        logging.info(f"add initial seed {file.name}")
        # Write seed to disk.
        seed_path = self.__target_workspace['inputs'] / p.name
        seed_path.write_bytes(p.read_bytes())

class AFL_QEMU(AFL):
    def __init__(self, agent: ClientAgent):
        super().__init__(agent)

    def init_agent(self, remote: str = "localhost", port: int = 5555):
        self._agent.register_start_callback(self.start_received)  # Register start because launched manually (not by pastisd)
        self._agent.connect(remote, port)
        self._agent.start()
        # Send initial HELLO message, whick will make the Broker send the START message.
        self._agent.send_hello([(FuzzingEngine.AFL_QEMU, self._AFL__afl_version)])

class AFL_UNICORN(AFL):
    def __init__(self, agent: ClientAgent):
        super().__init__(agent)

    def init_agent(self, remote: str = "localhost", port: int = 5555):
        self._agent.register_start_callback(self.start_received)  # Register start because launched manually (not by pastisd)
        self._agent.connect(remote, port)
        self._agent.start()
        # Send initial HELLO message, whick will make the Broker send the START message.
        self._agent.send_hello([(FuzzingEngine.AFL_UNICORN, self._AFL__afl_version)])
