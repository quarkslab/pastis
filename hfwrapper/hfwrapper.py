import inotify.adapters
import logging
import os
import pathlib
import random
import signal
import stat
import subprocess
import threading
import time

from typing import List

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


logging.basicConfig(level=logging.INFO)


class ManagedProcess:

    def __init__(self):
        self.__process = None

    def start(self, command, workspace='.'):
        logging.debug(f'Starting process...')
        logging.debug(f'\tCommand: {command}')
        logging.debug(f'\tWorkspace: {workspace}')

        # Remove empty strings when converting the command to a list.
        command = list(filter(None, command.split(' ')))

        # Create a new fuzzer process and set it apart into a new process group.
        self.__process = subprocess.Popen(command, cwd=str(workspace), preexec_fn=os.setsid)

        logging.debug(f'Process pid: {self.__process.pid}')

    def stop(self):
        if self.__process:
            logging.debug(f'Stopping process with pid: {self.__process.pid}')
            os.killpg(os.getpgid(self.__process.pid), signal.SIGTERM)

    def wait(self):
        self.__process.wait()


class HonggfuzzProcess:

    def __init__(self, path):
        self.__path = pathlib.Path(path) / 'honggfuzz'
        self.__process = ManagedProcess()

        if not self.__path.exists():
            raise Exception('Invalid Honggfuzz path!')

    def start(self, target, target_arguments, target_workspace):
        # Build target command line.
        target_cmdline = f"{target} {target_arguments}"

        # Build fuzzer arguments.
        # NOTE: Assuming the target receives inputs from stdin.
        hfuzz_arguments = ' '.join([
            f"--statsfile {target_workspace['stats']}/statsfile.log",
            f"--stdin_input",
            f"--logfile logfile.log",
            f"--input {target_workspace['inputs']}",
            f"--dynamic_input {target_workspace['dynamic-inputs']}",
            f"--output {target_workspace['coverage']}",
            f"--crashdir {target_workspace['crashes']}",
            f"--workspace {target_workspace['outputs']}"
        ])

        # Build fuzzer command line.
        hfuzz_cmdline = f'{self.__path} {hfuzz_arguments} -- {target_cmdline}'

        # Start fuzzer.
        self.__process.start(hfuzz_cmdline, target_workspace['main'])

    def stop(self):
        self.__process.stop()

    def wait(self):
        self.__process.wait()


class DirectoryEventWatcher:

    def __init__(self, path, event_type, callback):
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

    def __handler(self):
        self.__inotify.add_watch(str(self.__path))

        for event in self.__inotify.event_gen():
            if self.__terminate:
                break

            if event is not None:
                (header, type_names, watch_path, filename) = event

                if self.__event_type in type_names:
                    self.__callback(pathlib.Path(watch_path) / filename)

        self.__inotify.remove_watch(str(self.__path))


class Honggfuzz:

    def __init__(self, agent):
        self.__agent = agent

        self.__coverage_watcher = None
        self.__crashes_watcher = None
        self.__stats_watcher = None

        self.__hfuzz_path = os.environ['HFUZZ_PATH']
        self.__hfuzz_version = '2.1'
        self.__hfuzz_workspace = pathlib.Path(os.environ.get('HFUZZ_WS', '/tmp/hfuzz_workspace'))
        self.__hfuzz_process = HonggfuzzProcess(self.__hfuzz_path)

        self.__target_id = self.__generate_id()
        self.__target_path = None
        self.__target_workspace = None

        self.__setup_target_workspace()

        self.__setup_agent()

    def start(self, binary, argv):
        self.__setup_target(binary)
        self.__setup_watchers()

        self.__hfuzz_process.start(self.__target_path.absolute(), ' '.join(argv), self.__target_workspace)

        self.__start_watchers()

    def stop(self):
        self.__hfuzz_process.stop()

        self.__stop_watchers()

        self.__agent.send_stop_coverage_criteria()

    def add_seed(self, seed):
        # Write seed to disk.
        seed_path = self.__target_workspace['dynamic-inputs'] / f'seed-{self.__generate_id()}'

        seed_path.write_bytes(seed)

    def run(self, target='', target_arguments=''):
        # Connect with the Broker.
        self.__agent.connect()

        # Start main loop.
        self.__agent.start()

        # Send initial HELLO message, whick will make the Broker send the START message.
        self.__agent.send_hello([(FuzzingEngine.HONGGFUZZ, self.__hfuzz_version)], Arch.X86_64)

        if isinstance(self.__agent, FileAgent):
            target_path = pathlib.Path(target)
            binary = target_path.read_bytes()

            self.__start_received(target_path, binary, FuzzingEngine.HONGGFUZZ,
                ExecMode.SINGLE_EXEC, CheckMode.CHECK_ALL, CoverageMode.BLOCK,
                SeedInjectLoc.STDIN, '', target_arguments.split(' '), "")

        # # TODO: Remove.
        # # Send Alive message.
        # while True:
        #     self.__agent.send_log(LogLevel.DEBUG, f"Alive: {int(time.time())}")

        #     # TODO: REMOVE. This is just for testing purposes.
        #     logging.debug(f'[SEED] Sending fake new seed...')
        #     self.__seed_received(SeedType.INPUT, os.urandom(random.randint(1, 100)), FuzzingEngine.TRITON)

        #     time.sleep(2)

        # TODO: Do something better here. We have to wait until the Honggfuzz
        # process has started.
        # Wait until the START message is received and the process starts.
        time.sleep(5)

        self.__hfuzz_process.wait()

    def __setup_target_workspace(self):
        target_main_workspace = self.__hfuzz_workspace / f'{self.__target_id}'

        # Make sure there's no directory for the job id.
        if target_main_workspace.exists():
            raise Exception('Target workspace already exists.')

        self.__target_workspace = {
            'main': target_main_workspace,
            'target': target_main_workspace / 'target',
            'inputs': target_main_workspace / 'inputs' / 'initial',
            'dynamic-inputs': target_main_workspace / 'inputs' / 'dynamic',
            'outputs': target_main_workspace / 'outputs',
            'coverage': target_main_workspace / 'outputs' / 'coverage',
            'crashes': target_main_workspace / 'outputs' / 'crashes',
            'stats': target_main_workspace / 'stats',
        }

        for _, path in self.__target_workspace.items():
            path.mkdir(parents=True)

    def __setup_target(self, binary):
        # Write target to disk.
        self.__target_path = self.__target_workspace['target'] / f'target.bin'

        self.__target_path.write_bytes(binary)

        # Change target mode to execute.
        self.__target_path.chmod(stat.S_IRWXU)

    def __setup_agent(self):
        # Register callbacks.
        self.__agent.register_seed_callback(self.__seed_received)
        self.__agent.register_start_callback(self.__start_received)
        self.__agent.register_stop_callback(self.__stop_received)

    def __setup_watchers(self):
        self.__coverage_watcher = DirectoryEventWatcher(self.__target_workspace['coverage'], 'IN_CLOSE_WRITE', self.__send_seed)
        self.__crashes_watcher = DirectoryEventWatcher(self.__target_workspace['crashes'], 'IN_CLOSE_WRITE', self.__send_crash)
        self.__stats_watcher = DirectoryEventWatcher(self.__target_workspace['stats'], 'IN_MODIFY', self.__send_telemetry)

    def __start_watchers(self):
        self.__coverage_watcher.start()
        self.__crashes_watcher.start()
        self.__stats_watcher.start()

    def __stop_watchers(self):
        self.__coverage_watcher.stop()
        self.__crashes_watcher.stop()
        self.__stats_watcher.stop()

    def __generate_id(self):
        return int(time.time())

    def __send_seed(self, filename):
        logging.debug(f'[SEED] Sending new seed: {filename}')

        content = pathlib.Path(filename).read_bytes()

        self.__agent.send_seed(SeedType.INPUT, content, FuzzingEngine.HONGGFUZZ)

    def __send_crash(self, filename):
        logging.debug(f'[SEED] Sending new crash: {filename}')

        content = pathlib.Path(filename).read_bytes()

        self.__agent.send_seed(SeedType.CRASH, content, FuzzingEngine.HONGGFUZZ)

    def __send_telemetry(self, filename):
        logging.debug(f'[TELEMETRY] Stats file updated: {filename}')

        with open(filename, 'r') as stats_file:
            try:
                stats = stats_file.readlines()[-1]

                if not stats or stats.startswith("#"):
                    return

                stats = stats.split(',')

                # unix_time, thread_no, tot_exec_per_sec, mutations, crashes,
                # unique_crashes, hangs, current (i/b/hw/ed/ip/cmp),
                # total (i/b/hw/ed/ip/cmp)
                # NOTE: `cycle` and `coverage_path` does not apply here.
                state = State.RUNNING
                exec_per_sec = int(stats[2])                    # aka tot_exec_per_sec
                total_exec = int(stats[3])                      # aka mutations
                timeout = int(stats[6])                         # aka hangs
                coverage_block = int(stats[8].split('/')[4])    # aka total.ip
                coverage_edge = int(stats[8].split('/')[3])     # aka total.ed
                last_cov_update = int(stats[0])                 # aka unix_time

                self.__agent.send_telemetry(state=state, exec_per_sec=exec_per_sec,
                                            total_exec=total_exec, timeout=timeout,
                                            coverage_block=coverage_block,
                                            coverage_edge= coverage_edge,
                                            last_cov_update=last_cov_update)
            except:
                logging.error(f'Error retrieving stats!')

    def __start_received(self, fname: str, binary: bytes, engine: FuzzingEngine, exmode: ExecMode, chkmode: CheckMode,
                       covmode: CoverageMode, seed_inj: SeedInjectLoc, engine_args: str, argv: List[str], kl_report: str=None):
        logging.info(f"[START] bin:{fname} engine:{engine.name} exmode:{exmode.name} cov:{covmode.name} chk:{chkmode.name}")

        self.start(binary, argv)

    def __seed_received(self, typ: SeedType, seed: bytes, origin: FuzzingEngine):
        logging.info(f"[SEED] [{origin.name}] {seed.hex()} ({typ})")

        self.add_seed(seed)

    def __stop_received(self):
        logging.info(f"[STOP]")

        self.stop()
