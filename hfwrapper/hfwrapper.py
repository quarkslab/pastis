import inotify.adapters
import logging
import os
import pathlib
import shutil
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


HFUZZ_CONFIG = {
    'HFUZZ_PATH': pathlib.Path('/mnt/hdd/workspace/missions/pastis/repositories/honggfuzz'),
    'HFUZZ_VERSION': '2.1',
    'HFUZZ_WS': pathlib.Path('/tmp/hfuzz-workspace'),
}


class ManagedProcess:

    def __init__(self):
        self.__process = None

    def kill(self):
        if self.__process:
            logging.debug(f'Killing process with pid: {self.__process.pid}')
            os.killpg(os.getpgid(self.__process.pid), signal.SIGTERM)

    def start(self, command, workspace='.'):
        logging.debug(f'Starting process...')
        logging.debug(f'\tCommand: {command}')
        logging.debug(f'\tWorkspace: {workspace}')

        # NOTE: Make sure to remove empty strings when converting the command
        # from a string to a list.
        command = list(filter(None, command.split(' ')))

        # Create a new fuzzer process and set it apart into a new process group.
        self.__process = subprocess.Popen(command, cwd=str(workspace), preexec_fn=os.setsid)

        logging.debug(f'Process pid: {self.__process.pid}')


class HonggfuzzProcess:

    def __init__(self, path, workspace):
        self.__path = path
        self.__workspace = workspace
        self.__process = ManagedProcess()

    def start(self, target, target_arguments, workspace, job_id):
        # NOTE: Assuming the target receives inputs from stdin.

        # Build fuzzer arguments.
        hfuzz_arguments = ' '.join([
            f"--statsfile {workspace['stats']}/statsfile.log",
            f"--stdin_input",
            f"--logfile logfile.log",
            f"--input {workspace['inputs']}",
            f"--output {workspace['coverage']}",
            f"--crashdir {workspace['crashes']}",
            f"--workspace {workspace['outputs']}"
        ])

        # Build target command line.
        target_cmdline = f"{target} {target_arguments}"

        # Build fuzzer command line.
        hfuzz_cmdline = f'{self.__path} {hfuzz_arguments} -- {target_cmdline}'

        # Start fuzzer.
        self.__process.start(hfuzz_cmdline, self.__workspace / f'{job_id}')

    def stop(self):
        self.__process.kill()


class HonggfuzzJobManager:

    def __init__(self, path, workspace):
        # Job Id -> HFuzz instance map.
        self.__jobs = {}

        self.__path = path
        self.__workspace = workspace

    def start(self, target, arguments, seeds=None):
        # Make sure the target exists.
        target = pathlib.Path(target)

        if not target.exists():
            raise Exception('The target does not exists.')

        job_id = self.__generate_id()

        workspace = self.__create_workspace(job_id)

        if seeds:
            self.__copy_seeds(workspace['inputs'], seeds)

        hfuzz_instance = HonggfuzzProcess(self.__path, self.__workspace)

        hfuzz_instance.start(target, arguments, workspace, job_id)

        self.__jobs[job_id] = hfuzz_instance

        return job_id

    def stop(self, job_id):
        if job_id not in self.__jobs:
            raise Exception('Invalid job ID.')

        hfuzz_instance = self.__jobs[job_id]
        hfuzz_instance.stop()

    def get_stats_file(self, job_id):
        return pathlib.Path(self.__workspace / f'{job_id}' / 'statsfile.log')

    def get_coverage_files(self, job_id):
        files = []
        coverage_path = pathlib.Path(self.__workspace / f'{job_id}' / 'outputs' / 'coverage')

        for file in coverage_path.glob('**/*.cov'):
            files.append(file.name)

        return files

    def get_crash_files(self, job_id):
        files = []
        crashes_path = pathlib.Path(self.__workspace / f'{job_id}' / 'outputs' / 'crashes')

        for file in crashes_path.glob('**/*.hfuzz'):
            files.append(file.name)

        return files

    def __generate_id(self):
        return int(time.time())

    def __create_workspace(self, job_id):
        general_workspace = self.__workspace
        job_workspace = general_workspace / f'{job_id}'

        # Make sure there's no directory for the job id.
        if job_workspace.exists():
            raise Exception('Job workspace already exists.')

        workspace = {
            'workspace': job_workspace,
            'inputs': job_workspace / 'inputs',
            'outputs': job_workspace / 'outputs',
            'coverage': job_workspace / 'outputs' / 'coverage',
            'crashes': job_workspace / 'outputs' / 'crashes',
            'stats': job_workspace / 'stats',
        }

        for _, path in workspace.items():
            path.mkdir(parents=True)

        return workspace

    def __copy_seeds(self, destination, seeds):
        # Make sure the destination exists.
        if not destination.exists():
            raise Exception('Destination does not exist.')

        for seed in seeds.glob('**/*'):
            logging.debug('Copying {seed} to {destination}')

            shutil.copyfile(seed, destination / seed.name)


class Honggfuzz:

    def __init__(self, agent):
        self.__agent = agent

        self.__job_id = None

        self.__job_manager = HonggfuzzJobManager(HFUZZ_CONFIG['HFUZZ_PATH'] / 'honggfuzz', HFUZZ_CONFIG['HFUZZ_WS'])

        self.__coverage_monitor = None
        self.__crashes_monitor = None
        self.__stats_monitor = None

        self.__terminate = False

        self.__target_path = None
        self.__coverage_path = None
        self.__crashes_path = None
        self.__stats_path = None

        self.__setup_agent()

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
        # TODO: Make sure every Honggfuzz instance has been stopped.
        self.__job_manager.stop(self.__job_id)

        self.__terminate = True

        self.__coverage_monitor.join()
        self.__crashes_monitor.join()
        self.__stats_monitor.join()

        self.__agent.send_stop_coverage_criteria()

    def add_seed(self, seed):
        # TODO: Implement.
        pass

    def run(self, target='', target_arguments=''):
        # Connect with the Broker.
        self.__agent.connect()

        # Start main loop.
        self.__agent.start()

        # Send initial HELLO message, whick will make the Broker send the START message.
        self.__agent.send_hello([(FuzzingEngine.HONGGFUZZ, HFUZZ_CONFIG['HFUZZ_VERSION'])], Arch.X86_64)

        if isinstance(self.__agent, FileAgent):
            # def __start_received(self, fname: str, binary: bytes, engine: FuzzingEngine, exmode: ExecMode, chkmode: CheckMode,
            #                    covmode: CoverageMode, seed_inj: SeedInjectLoc, engine_args: str, argv: List[str], kl_report: str=None):
            target_path = pathlib.Path(target)
            binary = target_path.read_bytes()

            self.__start_received(target_path, binary, FuzzingEngine.HONGGFUZZ,
                ExecMode.SINGLE_EXEC, CheckMode.CHECK_ALL, CoverageMode.BLOCK,
                SeedInjectLoc.STDIN, '', target_arguments.split(' '), "")

        # Send Alive message.
        while True:
            self.__agent.send_log(LogLevel.DEBUG, f"Alive: {int(time.time())}")

            time.sleep(2)

    def __setup_agent(self):
        # Register callbacks.
        self.__agent.register_seed_callback(self.__seed_received)
        self.__agent.register_start_callback(self.__start_received)
        self.__agent.register_stop_callback(self.__stop_received)

    def __generate_id(self):
        return int(time.time())

    def __monitor_coverage(self):
        i = inotify.adapters.Inotify()

        i.add_watch(str(self.__coverage_path))

        for event in i.event_gen():
            if self.__terminate:
                break

            if event is not None:
                (header, type_names, watch_path, filename) = event

                if 'IN_CLOSE_WRITE' in type_names:
                    logging.debug(f'[SEED] Sending new seed: {filename}')

                    file = pathlib.Path(watch_path) / filename
                    bts = file.read_bytes()

                    self.__agent.send_seed(SeedType.INPUT, bts, FuzzingEngine.HONGGFUZZ)

        i.remove_watch(str(self.__coverage_path))

    def __monitor_crashes(self):
        i = inotify.adapters.Inotify()

        i.add_watch(str(self.__crashes_path))

        for event in i.event_gen():
            if self.__terminate:
                break

            if event is not None:
                (header, type_names, watch_path, filename) = event

                if 'IN_CLOSE_WRITE' in type_names:
                    logging.debug(f'[SEED] Sending new crash: {filename}')

                    file = pathlib.Path(watch_path) / filename
                    bts = file.read_bytes()

                    self.__agent.send_seed(SeedType.CRASH, bts, FuzzingEngine.HONGGFUZZ)

        i.remove_watch(str(self.__crashes_path))

    def __monitor_stats(self):
        i = inotify.adapters.Inotify()

        i.add_watch(str(self.__stats_path))

        for event in i.event_gen():
            if self.__terminate:
                break

            if event is not None:
                (header, type_names, watch_path, filename) = event

                if 'IN_MODIFY' in type_names:
                    logging.debug(f'[TELEMETRY] Stats file updated: {filename}')

                    file = pathlib.Path(watch_path) / filename

                    stats = ''
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

                        self.__agent.send_telemetry(state=State.RUNNING, total_exec=mutations, timeout=hangs)
                    except:
                        logging.error(f'Error parsing stats!')

        i.remove_watch(str(self.__stats_path))

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
