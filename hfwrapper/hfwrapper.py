import logging
import os
import pathlib
import shutil
import signal
import subprocess
import time


logging.basicConfig(level=logging.INFO)


class ManagedProcess():

    def __init__(self):
        self.__process = None

    def kill(self):
        if self.__process:
            os.killpg(os.getpgid(self.__process.pid), signal.SIGTERM)

    def start(self, command, workspace):
        logging.debug(f'Command: {command}')
        logging.debug(f'Workspace: {workspace}')

        # NOTE: Make sure to remove empty strings when converting the command
        # from a string to a list.
        command = list(filter(None, command.split(' ')))

        # Create a new fuzzer process and set it apart into a new process group.
        logging.info(f'Starting process: {command}')
        self.__process = subprocess.Popen(command, cwd=str(workspace), preexec_fn=os.setsid)

        logging.info('Command pid: {}'.format(self.__process.pid))


class HonggfuzzProcess():

    def __init__(self, path, workspace):
        self.__path = path
        self.__workspace = workspace
        self.__timeout = 15
        self.__process = ManagedProcess()

    def start(self, target, target_arguments, workspace, job_id):
        # NOTE: Assuming the target receives inputs from stdin.

        # TODO: Find out why it is not terminating given the `--timeout` option
        # is passed correctly.

        # Build fuzzer arguments.
        hfuzz_arguments = ' '.join([
            f"--statsfile {workspace['stats']}/statsfile.log",
            f"--stdin_input",
            f"--logfile logfile.log",
            f"--timeout {self.__timeout}",
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


class HonggfuzzJobManager():

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

        workspace = {}

        workspace['workspace'] = job_workspace
        workspace['inputs'] = job_workspace / 'inputs'
        workspace['outputs'] = job_workspace / 'outputs'
        workspace['coverage'] = job_workspace / 'outputs' / 'coverage'
        workspace['crashes'] = job_workspace / 'outputs' / 'crashes'
        workspace['stats'] = job_workspace / 'stats'

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
