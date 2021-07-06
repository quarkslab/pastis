import logging
import os
import subprocess
import re
import signal
import time
from pathlib import Path

# Local imports
from .workspace import Workspace


class HonggfuzzNotFound(Exception):
    """ Issue raised on """
    pass


class HonggfuzzProcess:

    HFUZZ_ENV_VAR = "HFUZZ_PATH"
    BINARY = "honggfuzz"
    STAT_FILE = "statsfile.log"
    VERSION = "2.1"

    def __init__(self, path: str = None):
        if path is None:
            path = os.environ.get(self.HFUZZ_ENV_VAR)
        self.__path = Path(path) / self.BINARY
        self.__process = None

        if not self.__path.exists():
            raise Exception('Invalid Honggfuzz path!')

    def start(self, target: str, target_arguments: str, workspace: Workspace, persistent: bool, stdin: bool, engine_args: str):
        # Build target command line.
        target_cmdline = f"{target} {target_arguments}"

        # Build fuzzer arguments.
        # NOTE: Assuming the target receives inputs from stdin.
        hfuzz_arguments = ' '.join([
            f"--statsfile {workspace.stats_file}",
            f"--stdin_input" if stdin else "",
            f"--persistent" if persistent else "",
            re.sub(r"\s", " ", engine_args),  # Any arguments coming right from the broker (remove \r\n)
            f"--logfile logfile.log",
            f"--sanitizers_del_report true",
            f"--input {workspace.input_dir}",
            f"--dynamic_input {workspace.dynamic_input_dir}",
            f"--output {workspace.corpus_dir}",
            f"--crashdir {workspace.crash_dir}",
            f"--workspace {workspace.root_dir}"
        ])

        # Build fuzzer command line.
        hfuzz_cmdline = f'{self.__path} {hfuzz_arguments} -- {target_cmdline}'

        logging.info(f"Run Honggfuzz with: {hfuzz_cmdline}")
        logging.debug(f"\tWorkspace: {workspace.root_dir}")

        # Remove empty strings when converting the command to a list.
        command = list(filter(None, hfuzz_cmdline.split(' ')))

        # Create a new fuzzer process and set it apart into a new process group.
        self.__process = subprocess.Popen(command, cwd=str(workspace.root_dir), preexec_fn=os.setsid)

        logging.debug(f'Process pid: {self.__process.pid}')

    @property
    def instanciated(self):
        return self.__process is not None

    def stop(self):
        if self.__process:
            logging.debug(f'Stopping process with pid: {self.__process.pid}')
            os.killpg(os.getpgid(self.__process.pid), signal.SIGTERM)
        else:
            logging.debug(f"Honggfuzz process seem's already killed")

    def wait(self):
        while not self.instanciated:
            time.sleep(0.1)
        self.__process.wait()

    @staticmethod
    def hfuzz_environ_check() -> bool:
        return os.environ.get(HonggfuzzProcess.HFUZZ_ENV_VAR) is not None
