import logging
import os
import re
import signal
import subprocess
import time

from libpastis.types import ExecMode, FuzzMode
from pathlib import Path

# Local imports
from .workspace import Workspace


class AFLPPNotFound(Exception):
    """ Issue raised on """
    pass


class AFLPPProcess:

    AFLPP_ENV_VAR = "AFLPP_PATH"
    BINARY = "afl-fuzz"
    STAT_FILE = "fuzzer_stats"
    VERSION = "master"

    def __init__(self, path: str = None):
        if path is None:
            path = os.environ.get(self.AFLPP_ENV_VAR)
        self.__path = Path(path) / self.BINARY
        self.__process = None
        self.__logfile = None

        if not self.__path.exists():
            raise Exception('Invalid AFL++ path!')

    def start(self, target: str, target_arguments: str, workspace: Workspace, exmode: ExecMode, fuzzmode: FuzzMode, stdin: bool, engine_args: str):
        # Build target command line.
        target_cmdline = f"{target} {target_arguments}"

        # Build fuzzer arguments.
        # NOTE: Assuming the target receives inputs from stdin.
        aflpp_arguments = ' '.join([
            re.sub(r"\s", " ", engine_args),  # Any arguments coming right from the broker (remove \r\n)
            f"-Q" if fuzzmode == FuzzMode.BINARY_ONLY else "",
            f"-M main", # Master MODE, seed distribution is ensured by the broker
            f"-i {workspace.input_dir}",
            f"-F {workspace.dynamic_input_dir}",
            f"-o {workspace.output_dir}",
        ])

        # Export environmental variables.
        os.environ.putenv("AFL_NO_UI", "1")
        os.environ.putenv("AFL_QUIET", "1")
        os.environ.putenv("AFL_IMPORT_FIRST", "1")
        os.environ.putenv("AFL_AUTORESUME", "1")

        # NOTE This prevents having to configure the system before running
        #      AFL++.
        # TODO Should we skip these steps?
        os.environ.putenv("AFL_SKIP_CPUFREQ", "1")
        os.environ.putenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")

        # Build fuzzer command line.
        aflpp_cmdline = f'{self.__path} {aflpp_arguments} -- {target_cmdline}'

        logging.info(f"Run AFL++ with: {aflpp_cmdline}")
        logging.debug(f"\tWorkspace: {workspace.root_dir}")

        # Remove empty strings when converting the command to a list.
        command = list(filter(None, aflpp_cmdline.split(' ')))

        # Open logfile (stdout will be redirected to this file).
        self.__logfile = open(workspace.root_dir / 'logfile.log', 'w')

        # Create a new fuzzer process and set it apart into a new process group.
        self.__process = subprocess.Popen(command, cwd=str(workspace.root_dir), preexec_fn=os.setsid, stdout=self.__logfile)

        logging.debug(f'Process pid: {self.__process.pid}')

    @property
    def instanciated(self):
        return self.__process is not None

    def stop(self):
        if self.__process:
            logging.debug(f'Stopping process with pid: {self.__process.pid}')
            os.killpg(os.getpgid(self.__process.pid), signal.SIGTERM)
        else:
            logging.debug(f"AFL++ process seems already killed")

        if self.__logfile:
            self.__logfile.close()

    def wait(self):
        while not self.instanciated:
            time.sleep(0.1)
        self.__process.wait()

    @staticmethod
    def aflpp_environ_check() -> bool:
        return os.environ.get(AFLPPProcess.AFLPP_ENV_VAR) is not None
