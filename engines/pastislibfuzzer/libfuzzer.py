# builtin imports
import logging
import os
import re
import signal
import subprocess
import time
from typing import Optional, Union
from pathlib import Path
from enum import Enum

# third-party imports
import shutil
from libpastis.types import ExecMode, FuzzMode

# Local imports
from .workspace import Workspace


class LibfuzzerState(Enum):
    """
    Enum to represent the state of the fuzzer.
    """
    IDLE = 0        # not started
    RUNNING = 1     # running
    RESTARTING = 2  # restarting
    TERMINATED = 3  # terminated (not meant to re-run)


class LibfuzzerProcess:

    LIBFUZZER_THREADS_VAR = "LIBFUZZER_THREADS"

    def __init__(self):
        self.__process = None
        self.__logfile = None
        self._threads = os.environ.get(self.LIBFUZZER_THREADS_VAR, "1")
        self.status = LibfuzzerState.IDLE

        # Runtime data for restart
        self.__workspace = None

    def start(self,
              target: str,
              target_arguments: list[str],
              workspace: Workspace,
              exmode: ExecMode,
              fuzzmode: FuzzMode,
              stdin: bool,
              engine_args: str,
              env_variables: list[str],
              cmplog: Optional[str] = None,
              dictionary: Optional[str] = None):
        
        # Build target command line.
        target_cmdline = f"{target} {' '.join(target_arguments)}"

        # Build fuzzer arguments.
        libfuzzer_cmdline = ' '.join([
            target_cmdline,  # The fuzzer is the target itself
            re.sub(r"\s", " ", engine_args),  # Any arguments coming right from the broker (remove \r\n)
            f"-fork={self._threads}",  # Enable fork-mode
            f"-ignore_crashes=1",  # Ignore crashes (to fuzz indefinitely)
            f"-rss_limit_mb=4096", # Limit memory usage to 4GB
            f"-workers=1",  # Number of workers (threads within a fork) (if was set to threads we would have: threads=fork x workers)
            # f"-jobs={self._threads}",  # Number of jobs (sequential tasks)
            f"-dict={dictionary}" if dictionary is not None else "",
            f"-artifact_prefix={workspace.crash_dir}/",
            f"{workspace.input_dir}"  # Last argument is the input directory
        ])

        # Iterate over environment variables and set them in the global environment.
        for env_var in env_variables:
            if '=' in env_var:
                key, value = env_var.split('=', 1)
                os.environ[key] = value
            else:
                logging.warning(f"Invalid environment variable format: {env_var}")


        # logging.info(f"Run Libfuzzer: {libfuzzer_cmdline}")
        logging.debug(f"\tWorkspace: {workspace.root_dir}")

        # Remove empty strings when converting the command to a list.
        command = list(filter(None, libfuzzer_cmdline.split(' ')))

        # Open logfile (stdout will be redirected to this file).
        self.__logfile = open(workspace.stats_file, 'w')

        self.start_process(command, workspace)


    def start_process(self, command: list[str], workspace: Workspace):
        """
        Start the libfuzzer process with the given command.
        """

        # Create a new fuzzer process and set it apart into a new process group.
        self.__workspace = workspace
        logging.info(f"Run Libfuzzer with: {' '.join(command)}")

        self.__process = subprocess.Popen(command,
                                          cwd=str(workspace.root_dir),
                                          preexec_fn=os.setsid,
                                        #   stdout=self.__logfile,
                                          stderr=self.__logfile,
                                          shell=False,
                                          env=os.environ)
        self.status = LibfuzzerState.RUNNING
        logging.debug(f'Process pid: {self.__process.pid}')

    @property
    def is_running(self) -> bool:
        return self.status in [LibfuzzerState.RUNNING, LibfuzzerState.RESTARTING]

    def stop(self, final_stop: bool = True):
        if self.is_running:
            assert self.__process is not None
            logging.debug(f'Stopping process with pid: {self.__process.pid}')
            os.killpg(os.getpgid(self.__process.pid), signal.SIGTERM)
            self.__process.wait()  # Wait for the process to terminate gently
            if final_stop:  # otherwise keep the process in running/restarting state
                self.status = LibfuzzerState.TERMINATED
            # self.__process = None
        else:
            logging.debug(f"Libfuzzer process seems already killed")

        if self.__logfile and final_stop:
            self.__logfile.close()

    def wait(self):
        logging.debug("Waiting for fuzzer process to start...")
        while self.status == LibfuzzerState.IDLE:
            time.sleep(0.1)
        logging.debug("Process started...")
        while self.status != LibfuzzerState.TERMINATED:
            time.sleep(0.1)
            # self.__process.wait()  # Do not use wait() as the process might be restarted multiple times
        retcode = self.__process.returncode if self.__process else None
        logging.info(f"Fuzzer terminated with code : {retcode}")

    def restart(self):
        """
        Restart the fuzzer process.
        """
        if self.__process and self.__workspace:
            self.status = LibfuzzerState.RESTARTING
            self.stop(final_stop=False)
            self.start_process(self.__process.args, self.__workspace) # type: ignore
        else:
            logging.warning("Fuzzer process is not running.")
