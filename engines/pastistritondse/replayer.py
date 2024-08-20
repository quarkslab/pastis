import logging
import os
import time
from pathlib import Path
from typing import Optional, Tuple

from tritondse import CoverageSingleRun
from tritondse.trace import QBDITrace, TraceException

from libpastis.types import SeedInjectLoc


class Replayer(object):

    INPUT_FILE_NAME = "input_file"

    RAMDISK_PATH = "/mnt/ramdisk"

    DEFAULT_WS_DIR = "tritondse_replayer_workspace"

    SEED_FILE = "tritondse.seed"
    TRACE_FILE = "tritondse.trace"

    def __init__(self, program, config, seed_inj):
        self.__config = config
        self.__program = program
        self.__seed_inj = seed_inj

        self.__coverage_strategy = self.__config.coverage_strategy
        self.__program_argv = None
        self.__program_cwd: Path = Path(self.__program.path).parent
        self.__program_path: Path = self.__program.path.resolve()
        self.__replay_timeout = 60
        self.__seed_file = None
        self.__stdin_file = None
        self.__trace_file = None

        self.__initialize_files()

        self.__initialize_stdin()
        self.__initialize_argv()

    def __initialize_files(self):
        ramdisk_dir = Path(self.RAMDISK_PATH)

        tmp_dir = ramdisk_dir if ramdisk_dir.exists() else Path(f"/tmp")
        tmp_dir = tmp_dir / self.DEFAULT_WS_DIR / f"{int(time.time())}"
        tmp_dir.mkdir(parents=True)

        logging.info(f"tmp directory for replayer set to: {tmp_dir}")

        self.__trace_file = tmp_dir / self.TRACE_FILE
        self.__seed_file = tmp_dir / self.SEED_FILE

    def __initialize_stdin(self):
        if self.__seed_inj == SeedInjectLoc.STDIN:
            self.__stdin_file = str(self.__seed_file)
        else:
            self.__stdin_file = None

    def __initialize_argv(self):
        # Copy program_argv as we might modify it.
        argv = self.__config.program_argv[:]

        if self.__seed_inj == SeedInjectLoc.ARGV:
            try:
                # Replace 'input_file' in argv with the temporary file name created
                idx = argv.index(self.INPUT_FILE_NAME)
                argv[idx] = str(self.__seed_file)
            except ValueError:
                logging.error(f"seed injection {self.__seed_inj.name} but can't find '{self.INPUT_FILE_NAME}' on program argv")
                raise Exception(f"No '{self.INPUT_FILE_NAME}' in program argv.")

        self.__program_argv = argv[1:] if len(argv) > 1 else []

    def run(self, seed: bytes) -> Tuple[Optional[CoverageSingleRun], float]:
        start_time = time.time()

        self.__seed_file.write_bytes(seed)

        coverage = None
        try:
            # Run the seed and obtain the coverage.
            rv = QBDITrace.run(self.__coverage_strategy,
                               str(self.__program_path),
                               self.__program_argv,
                               output_path=str(self.__trace_file),
                               stdin_file=self.__stdin_file,
                               cwd=str(self.__program_cwd),
                               timeout=self.__replay_timeout)
            if rv:
                coverage = QBDITrace.from_file(str(self.__trace_file)).coverage
        except TraceException:
            logging.warning('There was an error while trying to re-run the seed')
        except FileNotFoundError:
            logging.warning("Cannot load the coverage file generated (maybe had crashed?)")
        except Exception as e:
            logging.warning(f'Unexpected error occurred while trying to re-run the seed: {e}')

        replay_time = time.time() - start_time

        return coverage, replay_time
