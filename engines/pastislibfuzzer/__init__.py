import os
from pathlib import Path
from typing import Optional
import subprocess
import logging

from .driver import LibfuzzerDriver
from .replay import Replay
from .workspace import Workspace

__version__ = "1.0.0"


# Libfuzzer env variables
LIBFUZZER_ENV_VAR = "LIBFUZZER_WS"
LIBFUZZER_THREADS = "LIBFUZZER_THREADS"

def spawn_online_libfuzzer(workspace: Path, port: int = 5555, threads: int=0):
    env = os.environ
    env[LIBFUZZER_ENV_VAR] = str(workspace.absolute())
    logging.info(f"libfuzzer workspace: {str(workspace.absolute())}")
    if threads:
        env[LIBFUZZER_THREADS] = str(threads)
    cmd_line_libfuzzer = ["pastis-libfuzzer", "online", "-p", f"{port}"]
    logging.info(f"run: {' '.join(cmd_line_libfuzzer)}")
    return subprocess.Popen(cmd_line_libfuzzer, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
