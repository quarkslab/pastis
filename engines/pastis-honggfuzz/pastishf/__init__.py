import os
from pathlib import Path
from typing import Optional
import subprocess

from .driver import HonggfuzzDriver
from .replay import Replay
from .honggfuzz import HonggfuzzProcess, HonggfuzzNotFound
from .workspace import Workspace

__version__ = "1.0.0"

# Honggfuzz env variables
HFUZZ_ENV_VAR = "HFUZZ_WS"
HFUZZ_PATH_VAR = "HFUZZ_PATH"
HFUZZ_THREADS = "HFUZZ_THREADS"


def spawn_online_honggfuzz(workspace: Optional[Path], hf_path: Optional[str], port: int = 5555, threads: int=0):
    env = os.environ
    env[HFUZZ_ENV_VAR] = str(workspace.absolute())
    if hf_path:
        env[HFUZZ_PATH_VAR] = str(hf_path)
    if threads:
        env[HFUZZ_THREADS] = str(threads)
    cmd_line_honggfuzz = ["pastis-honggfuzz", "online", "-p", f"{port}"]
    subprocess.Popen(cmd_line_honggfuzz, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

