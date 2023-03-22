import os
from pathlib import Path
from typing import Optional
import subprocess
import logging

from .driver import AFLPPDriver
from .replay import Replay
from .aflpp import AFLPPProcess, AFLPPNotFound
from .workspace import Workspace

__version__ = "1.0.0"


# AFL++ env variables
AFLPP_ENV_VAR = "AFLPP_WS"

def spawn_online_aflpp(workspace: Optional[Path], port: int = 5555):
    env = os.environ
    env[AFLPP_ENV_VAR] = str(workspace.absolute())
    logging.info(f"aflpp workspace: {str(workspace.absolute())}")
    cmd_line_afl = ["pastis-aflpp", "online", "-p", f"{port}"]
    logging.info(f"run: {' '.join(cmd_line_afl)}")
    return subprocess.Popen(cmd_line_afl, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def check_scaling_frequency() -> bool:
    data = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read_text()
    return data == "performance\n"
