import os
from pathlib import Path
from typing import Optional
import subprocess
import logging

AFLPP_ENV_VAR = "AFLPP_WS"
HFUZZ_ENV_VAR = "HFUZZ_WS"


def spawn_online_aflpp(workspace: Optional[str], port: int = 5555):
    env = os.environ
    env[AFLPP_ENV_VAR] = str(workspace)
    cmd_line_afl = ["pastis-aflpp", "online", "-p", f"{port}"]
    logging.info(f"run: {' '.join(cmd_line_afl)}")
    return subprocess.Popen(cmd_line_afl, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def spawn_online_triton(port: int = 5555):
    tt = ["pastis-triton", "online", "-p", f"{port}"]
    subprocess.Popen(tt, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def spawn_online_honggfuzz(workspace: Optional[str], port: int = 5555):
    env = os.environ
    env[HFUZZ_ENV_VAR] = str(workspace)
    cmd_line_honggfuzz = ["pastis-honggfuzz", "online", "-p", f"{port}"]
    subprocess.Popen(cmd_line_honggfuzz, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def check_scaling_frequency() -> bool:
    data = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read_text()
    return data == "performance\n"
