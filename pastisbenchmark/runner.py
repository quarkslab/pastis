import os
from pathlib import Path
from typing import Optional
import subprocess
import logging

# AFL++ env variables
AFLPP_ENV_VAR = "AFLPP_WS"

# Honggfuzz env variables
HFUZZ_ENV_VAR = "HFUZZ_WS"
HFUZZ_PATH_VAR = "HFUZZ_PATH"
HFUZZ_THREADS = "HFUZZ_THREADS"

def spawn_online_aflpp(workspace: Optional[Path], port: int = 5555):
    env = os.environ
    env[AFLPP_ENV_VAR] = str(workspace.absolute())
    logging.info(f"aflpp workspace: {str(workspace.absolute())}")
    cmd_line_afl = ["pastis-aflpp", "online", "-p", f"{port}"]
    logging.info(f"run: {' '.join(cmd_line_afl)}")
    return subprocess.Popen(cmd_line_afl, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def spawn_online_triton(port: int = 5555):
    tt = ["pastis-triton", "online", "-p", f"{port}"]
    subprocess.Popen(tt, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def spawn_online_honggfuzz(workspace: Optional[Path], hf_path: Optional[str], port: int = 5555, threads: int=0):
    env = os.environ
    env[HFUZZ_ENV_VAR] = str(workspace.absolute())
    if hf_path:
        env[HFUZZ_PATH_VAR] = str(hf_path)
    if threads:
        env[HFUZZ_THREADS] = str(threads)
    cmd_line_honggfuzz = ["pastis-honggfuzz", "online", "-p", f"{port}"]
    subprocess.Popen(cmd_line_honggfuzz, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def check_scaling_frequency() -> bool:
    data = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read_text()
    return data == "performance\n"
