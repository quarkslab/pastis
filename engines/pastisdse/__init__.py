from typing import Tuple
import subprocess

from .pastisdse import PastisDSE

# Expose triton version
import tritondse

__version__ = "1.0.0"

TRITON_VERSION = tritondse.TRITON_VERSION


def spawn_online_triton(port: int = 5555, probe: Tuple[str] = ()):
    tt = ["pastis-triton", "online", "-p", f"{port}"]
    if len(probe) > 0:
        tt += ["--probe", f"{probe}"]
    subprocess.Popen(tt, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
