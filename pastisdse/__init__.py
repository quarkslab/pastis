from .pastisdse import PastisDSE

# Expose triton version
import tritondse

__version__ = "0.2"

TRITON_VERSION = tritondse.TRITON_VERSION
