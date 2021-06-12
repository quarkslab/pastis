from .pastisdse import PastisDSE

# Expose triton version
import tritondse

__version__ = "0.3"

TRITON_VERSION = tritondse.TRITON_VERSION
