from .pastisdse import PastisDSE

# Expose triton version
import tritondse
__version__ = tritondse.TRITON_VERSION
