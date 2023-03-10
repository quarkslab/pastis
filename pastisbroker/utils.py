#built-in imports
import logging
from typing import Optional
import importlib
import inspect

from libpastis.enginedesc import FuzzingEngineDescriptor


HF_PERSISTENT_SIG = b"\x01_LIBHFUZZ_PERSISTENT_BINARY_SIGNATURE_\x02\xFF"


def load_engine_descriptor(py_module: str) -> Optional[FuzzingEngineDescriptor]:
    try:
        mod = importlib.import_module(py_module)
        mems = inspect.getmembers(mod, lambda x: inspect.isclass(x) and issubclass(x, FuzzingEngineDescriptor) and x != FuzzingEngineDescriptor)
        if not mems:
            logging.error(f"can't find FuzzingEngineDescriptor in module {py_module}")
            return None
        else:
            if len(mems) > 1:
                logging.warning(f"module {py_module} contain multiple subclass of {FuzzingEngineDescriptor} (take first)")
            return mems[0][1]
    except ImportError:
        logging.error(f"cannot import py_module: {py_module}")
