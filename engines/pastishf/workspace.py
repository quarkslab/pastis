# builtin imports
from typing import Callable
import time
import tempfile
import os
import logging
from pathlib import Path
from hashlib import md5

# third-party imports
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class Workspace(FileSystemEventHandler):

    HFUZZ_WS_ENV_VAR = "HFUZZ_WS"
    DEFAULT_WS_PATH = "hfuzz_workspace"
    STATS_FILE = "statsfile.log"

    def __init__(self):
        self.observer = Observer()
        self.modif_callbacks = {}  # Map fullpath -> callback
        self.created_callbacks = {}
        self.root_dir = None
        self._setup_workspace()

    def _setup_workspace(self):
        ws = os.environ.get(self.HFUZZ_WS_ENV_VAR, None)
        if ws is None:
            self.root_dir = (Path(tempfile.gettempdir()) / self.DEFAULT_WS_PATH) / str(time.time()).replace(".", "")
        else:
            self.root_dir = Path(ws)  # Use the one provided

        for d in [self.target_dir, self.input_dir, self.dynamic_input_dir, self.corpus_dir, self.crash_dir, self.stats_dir]:
            d.mkdir(parents=True)

    @property
    def target_dir(self):
        return self.root_dir / 'target'

    @property
    def input_dir(self):
        return self.root_dir / 'inputs' / 'initial'

    @property
    def dynamic_input_dir(self):
        return self.root_dir / 'inputs' / 'dynamic'

    @property
    def corpus_dir(self):
        return self.root_dir / 'outputs' / 'coverage'

    @property
    def crash_dir(self):
        return self.root_dir / 'outputs' / 'crashes'

    @property
    def stats_dir(self):
        return self.root_dir / 'stats'

    @property
    def stats_file(self):
        return self.stats_dir / self.STATS_FILE

    def on_modified(self, event):
        path = Path(event.src_path)
        if path.is_dir():
            return  # We don't care about directories
        if path.parent in self.modif_callbacks:
            self.modif_callbacks[path.parent](path)  # call the callback
        else:
            pass  # Do nothing at the moment

    def on_created(self, event):
        path = Path(event.src_path)
        if path.is_dir():
            return  # We don't care about directories
        if path.parent in self.created_callbacks:
            self.created_callbacks[path.parent](path)  # call the callback
        else:
            pass  # Do nothing at the moment

    def add_file_modification_hook(self, path: str, callback: Callable):
        self.observer.schedule(self, path=path, recursive=True)
        self.modif_callbacks[path] = callback

    def add_creation_hook(self, path: str, callback: Callable):
        self.observer.schedule(self, path=path, recursive=True)
        self.created_callbacks[path] = callback

    def start(self):
        self.observer.start()

    def stop(self):
        self.observer.stop()
