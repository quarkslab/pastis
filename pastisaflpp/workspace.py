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

    AFLPP_WS_ENV_VAR = "AFLPP_WS"
    DEFAULT_WS_PATH = "aflpp_workspace"
    STATS_FILE = "fuzzer_stats"

    def __init__(self):
        self.observer = Observer()
        self.modif_callbacks = {}  # Map fullpath -> callback
        self.created_callbacks = {}
        self.root_dir = None
        self._setup_workspace()

    def _setup_workspace(self):
        ws = os.environ.get(self.AFLPP_WS_ENV_VAR, None)
        if ws is None:
            self.root_dir = (Path(tempfile.gettempdir()) / self.DEFAULT_WS_PATH) / str(time.time()).replace(".", "")
        else:
            self.root_dir = Path(ws)  # Use the one provided


        for d in [self.target_dir, self.input_dir, self.dynamic_input_dir, self.corpus_dir, self.crash_dir]:
            d.mkdir(parents=True)

        # Create dummy input file.
        # AFLPP requires that the initial seed directory is not empty.
        # TODO Is there a better approach to this?
        seed_path = self.input_dir / 'seed-dummy'
        seed_path.write_bytes(b'A')

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
    def output_dir(self):
        return self.root_dir / 'outputs'

    @property
    def corpus_dir(self):
        return self.output_dir / 'main' / 'queue'

    @property
    def crash_dir(self):
        return self.output_dir / 'main' / 'crashes'

    @property
    def stats_dir(self):
        return self.output_dir / 'main'

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
