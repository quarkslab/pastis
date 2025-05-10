# builtin imports
from typing import Callable
import time
import tempfile
import os
import logging
from pathlib import Path

# third-party imports
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class Workspace(FileSystemEventHandler):

    LIBFUZZER_WS_ENV_VAR = "LIBFUZZER_WS"
    DEFAULT_WS_PATH = "libfuzzer_workspace"
    STATS_FILE = "fuzzer_stats"

    def __init__(self):
        self.observer = Observer()
        self.modif_callbacks: dict[Path, Callable[[Path], None]] = {}  # Map fullpath -> callback
        self.created_callbacks: dict[Path, Callable[[Path], None]] = {}

        ws = os.environ.get(self.LIBFUZZER_WS_ENV_VAR, None)
        if ws is None:
            self.root_dir = (Path(tempfile.gettempdir()) / self.DEFAULT_WS_PATH) / str(time.time()).replace(".", "")
        else:
            self.root_dir = Path(ws)  # Use the one provided

        logging.info(f"Libfuzzer workspace: {self.root_dir}")
        for d in [self.target_dir, self.input_dir, self.crash_dir]:
            d.mkdir(parents=True)

    @property
    def target_dir(self) -> Path:
        return self.root_dir / 'target'

    @property
    def input_dir(self) -> Path:
        return self.root_dir / 'inputs'

    @property
    def crash_dir(self) -> Path:
        return self.root_dir / 'crashes'

    @property
    def stats_file(self):
        return self.root_dir / self.STATS_FILE

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

    def add_file_modification_hook(self, path: Path, callback: Callable[[Path], None]):
        self.observer.schedule(self, path=path, recursive=True)
        self.modif_callbacks[path] = callback

    def add_creation_hook(self, path: Path, callback: Callable[[Path], None]):
        self.observer.schedule(self, path=path, recursive=True)
        self.created_callbacks[path] = callback

    def start(self) -> None:
        self.observer.start()

    def stop(self):
        self.observer.stop()
