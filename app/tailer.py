from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

StoreLogsFn = Callable[[list[str]], dict[str, int]]


@dataclass
class TailState:
    running: bool = False
    file_path: str | None = None
    from_start: bool = False
    interval_sec: float = 1.0
    position: int = 0
    ingested_total: int = 0
    last_error: str | None = None


class LiveTailManager:
    def __init__(self, store_logs_fn: StoreLogsFn):
        self._store_logs_fn = store_logs_fn
        self._state = TailState()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def start(self, file_path: str, from_start: bool = False, interval_sec: float = 1.0) -> TailState:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            raise ValueError(f"Log file not found: {file_path}")

        with self._lock:
            if self._state.running:
                raise ValueError("Live tail is already running")

            self._state.running = True
            self._state.file_path = str(path)
            self._state.from_start = from_start
            self._state.interval_sec = max(0.2, float(interval_sec))
            self._state.position = 0
            self._state.ingested_total = 0
            self._state.last_error = None
            self._stop_event.clear()

            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            return TailState(**self._state.__dict__)

    def stop(self) -> TailState:
        thread: threading.Thread | None = None
        with self._lock:
            if self._state.running:
                self._stop_event.set()
                thread = self._thread

        if thread is not None:
            thread.join(timeout=2)

        with self._lock:
            self._state.running = False
            return TailState(**self._state.__dict__)

    def status(self) -> TailState:
        with self._lock:
            return TailState(**self._state.__dict__)

    def _run(self) -> None:
        state = self.status()
        file_path = state.file_path
        from_start = state.from_start

        if not file_path:
            return

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                if not from_start:
                    handle.seek(0, os.SEEK_END)

                while not self._stop_event.is_set():
                    line = handle.readline()
                    if not line:
                        # handle log rotation/truncation
                        try:
                            if os.path.getsize(file_path) < handle.tell():
                                handle.seek(0)
                        except OSError:
                            pass
                        time.sleep(self.status().interval_sec)
                        continue

                    lines = [line.rstrip("\n")]
                    result = self._store_logs_fn(lines)

                    with self._lock:
                        self._state.position = handle.tell()
                        self._state.ingested_total += int(result.get("ingested", 0))

        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._state.last_error = str(exc)

        finally:
            with self._lock:
                self._state.running = False
