"""Polling-based file watcher used for lightweight real-time protection."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from engine.scanner import ScanEngine


class RealtimeProtection:
    """Monitors a directory tree and scans files when they change."""

    def __init__(self, engine: ScanEngine, poll_interval: float = 3.0) -> None:
        self.engine = engine
        self.poll_interval = poll_interval
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._target: Path | None = None
        self._snapshot: dict[str, tuple[int, float]] = {}

    def start(self, target: Path) -> None:
        self.stop()
        self._target = target
        self._stop_event.clear()
        self._snapshot = self._take_snapshot(target)
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.engine.logger.info("Real-time protection started for %s", target)

    def stop(self) -> None:
        if self._thread and self._thread.is_alive():
            self._stop_event.set()
            self._thread.join(timeout=5)
            self.engine.logger.info("Real-time protection stopped")
        self._thread = None

    def _monitor_loop(self) -> None:
        if self._target is None:
            return

        while not self._stop_event.is_set():
            current_snapshot = self._take_snapshot(self._target)
            changed_paths = self._find_changes(self._snapshot, current_snapshot)
            for changed_file in changed_paths:
                self.engine.logger.info("File changed: %s", changed_file)
                self.engine.scan_file(Path(changed_file))
            self._snapshot = current_snapshot
            time.sleep(self.poll_interval)

    def _take_snapshot(self, root: Path) -> dict[str, tuple[int, float]]:
        snapshot: dict[str, tuple[int, float]] = {}
        if root.is_file():
            try:
                stat = root.stat()
                snapshot[str(root)] = (stat.st_size, stat.st_mtime)
            except OSError:
                pass
            return snapshot

        for current_root, _, files in os.walk(root):
            for file_name in files:
                file_path = Path(current_root) / file_name
                try:
                    stat = file_path.stat()
                    snapshot[str(file_path)] = (stat.st_size, stat.st_mtime)
                except OSError:
                    continue
        return snapshot

    def _find_changes(
        self,
        old_snapshot: dict[str, tuple[int, float]],
        new_snapshot: dict[str, tuple[int, float]],
    ) -> list[str]:
        changes: list[str] = []
        for path, metadata in new_snapshot.items():
            if path not in old_snapshot or old_snapshot[path] != metadata:
                changes.append(path)
        return changes
