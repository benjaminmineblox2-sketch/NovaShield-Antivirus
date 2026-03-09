"""Main scan engine used by the CLI, real-time monitor, and other modules."""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from database.signature_db import SignatureDatabase
from detection.heuristics import HeuristicDetector
from detection.signature_detector import SignatureDetector
from logs.logger import get_logger
from quarantine.manager import QuarantineManager


@dataclass
class DetectionRecord:
    path: str
    reason: str
    detector: str


@dataclass
class ScanReport:
    scanned_files: int = 0
    detections: list[DetectionRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def format_summary(self) -> str:
        lines = [
            f"Scanned files: {self.scanned_files}",
            f"Detections: {len(self.detections)}",
            f"Errors: {len(self.errors)}",
        ]
        if self.detections:
            lines.append("")
            lines.append("Detected threats:")
            for detection in self.detections:
                lines.append(
                    f"- {detection.path} [{detection.detector}] {detection.reason}"
                )
        return "\n".join(lines)


class ScanEngine:
    """Coordinates hash detection, heuristics, quarantine, and logging."""

    def __init__(self) -> None:
        self.logger = get_logger()
        self.database = SignatureDatabase()
        self.signature_detector = SignatureDetector(self.database)
        self.heuristic_detector = HeuristicDetector(self.database)
        self.quarantine_manager = QuarantineManager(self.logger)

    def scan_file(self, file_path: Path, quarantine_on_detect: bool = True) -> list[DetectionRecord]:
        detections: list[DetectionRecord] = []
        if not file_path.is_file():
            return detections

        signature_hit = self.signature_detector.scan(file_path)
        if signature_hit:
            detections.append(
                DetectionRecord(
                    path=str(file_path),
                    reason=signature_hit,
                    detector="hash-signature",
                )
            )

        for heuristic_hit in self.heuristic_detector.scan(file_path):
            detections.append(
                DetectionRecord(
                    path=str(file_path),
                    reason=heuristic_hit,
                    detector="heuristic",
                )
            )

        if detections:
            self.logger.warning("Threat detected in %s", file_path)
            if quarantine_on_detect:
                quarantine_result = self.quarantine_manager.quarantine_file(file_path, detections)
                self.logger.warning("File quarantined: %s", quarantine_result)
        return detections

    def scan_path(self, target_path: Path, quarantine_on_detect: bool = True) -> ScanReport:
        report = ScanReport()
        paths = [target_path] if target_path.is_file() else self._walk_files(target_path)

        for file_path in paths:
            try:
                report.scanned_files += 1
                report.detections.extend(self.scan_file(file_path, quarantine_on_detect))
            except PermissionError:
                message = f"Permission denied: {file_path}"
                report.errors.append(message)
                self.logger.info(message)
            except OSError as exc:
                message = f"Scan error for {file_path}: {exc}"
                report.errors.append(message)
                self.logger.error(message)

        return report

    def full_system_scan(self) -> ScanReport:
        combined = ScanReport()
        for drive in self._windows_drives():
            self.logger.info("Starting full scan for drive %s", drive)
            report = self.scan_path(drive)
            combined.scanned_files += report.scanned_files
            combined.detections.extend(report.detections)
            combined.errors.extend(report.errors)
        return combined

    def _walk_files(self, root: Path) -> Iterable[Path]:
        for current_root, _, filenames in os.walk(root, topdown=True):
            for filename in filenames:
                yield Path(current_root) / filename

    def _windows_drives(self) -> list[Path]:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        drives: list[Path] = []
        for index in range(26):
            if bitmask & (1 << index):
                letter = chr(65 + index)
                drives.append(Path(f"{letter}:\\"))
        return drives
