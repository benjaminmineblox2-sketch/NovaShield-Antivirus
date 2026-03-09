"""Simple heuristic checks for spyware, keyloggers, and obviously suspicious files."""

from __future__ import annotations

from pathlib import Path

from database.signature_db import SignatureDatabase


class HeuristicDetector:
    """Uses filename and content rules to catch basic suspicious behavior."""

    def __init__(self, database: SignatureDatabase) -> None:
        self.database = database

    def scan(self, file_path: Path) -> list[str]:
        findings: list[str] = []
        file_name = file_path.name.lower()

        for keyword in self.database.spyware_keywords:
            if keyword in file_name:
                findings.append(f"Filename contains spyware keyword '{keyword}'")

        if file_path.suffix.lower() in {".ps1", ".vbs", ".bat", ".scr"}:
            findings.append(f"Suspicious scriptable extension detected: {file_path.suffix}")

        preview = self._read_preview(file_path)
        for term in self.database.content_indicators:
            if term in preview:
                findings.append(f"File content contains suspicious term '{term}'")

        return findings

    def _read_preview(self, file_path: Path) -> str:
        try:
            with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
                return handle.read(4096).lower()
        except OSError:
            return ""
