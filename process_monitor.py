"""Basic Windows process inspection for suspicious spyware and keylogger traits."""

from __future__ import annotations

import json
import subprocess
from logging import Logger


class ProcessMonitor:
    """Reads the process list through PowerShell and applies simple heuristics."""

    def __init__(self, logger: Logger) -> None:
        self.logger = logger

    def inspect_processes(self) -> list[str]:
        findings: list[str] = []
        for process in self._read_processes():
            name = (process.get("Name") or "").lower()
            path = (process.get("ExecutablePath") or "").lower()
            command_line = (process.get("CommandLine") or "").lower()

            if any(token in name for token in ("keylog", "spy", "stealer", "hook")):
                findings.append(f"{process.get('Name')} flagged by suspicious name.")
            elif any(token in path for token in ("\\appdata\\", "\\temp\\", "\\public\\")):
                findings.append(f"{process.get('Name')} running from a suspicious folder: {process.get('ExecutablePath')}")
            elif any(token in command_line for token in ("setwindowshookex", "getasynckeystate", "pynput", "keyboard")):
                findings.append(f"{process.get('Name')} flagged by command line content.")

        for finding in findings:
            self.logger.warning("Suspicious process: %s", finding)
        return findings

    def _read_processes(self) -> list[dict[str, str]]:
        command = [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "Get-CimInstance Win32_Process | "
                "Select-Object Name, ExecutablePath, CommandLine | "
                "ConvertTo-Json -Depth 2"
            ),
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            self.logger.error("Could not inspect processes: %s", exc)
            return []

        raw_output = result.stdout.strip()
        if not raw_output:
            return []

        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            self.logger.error("Invalid process list output: %s", exc)
            return []

        if isinstance(parsed, dict):
            return [parsed]
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        return []
