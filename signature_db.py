"""Loads the JSON virus signature database used by NovaShield."""

from __future__ import annotations

import json
from pathlib import Path


class SignatureDatabase:
    """Reads known hashes and heuristic keywords from a JSON file."""

    def __init__(self) -> None:
        self.database_file = Path(__file__).resolve().parent / "signatures.json"
        self._data = self._load()

    @property
    def hashes(self) -> dict[str, str]:
        return self._data.get("hashes", {})

    @property
    def spyware_keywords(self) -> list[str]:
        return self._data.get("spyware_keywords", [])

    @property
    def content_indicators(self) -> list[str]:
        return self._data.get("content_indicators", [])

    def _load(self) -> dict[str, object]:
        if not self.database_file.exists():
            default_data = {
                "hashes": {},
                "spyware_keywords": ["keylog", "spy", "stealer", "credential", "hook"],
                "content_indicators": [
                    "getasynckeystate",
                    "setwindowshookex",
                    "pynput",
                    "keyboard.Listener",
                    "clipboard",
                    "smtp",
                ],
            }
            self.database_file.write_text(json.dumps(default_data, indent=2), encoding="utf-8")
            return default_data

        return json.loads(self.database_file.read_text(encoding="utf-8"))
