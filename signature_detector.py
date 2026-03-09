"""Hash-based malware signature detection."""

from __future__ import annotations

import hashlib
from pathlib import Path

from database.signature_db import SignatureDatabase


class SignatureDetector:
    """Compares file hashes against the JSON signature database."""

    def __init__(self, database: SignatureDatabase) -> None:
        self.database = database

    def scan(self, file_path: Path) -> str | None:
        sha256 = hashlib.sha256()
        try:
            with file_path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(8192), b""):
                    sha256.update(chunk)
        except OSError:
            return None

        digest = sha256.hexdigest()
        entry = self.database.hashes.get(digest)
        if entry:
            return f"Matched known signature: {entry}"
        return None
