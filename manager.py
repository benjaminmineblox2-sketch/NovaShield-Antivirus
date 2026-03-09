"""Moves infected files into a safe quarantine folder and keeps a JSON record."""

from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime
from logging import Logger
from pathlib import Path


class QuarantineManager:
    """Stores quarantined files and metadata without deleting them."""

    def __init__(self, logger: Logger) -> None:
        self.logger = logger
        self.base_dir = Path(__file__).resolve().parent
        self.storage_dir = self.base_dir / "storage"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.records_file = self.base_dir / "quarantine_records.json"
        if not self.records_file.exists():
            self.records_file.write_text("[]", encoding="utf-8")

    def quarantine_file(self, file_path: Path, detections: list[object]) -> str:
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        quarantined_name = f"{timestamp}_{uuid.uuid4().hex}_{file_path.name}.quarantine"
        destination = self.storage_dir / quarantined_name
        shutil.move(str(file_path), str(destination))

        records = self.list_records()
        records.append(
            {
                "original_path": str(file_path),
                "quarantined_name": quarantined_name,
                "quarantined_path": str(destination),
                "detections": [str(item.reason) if hasattr(item, "reason") else str(item) for item in detections],
                "timestamp_utc": datetime.utcnow().isoformat() + "Z",
            }
        )
        self.records_file.write_text(json.dumps(records, indent=2), encoding="utf-8")
        self.logger.warning("File moved to quarantine: %s", destination)
        return quarantined_name

    def list_records(self) -> list[dict[str, str]]:
        try:
            return json.loads(self.records_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
