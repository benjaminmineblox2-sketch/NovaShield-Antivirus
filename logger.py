"""Central logging setup for NovaShield."""

from __future__ import annotations

import logging
from pathlib import Path


def get_logger() -> logging.Logger:
    """Returns a singleton logger configured for both console and file logging."""

    logger = logging.getLogger("novashield")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    log_dir = Path(__file__).resolve().parent
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "novashield.log"

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger
