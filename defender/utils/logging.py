"""Structured JSON-lines logging shared by all tools."""

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

LOGS_DIR = Path.home() / ".bt-defender" / "logs"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "tool": getattr(record, "tool", "unknown"),
            "message": record.getMessage(),
        }
        extra = getattr(record, "extra_data", None)
        if extra:
            entry["data"] = extra
        return json.dumps(entry)


def get_logger(tool_name: str, *, to_file: bool = True) -> logging.Logger:
    """Create a logger that writes JSON lines to logs/{tool}_{date}.jsonl and stderr."""
    logger = logging.getLogger(f"bt_defender.{tool_name}")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    # Stderr handler for human-readable output
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(stderr_handler)

    # File handler for structured JSON lines
    if to_file:
        LOGS_DIR.mkdir(exist_ok=True)
        date_str = datetime.now().strftime("%Y-%m-%d")
        log_file = LOGS_DIR / f"{tool_name}_{date_str}.jsonl"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)

    return logger


def log_event(logger: logging.Logger, tool: str, message: str, **data) -> None:
    """Log a structured event with optional extra data fields."""
    record = logger.makeRecord(
        name=logger.name,
        level=logging.INFO,
        fn="",
        lno=0,
        msg=message,
        args=(),
        exc_info=None,
    )
    record.tool = tool
    record.extra_data = data if data else None
    logger.handle(record)
