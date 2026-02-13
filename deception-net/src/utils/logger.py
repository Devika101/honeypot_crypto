"""Structured logging configuration for DeceptionNet.

Uses structlog for JSON-formatted, context-rich logging throughout the system.
All modules should use `get_logger(__name__)` to obtain a logger instance.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

import structlog


_configured = False


def configure_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_format: bool = True,
    max_bytes: int = 10_485_760,
    backup_count: int = 5,
) -> None:
    """Configure the global logging system.

    Should be called once at application startup. Subsequent calls are no-ops.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional path to a log file. Creates parent directories if needed.
        json_format: If True, output JSON logs. Otherwise, use colored console output.
        max_bytes: Max log file size before rotation.
        backup_count: Number of rotated log files to keep.
    """
    global _configured
    if _configured:
        return
    _configured = True

    log_level = getattr(logging, level.upper(), logging.INFO)

    # Standard library logging setup
    handlers: list[logging.Handler] = []

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(log_level)
    handlers.append(console)

    # File handler (if specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        file_handler.setLevel(log_level)
        handlers.append(file_handler)

    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=handlers,
        force=True,
    )

    # Structlog processors
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_format:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Apply structlog formatting to stdlib handlers
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )
    for handler in handlers:
        handler.setFormatter(formatter)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger for the given module.

    Args:
        name: Module name, typically __name__.

    Returns:
        A bound structlog logger.
    """
    if not _configured:
        configure_logging()
    return structlog.get_logger(name)
