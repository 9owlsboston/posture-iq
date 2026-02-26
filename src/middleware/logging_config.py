"""PostureIQ — Structured JSON logging configuration.

Configures structlog for production-ready JSON logging with the required fields:
  {"timestamp", "level", "tool", "session_id", "duration_ms", "status"}

All logs pass through PII redaction before emission. No tenant IDs, emails,
or other PII should ever appear in log output.
"""

from __future__ import annotations

import logging
import sys

import structlog


def setup_logging(
    log_level: str = "INFO",
    json_format: bool = True,
) -> None:
    """Configure structured JSON logging for PostureIQ.

    Args:
        log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_format: If True, output JSON. If False, output human-readable (dev).
    """
    # ── Shared processors ────────────────────────────────
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        _redact_pii_processor,
    ]

    if json_format:
        # Production: JSON to stdout
        renderer = structlog.processors.JSONRenderer()
    else:
        # Development: colored, human-readable
        renderer = structlog.dev.ConsoleRenderer()  # type: ignore[assignment]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # ── Configure stdlib logging ─────────────────────────
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Quiet noisy libraries
    for noisy_logger in [
        "azure",
        "urllib3",
        "httpcore",
        "httpx",
        "opentelemetry",
    ]:
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)


def _redact_pii_processor(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Structlog processor that redacts PII from all log event values.

    Ensures no tenant IDs, emails, UPNs, or IP addresses leak into logs.
    """
    from src.middleware.pii_redaction import redact_pii

    for key, value in event_dict.items():
        if isinstance(value, str) and key not in (
            "timestamp",
            "level",
            "logger",
        ):
            event_dict[key] = redact_pii(value)

    return event_dict
