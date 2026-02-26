"""PostureIQ — Input validation for user queries.

Enforces length limits, character-set restrictions, and structural rules
on user queries before they reach the LLM or tools.

This is the first line of defense — it runs BEFORE content safety checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Configuration ──────────────────────────────────────────────────────

MAX_QUERY_LENGTH = 5000  # characters
MIN_QUERY_LENGTH = 3     # minimum meaningful query
MAX_LINE_COUNT = 100     # prevent multi-line injection payloads

# Characters allowed: letters, digits, punctuation, whitespace, common symbols
# Block control characters, zero-width chars, and other adversarial inputs
_ALLOWED_CHARS_PATTERN = (
    r"^[\x20-\x7E"          # printable ASCII
    r"\u00A0-\u024F"        # Latin Extended
    r"\u2000-\u206F"        # General Punctuation
    r"\u2010-\u2027"        # Dashes and quotation marks
    r"\n\r\t"               # whitespace
    r"]*$"
)

import re

_ALLOWED_RE = re.compile(_ALLOWED_CHARS_PATTERN)

# Blocked character patterns (zero-width, RTL override, etc.)
_BLOCKED_CHARS = re.compile(
    r"[\u200B-\u200F"      # zero-width spaces / directional marks
    r"\u202A-\u202E"       # directional overrides (LRE, RLE, etc.)
    r"\u2060-\u2064"       # invisible operators
    r"\uFEFF"              # BOM
    r"\x00-\x08"           # null + control chars
    r"\x0E-\x1F]"          # more control chars
)


@dataclass
class ValidationResult:
    """Result of input validation.

    Attributes:
        is_valid: Whether the input passes all checks.
        reason: Human-readable reason if invalid.
        sanitized_input: The cleaned input (trimmed, normalized).
    """

    is_valid: bool
    reason: str | None = None
    sanitized_input: str = ""


def validate_user_input(query: str) -> ValidationResult:
    """Validate and sanitize user input before processing.

    Checks:
      1. Non-empty / non-whitespace
      2. Minimum length (≥ 3 chars)
      3. Maximum length (≤ 5000 chars)
      4. Line count limit (≤ 100 lines)
      5. No blocked characters (zero-width, control chars)

    Args:
        query: The raw user query string.

    Returns:
        ValidationResult with validity status and sanitized input.
    """
    if not query or not query.strip():
        return ValidationResult(
            is_valid=False,
            reason="Query cannot be empty",
        )

    trimmed = query.strip()

    if len(trimmed) < MIN_QUERY_LENGTH:
        return ValidationResult(
            is_valid=False,
            reason=f"Query too short (minimum {MIN_QUERY_LENGTH} characters)",
        )

    if len(trimmed) > MAX_QUERY_LENGTH:
        logger.warning(
            "input_validation.too_long",
            length=len(trimmed),
            max_length=MAX_QUERY_LENGTH,
        )
        return ValidationResult(
            is_valid=False,
            reason=f"Query too long (maximum {MAX_QUERY_LENGTH} characters)",
        )

    line_count = trimmed.count("\n") + 1
    if line_count > MAX_LINE_COUNT:
        logger.warning(
            "input_validation.too_many_lines",
            line_count=line_count,
            max_lines=MAX_LINE_COUNT,
        )
        return ValidationResult(
            is_valid=False,
            reason=f"Query has too many lines (maximum {MAX_LINE_COUNT})",
        )

    # Check for blocked characters
    blocked_match = _BLOCKED_CHARS.search(trimmed)
    if blocked_match:
        char_code = hex(ord(blocked_match.group(0)))
        logger.warning(
            "input_validation.blocked_character",
            char_code=char_code,
        )
        return ValidationResult(
            is_valid=False,
            reason="Query contains invalid characters",
        )

    # Sanitize: normalize whitespace
    sanitized = re.sub(r"[ \t]+", " ", trimmed)  # collapse spaces/tabs
    sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)  # max 2 consecutive newlines

    return ValidationResult(
        is_valid=True,
        sanitized_input=sanitized,
    )
