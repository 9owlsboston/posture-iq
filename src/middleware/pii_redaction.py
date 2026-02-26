"""PostureIQ — PII redaction middleware.

Redacts personally identifiable information and tenant-sensitive data
before sending content to Azure OpenAI or including in logs/traces.

Redaction targets:
  - Tenant GUIDs → ``[TENANT_ID]``
  - User emails and UPNs → ``[USER_EMAIL]``
  - IP addresses (v4 and v6) → ``[IP_ADDRESS]``
  - Display names (in structured data) → ``[USER_NAME]``

Re-hydration support:
  - :func:`create_redaction_map` captures original values with placeholders
  - :func:`rehydrate` restores placeholders to original values for
    customer-facing display after LLM processing
"""

from __future__ import annotations

import re
from typing import Any


# ── Regex patterns for PII detection ────────────────────────────────────
_GUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
)

_UPN_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"  # UPNs look like emails
)

_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
)

# Display‐name pattern: "First Last" or "First M. Last" (2–4 word names)
# Only applied via redact_display_name() or inside redact_dict(), not globally
_DISPLAY_NAME_PATTERN = re.compile(
    r"\b[A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b"
)


def redact_pii(text: str) -> str:
    """Redact PII from text before sending to LLM or logging.

    Args:
        text: Raw text that may contain PII.

    Returns:
        Text with PII replaced by safe placeholders.

    Examples:
        >>> redact_pii("Tenant abc12345-1234-1234-1234-123456789abc has issues")
        'Tenant [TENANT_ID] has issues'
        >>> redact_pii("Contact user@contoso.com for details")
        'Contact [USER_EMAIL] for details'
        >>> redact_pii("IP 10.0.0.1 was flagged")
        'IP [IP_ADDRESS] was flagged'
    """
    result = text

    # Redact GUIDs (tenant IDs, object IDs, etc.)
    result = _GUID_PATTERN.sub("[TENANT_ID]", result)

    # Redact email addresses and UPNs
    result = _EMAIL_PATTERN.sub("[USER_EMAIL]", result)

    # Redact IPv4 addresses
    result = _IPV4_PATTERN.sub("[IP_ADDRESS]", result)

    # Redact IPv6 addresses
    result = _IPV6_PATTERN.sub("[IP_ADDRESS]", result)

    return result


def redact_display_name(text: str) -> str:
    """Redact display names (e.g. 'John Doe') from text.

    This is applied selectively — only on fields or contexts known to
    contain user display names, to avoid false positives on normal prose.

    Args:
        text: Text that may contain display names.

    Returns:
        Text with display names replaced by ``[USER_NAME]``.
    """
    return _DISPLAY_NAME_PATTERN.sub("[USER_NAME]", text)


def redact_dict(data: dict[str, Any], sensitive_keys: set[str] | None = None) -> dict[str, Any]:
    """Redact PII from dictionary values recursively.

    Args:
        data: Dictionary that may contain PII in values.
        sensitive_keys: Optional set of key names to always redact entirely.

    Returns:
        Dictionary with PII redacted from string values.
    """
    if sensitive_keys is None:
        sensitive_keys = {
            "tenant_id", "tenantId",
            "email", "mail", "userPrincipalName", "upn",
            "displayName", "display_name",
            "ipAddress", "ip_address",
            "client_secret", "password", "token",
        }

    # Keys whose values should be treated as display names
    _name_keys = {"displayName", "display_name", "name", "givenName", "surname"}

    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if key in sensitive_keys:
            if isinstance(value, str):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = "[REDACTED]"
        elif key in _name_keys and isinstance(value, str):
            redacted[key] = "[USER_NAME]"
        elif isinstance(value, str):
            redacted[key] = redact_pii(value)
        elif isinstance(value, dict):
            redacted[key] = redact_dict(value, sensitive_keys)
        elif isinstance(value, list):
            redacted[key] = [
                redact_dict(item, sensitive_keys) if isinstance(item, dict)
                else (redact_pii(item) if isinstance(item, str) else item)
                for item in value
            ]
        else:
            redacted[key] = value

    return redacted


# ── Re-hydration Support ───────────────────────────────────────────────

def create_redaction_map(text: str) -> tuple[str, dict[str, str]]:
    """Redact PII and return a mapping from placeholder → original value.

    This allows re-hydrating the original values after LLM processing
    for customer-facing display.

    Args:
        text: Raw text with PII.

    Returns:
        Tuple of (redacted_text, redaction_map) where redaction_map
        maps indexed placeholders like ``[TENANT_ID_1]`` to originals.

    Example:
        >>> redacted, rmap = create_redaction_map(
        ...     "Tenant abc12345-1234-1234-1234-123456789abc contacted user@x.com"
        ... )
        >>> rmap  # {\"[TENANT_ID_1]\": \"abc12345-...\", \"[USER_EMAIL_1]\": \"user@x.com\"}
    """
    redaction_map: dict[str, str] = {}
    counters: dict[str, int] = {}
    result = text

    def _replace_with_indexed(pattern: re.Pattern, placeholder_base: str, text_in: str) -> str:
        nonlocal counters

        def _replacer(match: re.Match) -> str:
            original = match.group(0)
            counters[placeholder_base] = counters.get(placeholder_base, 0) + 1
            idx = counters[placeholder_base]
            key = f"[{placeholder_base}_{idx}]"
            redaction_map[key] = original
            return key

        return pattern.sub(_replacer, text_in)

    result = _replace_with_indexed(_GUID_PATTERN, "TENANT_ID", result)
    result = _replace_with_indexed(_EMAIL_PATTERN, "USER_EMAIL", result)
    result = _replace_with_indexed(_IPV4_PATTERN, "IP_ADDRESS", result)
    result = _replace_with_indexed(_IPV6_PATTERN, "IP_ADDRESS", result)

    return result, redaction_map


def rehydrate(text: str, redaction_map: dict[str, str]) -> str:
    """Restore redacted placeholders to their original values.

    Args:
        text: Text with indexed placeholders (e.g. ``[TENANT_ID_1]``).
        redaction_map: Mapping from placeholder to original value
            (as returned by :func:`create_redaction_map`).

    Returns:
        Text with placeholders replaced by original values.
    """
    result = text
    for placeholder, original in redaction_map.items():
        result = result.replace(placeholder, original)
    return result
