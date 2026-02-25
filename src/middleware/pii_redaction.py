"""PostureIQ — PII redaction middleware.

Redacts personally identifiable information and tenant-sensitive data
before sending content to Azure OpenAI or including in logs/traces.

Redaction targets:
  - Tenant GUIDs
  - User emails and UPNs
  - IP addresses
  - Display names (when in structured data)
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

    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if key in sensitive_keys:
            if isinstance(value, str):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = "[REDACTED]"
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
