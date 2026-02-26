"""Unit tests for PII redaction middleware."""

from src.middleware.pii_redaction import redact_dict, redact_pii


class TestRedactPii:
    """Tests for the redact_pii() function."""

    def test_redacts_guid(self):
        text = "Tenant ID: 12345678-1234-1234-1234-123456789abc"
        result = redact_pii(text)
        assert "12345678-1234-1234-1234-123456789abc" not in result
        assert "[TENANT_ID]" in result

    def test_redacts_email(self):
        text = "User: admin@contoso.com logged in"
        result = redact_pii(text)
        assert "admin@contoso.com" not in result
        assert "[USER_EMAIL]" in result

    def test_redacts_ipv4(self):
        text = "Connection from 192.168.1.100"
        result = redact_pii(text)
        assert "192.168.1.100" not in result
        assert "[IP_ADDRESS]" in result

    def test_preserves_safe_text(self):
        text = "Secure Score is 47.3 out of 100"
        result = redact_pii(text)
        assert result == text

    def test_redacts_multiple_types(self):
        text = "User admin@contoso.com from 10.0.0.1 in tenant 12345678-1234-1234-1234-123456789abc"
        result = redact_pii(text)
        assert "admin@contoso.com" not in result
        assert "10.0.0.1" not in result
        assert "12345678-1234-1234-1234-123456789abc" not in result

    def test_empty_string(self):
        assert redact_pii("") == ""


class TestRedactDict:
    """Tests for the redact_dict() function."""

    def test_redacts_sensitive_keys(self):
        data = {"email": "admin@contoso.com", "score": 47.3}
        result = redact_dict(data)
        assert result["email"] == "[REDACTED]"
        assert result["score"] == 47.3

    def test_redacts_nested_dict(self):
        data = {
            "user": {
                "displayName": "John Doe",
                "email": "john@contoso.com",
            },
            "score": 85,
        }
        result = redact_dict(data)
        assert result["user"]["displayName"] == "[REDACTED]"
        assert result["user"]["email"] == "[REDACTED]"
        assert result["score"] == 85

    def test_redacts_guid_in_values(self):
        data = {"id": "12345678-1234-1234-1234-123456789abc", "name": "test"}
        result = redact_dict(data)
        assert "12345678-1234-1234-1234-123456789abc" not in str(result)

    def test_handles_list_values(self):
        data = {"users": ["admin@contoso.com", "user@contoso.com"]}
        result = redact_dict(data)
        for item in result["users"]:
            assert "@contoso.com" not in str(item)

    def test_empty_dict(self):
        assert redact_dict({}) == {}
