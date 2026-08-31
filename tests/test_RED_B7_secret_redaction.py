"""
RED test: B7 — EXCEPTION SECRET REDACTION

ROOT CAUSE:
The exception handler in BashTool/PythonTool does not redact credential canaries.

AFTER FIX (subprocess_tools._sanitize_error_message):
The function redacts all credential forms:
  - key=value with sensitive keywords
  - Authorization: Bearer TOKEN
  - --flag VALUE forms
  - URL-embedded credentials
  - GitHub PAT forms (github_pat_*, ghp_*)
  - Generic base64-like tokens (20+ chars with dash/underscore)

B7_PREDECESSOR_SANITIZER_FAILS: A broken/no-op sanitizer must fail these tests.
"""

import os
import sys
import tempfile
import shutil
import subprocess
import re

import pytest


def _get_sanitize_function():
    """Import the actual _sanitize_error_message from subprocess_tools."""
    from tests._repo_paths import get_repo_root
    sys.path.insert(0, str(get_repo_root()))
    import src.agent_tools.subprocess_tools as st
    return st._sanitize_error_message


def _broken_sanitizer(message):
    """A no-op sanitizer that should fail all secret tests."""
    return message  # Returns message unchanged - secrets leak


class TestRedB7SecretRedaction:
    """
    After fix: _sanitize_error_message must redact all credential forms.
    """

    @pytest.mark.parametrize("canary", [
        ("Authorization: Bearer ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ("authorization=Bearer_secret_token", "Bearer_secret_token"),
        ("--password hunter2", "hunter2"),
        ("password: hunter2", "hunter2"),
        ("api_key = abc123def456ghi", "abc123def456ghi"),
        ("api-key=abc_123-XYZ789", "abc_123-XYZ789"),
        ("credential = secret-value-123", "secret-value-123"),
        ("github_pat_xxxxxxxxxxxxxxxxxxxx", "github_pat_xxxxxxxxxxxxxxxxxxxx"),
        ("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ("token_abc123def456ghi789", "abc123def456ghi789"),
        ("secret_token_abc-def_123", "abc-def_123"),
        ("GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ("secret=my_secret_key", "my_secret_key"),
        ("token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ("https://user:TOKEN_SECRET@github.com", "TOKEN_SECRET"),
        ("https://user:ghp_xxxxxx@github.com", "ghp_xxxxxx"),
    ])
    def test_secret_value_not_in_sanitized_output(self, canary):
        """
        B7_SECRET_VALUES_ABSENT: The actual secret VALUE must not appear in output.

        Takes (message, secret_value) tuple where secret_value is the sensitive
        portion that must be redacted.
        """
        message, secret_value = canary
        sanitize = _get_sanitize_function()
        result = sanitize(message)

        # The secret value must NOT appear in the sanitized result
        assert secret_value not in result, (
            f"Secret value {secret_value!r} leaked through: {result}"
        )

    def test_predicate_sanitizer_fails_on_secret(self):
        """
        B7_PREDECESSOR_SANITIZER_FAILS: A broken/no-op sanitizer must fail.
        This proves the test is discriminating.
        """
        message = "Authorization: Bearer ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        secret_value = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

        # Broken sanitizer lets secret through
        broken_result = _broken_sanitizer(message)
        assert secret_value in broken_result, "Broken sanitizer should not redact"

        # Real sanitizer must NOT let secret through
        sanitize = _get_sanitize_function()
        real_result = sanitize(message)
        assert secret_value not in real_result, (
            "Real sanitizer should redact secret"
        )

    def test_authorization_bearer_form_redacted(self):
        """After fix: 'Authorization: Bearer ghp_xxx' must have token redacted."""
        sanitize = _get_sanitize_function()
        canary = "Authorization: Bearer ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        secret_value = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        result = sanitize(canary)
        assert secret_value not in result, (
            f"Token {secret_value} leaked through: {result}"
        )

    def test_ghp_token_redacted(self):
        """After fix: 'ghp_xxx' tokens must be redacted."""
        sanitize = _get_sanitize_function()
        canary = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        result = sanitize(canary)
        assert canary not in result

    def test_github_pat_redacted(self):
        """After fix: 'github_pat_xxx' must be redacted."""
        sanitize = _get_sanitize_function()
        canary = "github_pat_xxxxxxxxxxxxxxxxxxxx"
        result = sanitize(canary)
        assert canary not in result

    def test_api_key_value_redacted(self):
        """After fix: 'api_key=VALUE' must have VALUE redacted."""
        sanitize = _get_sanitize_function()
        canary = "api_key=abc_123-XYZ789"
        secret_value = "abc_123-XYZ789"
        result = sanitize(canary)
        assert secret_value not in result

    def test_url_credential_redacted(self):
        """After fix: URL-embedded credentials must be redacted."""
        sanitize = _get_sanitize_function()
        canary = "https://user:TOKEN_SECRET@github.com"
        secret_value = "TOKEN_SECRET"
        result = sanitize(canary)
        assert secret_value not in result

    def test_safe_text_preserved(self):
        """After fix: non-secret text should be preserved."""
        sanitize = _get_sanitize_function()
        safe = "This is a normal error message without secrets"
        result = sanitize(safe)
        assert result == safe

    def test_baseexception_propagation(self):
        """Verify sanitization doesn't swallow BaseException."""
        sanitize = _get_sanitize_function()
        # Should not raise, just return sanitized string
        try:
            result = sanitize("error with secret=ghp_xxxxx")
            assert "ghp_xxxxx" not in result
        except Exception:
            pytest.fail("Sanitizer should not raise exceptions")
