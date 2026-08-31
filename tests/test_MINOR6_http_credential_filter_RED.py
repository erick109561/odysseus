"""
RED test: MINOR-6 Git credential filter for http.extraheader/http.proxy forms.

Verifies the production _assert_git_config_safe in container_executor.py blocks:
  - bare   http.proxy / http.extraheader         (MINOR-6 repair target)
  - URL-prefixed http.<url>.proxy / extraheader (already blocked before fix)

Run with:
  python -m pytest tests/test_MINOR6_http_credential_filter_RED.py -v
"""
import os
import subprocess
import tempfile
from pathlib import Path

import pytest


def _executor():
    try:
        import importlib
        return importlib.import_module("src.agent_tools.container_executor")
    except ModuleNotFoundError:
        pytest.skip("container_executor module not found")


def _git_config_set(tmp_path: Path, key: str, value: str) -> Path:
    """Create a temp git config file with the given key=value using git config."""
    cfg = tmp_path / "gitconfig"
    subprocess.run(
        ["git", "config", "--file", str(cfg), key, value],
        check=True,
    )
    return cfg


class TestHttpCredentialFilter:
    """
    RED: _assert_git_config_safe must block bare and URL-prefixed
    http.proxy / http.extraheader while allowing non-credential http.* keys.
    """

    @pytest.mark.parametrize(
        "key,value,expect_blocked",
        [
            # ── MINOR-6 repair: bare forms ───────────────────────────────
            ("http.proxy",                           "http://proxy.example.com", True),
            ("http.extraheader",                     "Authorization: Bearer xxx", True),
            ("HTTP.PROXY",                          "http://proxy.example.com", True),
            ("HTTP.EXTRAHEADER",                    "Authorization: Bearer xxx", True),
            # ── Already-blocked before MINOR-6 ─────────────────────────
            ("http.https://example.com.proxy",       "http://proxy.example.com", True),
            ("http.https://example.com.extraheader", "Authorization: Bearer xxx", True),
            ("http.https://github.com/.proxy",       "http://proxy.example.com", True),
            ("http.https://foo.com/bar.proxy",       "http://proxy.example.com", True),
            # ── Must NOT be blocked ───────────────────────────────────
            ("http.cookiepath",                     "/cookies",                False),
            ("http.cookiepersistent",               "true",                    False),
            ("http.postbuffer",                     "524288",                  False),
            ("http.followredirect",                 "true",                    False),
            ("http.useragent",                     "git/2.0",                 False),
            # ── Other credential patterns (existing) ────────────────────
            ("credential.helper",                   "store",                   True),
            ("credential.https://example.com",       "helper",                  True),
            ("remote.origin.proxy",                 "http://proxy.example.com", True),
            ("core.sshcommand",                     "/usr/bin/ssh",            True),
            ("include.path",                        "/etc/gitconfig",           True),
            ("url.https://github.com.insteadof",    "git://github.com",        True),
        ],
    )
    def test_git_config_blocks_sensitive_keys(self, key, value, expect_blocked, tmp_path):
        """
        RED: _assert_git_config_safe must raise ValueError for credential keys
        and pass silently for safe http.* keys.
        """
        ex = _executor()
        cfg = _git_config_set(tmp_path, key, value)

        if expect_blocked:
            with pytest.raises(ValueError, match="credential"):
                ex._assert_git_config_safe(str(cfg))
        else:
            # Must NOT raise.
            try:
                ex._assert_git_config_safe(str(cfg))
            except ValueError:
                pytest.fail(
                    f"Expected {key!r} NOT to be blocked, but ValueError was raised"
                )

    def test_bare_http_proxy_triggers_minor6(self, tmp_path):
        """
        MINOR-6 specific: bare http.proxy must be blocked.
        Before the fix: PASSED (not blocked).
        After the fix: raises ValueError.
        """
        ex = _executor()
        cfg = _git_config_set(tmp_path, "http.proxy", "http://proxy.example.com")
        with pytest.raises(ValueError, match="credential"):
            ex._assert_git_config_safe(str(cfg))

    def test_bare_http_extraheader_triggers_minor6(self, tmp_path):
        """
        MINOR-6 specific: bare http.extraheader must be blocked.
        Before the fix: PASSED (not blocked).
        After the fix: raises ValueError.
        """
        ex = _executor()
        cfg = _git_config_set(tmp_path, "http.extraheader", "Authorization: Bearer xxx")
        with pytest.raises(ValueError, match="credential"):
            ex._assert_git_config_safe(str(cfg))

    def test_url_prefixed_http_proxy_still_blocked(self, tmp_path):
        """
        URL-prefixed http.<url>.proxy was already blocked before MINOR-6.
        This verifies the repair did not regress that.
        """
        ex = _executor()
        cfg = _git_config_set(tmp_path, "http.https://example.com.proxy", "http://proxy.example.com")
        with pytest.raises(ValueError, match="credential"):
            ex._assert_git_config_safe(str(cfg))
