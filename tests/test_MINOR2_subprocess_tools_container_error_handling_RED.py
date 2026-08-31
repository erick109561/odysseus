"""
RED test: MINOR-2 run_container_command exception handling in subprocess_tools.

Verifies that when container_executor is enabled and run_container_command raises
an Exception (not BaseException), BashTool and PythonTool convert it to a
structured error result rather than letting it propagate.

Requirements:
  - Catch ordinary Exception (not BaseException)
  - Return structured {"error": ..., "exit_code": 1} dict
  - Do NOT leak secrets or unnecessary stack traces

Run with:
  python -m pytest tests/test_MINOR2_subprocess_tools_container_error_handling_RED.py -v
"""
import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestMINOR2ContainerExceptionHandling:
    """
    RED: BashTool and PythonTool must handle run_container_command exceptions
    as structured errors, not propagate them.
    """

    def _mock_container_enabled(self):
        """Patch container_executor_enabled to return True."""
        return patch(
            "src.agent_tools.subprocess_tools.container_executor_enabled",
            return_value=True,
        )

    def _mock_run_container_command_raises(self, exc):
        """Patch run_container_command to raise an Exception."""
        return patch(
            "src.agent_tools.subprocess_tools.run_container_command",
            side_effect=exc,
        )

    # ── pre-fix state ─────────────────────────────────────────────────────────
    # The candidate had NO try-except around run_container_command.
    # If it raised any Exception (e.g., RuntimeError from missing podman,
    # ValueError from bad config, etc.), it would propagate straight to the
    # caller in tool_execution.py — unhandled, no structured result, no
    # exit_code, secret leak possible via stack trace.

    @pytest.mark.asyncio
    async def test_bash_tool_handles_runtime_error_from_container(self):
        """
        Pre-fix: FAILS — run_container_command raises RuntimeError, propagates up
        Post-fix: PASSES — RuntimeError caught, returns {"error": ..., "exit_code": 1}
        """
        bt = __import__(
            "src.agent_tools.subprocess_tools",
            fromlist=["BashTool"]
        ).BashTool()

        with self._mock_container_enabled():
            with self._mock_run_container_command_raises(
                RuntimeError("container executor enabled but podman is unavailable")
            ):
                result = await bt.execute("echo hello", ctx={})

        assert "error" in result, f"Expected error key in result, got: {result!r}"
        assert result["exit_code"] == 1, f"Expected exit_code 1, got: {result['exit_code']}"
        assert "podman" in result["error"] or "container" in result["error"].lower(), (
            f"Error message should mention container issue, got: {result['error']!r}"
        )

    @pytest.mark.asyncio
    async def test_bash_tool_handles_value_error_from_container(self):
        """
        Pre-fix: FAILS — ValueError propagates
        Post-fix: PASSES — ValueError caught, structured result returned
        """
        bt = __import__(
            "src.agent_tools.subprocess_tools",
            fromlist=["BashTool"]
        ).BashTool()

        with self._mock_container_enabled():
            with self._mock_run_container_command_raises(
                ValueError("workspace is required")
            ):
                result = await bt.execute("echo hello", ctx={})

        assert "error" in result
        assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_bash_tool_handles_generic_exception_from_container(self):
        """
        Pre-fix: FAILS — generic Exception propagates
        Post-fix: PASSES — generic Exception caught, structured result returned
        """
        bt = __import__(
            "src.agent_tools.subprocess_tools",
            fromlist=["BashTool"]
        ).BashTool()

        with self._mock_container_enabled():
            with self._mock_run_container_command_raises(
                Exception("unexpected internal error in container executor")
            ):
                result = await bt.execute("echo hello", ctx={})

        assert "error" in result
        assert result["exit_code"] == 1
        # Must NOT contain internal stack trace or secret details
        assert "Traceback" not in result.get("error", ""), (
            "Error must not contain Python Traceback"
        )

    @pytest.mark.asyncio
    async def test_python_tool_handles_runtime_error_from_container(self):
        """
        Pre-fix: FAILS — RuntimeError propagates from PythonTool
        Post-fix: PASSES — RuntimeError caught, returns structured error
        """
        pt = __import__(
            "src.agent_tools.subprocess_tools",
            fromlist=["PythonTool"]
        ).PythonTool()

        with self._mock_container_enabled():
            with self._mock_run_container_command_raises(
                RuntimeError("podman not found in PATH")
            ):
                result = await pt.execute("print('hello')", ctx={})

        assert "error" in result
        assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_python_tool_handles_value_error_from_container(self):
        """
        Pre-fix: FAILS — ValueError propagates from PythonTool
        Post-fix: PASSES — ValueError caught, structured result returned
        """
        pt = __import__(
            "src.agent_tools.subprocess_tools",
            fromlist=["PythonTool"]
        ).PythonTool()

        with self._mock_container_enabled():
            with self._mock_run_container_command_raises(
                ValueError("invalid container image reference")
            ):
                result = await pt.execute("print('hello')", ctx={})

        assert "error" in result
        assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_python_tool_does_not_leak_secrets_in_error(self):
        """
        Error messages must not contain secrets or stack traces.
        """
        pt = __import__(
            "src.agent_tools.subprocess_tools",
            fromlist=["PythonTool"]
        ).PythonTool()

        class SecretLeakException(Exception):
            def __str__(self):
                return (
                    "Failed to run container: "
                    "ODYSSEUS_CONTAINER_IMAGE=docker.io/user:abcdefghijklmnopqrstuvwxyz123456@"
                    "sha256:abcd  - podman exec failed"
                )

        with self._mock_container_enabled():
            with self._mock_run_container_command_raises(SecretLeakException()):
                result = await pt.execute("print('hello')", ctx={})

        assert "error" in result
        # Must not expose the secret token value
        # The token "abcdefghijklmnopqrstuvwxyz123456" (31 chars) matches the
        # [A-Za-z0-9+/]{20,}={0,2} redaction pattern and must be redacted.
        assert "abcdefghijklmnopqrstuvwxyz123456" not in result.get("error", ""), (
            "Error must not contain secret credentials"
        )
        # The env var name ODYSSEUS_CONTAINER_IMAGE itself is not a secret;
        # only its value (the token) is. So we only check the token is redacted.

    @pytest.mark.asyncio
    async def test_bash_tool_does_not_leak_secrets_in_error(self):
        """
        Error messages must not contain secrets or stack traces.
        """
        bt = __import__(
            "src.agent_tools.subprocess_tools",
            fromlist=["BashTool"]
        ).BashTool()

        class SecretLeakException(Exception):
            def __str__(self):
                return "podman failed: GIT_TOKEN=ghp_secretTOKEN123 workspace=/home/user"

        with self._mock_container_enabled():
            with self._mock_run_container_command_raises(SecretLeakException()):
                result = await bt.execute("echo hello", ctx={})

        assert "error" in result
        assert "ghp_secretTOKEN123" not in result.get("error", ""), (
            "Error must not contain GitHub token"
        )
        assert "Traceback" not in result.get("error", ""), (
            "Error must not contain Python Traceback"
        )

    @pytest.mark.asyncio
    async def test_bash_tool_does_not_catch_base_exception(self):
        """
        Do NOT catch BaseException (KeyboardInterrupt, SystemExit).
        If run_container_command raises KeyboardInterrupt, it must propagate.
        """
        bt = __import__(
            "src.agent_tools.subprocess_tools",
            fromlist=["BashTool"]
        ).BashTool()

        with self._mock_container_enabled():
            with self._mock_run_container_command_raises(KeyboardInterrupt()):
                with pytest.raises(KeyboardInterrupt):
                    await bt.execute("echo hello", ctx={})

    @pytest.mark.asyncio
    async def test_python_tool_does_not_catch_base_exception(self):
        """
        Do NOT catch BaseException (KeyboardInterrupt, SystemExit).
        """
        pt = __import__(
            "src.agent_tools.subprocess_tools",
            fromlist=["PythonTool"]
        ).PythonTool()

        with self._mock_container_enabled():
            with self._mock_run_container_command_raises(KeyboardInterrupt()):
                with pytest.raises(KeyboardInterrupt):
                    await pt.execute("print('hello')", ctx={})
