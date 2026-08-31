"""
RED test: MINOR-1 ImportError vs ModuleNotFoundError in task_scheduler._execute_action.

Verifies that when container_executor is enabled:
  - Genuine ModuleNotFoundError (container_executor absent) -> allow legacy behaviour
  - Transitive ImportError (container_executor exists but internal dep fails) -> FAIL CLOSED

The broad `except ImportError` in the candidate allowed internal/transitive ImportError
to silently authorize host shell, which is wrong. The fix narrows to ModuleNotFoundError.

Run with:
  python -m pytest tests/test_MINOR1_task_scheduler_container_blocking_RED.py -v
"""
import asyncio
import builtins
import sys
from unittest.mock import MagicMock

import pytest

# Capture the real __import__ before any patching at module level.
_REAL_IMPORT = builtins.__import__


def _make_task(action="run_script", prompt="echo hello", owner="alice"):
    t = MagicMock()
    t.action = action
    t.prompt = prompt
    t.owner = owner
    t.name = "test-task"
    return t


class TestMINOR1ContainerBlocking:

    def _fake_import_absent(self, name, *args, **kwargs):
        if name == "src.agent_tools.container_executor" or name.startswith(
            "src.agent_tools.container_executor."
        ):
            # Real Python import machinery sets e.name to the module path.
            # Replicate exact real semantics.
            exc = ModuleNotFoundError(f"No module named {name!r}")
            exc.name = name  # matches real Python import behavior
            raise exc
        return _REAL_IMPORT(name, *args, **kwargs)

    def _fake_import_transitive_error(self, name, *args, **kwargs):
        if name == "src.agent_tools.container_executor":
            # ImportError catches the broad ModuleNotFoundError mutant too,
            # so also test with ModuleNotFoundError for the transitive case.
            raise ImportError(
                "cannot import name 'something' from 'nonexistent.internal'"
            )
        return _REAL_IMPORT(name, *args, **kwargs)

    def _fake_import_transitive_mne(self, name, *args, **kwargs):
        if name == "src.agent_tools.container_executor":
            # ModuleNotFoundError with transitive name — tests the M6 mutant
            exc = ModuleNotFoundError(
                "cannot import name 'something' from 'nonexistent.internal'"
            )
            exc.name = "nonexistent.internal"
            raise exc
        return _REAL_IMPORT(name, *args, **kwargs)

    def _cleanup_modules(self):
        for mod in list(sys.modules.keys()):
            if mod.startswith("src.agent_tools.container_executor"):
                del sys.modules[mod]
        for mod in list(sys.modules.keys()):
            if mod.startswith("src.task_scheduler"):
                del sys.modules[mod]

    def test_module_not_found_allows_legacy_behaviour(self):
        """
        When container_executor module is genuinely absent (ModuleNotFoundError),
        legacy host-shell behaviour must remain available.

        Pre-fix: PASS  (broad ImportError caught -> legacy allowed)
        Post-fix: PASS  (ModuleNotFoundError caught -> legacy allowed)
        """
        self._cleanup_modules()
        saved = builtins.__import__
        builtins.__import__ = self._fake_import_absent
        try:
            self._cleanup_modules()
            from src.task_scheduler import TaskScheduler
            sched = TaskScheduler.__new__(TaskScheduler)
            task = _make_task(action="run_script", prompt="echo hello")
            result, ok = asyncio.run(sched._execute_action(task))
            assert ok is True, (
                "ModuleNotFoundError for container_executor should allow legacy behaviour"
            )
        finally:
            builtins.__import__ = saved
            self._cleanup_modules()

    def test_transitive_import_error_fails_closed(self):
        """
        When container_executor module EXISTS but a transitive import inside it fails
        with ImportError, host-shell execution MUST be blocked (fail closed).
        """
        self._cleanup_modules()
        saved = builtins.__import__
        builtins.__import__ = self._fake_import_transitive_error
        try:
            self._cleanup_modules()
            from src.task_scheduler import TaskScheduler
            sched = TaskScheduler.__new__(TaskScheduler)
            task = _make_task(action="run_script", prompt="echo hello")
            result, ok = asyncio.run(sched._execute_action(task))
            assert ok is False, (
                "Transitive ImportError from container_executor should block "
                "host-shell actions (fail closed)"
            )
            assert "not available" in result
        finally:
            builtins.__import__ = saved
            self._cleanup_modules()

    def test_transitive_mne_fails_closed(self):
        """
        When container_executor module EXISTS but a transitive import inside it fails
        with ModuleNotFoundError (e.g. missing dependency inside container_executor),
        host-shell execution MUST be blocked (fail closed).

        This is the critical M6 mutant case: if broad ModuleNotFoundError fallback
        is restored, this test will FAIL.
        """
        self._cleanup_modules()
        saved = builtins.__import__
        builtins.__import__ = self._fake_import_transitive_mne
        try:
            self._cleanup_modules()
            from src.task_scheduler import TaskScheduler
            sched = TaskScheduler.__new__(TaskScheduler)
            task = _make_task(action="run_script", prompt="echo hello")
            result, ok = asyncio.run(sched._execute_action(task))
            assert ok is False, (
                "Transitive ModuleNotFoundError from container_executor should block "
                "host-shell actions (fail closed)"
            )
            assert "not available" in result
        finally:
            builtins.__import__ = saved
            self._cleanup_modules()

    def test_run_local_allows_legacy_when_module_absent(self):
        self._cleanup_modules()
        saved = builtins.__import__
        builtins.__import__ = self._fake_import_absent
        try:
            self._cleanup_modules()
            from src.task_scheduler import TaskScheduler
            sched = TaskScheduler.__new__(TaskScheduler)
            task = _make_task(action="run_local", prompt="ls")
            result, ok = asyncio.run(sched._execute_action(task))
            assert ok is True
        finally:
            builtins.__import__ = saved
            self._cleanup_modules()

    def test_ssh_command_allows_legacy_when_module_absent(self):
        self._cleanup_modules()
        saved = builtins.__import__
        builtins.__import__ = self._fake_import_absent
        try:
            self._cleanup_modules()
            from src.task_scheduler import TaskScheduler
            sched = TaskScheduler.__new__(TaskScheduler)
            task = _make_task(action="ssh_command", prompt="echo hi")
            result, ok = asyncio.run(sched._execute_action(task))
            assert ok is True
        finally:
            builtins.__import__ = saved
            self._cleanup_modules()
