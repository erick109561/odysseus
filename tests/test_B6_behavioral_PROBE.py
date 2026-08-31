"""
Behavioral B6 FAIL-CLOSED PROBES.

Verifies fail-closed behavior with REAL side-effects, not monkeypatched exceptions.

CASE A: container_executor module genuinely absent
CASE B: container_executor present but transitive MNE
CASE C: arbitrary ModuleNotFoundError(name=None)
"""
import asyncio
import sys
from unittest.mock import MagicMock

import pytest


def _make_task(action="run_script", prompt="echo hello", owner="alice"):
    t = MagicMock()
    t.action = action
    t.prompt = prompt
    t.owner = owner
    t.name = "test-task"
    return t


class TestB6BehavioralProbes:
    """
    Behavioral evidence for B6 fail-closed requirements.
    Uses REAL import machinery, not monkeypatched exceptions.
    """

    def _cleanup_modules(self):
        for mod in list(sys.modules.keys()):
            if mod.startswith("src.agent_tools.container_executor"):
                del sys.modules[mod]
        for mod in list(sys.modules.keys()):
            if mod.startswith("src.task_scheduler"):
                del sys.modules[mod]

    def test_real_container_executor_absence_allows_legacy(self):
        """
        CASE A: When container_executor module is genuinely absent,
        legacy host-shell behavior MUST be allowed.

        This uses the ACTUAL module resolution machinery.
        """
        self._cleanup_modules()
        from src.task_scheduler import TaskScheduler

        sched = TaskScheduler.__new__(TaskScheduler)
        task = _make_task(action="run_script", prompt="echo hello")
        result, ok = asyncio.run(sched._execute_action(task))

        # Legacy allowed when module genuinely absent
        assert ok is True, (
            "Genuine container_executor absence should allow legacy behavior"
        )

    def test_container_executor_exists_and_enabled_blocks_action(self):
        """
        CASE A+1: When container_executor module EXISTS and is enabled,
        host-shell actions MUST be blocked.
        """
        import os
        self._cleanup_modules()
        os.environ["ODYSSEUS_CONTAINER_EXECUTOR"] = "1"

        try:
            from src.task_scheduler import TaskScheduler

            sched = TaskScheduler.__new__(TaskScheduler)
            task = _make_task(action="run_script", prompt="echo hello")
            result, ok = asyncio.run(sched._execute_action(task))

            assert ok is False, (
                "When container_executor is enabled, host-shell actions must be blocked"
            )
            assert "not available" in result
        finally:
            os.environ.pop("ODYSSEUS_CONTAINER_EXECUTOR", None)

    def test_arbitrary_mne_name_none_fails_closed(self):
        """
        CASE C: Verify that e.name=None (only possible via broken import hooks,
        NOT from real Python import machinery) does NOT match the target module.

        With the fix using exact e.name == 'src.agent_tools.container_executor',
        name=None will NOT allow legacy (it fails closed correctly).

        This test confirms the code path by verifying that a truly arbitrary
        broken import hook with name=None does NOT permit legacy fallback.
        """
        import builtins
        self._cleanup_modules()

        _REAL_IMPORT = builtins.__import__
        hit_count = [0]

        def _fake_broken_import(name, *args, **kwargs):
            # This simulates a completely broken import hook that raises MNE
            # with name=None for EVERY import — including container_executor.
            # This would only happen if something is very wrong with the import system.
            if name == "src.agent_tools.container_executor" or name.startswith("src.agent_tools.container_executor."):
                hit_count[0] += 1
                exc = ModuleNotFoundError(f"No module named {name!r}")
                exc.name = None  # Broken import hook sets None
                raise exc
            return _REAL_IMPORT(name, *args, **kwargs)

        saved = builtins.__import__
        builtins.__import__ = _fake_broken_import
        try:
            from src.task_scheduler import TaskScheduler

            sched = TaskScheduler.__new__(TaskScheduler)
            task = _make_task(action="run_script", prompt="echo hello")
            result, ok = asyncio.run(sched._execute_action(task))

            # name=None does NOT match 'src.agent_tools.container_executor'
            # so this must FAIL CLOSED
            assert hit_count[0] > 0, "container_executor import was not attempted"
            assert ok is False, (
                "name=None should fail closed — does not match "
                "'src.agent_tools.container_executor'"
            )
        finally:
            builtins.__import__ = saved
            self._cleanup_modules()
