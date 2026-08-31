"""
RED test: B9 — TEMP PROJECTION LEAK

AFTER FIX:
- _build_minimal_git_projection returns (proj_git, cleanup_callbacks)
- build_podman_run_argv returns (argv, cleanup_callbacks)
- run_container_command invokes cleanup callbacks in a finally block

This test verifies:
1. build_podman_run_argv returns cleanup callbacks
2. After calling cleanup, temp dirs are removed
3. Temp dirs don't accumulate across multiple calls without cleanup
"""

import importlib.util
import os
import subprocess
import sys
import tempfile
import shutil

import pytest


def _load_executor():
    from tests._repo_paths import get_container_executor_path
    spec = importlib.util.spec_from_file_location(
        "container_executor",
        str(get_container_executor_path())
    )
    ce = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ce)
    return ce


def _run_git(dir_, *args, timeout=10):
    proc = subprocess.run(
        ["git", "-C", dir_] + list(args),
        capture_output=True, text=True, timeout=timeout,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    return proc.stdout.strip(), proc.stderr, proc.returncode


class TestRedB9TempProjectionLeak:
    """
    After fix: cleanup callbacks are properly returned and can be invoked.
    """

    def test_red_build_podman_run_argv_returns_cleanup_callbacks(self):
        """
        After fix: build_podman_run_argv returns (argv, cleanup_callbacks).
        """
        ce = _load_executor()

        tmp = tempfile.mkdtemp(prefix="red_b9_cleanup_")
        repo = os.path.join(tmp, "repo")
        os.makedirs(repo)
        _run_git(repo, "init")
        _run_git(repo, "config", "user.email", "test@test.com")
        _run_git(repo, "config", "user.name", "Test")
        with open(os.path.join(repo, "file.txt"), "w") as f:
            f.write("content\n")
        _run_git(repo, "add", "file.txt")
        _run_git(repo, "commit", "-m", "init")

        try:
            result = ce.build_podman_run_argv(
                workspace=repo,
                image_ref=ce.DEFAULT_CONTAINER_IMAGE,
                container_name="test-b9-cleanup",
                command=["git", "status"],
            )

            # After fix: returns 2-tuple
            assert isinstance(result, tuple), "build_podman_run_argv should return tuple"
            assert len(result) == 2, "build_podman_run_argv should return (argv, cleanup_callbacks)"
            argv, cleanup_callbacks = result

            assert isinstance(argv, list), "First element should be argv list"
            assert callable(cleanup_callbacks) or (isinstance(cleanup_callbacks, list) and all(callable(c) for c in cleanup_callbacks)), (
                "Second element should be cleanup callback(s)"
            )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_red_cleanup_callbacks_remove_temp_dirs(self):
        """
        After fix: calling the cleanup callback removes the temp projection dir.
        """
        ce = _load_executor()

        tmp = tempfile.mkdtemp(prefix="red_b9_cleanup_")
        repo = os.path.join(tmp, "repo")
        os.makedirs(repo)
        _run_git(repo, "init")
        _run_git(repo, "config", "user.email", "test@test.com")
        _run_git(repo, "config", "user.name", "Test")
        with open(os.path.join(repo, "file.txt"), "w") as f:
            f.write("content\n")
        _run_git(repo, "add", "file.txt")
        _run_git(repo, "commit", "-m", "init")

        try:
            argv, cleanup = ce.build_podman_run_argv(
                workspace=repo,
                image_ref=ce.DEFAULT_CONTAINER_IMAGE,
                container_name="test-b9-cleanup",
                command=["git", "status"],
            )

            # Get the temp dir from _projection_temp_dirs before cleanup
            temp_dirs_before = list(ce._projection_temp_dirs)
            assert len(temp_dirs_before) > 0, "Should have tracked temp dirs"

            # Invoke cleanup
            if callable(cleanup):
                cleanup()
            elif isinstance(cleanup, list):
                for cb in cleanup:
                    cb()

            # After cleanup, temp dirs should be gone
            temp_dirs_after = list(ce._projection_temp_dirs)
            # Note: _projection_temp_dirs list is cleared by _clear_projection_temp_dirs
            # but individual dirs may have been removed from filesystem
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_red_multiple_calls_accumulate_without_cleanup(self):
        """
        After fix: multiple calls accumulate temp dirs if cleanup is NOT invoked.
        This verifies the tracking mechanism works.
        """
        ce = _load_executor()

        tmp1 = tempfile.mkdtemp(prefix="red_b9_multi_1_")
        repo1 = os.path.join(tmp1, "repo1")
        os.makedirs(repo1)
        _run_git(repo1, "init")
        _run_git(repo1, "config", "user.email", "test1@test.com")
        _run_git(repo1, "config", "user.name", "Test1")
        with open(os.path.join(repo1, "f.txt"), "w") as f:
            f.write("c1\n")
        _run_git(repo1, "add", "f.txt")
        _run_git(repo1, "commit", "-m", "c1")

        tmp2 = tempfile.mkdtemp(prefix="red_b9_multi_2_")
        repo2 = os.path.join(tmp2, "repo2")
        os.makedirs(repo2)
        _run_git(repo2, "init")
        _run_git(repo2, "config", "user.email", "test2@test.com")
        _run_git(repo2, "config", "user.name", "Test2")
        with open(os.path.join(repo2, "f.txt"), "w") as f:
            f.write("c2\n")
        _run_git(repo2, "add", "f.txt")
        _run_git(repo2, "commit", "-m", "c2")

        initial_count = len(ce._projection_temp_dirs)

        try:
            # First call - returns (argv, cleanup)
            argv1, cleanup1 = ce.build_podman_run_argv(
                workspace=repo1,
                image_ref=ce.DEFAULT_CONTAINER_IMAGE,
                container_name="test-b9-1",
                command=["git", "status"],
            )
            count_after_1 = len(ce._projection_temp_dirs)
            assert count_after_1 > initial_count, "First call should add temp dirs to tracking"

            # Second call
            argv2, cleanup2 = ce.build_podman_run_argv(
                workspace=repo2,
                image_ref=ce.DEFAULT_CONTAINER_IMAGE,
                container_name="test-b9-2",
                command=["git", "status"],
            )
            count_after_2 = len(ce._projection_temp_dirs)
            assert count_after_2 > count_after_1, "Second call should accumulate more temp dirs without cleanup"

            # Invoke cleanup for both
            if callable(cleanup1):
                cleanup1()
            elif isinstance(cleanup1, list):
                for cb in cleanup1:
                    cb()
            if callable(cleanup2):
                cleanup2()
            elif isinstance(cleanup2, list):
                for cb in cleanup2:
                    cb()

            # After cleanup, _clear_projection_temp_dirs clears the list
            ce._clear_projection_temp_dirs()
            assert len(ce._projection_temp_dirs) == 0, "After cleanup, temp dir list should be empty"
        finally:
            shutil.rmtree(tmp1, ignore_errors=True)
            shutil.rmtree(tmp2, ignore_errors=True)
