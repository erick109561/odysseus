"""
RED test: B10 — FAIL-CLOSED PROJECTION-INTEGRITY VIOLATIONS

ROOT CAUSE:
Git metadata projection-building uses ValueError for security/integrity violations,
but ValueError raised during _build_minimal_git_projection is caught and converted
to "no Git metadata" (return [], None) by the caller _git_metadata_mount_args.

Security/integrity violations (symlink traversal, forbidden files) must raise,
not silently become "no Git metadata".

Also: _copy_git_refs rejects symlinks in refs/ files, but traversal validation
for refs/heads/ etc. may not be robust against dotdot or absolute path attacks.
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


class TestRedB10ProjectionIntegrityViolation:
    """
    RED: Security/integrity ValueErrors during projection building must NOT
    be silently swallowed and converted to "no Git metadata".
    """

    def test_red_symlink_file_in_refs_raises_valueerror(self):
        """
        RED: A symlink FILE inside refs/heads/ that points to an arbitrary path
        must raise ValueError.
        """
        ce = _load_executor()
        tmp = tempfile.mkdtemp(prefix="red_b10_symlink_refs_")
        try:
            repo = os.path.join(tmp, "repo")
            os.makedirs(repo)
            _run_git(repo, "init")
            _run_git(repo, "config", "user.email", "test@test.com")
            _run_git(repo, "config", "user.name", "Test")
            with open(os.path.join(repo, "f.txt"), "w") as f:
                f.write("c\n")
            _run_git(repo, "add", "f.txt")
            _run_git(repo, "commit", "-m", "init")

            # Create a symlink file inside refs/heads that points outside
            refs_heads = os.path.join(repo, ".git", "refs", "heads")
            os.makedirs(refs_heads, exist_ok=True)

            # Create a symlink FILE to /etc/passwd
            evil_link = os.path.join(refs_heads, "evil_file")
            if os.path.exists(evil_link):
                os.remove(evil_link)
            os.symlink("/etc/passwd", evil_link)

            dst_git = tempfile.mkdtemp(prefix="red_b10_dst_")
            try:
                with pytest.raises(ValueError, match="symlink"):
                    ce._copy_git_refs(os.path.join(repo, ".git"), dst_git)
            finally:
                shutil.rmtree(dst_git, ignore_errors=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_red_symlink_dir_in_refs_raises_valueerror(self):
        """
        RED: A symlink DIRECTORY inside refs/heads/ that points to an arbitrary path
        must raise ValueError.

        This was previously NOT caught because os.walk returns symlinks to directories
        in the 'dirs' list, not the 'files' list.
        """
        ce = _load_executor()
        tmp = tempfile.mkdtemp(prefix="red_b10_symlink_dir_")
        try:
            repo = os.path.join(tmp, "repo")
            os.makedirs(repo)
            _run_git(repo, "init")
            _run_git(repo, "config", "user.email", "test@test.com")
            _run_git(repo, "config", "user.name", "Test")
            with open(os.path.join(repo, "f.txt"), "w") as f:
                f.write("c\n")
            _run_git(repo, "add", "f.txt")
            _run_git(repo, "commit", "-m", "init")

            # Create a symlink DIRECTORY inside refs/heads that points outside
            refs_heads = os.path.join(repo, ".git", "refs", "heads")
            os.makedirs(refs_heads, exist_ok=True)

            # Create a symlink DIRECTORY to /tmp
            evil_dir = os.path.join(refs_heads, "evil_dir")
            if os.path.exists(evil_dir):
                if os.path.islink(evil_dir):
                    os.remove(evil_dir)
                else:
                    shutil.rmtree(evil_dir)
            os.symlink("/tmp", evil_dir)

            dst_git = tempfile.mkdtemp(prefix="red_b10_dst_")
            try:
                with pytest.raises(ValueError, match="symlink"):
                    ce._copy_git_refs(os.path.join(repo, ".git"), dst_git)
            finally:
                shutil.rmtree(dst_git, ignore_errors=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_red_symlink_refs_points_to_real_git_file(self):
        """
        RED: A symlink inside refs/heads/ that points to a real Git file
        (e.g., HEAD) must raise ValueError.
        """
        ce = _load_executor()
        tmp = tempfile.mkdtemp(prefix="red_b10_symlink_to_head_")
        try:
            repo = os.path.join(tmp, "repo")
            os.makedirs(repo)
            _run_git(repo, "init")
            _run_git(repo, "config", "user.email", "test@test.com")
            _run_git(repo, "config", "user.name", "Test")
            with open(os.path.join(repo, "f.txt"), "w") as f:
                f.write("c\n")
            _run_git(repo, "add", "f.txt")
            _run_git(repo, "commit", "-m", "init")

            # Create symlink refs/heads/main -> ../HEAD (points to real Git file)
            refs_heads = os.path.join(repo, ".git", "refs", "heads")
            os.makedirs(refs_heads, exist_ok=True)
            evil_link = os.path.join(refs_heads, "main")
            if os.path.exists(evil_link):
                os.remove(evil_link)
            os.symlink("../HEAD", evil_link)

            dst_git = tempfile.mkdtemp(prefix="red_b10_dst_")
            try:
                with pytest.raises(ValueError, match="symlink not allowed"):
                    ce._copy_git_refs(os.path.join(repo, ".git"), dst_git)
            finally:
                shutil.rmtree(dst_git, ignore_errors=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_red_build_projection_valueerror_not_silenced(self):
        """
        RED: ValueError from security check inside _build_minimal_git_projection
        must NOT be caught and converted to "no Git metadata" by the caller.

        Currently: _git_metadata_mount_args catches ValueError from
        _build_minimal_git_projection and returns ([], None) — silent degradation.

        After fix: security ValueError must propagate.
        """
        ce = _load_executor()
        # Use ~/Library/Caches to avoid macOS /var->/private/var path aliasing.
        # On macOS, /var/folders and /tmp both resolve to /private/* paths.
        # This caused the traversal check (commonpath) to fire BEFORE the
        # projection-building ValueError was reached, preventing the test from
        # exercising the intended security boundary (_build_minimal_git_projection).
        cache_tmp = os.path.expanduser("~/Library/Caches")
        tmp = tempfile.mkdtemp(prefix="red_b10_valueerror_", dir=cache_tmp)
        try:
            repo = os.path.join(tmp, "repo")
            os.makedirs(repo)
            _run_git(repo, "init")
            _run_git(repo, "config", "user.email", "test@test.com")
            _run_git(repo, "config", "user.name", "Test")
            with open(os.path.join(repo, "f.txt"), "w") as f:
                f.write("c\n")
            _run_git(repo, "add", "f.txt")
            _run_git(repo, "commit", "-m", "init")

            # Plant a symlink attack in refs/heads that triggers _copy_git_refs.
            # With ~/Library/Caches (no path aliasing), commonpath check passes,
            # so _build_minimal_git_projection runs and raises ValueError from
            # _copy_git_refs (symlink not allowed in refs/ tree). This ValueError
            # propagates through _build_minimal_git_projection and would be caught
            # by the vulnerable silencing code at _git_metadata_mount_args line 762-763.
            refs_heads = os.path.join(repo, ".git", "refs", "heads")
            os.makedirs(refs_heads, exist_ok=True)
            evil_link = os.path.join(refs_heads, "attack")
            if os.path.exists(evil_link):
                os.remove(evil_link)
            os.symlink("/etc/passwd", evil_link)

            # After fix: _git_metadata_mount_args raises ValueError for symlink attacks
            with pytest.raises(ValueError):
                ce._git_metadata_mount_args(repo)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_red_absolute_symlink_in_refs_rejected(self):
        """
        RED: refs/heads/<name> must not resolve to an absolute path.
        """
        ce = _load_executor()
        tmp = tempfile.mkdtemp(prefix="red_b10_absolute_ref_")
        try:
            repo = os.path.join(tmp, "repo")
            os.makedirs(repo)
            _run_git(repo, "init")
            _run_git(repo, "config", "user.email", "test@test.com")
            _run_git(repo, "config", "user.name", "Test")
            with open(os.path.join(repo, "f.txt"), "w") as f:
                f.write("c\n")
            _run_git(repo, "add", "f.txt")
            _run_git(repo, "commit", "-m", "init")

            refs_heads = os.path.join(repo, ".git", "refs", "heads")
            os.makedirs(refs_heads, exist_ok=True)

            # Attack: refs/heads/abs -> /absolute/path (absolute symlink)
            abs_link = os.path.join(refs_heads, "abs")
            if os.path.exists(abs_link):
                os.remove(abs_link)
            os.symlink("/some/absolute/path", abs_link)

            dst_git = tempfile.mkdtemp(prefix="red_b10_dst_")
            try:
                with pytest.raises(ValueError, match="symlink not allowed"):
                    ce._copy_git_refs(os.path.join(repo, ".git"), dst_git)
            finally:
                shutil.rmtree(dst_git, ignore_errors=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
