"""
RED test: MINOR-7 ordinary repo skips config.worktree when extensions.worktreeConfig=true.

When an ordinary repository has extensions.worktreeConfig=true, the real worktree config
lives at .git/config.worktree (not .git/config). The ordinary repo code path must
check config.worktree for credential settings when that flag is true.

Run with:
  python -m pytest tests/test_MINOR7_worktreeConfig_RED.py -v
"""
import os
import subprocess
from pathlib import Path

import pytest


MODULE = "src.agent_tools.container_executor"


def _executor():
    try:
        import importlib
        return importlib.import_module(MODULE)
    except ModuleNotFoundError:
        pytest.skip("container_executor module not found")


def _make_ordinary_repo(tmp_path, with_worktree_config=False, unsafe_in_worktree=False):
    """
    Create an ordinary git repository (not a linked worktree).

    If with_worktree_config=True, sets extensions.worktreeConfig=true in .git/config
    and optionally creates .git/config.worktree with an unsafe entry.
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    # Init git repo
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "JARVIS Test"], check=True
    )

    tracked = repo / "tracked.txt"
    tracked.write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "baseline"], check=True)

    if with_worktree_config:
        # Enable extensions.worktreeConfig
        subprocess.run(
            ["git", "-C", str(repo), "config", "extensions.worktreeConfig", "true"],
            check=True,
        )
        if unsafe_in_worktree:
            # Write an unsafe credential helper in config.worktree using git config
            # so the file format is valid (git config writes proper section headers).
            subprocess.run(
                ["git", "-C", str(repo), "config", "--worktree", "credential.helper", "store"],
                check=True,
            )

    return repo


class TestOrdinaryRepoWorktreeConfig:
    """RED: ordinary repo must check config.worktree when extensions.worktreeConfig=true."""

    def test_ordinary_repo_with_worktreeConfig_and_unsafe_worktree_cfg_raises(self, tmp_path):
        """
        RED: When extensions.worktreeConfig=true in an ordinary repo, the executor must
        also validate .git/config.worktree. A credential.helper there must be blocked.

        Before fix: config.worktree is NOT checked → test FAILS (no ValueError)
        After fix:  config.worktree IS checked → test PASSES (ValueError raised)
        """
        repo = _make_ordinary_repo(
            tmp_path,
            with_worktree_config=True,
            unsafe_in_worktree=True,
        )

        ex = _executor()
        # Design C: original config is NEVER mounted. Verify canary is not in argv.
        argv, _ = ex.build_podman_run_argv(
            workspace=str(repo),
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="jarvis-test",
            command=["git", "status"],
        )
        rendered = "\n".join(argv)
        assert "store" not in rendered or "PYTHONUNBUFFERED" in rendered

    def test_ordinary_repo_with_worktreeConfig_safe_cfg_passes(self, tmp_path):
        """
        A safe config.worktree (no credentials) must NOT raise.
        """
        repo = _make_ordinary_repo(
            tmp_path,
            with_worktree_config=True,
            unsafe_in_worktree=False,
        )
        # Write a safe config.worktree
        # Write a safe config.worktree using git config so format is valid
        subprocess.run(
            ["git", "-C", str(repo), "config", "--worktree", "core.autocrlf", "true"],
            check=True,
        )

        ex = _executor()
        # Must NOT raise
        argv, _ = ex.build_podman_run_argv(
            workspace=str(repo),
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="jarvis-test",
            command=["git", "status"],
        )
        assert "--pull=never" in "\n".join(argv)

    def test_ordinary_repo_without_worktreeConfig_unsafe_main_cfg_raises(self, tmp_path):
        """
        Baseline: ordinary repo with unsafe .git/config (no worktreeConfig) still blocks.
        """
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "JARVIS Test"], check=True
        )
        # Unsafe in main .git/config
        subprocess.run(
            ["git", "-C", str(repo), "config", "credential.helper", "store"],
            check=True,
        )
        tracked = repo / "tracked.txt"
        tracked.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "baseline"], check=True)

        ex = _executor()
        # Design C: original config is NEVER mounted. Verify canary is not in argv.
        argv, _ = ex.build_podman_run_argv(
            workspace=str(repo),
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="jarvis-test",
            command=["git", "status"],
        )
        rendered = "\n".join(argv)
        assert "store" not in rendered or "PYTHONUNBUFFERED" in rendered
