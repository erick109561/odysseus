"""
RED test: B5 — HOST GIT ENVIRONMENT INHERITANCE

ROOT CAUSE:
_copy_objects uses subprocess.check_output with NO explicit env parameter,
so it inherits the full host environment including hostile GIT_* variables.

The bug:
  subprocess.check_output(["git", "-C", src_git, "rev-parse", "--verify", "HEAD"], ...)
  # No env= parameter — inherits os.environ

Expected before fix:
  _copy_objects can be affected by GIT_DIR, GIT_WORK_TREE, GIT_OBJECT_DIRECTORY,
  GIT_ALTERNATE_OBJECT_DIRECTORIES, GIT_CONFIG_COUNT, or credential helpers.

Expected after fix:
  _copy_objects uses _git_env() to strip GIT_* overrides before calling git.
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


def _run_git_sanitized(dir_, *args, timeout=10, git_env=None):
    """Run git with sanitized GIT_* environment variables."""
    from tests._repo_paths import get_container_executor_path
    import importlib.util
    import sys
    spec = importlib.util.spec_from_file_location(
        "container_executor",
        str(get_container_executor_path())
    )
    ce = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ce)
    sanitized_env = ce._git_env()
    sanitized_env["GIT_TERMINAL_PROMPT"] = "0"
    proc = subprocess.run(
        ["git", "-C", dir_] + list(args),
        capture_output=True, text=True, timeout=timeout,
        env=sanitized_env,
    )
    return proc.stdout.strip(), proc.stderr, proc.returncode


class TestRedB5HostileGitEnvironment:
    """
    RED: Hostile GIT_* environment variables must not affect _copy_objects.
    """

    @pytest.fixture
    def repo_fixture(self):
        tmp = tempfile.mkdtemp(prefix="red_b5_")
        repo = os.path.join(tmp, "test_repo")
        os.makedirs(repo)
        _run_git(repo, "init")
        _run_git(repo, "config", "user.email", "test@test.com")
        _run_git(repo, "config", "user.name", "Test")
        with open(os.path.join(repo, "file.txt"), "w") as f:
            f.write("content\n")
        _run_git(repo, "add", "file.txt")
        _run_git(repo, "commit", "-m", "init")
        original_head = _run_git(repo, "rev-parse", "HEAD")[0]
        yield {"tmp": tmp, "repo": repo, "original_head": original_head}
        shutil.rmtree(tmp, ignore_errors=True)

    def test_red_copy_objects_rejects_hostile_git_dir(self, repo_fixture):
        """
        RED: GIT_DIR pointing to a different repo must not redirect object copying.

        Before fix: the hostile GIT_DIR could cause _copy_objects to read from
        the wrong repository.
        """
        ce = _load_executor()
        repo = repo_fixture["repo"]

        # Create a second repo that will be the hostile target
        hostile = tempfile.mkdtemp(prefix="red_b5_hostile_")
        try:
            hostile_repo = os.path.join(hostile, "hostile_repo")
            os.makedirs(hostile_repo)
            _run_git(hostile_repo, "init")
            _run_git(hostile_repo, "config", "user.email", "evil@test.com")
            _run_git(hostile_repo, "config", "user.name", "Evil")
            with open(os.path.join(hostile_repo, "evil.txt"), "w") as f:
                f.write("evil\n")
            _run_git(hostile_repo, "add", "evil.txt")
            _run_git(hostile_repo, "commit", "-m", "evil commit")
            hostile_head = _run_git(hostile_repo, "rev-parse", "HEAD")[0]

            # Build projection with hostile GIT_DIR set
            old_git_dir = os.environ.get("GIT_DIR")
            old_git_common_dir = os.environ.get("GIT_COMMON_DIR")
            try:
                os.environ["GIT_DIR"] = hostile_repo
                os.environ["GIT_COMMON_DIR"] = hostile_repo

                proj_git, _ = ce._build_minimal_git_projection(repo, os.path.join(repo, ".git"))

                # The projected HEAD must match the original repo, not the hostile one
                # Use sanitized env for verification since hostile GIT_DIR is still set
                proj_head, _, rc = _run_git_sanitized(proj_git, "rev-parse", "HEAD")
                assert rc == 0, "Failed to rev-parse projected HEAD"

                assert proj_head == repo_fixture["original_head"], (
                    f"Hostile GIT_DIR ({hostile_head}) leaked into projection: "
                    f"got {proj_head}, expected {repo_fixture['original_head']}"
                )
            finally:
                if old_git_dir is not None:
                    os.environ["GIT_DIR"] = old_git_dir
                elif "GIT_DIR" in os.environ:
                    del os.environ["GIT_DIR"]
                if old_git_common_dir is not None:
                    os.environ["GIT_COMMON_DIR"] = old_git_common_dir
                elif "GIT_COMMON_DIR" in os.environ:
                    del os.environ["GIT_COMMON_DIR"]
        finally:
            shutil.rmtree(hostile, ignore_errors=True)

    def test_red_copy_objects_rejects_hostile_git_object_directory(self, repo_fixture):
        """
        RED: GIT_OBJECT_DIRECTORY pointing outside the repo must not affect projection.
        """
        ce = _load_executor()
        repo = repo_fixture["repo"]

        # Create a temp dir that will be a hostile GIT_OBJECT_DIRECTORY
        hostile_objdir = tempfile.mkdtemp(prefix="red_b5_hostile_obj_")
        try:
            # Create a fake objects structure in the hostile directory
            os.makedirs(os.path.join(hostile_objdir, "info"))
            os.makedirs(os.path.join(hostile_objdir, "pack"))

            old_git_object_dir = os.environ.get("GIT_OBJECT_DIRECTORY")
            old_git_alternate = os.environ.get("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            try:
                os.environ["GIT_OBJECT_DIRECTORY"] = hostile_objdir
                if "GIT_ALTERNATE_OBJECT_DIRECTORIES" in os.environ:
                    del os.environ["GIT_ALTERNATE_OBJECT_DIRECTORIES"]

                # Build projection with hostile GIT_OBJECT_DIRECTORY
                proj_git, _ = ce._build_minimal_git_projection(repo, os.path.join(repo, ".git"))

                proj_head, _, rc = _run_git_sanitized(proj_git, "rev-parse", "HEAD")
                assert rc == 0

                assert proj_head == repo_fixture["original_head"], (
                    f"Hostile GIT_OBJECT_DIRECTORY leaked into projection: "
                    f"got {proj_head}, expected {repo_fixture['original_head']}"
                )
            finally:
                if old_git_object_dir is not None:
                    os.environ["GIT_OBJECT_DIRECTORY"] = old_git_object_dir
                elif "GIT_OBJECT_DIRECTORY" in os.environ:
                    del os.environ["GIT_OBJECT_DIRECTORY"]
                if old_git_alternate is not None:
                    os.environ["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = old_git_alternate
                elif "GIT_ALTERNATE_OBJECT_DIRECTORIES" in os.environ:
                    del os.environ["GIT_ALTERNATE_OBJECT_DIRECTORIES"]
        finally:
            shutil.rmtree(hostile_objdir, ignore_errors=True)

    def test_red_run_git_uses_sanitized_env(self, repo_fixture):
        """
        RED: _run_git must use _git_env() to strip hostile GIT_* vars.

        This test verifies that _run_git (which does use _git_env()) properly
        sanitizes the environment, while _copy_objects (which does not) is the bug.
        """
        ce = _load_executor()
        repo = repo_fixture["repo"]

        # Set hostile GIT_DIR pointing to wrong repo
        hostile = tempfile.mkdtemp(prefix="red_b5_hostile_")
        try:
            hostile_repo = os.path.join(hostile, "hostile_repo")
            os.makedirs(hostile_repo)
            _run_git(hostile_repo, "init")
            _run_git(hostile_repo, "config", "user.email", "evil@test.com")
            _run_git(hostile_repo, "config", "user.name", "Evil")
            hostile_head = _run_git(hostile_repo, "rev-parse", "HEAD")[0]

            old_git_dir = os.environ.get("GIT_DIR")
            try:
                os.environ["GIT_DIR"] = hostile_repo

                # _run_git is called by _git_metadata_mount_args to verify worktree identity.
                # It MUST return the correct workspace, not be affected by hostile GIT_DIR.
                result = ce._run_git(
                    repo,
                    "rev-parse",
                    "--path-format=absolute",
                    "--show-toplevel",
                )

                # The result should be the actual repo path, not influenced by GIT_DIR
                assert os.path.realpath(result) == os.path.realpath(repo), (
                    f"_run_git returned {result} but should return {repo} — "
                    f"hostile GIT_DIR leaked through!"
                )
            finally:
                if old_git_dir is not None:
                    os.environ["GIT_DIR"] = old_git_dir
                elif "GIT_DIR" in os.environ:
                    del os.environ["GIT_DIR"]
        finally:
            shutil.rmtree(hostile, ignore_errors=True)
