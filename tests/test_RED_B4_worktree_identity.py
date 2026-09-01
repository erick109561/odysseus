"""
RED test: B4 — LINKED WORKTREE IDENTITY BUG

ROOT CAUSE:
_build_minimal_git_projection(workspace, common) sources HEAD and index
from `common` instead of the worktree-specific gitdir.

For linked worktrees, HEAD and index are in the gitdir, not in the
common directory. The comment at line 142 correctly states this:
  "For linked worktrees: refs/ and objects/ are in the common dir,
   but HEAD and index are in the worktree-specific gitdir."

But line 144 passes `common` to _build_minimal_git_projection, so HEAD
and index come from the wrong directory.

EXPECTED BEHAVIOR BEFORE FIX:
- proj_git/HEAD reflects main worktree's branch, not the linked worktree's
- proj_git/index reflects main worktree's staged state
- git rev-parse in container shows wrong identity

EXPECTED BEHAVIOR AFTER FIX:
- proj_git/HEAD reflects linked worktree's branch
- proj_git/index reflects linked worktree's staged state
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


class TestRedB4LinkedWorktreeIdentityBug:
    """
    RED: Linked worktree must use its own HEAD and index, not main's.

    Setup:
      main_repo ---> main branch (HEAD = main)
                 \\-> linked worktree ---> feature/wt branch (HEAD = feature/wt)

    The container projection for the linked worktree MUST reflect
    feature/wt, not main.
    """

    @pytest.fixture
    def worktree_fixture(self):
        tmp = tempfile.mkdtemp(prefix="red_b4_")
        main = os.path.join(tmp, "main_repo")
        linked = os.path.join(tmp, "linked_wt")
        os.makedirs(main)

        _run_git(main, "init")
        _run_git(main, "config", "user.email", "test@test.com")
        _run_git(main, "config", "user.name", "Test")

        # Create initial commit on main
        with open(os.path.join(main, "file.txt"), "w") as f:
            f.write("main content\n")
        _run_git(main, "add", "file.txt")
        _run_git(main, "commit", "-m", "main commit")

        main_head = _run_git(main, "rev-parse", "HEAD")[0]

        # Create linked worktree on a different branch
        _run_git(main, "worktree", "add", "-q", "-b", "feature/wt", linked)

        # Make the linked worktree different from main
        with open(os.path.join(linked, "file.txt"), "w") as f:
            f.write("linked content\n")
        _run_git(linked, "add", "file.txt")
        _run_git(linked, "commit", "-m", "linked commit")

        # Capture linked worktree state AFTER all commits are made
        linked_head = _run_git(linked, "rev-parse", "HEAD")[0]
        linked_branch = _run_git(linked, "rev-parse", "--abbrev-ref", "HEAD")[0]

        yield {
            "tmp": tmp,
            "main": main,
            "linked": linked,
            "main_head": main_head,
            "linked_head": linked_head,
            "linked_branch": linked_branch,
        }

        shutil.rmtree(tmp, ignore_errors=True)

    def test_red_worktree_projection_uses_correct_head(self, worktree_fixture):
        """
        RED: The projected git dir must contain the linked worktree's HEAD,
        not the main worktree's HEAD.

        Before fix: proj_git/HEAD == main_repo HEAD (main branch)
        After fix:  proj_git/HEAD == linked_wt HEAD (feature/wt branch)
        """
        ce = _load_executor()
        linked = worktree_fixture["linked"]
        linked_head = worktree_fixture["linked_head"]
        linked_branch = worktree_fixture["linked_branch"]

        # Get the gitdir and common dir for the linked worktree
        gitdir = _run_git(
            linked, "rev-parse", "--path-format=absolute", "--git-dir"
        )[0]
        common = _run_git(
            linked, "rev-parse", "--path-format=absolute", "--git-common-dir"
        )[0]

        # Verify setup: linked worktree gitdir != common (they are separate)
        assert gitdir != common, "Test setup: gitdir should differ from common"

        # Verify the worktree is actually on a different branch
        assert linked_branch == "feature/wt", f"Expected feature/wt, got {linked_branch}"

        # Build the projection — for linked worktrees, pass gitdir and common separately
        # git_real = worktree-specific gitdir (has HEAD+index)
        # git_common = shared common dir (has refs/objects)
        proj_git, _ = ce._build_minimal_git_projection(linked, gitdir, common)

        # Read the projected HEAD
        proj_head_path = os.path.join(proj_git, "HEAD")
        assert os.path.isfile(proj_head_path), "Projected HEAD file missing"

        with open(proj_head_path) as f:
            proj_head_content = f.read()

        # Resolve the projected HEAD to a SHA
        proj_head_sha, _, rc = _run_git(proj_git, "rev-parse", "HEAD")
        assert rc == 0, "Failed to rev-parse projected HEAD"

        # The projected HEAD must match the LINKED worktree's HEAD
        assert proj_head_sha == linked_head, (
            f"Projected HEAD ({proj_head_sha}) should match "
            f"linked worktree HEAD ({linked_head}), "
            f"but it does not — identity substitution bug!"
        )

    def test_red_worktree_projection_uses_worktree_gitdir_for_index(self, worktree_fixture):
        """
        RED: For linked worktrees, _copy_index must copy from gitdir (worktree-specific),
        not from common.

        The bug passes `common` to _build_minimal_git_projection, so index comes
        from common/.git/index instead of gitdir/index.

        After fix: index must be copied from gitdir.
        """
        ce = _load_executor()
        linked = worktree_fixture["linked"]

        gitdir = _run_git(
            linked, "rev-parse", "--path-format=absolute", "--git-dir"
        )[0]
        common = _run_git(
            linked, "rev-parse", "--path-format=absolute", "--git-common-dir"
        )[0]

        # Verify that gitdir and common are actually different directories
        assert os.path.realpath(gitdir) != os.path.realpath(common), (
            "Test requires gitdir != common"
        )

        # The gitdir (worktree-specific) should have an index
        gitdir_index = os.path.join(gitdir, "index")
        common_index = os.path.join(common, "index")

        has_gitdir_index = os.path.isfile(gitdir_index)
        has_common_index = os.path.isfile(common_index)

        # This test is only meaningful if the worktree has an index
        # (it should, since there are commits)
        if not has_gitdir_index:
            pytest.skip("Worktree gitdir has no index — test not applicable")

        # Build the projection — for linked worktrees, pass gitdir and common separately
        proj_git, _ = ce._build_minimal_git_projection(linked, gitdir, common)
        proj_index = os.path.join(proj_git, "index")

        # The projected index must exist
        assert os.path.isfile(proj_index), (
            "Projected index is missing — this would break git status"
        )

        # The projected index content must match the WORKTREE's index, not common's
        if has_gitdir_index and has_common_index:
            with open(gitdir_index, "rb") as f:
                gitdir_index_bytes = f.read()
            with open(common_index, "rb") as f:
                common_index_bytes = f.read()
            with open(proj_index, "rb") as f:
                proj_index_bytes = f.read()

            # The bug causes proj_index to match common_index instead of gitdir_index
            if gitdir_index_bytes != common_index_bytes:
                # Only meaningful if they actually differ
                assert proj_index_bytes == gitdir_index_bytes, (
                    "Projected index matches common/ (worktree gitdir) instead of "
                    "worktree gitdir — wrong source directory!"
                )

    def test_red_worktree_git_rev_parse_shows_correct_branch(self, worktree_fixture):
        """
        RED: git rev-parse in the projected gitdir must show the linked worktree's
        branch, not the main worktree's branch.
        """
        ce = _load_executor()
        linked = worktree_fixture["linked"]
        linked_branch = worktree_fixture["linked_branch"]

        gitdir = _run_git(
            linked, "rev-parse", "--path-format=absolute", "--git-dir"
        )[0]
        common = _run_git(
            linked, "rev-parse", "--path-format=absolute", "--git-common-dir"
        )[0]

        proj_git, _ = ce._build_minimal_git_projection(linked, gitdir, common)

        # Run git rev-parse in the projected gitdir
        proj_branch, _, rc = _run_git(proj_git, "rev-parse", "--abbrev-ref", "HEAD")
        assert rc == 0, "rev-parse failed in projected gitdir"

        assert proj_branch == linked_branch, (
            f"Projected gitdir reports branch '{proj_branch}', "
            f"but should be '{linked_branch}' — linked worktree identity not preserved!"
        )
