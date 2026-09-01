"""
RED test: MAJOR-9 sibling worktree config.worktree exposure via common-dir mount.

The linked-worktree path mounts the entire Git common directory read-only, but
credential/config safety scans do not cover every worktree-specific config.worktree
exposed by that mount.

Setup:
  main (bare git dir, with extensions.worktreeConfig=true)
  sibling worktree (has sensitive config.worktree)
  target worktree (the one being validated)

Exposure:
  When target is validated, the entire common dir is mounted, including
  sibling's worktrees/<sibling>/config.worktree

Vulnerability:
  A sensitive credential (e.g. http.extraheader with Authorization: Bearer ...)
  in sibling's config.worktree is NOT scanned, because only
  common/config and target_gitdir/config.worktree are validated.

Run with:
  python -m pytest tests/test_MAJOR9_sibling_worktree_config_RED.py -v
"""
import os
import subprocess
from pathlib import Path

import pytest


MODULE = "src.agent_tools.container_executor"


def _executor():
    """
    Return the container_executor module with build_podman_run_argv wrapped
    to return (argv, cleanup_callbacks).
    """
    try:
        import importlib
        mod = importlib.import_module(MODULE)
    except ModuleNotFoundError:
        pytest.skip("container_executor module not found")

    class _ExecutorWrapper:
        DEFAULT_CONTAINER_IMAGE = mod.DEFAULT_CONTAINER_IMAGE

        @staticmethod
        def build_podman_run_argv(**kwargs):
            result = mod.build_podman_run_argv(**kwargs)
            if isinstance(result, tuple) and len(result) == 2:
                return result
            return (result, [])

    return _ExecutorWrapper()


def _make_three_worktree_fixture(tmp_path):
    """
    Create a 3-worktree fixture:
      main_repo/          <- the "main" worktree (regular repo with worktrees/)
      sibling_worktree/   <- a sibling linked worktree with sensitive config.worktree
      target_worktree/    <- the "target" linked worktree being validated

    All share: main_repo/.git (the git common dir)

    main_repo has extensions.worktreeConfig=true so credential settings
    live in config.worktree files, not in the main config.

    sibling_worktree has a sensitive http.extraheader in its config.worktree.
    """
    main_repo = tmp_path / "main_repo"
    sibling_wt = tmp_path / "sibling_worktree"
    target_wt = tmp_path / "target_worktree"

    # Init main repo
    subprocess.run(["git", "init", "-q", str(main_repo)], check=True)
    subprocess.run(
        ["git", "-C", str(main_repo), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(main_repo), "config", "user.name", "JARVIS Test"],
        check=True,
    )

    # Enable extensions.worktreeConfig on main repo
    # This makes credential settings go to config.worktree files
    subprocess.run(
        ["git", "-C", str(main_repo), "config", "extensions.worktreeConfig", "true"],
        check=True,
    )

    # Create a commit so worktrees can be added
    (main_repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(main_repo), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(main_repo), "commit", "-q", "-m", "baseline"],
        check=True,
    )

    # Add sibling worktree
    subprocess.run(
        [
            "git", "-C", str(main_repo),
            "worktree", "add",
            "-q", "-b", "sibling-branch",
            str(sibling_wt),
        ],
        check=True,
    )

    # Add target worktree
    subprocess.run(
        [
            "git", "-C", str(main_repo),
            "worktree", "add",
            "-q", "-b", "target-branch",
            str(target_wt),
        ],
        check=True,
    )

    # Get the sibling's worktree-specific config path
    # In a linked worktree with extensions.worktreeConfig, the config.worktree
    # lives at: .git/worktrees/<wt-name>/config.worktree
    # But we need the path inside the common git dir.
    common_git_dir = subprocess.check_output(
        ["git", "-C", str(sibling_wt), "rev-parse", "--git-common-dir"],
        text=True,
    ).strip()

    # List the worktrees to find sibling's worktree id
    worktree_list = subprocess.check_output(
        ["git", "-C", str(sibling_wt), "worktree", "list", "--porcelain"],
        text=True,
    ).strip()

    # Parse worktree list to find sibling's worktree path
    sibling_path_in_list = None
    current_path = None
    for line in worktree_list.splitlines():
        if line.startswith("worktree "):
            current_path = line[len("worktree "):].strip()
        if current_path and current_path == str(sibling_wt):
            break

    # Get the sibling's gitdir (should be inside common dir)
    sibling_gitdir = subprocess.check_output(
        ["git", "-C", str(sibling_wt), "rev-parse", "--git-dir"],
        text=True,
    ).strip()

    # sibling's worktree config lives at sibling_gitdir/config.worktree
    sibling_config_worktree = os.path.join(sibling_gitdir, "config.worktree")

    # Write sensitive value to sibling's config.worktree
    # Using git config to ensure proper format
    subprocess.run(
        [
            "git", "-C", str(sibling_wt),
            "config",
            "--worktree",
            "http.extraheader",
            "Authorization: Bearer SIBLING_SECRET_TOKEN_XYZ",
        ],
        check=True,
    )

    return {
        "main_repo": main_repo,
        "sibling_wt": sibling_wt,
        "target_wt": target_wt,
        "common_git_dir": common_git_dir,
        "sibling_gitdir": sibling_gitdir,
        "sibling_config_worktree": sibling_config_worktree,
    }


def _make_three_worktree_fixture_main_config_worktree(tmp_path):
    """
    Variant: sensitive config.worktree in the MAIN repo's .git/config.worktree
    (not in a sibling worktree gitdir).

    This tests the case where the MAIN worktree's config.worktree contains
    a sensitive value and is exposed via the common-dir mount.
    """
    main_repo = tmp_path / "main_repo"
    sibling_wt = tmp_path / "sibling_worktree"
    target_wt = tmp_path / "target_worktree"

    # Init main repo
    subprocess.run(["git", "init", "-q", str(main_repo)], check=True)
    subprocess.run(
        ["git", "-C", str(main_repo), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(main_repo), "config", "user.name", "JARVIS Test"],
        check=True,
    )

    # Enable extensions.worktreeConfig on main repo
    subprocess.run(
        ["git", "-C", str(main_repo), "config", "extensions.worktreeConfig", "true"],
        check=True,
    )

    # Create a commit so worktrees can be added
    (main_repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(main_repo), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(main_repo), "commit", "-q", "-m", "baseline"],
        check=True,
    )

    # Add sibling worktree
    subprocess.run(
        [
            "git", "-C", str(main_repo),
            "worktree", "add",
            "-q", "-b", "sibling-branch",
            str(sibling_wt),
        ],
        check=True,
    )

    # Add target worktree
    subprocess.run(
        [
            "git", "-C", str(main_repo),
            "worktree", "add",
            "-q", "-b", "target-branch",
            str(target_wt),
        ],
        check=True,
    )

    # Write sensitive value to main repo's .git/config.worktree
    subprocess.run(
        [
            "git", "-C", str(main_repo),
            "config",
            "--worktree",
            "http.extraheader",
            "Authorization: Bearer MAIN_SECRET_TOKEN_XYZ",
        ],
        check=True,
    )

    # Get paths for verification
    common_git_dir = subprocess.check_output(
        ["git", "-C", str(target_wt), "rev-parse", "--git-common-dir"],
        text=True,
    ).strip()

    return {
        "main_repo": main_repo,
        "sibling_wt": sibling_wt,
        "target_wt": target_wt,
        "common_git_dir": common_git_dir,
        "main_config_worktree": os.path.join(common_git_dir, "config.worktree"),
    }


class TestMajor9SiblingWorktreeConfigExposure:
    """
    MAJOR-9: sibling worktree config.worktree exposed via common-dir mount.

    These tests demonstrate the vulnerability BEFORE the production fix.
    After the fix, tests should PASS (ValueError raised = vulnerability closed).
    """

    def test_sibling_worktree_unsafe_config_worktree_rejected(self, tmp_path):
        """
        RED (Design C supersession): With the projection architecture, the
        sibling worktree's config.worktree is structurally inaccessible —
        the original .git tree is NEVER mounted.

        The security invariant is preserved via: original config files are
        never exposed to the container, not via scanner-based detection.

        Before fix: scanner runs on raw mount → ValueError (but incomplete coverage)
        After fix:  original config never mounted → canary structurally inaccessible
        """
        fixture = _make_three_worktree_fixture(tmp_path)

        ex = _executor()

        # Verify sibling config.worktree exists and has the sensitive value
        assert os.path.isfile(fixture["sibling_config_worktree"]), (
            f"sibling config.worktree not found at {fixture['sibling_config_worktree']}"
        )

        sibling_cfg = subprocess.check_output(
            ["git", "config", "--file", fixture["sibling_config_worktree"], "--list"],
            text=True,
        ).strip()
        assert "SIBLING_SECRET_TOKEN_XYZ" in sibling_cfg, (
            f"Expected sensitive token in sibling config.worktree: {sibling_cfg}"
        )

        # Design C: original config is NEVER mounted. Verify canary is not in argv.
        argv, _ = ex.build_podman_run_argv(
            workspace=str(fixture["target_wt"]),
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="jarvis-test",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        assert "SIBLING_SECRET_TOKEN_XYZ" not in rendered, (
            "Sibling config.worktree canary visible in container argv — "
            "original config must never be mounted"
        )

    def test_main_repo_config_worktree_unsafe_rejected(self, tmp_path):
        """
        RED (Design C supersession): Main repo's config.worktree is structurally
        inaccessible with the projection architecture.
        """
        fixture = _make_three_worktree_fixture_main_config_worktree(tmp_path)

        ex = _executor()

        # Verify main config.worktree exists and has the sensitive value
        assert os.path.isfile(fixture["main_config_worktree"]), (
            f"main config.worktree not found at {fixture['main_config_worktree']}"
        )

        main_cfg = subprocess.check_output(
            ["git", "config", "--file", fixture["main_config_worktree"], "--list"],
            text=True,
        ).strip()
        assert "MAIN_SECRET_TOKEN_XYZ" in main_cfg, (
            f"Expected sensitive token in main config.worktree: {main_cfg}"
        )

        # Design C: original config is NEVER mounted. Verify canary is not in argv.
        argv, _ = ex.build_podman_run_argv(
            workspace=str(fixture["target_wt"]),
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="jarvis-test",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        assert "MAIN_SECRET_TOKEN_XYZ" not in rendered, (
            "Main config.worktree canary visible in container argv"
        )

    def test_sibling_safe_config_worktree_accepted(self, tmp_path):
        """
        Control: sibling worktree with SAFE per-worktree config must still work.
        A non-credential config.worktree (e.g. core.autocrlf) must NOT cause rejection.
        """
        main_repo = tmp_path / "main_repo"
        sibling_wt = tmp_path / "sibling_worktree"
        target_wt = tmp_path / "target_worktree"

        # Init
        subprocess.run(["git", "init", "-q", str(main_repo)], check=True)
        subprocess.run(
            ["git", "-C", str(main_repo), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(main_repo), "config", "user.name", "JARVIS Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(main_repo), "config", "extensions.worktreeConfig", "true"],
            check=True,
        )

        (main_repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(main_repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(main_repo), "commit", "-q", "-m", "baseline"],
            check=True,
        )

        subprocess.run(
            [
                "git", "-C", str(main_repo),
                "worktree", "add", "-q", "-b", "sibling-branch", str(sibling_wt),
            ],
            check=True,
        )
        subprocess.run(
            [
                "git", "-C", str(main_repo),
                "worktree", "add", "-q", "-b", "target-branch", str(target_wt),
            ],
            check=True,
        )

        # Write SAFE per-worktree config (no credentials)
        subprocess.run(
            ["git", "-C", str(sibling_wt), "config", "--worktree", "core.autocrlf", "true"],
            check=True,
        )

        ex = _executor()
        # Must NOT raise — safe config.worktree should be accepted
        argv, _ = ex.build_podman_run_argv(
            workspace=str(target_wt),
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="jarvis-test",
            command=["git", "status"],
        )
        assert "--pull=never" in "\n".join(argv)

    def test_unregistered_worktree_rejected(self, tmp_path):
        """
        M9 discriminating test: unauthorized worktree relationship must be rejected.

        An attacker creates a directory with a .git file pointing to a gitdir
        inside the common directory (passes commonpath check), but the directory
        is NOT a registered worktree in `git worktree list`.

        CAND: raises ValueError("workspace is not a registered Git worktree")
        M9:   accepts (membership check bypassed)

        The membership check is the EFFECTIVE authorization guard, not the
        redundant commonpath check.
        """
        import shutil as _shutil

        main_repo = tmp_path / "main_repo"
        legit_wt = tmp_path / "legit_worktree"
        fake_wt = tmp_path / "fake_worktree"

        # Init main repo
        subprocess.run(["git", "init", "-q", str(main_repo)], check=True)
        subprocess.run(
            ["git", "-C", str(main_repo), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(main_repo), "config", "user.name", "JARVIS Test"],
            check=True,
        )
        (main_repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(main_repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(main_repo), "commit", "-q", "-m", "baseline"],
            check=True,
        )

        # Create a legitimate linked worktree
        subprocess.run(
            [
                "git", "-C", str(main_repo),
                "worktree", "add", "-q", "-b", "legit-branch", str(legit_wt),
            ],
            check=True,
        )

        # Get the legitimate worktree's gitdir structure as template
        legit_gitdir = subprocess.check_output(
            ["git", "-C", str(legit_wt), "rev-parse", "--git-dir"],
            text=True,
        ).strip()

        # Create fake worktree directory with attacker-controlled .git file
        # The gitdir is inside common (passes commonpath check)
        # But fake_wt is NOT in git worktree list (fails membership check)
        fake_gitdir = main_repo / ".git" / "worktrees" / "fake_attack"
        _shutil.copytree(legit_gitdir, fake_gitdir)

        fake_wt.mkdir()
        (fake_wt / ".git").write_text(f"gitdir: {fake_gitdir}\n", encoding="utf-8")
        (fake_wt / "file.txt").write_text("attacker content\n", encoding="utf-8")

        # Verify: fake worktree is NOT in git worktree list
        worktree_list = subprocess.check_output(
            ["git", "-C", str(main_repo), "worktree", "list", "--porcelain"],
            text=True,
        )
        assert str(fake_wt) not in worktree_list, (
            "Fake worktree should NOT appear in git worktree list"
        )

        # Verify: rev-parse succeeds (worktree top check passes)
        top_result = subprocess.run(
            ["git", "-C", str(fake_wt), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True,
        )
        assert top_result.returncode == 0, (
            f"rev-parse should succeed for fake worktree: {top_result.stderr}"
        )

        # Verify: gitdir is inside common (commonpath check would pass)
        gitdir_for_fake = subprocess.check_output(
            ["git", "-C", str(fake_wt), "rev-parse", "--git-dir"],
            text=True,
        ).strip()
        common_for_fake = subprocess.check_output(
            ["git", "-C", str(fake_wt), "rev-parse", "--git-common-dir"],
            text=True,
        ).strip()
        import os as _os
        assert _os.path.commonpath([gitdir_for_fake, common_for_fake]) == common_for_fake, (
            "Fake gitdir should be inside common"
        )

        # THE ACTUAL TEST: CAND must reject, M9 would accept
        ex = _executor()
        with pytest.raises(ValueError, match="not a registered Git worktree"):
            ex.build_podman_run_argv(
                workspace=str(fake_wt),
                image_ref=ex.DEFAULT_CONTAINER_IMAGE,
                container_name="jarvis-test",
                command=["git", "status"],
            )
