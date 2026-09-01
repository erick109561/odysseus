"""
MAJOR-10 RED regression tests: Git config surface exposure / scan asymmetry.

These tests verify that credential-bearing Git config files hidden at
non-obvious paths inside a mounted Git metadata tree are correctly
detected and rejected BEFORE the container boundary.

Test layout theory (per Git upstream):
  .git/
    config                  — main repo config
    config.worktree         — worktreeConfig (optional)
    modules/                — submodule Git dirs
      <name>/
        config              — submodule config (may have credentials)
        config.worktree     — submodule worktreeConfig
        modules/            — nested submodules
          <nested>/
            config
    worktrees/              — linked worktree metadata
      <id>/
        config.worktree
    objects/
    refs/
    ... (non-config surface, not scanned)

The boundary currently checks:
  ✓ .git/config
  ✓ .git/config.worktree
  ✓ common/config
  ✓ common/config.worktree
  ✓ common/worktrees/<id>/config.worktree
  ✓ gitdir/config.worktree

MISSING (MAJOR-10 attack surface):
  ✗ .git/modules/<name>/config
  ✗ .git/modules/<name>/config.worktree
  ✗ .git/modules/<name>/modules/<nested>/config
  ✗ .git/modules/<name>/modules/<nested>/config.worktree
  ✗ .git/worktrees/<id>/config.worktree (ordinary repo worktrees)
  ✗ common/modules/<name>/config (linked-worktree submodule config)
  ✗ common/modules/<name>/config.worktree
  ✗ config/config.worktree SYMLINK anywhere in surface => must FAIL CLOSED
"""

import multiprocessing
import os
import subprocess
import sys
import tempfile
import shutil
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _run_git(dir_, *args, env=None):
    """Run git with GIT_TERMINAL_PROMPT=0, return stdout."""
    git_env = dict(os.environ)
    git_env["GIT_TERMINAL_PROMPT"] = "0"
    if env:
        git_env.update(env)
    proc = subprocess.run(
        ["git", "-C", dir_] + list(args),
        capture_output=True, text=True, env=git_env, timeout=10,
    )
    return proc.stdout.strip(), proc.stderr, proc.returncode


class TestMAJOR10ConfigSurfaceRED:
    """RED: verify current boundary EXPOSES these attack vectors."""

    @pytest.fixture
    def temp_git_root(self):
        """Create a temporary directory that is cleaned up after the test."""
        d = tempfile.mkdtemp(prefix="m10_red_")
        yield d
        shutil.rmtree(d, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Helper: build fixture repos
    # -------------------------------------------------------------------------

    def _build_superproject_with_submodule(
        self, temp_git_root, sub_path="vendor/up", secret="SUBMODULE_SECRET_abc123"
    ):
        """
        Create:
          temp_git_root/super/         ← superproject (ordinary repo)
            .git/modules/vendor/up/   ← submodule Git dir
              config                    ← SUBMODULE CONFIG with credential
        Returns (superproject_path, submodule_git_dir).
        """
        super_path = os.path.join(temp_git_root, "super")
        sub_repo_path = os.path.join(temp_git_root, "sub_repo")
        os.makedirs(super_path)
        os.makedirs(sub_repo_path)

        _run_git(super_path, "init")
        _run_git(super_path, "config", "user.email", "test@test.com")
        _run_git(super_path, "config", "user.name", "Test")
        _run_git(sub_repo_path, "init")
        _run_git(sub_repo_path, "config", "user.email", "sub@test.com")
        _run_git(sub_repo_path, "config", "user.name", "Sub Test")
        # Commit so submodule add works
        subprocess.run(
            ["git", "-C", sub_repo_path, "commit", "--allow-empty", "-m", "init"],
            capture_output=True, timeout=10,
            env={**subprocess.os.environ, "GIT_TERMINAL_PROMPT": "0"}
        )
        subprocess.run(
            ["git", "-C", super_path, "submodule", "add", sub_repo_path, sub_path],
            capture_output=True, timeout=15,
            env={**subprocess.os.environ, "GIT_TERMINAL_PROMPT": "0"}
        )

        module_git_dir = os.path.join(super_path, ".git", "modules", sub_path)
        module_config = os.path.join(module_git_dir, "config")
        if not os.path.isfile(module_config):
            raise AssertionError(
                f"Expected submodule config at {module_config}; "
                f"modules dir: {os.listdir(os.path.join(super_path, '.git', 'modules'))}"
            )

        with open(module_config, "a") as f:
            f.write(f"\n[http]\n\textraheader = Authorization: Bearer {secret}\n")

        return super_path, module_git_dir

    def _build_nested_submodule(
        self, temp_git_root, secret="NESTED_SECRET_xyz789"
    ):
        """
        Create a superproject with a manually-constructed nested module Git dir:
          super/.git/modules/outer_sub/modules/inner_sub/config ← credential

        Git stores nested submodule Git dirs inside the parent's module Git dir.
        We construct it directly since git submodule add does not carry nested
        structures across levels.
        """
        super_path = os.path.join(temp_git_root, "super")
        os.makedirs(super_path)
        _run_git(super_path, "init")
        _run_git(super_path, "config", "user.email", "super@test.com")
        _run_git(super_path, "config", "user.name", "Super Test")

        nested_module_git = os.path.join(
            super_path, ".git", "modules", "outer_sub", "modules", "inner_sub"
        )
        os.makedirs(nested_module_git)
        for sub in ["objects", "refs"]:
            os.makedirs(os.path.join(nested_module_git, sub), exist_ok=True)

        nested_config = os.path.join(nested_module_git, "config")
        with open(nested_config, "w") as f:
            f.write("[core]\n\trepositoryformatversion = 0\n")
            f.write("[user]\n\tname = Nested Test\n\temail = nested@test.com\n")
            f.write(f"\n[http]\n\textraheader = Authorization: Bearer {secret}\n")

        outer_config = os.path.join(
            super_path, ".git", "modules", "outer_sub", "config"
        )
        with open(outer_config, "w") as f:
            f.write("[core]\n\trepositoryformatversion = 0\n")
            f.write("[user]\n\tname = Outer Sub\n\temail = outer@test.com\n")

        return super_path, nested_module_git

    def _build_stale_module_dir(
        self, temp_git_root, secret="STALE_SECRET_stale123"
    ):
        """
        Create a deinitialized/submodule Git dir that remains on disk
        but is not a valid registered submodule.

          temp_git_root/stale_repo/.git/
            modules/
              stale/
                config   ← STALE MODULE CONFIG with credential
        """
        stale_path = os.path.join(temp_git_root, "stale_repo")
        os.makedirs(stale_path)
        _run_git(stale_path, "init")
        _run_git(stale_path, "config", "user.email", "stale@test.com")

        # Create a fake submodule Git dir structure
        stale_module_git = os.path.join(stale_path, ".git", "modules", "stale")
        os.makedirs(stale_module_git)

        # Create minimal Git metadata
        for subdir in ["objects", "refs"]:
            os.makedirs(os.path.join(stale_module_git, subdir), exist_ok=True)

        stale_config = os.path.join(stale_module_git, "config")
        with open(stale_config, "w") as f:
            f.write("[core]\n\trepositoryformatversion = 0\n")
            f.write(f"\n[http]\n\textraheader = Authorization: Bearer {secret}\n")

        return stale_path, stale_module_git

    def _build_symlink_config_attack(
        self, temp_git_root, secret="SYMLINK_SECRET_link123"
    ):
        """
        Create a symlink attack inside the Git metadata surface:
          .git/config.worktree -> ../../secrets/evil_config

        The boundary MUST fail closed when encountering any symlink
        in the config surface.
        """
        repo_path = os.path.join(temp_git_root, "symlink_repo")
        os.makedirs(repo_path)
        _run_git(repo_path, "init")
        _run_git(repo_path, "config", "user.email", "test@test.com")

        # Create a secret file OUTSIDE the Git metadata
        secrets_dir = os.path.join(temp_git_root, "secrets")
        os.makedirs(secrets_dir)
        evil_config = os.path.join(secrets_dir, "evil_config")
        with open(evil_config, "w") as f:
            f.write("[http]\n\textraheader = Authorization: Bearer {}\n".format(secret))

        # Create symlink inside .git
        dotgit = os.path.join(repo_path, ".git")
        symlink_target = os.path.join(dotgit, "config.worktree")
        relative_evil = os.path.relpath(evil_config, dotgit)
        os.symlink(relative_evil, symlink_target)

        return repo_path, symlink_target

    def _build_linked_worktree_with_submodule(
        self, temp_git_root, secret="WORKTREE_SUBMODULE_SECRET_wtsub123"
    ):
        """
        Create a linked worktree whose common Git dir contains:
          common/modules/<name>/config   ← credential in submodule config

        The common Git dir is mounted read-only, so this must be caught.
        """
        main_path = os.path.join(temp_git_root, "main_repo")
        sub_repo_path = os.path.join(temp_git_root, "sub_repo")
        wt_path = os.path.join(temp_git_root, "worktree_linked")
        for d in [main_path, sub_repo_path, wt_path]:
            os.makedirs(d)

        _run_git(main_path, "init")
        _run_git(main_path, "config", "user.email", "main@test.com")
        _run_git(main_path, "config", "user.name", "Main Test")
        _run_git(sub_repo_path, "init")
        _run_git(sub_repo_path, "config", "user.email", "sub@test.com")
        subprocess.run(
            ["git", "-C", sub_repo_path, "commit", "--allow-empty", "-m", "init"],
            capture_output=True, timeout=10,
            env={**subprocess.os.environ, "GIT_TERMINAL_PROMPT": "0"}
        )
        subprocess.run(
            ["git", "-C", main_path, "submodule", "add", sub_repo_path, "vendor/up"],
            capture_output=True, timeout=15,
            env={**subprocess.os.environ, "GIT_TERMINAL_PROMPT": "0"}
        )
        subprocess.run(
            ["git", "-C", main_path, "commit", "--allow-empty", "-m", "main init"],
            capture_output=True, timeout=10,
            env={**subprocess.os.environ, "GIT_TERMINAL_PROMPT": "0"}
        )
        subprocess.run(
            ["git", "-C", main_path, "worktree", "add", wt_path],
            capture_output=True, timeout=15,
            env={**subprocess.os.environ, "GIT_TERMINAL_PROMPT": "0"}
        )

        common_git_dir = os.path.join(main_path, ".git")
        sub_module_git = os.path.join(common_git_dir, "modules", "vendor", "up")
        sub_module_config = os.path.join(sub_module_git, "config")
        if not os.path.isfile(sub_module_config):
            raise AssertionError(
                f"Expected submodule config at {sub_module_config}; "
                f"modules: {os.listdir(os.path.join(common_git_dir, 'modules'))}"
            )
        with open(sub_module_config, "a") as f:
            f.write(f"\n[http]\n\textraheader = Authorization: Bearer {secret}\n")
        return wt_path, sub_module_config

    def _build_ordinary_repo_with_worktree_config(
        self, temp_git_root, secret="WORKTREE_CONFIG_SECRET_wtc123"
    ):
        """
        Create an ordinary repo with extensions.worktreeConfig=true
        and a credential in config.worktree.
        """
        repo_path = os.path.join(temp_git_root, "wtconfig_repo")
        os.makedirs(repo_path)
        _run_git(repo_path, "init")
        _run_git(repo_path, "config", "user.email", "test@test.com")
        _run_git(repo_path, "config", "extensions.worktreeConfig", "true")

        wt_config = os.path.join(repo_path, ".git", "config.worktree")
        with open(wt_config, "w") as f:
            f.write("[core]\n\trepositoryformatversion = 0\n")
            f.write(f"\n[http]\n\textraheader = Authorization: Bearer {secret}\n")

        return repo_path, wt_config

    def _build_ordinary_repo_with_stale_worktrees_dir(
        self, temp_git_root, secret="STALE_WORKTREE_SECRET_stalewt123"
    ):
        """
        Create an ordinary repo with a leftover worktrees/<id> directory
        from a deleted/never-properly-cleaned worktree.
        """
        repo_path = os.path.join(temp_git_root, "stale_wt_repo")
        os.makedirs(repo_path)
        _run_git(repo_path, "init")
        _run_git(repo_path, "config", "user.email", "test@test.com")

        # Create a fake stale worktree metadata directory
        wt_meta_dir = os.path.join(repo_path, ".git", "worktrees", "stale_id")
        os.makedirs(wt_meta_dir)

        # Write a config.worktree with credentials in the stale worktree dir
        wt_config = os.path.join(wt_meta_dir, "config.worktree")
        with open(wt_config, "w") as f:
            f.write("[core]\n\trepositoryformatversion = 0\n")
            f.write(f"\n[http]\n\textraheader = Authorization: Bearer {secret}\n")

        return repo_path, wt_config

    def _build_benign_all_locations(
        self, temp_git_root
    ):
        """
        Create a repo with benign configs in all representative locations.
        This should NOT be rejected.

        Layout:
          .git/
            config                    ← benign
            config.worktree           ← benign (no credentials)
            modules/
              benign_sub/
                config                ← benign
                config.worktree       ← benign
                modules/
                  nested_benign/
                    config            ← benign
                    config.worktree   ← benign
            worktrees/
              benign_wt/
                config.worktree       ← benign
        """
        repo_path = os.path.join(temp_git_root, "benign_repo")
        os.makedirs(repo_path)
        _run_git(repo_path, "init")
        _run_git(repo_path, "config", "user.email", "test@test.com")
        _run_git(repo_path, "config", "user.name", "Benign Test")
        _run_git(repo_path, "config", "extensions.worktreeConfig", "true")

        # Benign main config (already has user.email/name, no credentials)
        main_config = os.path.join(repo_path, ".git", "config")

        # Benign main config.worktree
        main_wt_config = os.path.join(repo_path, ".git", "config.worktree")
        with open(main_wt_config, "w") as f:
            f.write("[core]\n\trepositoryformatversion = 0\n")
            f.write("[user]\n\tname = Benign Test\n\temail = benign@test.com\n")

        # Benign submodule
        benign_sub_dir = os.path.join(repo_path, ".git", "modules", "benign_sub")
        os.makedirs(benign_sub_dir)
        benign_sub_config = os.path.join(benign_sub_dir, "config")
        with open(benign_sub_config, "w") as f:
            f.write("[core]\n\trepositoryformatversion = 0\n")
            f.write("[user]\n\tname = Benign Sub\n\temail = benign_sub@test.com\n")

        benign_sub_wt = os.path.join(benign_sub_dir, "config.worktree")
        with open(benign_sub_wt, "w") as f:
            f.write("[user]\n\tname = Benign Sub WT\n\temail = benign_sub_wt@test.com\n")

        # Nested benign submodule
        nested_sub_dir = os.path.join(benign_sub_dir, "modules", "nested_benign")
        os.makedirs(nested_sub_dir)
        nested_config = os.path.join(nested_sub_dir, "config")
        with open(nested_config, "w") as f:
            f.write("[core]\n\trepositoryformatversion = 0\n")
            f.write("[user]\n\tname = Nested Benign\n\temail = nested_benign@test.com\n")

        nested_wt = os.path.join(nested_sub_dir, "config.worktree")
        with open(nested_wt, "w") as f:
            f.write("[user]\n\tname = Nested Benign WT\n\temail = nested_benign_wt@test.com\n")

        # Benign worktree
        benign_wt_dir = os.path.join(repo_path, ".git", "worktrees", "benign_wt")
        os.makedirs(benign_wt_dir)
        benign_wt_config = os.path.join(benign_wt_dir, "config.worktree")
        with open(benign_wt_config, "w") as f:
            f.write("[user]\n\tname = Benign WT\n\temail = benign_wt@test.com\n")

        return repo_path

    # -------------------------------------------------------------------------
    # Helper
    # -------------------------------------------------------------------------

    def _read_proj_file(self, proj_git, rel_path):
        """Read a file from the projection by relative path."""
        import os as _os
        full = _os.path.join(proj_git, rel_path.replace("/", _os.sep))
        if _os.path.isfile(full):
            with open(full) as f:
                return f.read()
        return ""

    # -------------------------------------------------------------------------
    # RED test cases — current boundary MUST REJECT after fix
    # -------------------------------------------------------------------------

    def test_red_Z_projection_filesystem_isolates_host_config(self, temp_git_root):
        """
        RED-Z (behavioral): Verify _build_minimal_git_projection does NOT copy
        .git/config into the projected filesystem. The projection must contain
        ONLY the minimal Git metadata (HEAD, index, refs/, objects/) — the
        original .git/config with host credentials must be structurally absent.

        This is a BEHAVIORAL test (not argv-only) that inspects the actual
        projected filesystem by calling _build_minimal_git_projection directly.
        """
        from src.agent_tools.container_executor import _build_minimal_git_projection

        # Use ~/Library/Caches to avoid macOS /var->/private/var aliasing
        cache_tmp = os.path.expanduser("~/Library/Caches")
        work_dir = tempfile.mkdtemp(prefix="m10_fs_", dir=cache_tmp)
        try:
            repo = os.path.join(work_dir, "repo")
            os.makedirs(repo)
            _run_git(repo, "init")
            _run_git(repo, "config", "user.email", "test@test.com")
            _run_git(repo, "config", "user.name", "Test")
            with open(os.path.join(repo, "file.txt"), "w") as f:
                f.write("content\n")
            _run_git(repo, "add", "file.txt")
            _run_git(repo, "commit", "-m", "init")

            # Plant credential in .git/config
            host_config = os.path.join(repo, ".git", "config")
            with open(host_config, "a") as f:
                f.write("\n[http]\n\textraheader = Authorization: Bearer HOST_CONFIG_SECRET_abc123\n")

            # Verify credential exists in host config
            with open(host_config) as f:
                assert "HOST_CONFIG_SECRET_abc123" in f.read()

            # Build the projection
            proj_git, cleanup = _build_minimal_git_projection(repo, os.path.join(repo, ".git"))

            # Collect ALL files in the projection (recursive)
            proj_files = []
            for root, dirs, files in os.walk(proj_git):
                for fname in files:
                    rel = os.path.relpath(os.path.join(root, fname), proj_git)
                    proj_files.append(rel)
                for dname in dirs:
                    rel = os.path.relpath(os.path.join(root, dname), proj_git)
                    proj_files.append(rel + "/")

            proj_files.sort()

            # Projection MUST contain essential Git metadata
            assert any("HEAD" in f for f in proj_files), \
                f"Projection missing HEAD: {proj_files}"
            assert any("refs/heads" in f for f in proj_files), \
                f"Projection missing refs/heads: {proj_files}"

            # Projection MUST NOT contain .git/config
            config_files = [f for f in proj_files if "config" in f.lower()]
            assert not any("HOST_CONFIG_SECRET" in _read_proj_file(proj_git, f) for f in config_files if not f.endswith("/")), \
                f"Host config canary found in projection files: {[f for f in config_files if not f.endswith('/')]}"

            # Cleanup
            if callable(cleanup):
                cleanup()
            elif isinstance(cleanup, list):
                for cb in cleanup:
                    cb()
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def test_red_A_superproject_submodule_config(self, temp_git_root):
        """
        RED-A (Design C supersession): .git/modules/<name>/config with credential.
        The original config file is NEVER mounted — canary structurally inaccessible.
        """
        from src.agent_tools.container_executor import (
            build_podman_run_argv,
        )

        super_path, module_git_dir = self._build_superproject_with_submodule(
            temp_git_root
        )

        # Verify credential is planted
        with open(os.path.join(module_git_dir, "config")) as f:
            cred_content = f.read()
        assert "SUBMODULE_SECRET" in cred_content, "Credential not planted in submodule config"

        # Design C: original config is NEVER mounted
        argv, _ = build_podman_run_argv(
            workspace=super_path,
            image_ref="docker.io/library/python@sha256:0feb54d0096c86df7f3050e34563e07b2c156d38d0971d3c86cb0069f6be26e0",
            container_name="test-m10-a",
            command=["echo", "hello"],
        )
        rendered = "\n".join(argv)
        assert "SUBMODULE_SECRET" not in rendered, "Submodule config canary visible in argv"

    def test_red_B_superproject_submodule_config_worktree(self, temp_git_root):
        """
        RED-B (Design C supersession): .git/modules/<name>/config.worktree with credential.
        """
        from src.agent_tools.container_executor import (
            build_podman_run_argv,
        )

        super_path, module_git_dir = self._build_superproject_with_submodule(
            temp_git_root
        )

        # Add a worktree config file to the submodule's Git dir
        module_wt_config = os.path.join(module_git_dir, "config.worktree")
        with open(module_wt_config, "w") as f:
            f.write("[core]\n\trepositoryformatversion = 0\n")
            f.write("[http]\n\textraheader = Authorization: Bearer MODULE_WORKTREE_SECRET_xyz\n")

        # Design C: original config is NEVER mounted
        argv, _ = build_podman_run_argv(
            workspace=super_path,
            image_ref="docker.io/library/python@sha256:0feb54d0096c86df7f3050e34563e07b2c156d38d0971d3c86cb0069f6be26e0",
            container_name="test-m10-b",
            command=["echo", "hello"],
        )
        rendered = "\n".join(argv)
        assert "MODULE_WORKTREE_SECRET_xyz" not in rendered, "Submodule config.worktree canary visible in argv"

    def test_red_C_nested_submodule_config(self, temp_git_root):
        """
        RED-C (Design C supersession): nested submodule config with credential.
        """
        from src.agent_tools.container_executor import (
            build_podman_run_argv,
        )

        outer_path, inner_module_git = self._build_nested_submodule(temp_git_root)

        # Verify credential is planted
        inner_config = os.path.join(inner_module_git, "config")
        with open(inner_config) as f:
            cred_content = f.read()
        assert "NESTED_SECRET" in cred_content

        argv, _ = build_podman_run_argv(
            workspace=outer_path,
            image_ref="docker.io/library/python@sha256:0feb54d0096c86df7f3050e34563e07b2c156d38d0971d3c86cb0069f6be26e0",
            container_name="test-m10-c",
            command=["echo", "hello"],
        )
        rendered = "\n".join(argv)
        assert "NESTED_SECRET" not in rendered, "Nested submodule config canary visible in argv"

    def test_red_D_stale_module_git_dir(self, temp_git_root):
        """
        RED-D (Design C supersession): stale .git/modules/<name>/config with credential.
        """
        from src.agent_tools.container_executor import (
            build_podman_run_argv,
        )

        stale_path, stale_module_git = self._build_stale_module_dir(temp_git_root)

        # Verify credential
        stale_config = os.path.join(stale_module_git, "config")
        with open(stale_config) as f:
            cred_content = f.read()
        assert "STALE_SECRET" in cred_content

        argv, _ = build_podman_run_argv(
            workspace=stale_path,
            image_ref="docker.io/library/python@sha256:0feb54d0096c86df7f3050e34563e07b2c156d38d0971d3c86cb0069f6be26e0",
            container_name="test-m10-d",
            command=["echo", "hello"],
        )
        rendered = "\n".join(argv)
        assert "STALE_SECRET" not in rendered, "Stale module config canary visible in argv"

    def test_red_E_symlink_config_in_metadata(self, temp_git_root):
        """
        RED-E: A symlink at .git/config.worktree pointing outside the metadata tree.

        Design C: The original .git is NEVER mounted. The symlink is not copied
        into the projection because only regular files (HEAD, index, refs/*,
        packed-refs, shallow, objects/*) are projected. The symlink does not appear
        in the container argv at all — structural non-exposure, not scanner-based
        denial. This is the correct secure behavior.
        """
        from src.agent_tools.container_executor import (
            build_podman_run_argv,
        )

        symlink_repo, symlink_target = self._build_symlink_config_attack(temp_git_root)

        # Verify symlink exists and points outside .git
        assert os.path.islink(symlink_target), "Symlink was not created"

        # Design C: NO ValueError — original metadata is structurally inaccessible
        argv, _ = build_podman_run_argv(
            workspace=symlink_repo,
            image_ref="docker.io/library/python@sha256:0feb54d0096c86df7f3050e34563e07b2c156d38d0971d3c86cb0069f6be26e0",
            container_name="test-m10-e",
            command=["echo", "hello"],
        )

        # Verify the symlink target (the secret file) is NOT visible in argv
        rendered = "\n".join(argv)
        assert "SYMLINK_SECRET" not in rendered, (
            "Symlink target canary visible in container argv — "
            "original config must never be mounted"
        )

    def test_red_F_linked_worktree_submodule_config(self, temp_git_root):
        """
        RED-F (Design C supersession): linked worktree with submodule config credential.
        """
        from src.agent_tools.container_executor import (
            build_podman_run_argv,
        )

        wt_path, sub_module_config = self._build_linked_worktree_with_submodule(
            temp_git_root
        )

        # Verify credential is planted
        with open(sub_module_config) as f:
            cred_content = f.read()
        assert "WORKTREE_SUBMODULE_SECRET" in cred_content

        argv, _ = build_podman_run_argv(
            workspace=wt_path,
            image_ref="docker.io/library/python@sha256:0feb54d0096c86df7f3050e34563e07b2c156d38d0971d3c86cb0069f6be26e0",
            container_name="test-m10-f",
            command=["echo", "hello"],
        )
        rendered = "\n".join(argv)
        assert "WORKTREE_SUBMODULE_SECRET" not in rendered, "Linked worktree submodule config canary visible"

    def test_red_G_ordinary_repo_stale_worktrees_dir(self, temp_git_root):
        """
        RED-G (Design C supersession): stale worktrees/<id>/config.worktree credential.
        """
        from src.agent_tools.container_executor import (
            build_podman_run_argv,
        )

        repo_path, wt_config = self._build_ordinary_repo_with_stale_worktrees_dir(
            temp_git_root
        )

        # Verify credential
        with open(wt_config) as f:
            cred_content = f.read()
        assert "STALE_WORKTREE_SECRET" in cred_content

        argv, _ = build_podman_run_argv(
            workspace=repo_path,
            image_ref="docker.io/library/python@sha256:0feb54d0096c86df7f3050e34563e07b2c156d38d0971d3c86cb0069f6be26e0",
            container_name="test-m10-g",
            command=["echo", "hello"],
        )
        rendered = "\n".join(argv)
        assert "STALE_WORKTREE_SECRET" not in rendered, "Stale worktree config canary visible"

    # -------------------------------------------------------------------------
    # GREEN (benign) — should still be allowed after fix
    # -------------------------------------------------------------------------

    def test_green_benign_configs_all_locations(self, temp_git_root):
        """
        GREEN: Benign configs in all locations must remain ALLOWED.

        main .git/config
        main .git/config.worktree
        .git/modules/benign_sub/config
        .git/modules/benign_sub/config.worktree
        .git/modules/benign_sub/modules/nested_benign/config
        .git/modules/benign_sub/modules/nested_benign/config.worktree
        .git/worktrees/benign_wt/config.worktree

        After fix: ALLOW.
        """
        from src.agent_tools.container_executor import (
            build_podman_run_argv,
        )

        benign_path = self._build_benign_all_locations(temp_git_root)

        # Must NOT raise — benign configs must remain allowed
        argv, _ = build_podman_run_argv(
            workspace=benign_path,
            image_ref="docker.io/library/python@sha256:0feb54d0096c86df7f3050e34563e07b2c156d38d0971d3c86cb0069f6be26e0",
            container_name="test-m10-green",
            command=["echo", "hello"],
        )
        assert isinstance(argv, list)
        assert len(argv) > 0

    def test_green_ordinary_worktree_config_already_covered(self, temp_git_root):
        """
        GREEN: An ordinary repo with worktreeConfig and benign config.worktree
        must remain ALLOWED.
        """
        from src.agent_tools.container_executor import (
            build_podman_run_argv,
        )

        repo_path, _ = self._build_ordinary_repo_with_worktree_config(
            temp_git_root, secret="SHOULD_NOT_BE_REJECTED_allow"
        )

        # Replace with benign content
        wt_config = os.path.join(repo_path, ".git", "config.worktree")
        with open(wt_config, "w") as f:
            f.write("[user]\n\tname = Benign\n\temail = benign@test.com\n")

        argv, _ = build_podman_run_argv(
            workspace=repo_path,
            image_ref="docker.io/library/python@sha256:0feb54d0096c86df7f3050e34563e07b2c156d38d0971d3c86cb0069f6be26e0",
            container_name="test-m10-green2",
            command=["echo", "hello"],
        )
        assert isinstance(argv, list)
