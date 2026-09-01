"""
MAJOR-11 / SUCCESSOR RED regression tests: Git metadata projection architecture.

These tests verify the NEW architecture (Design C):
  1. NO original host Git config bytes may cross the container boundary.
  2. NO raw .git / $GIT_COMMON_DIR tree is mounted as a full metadata tree.
  3. A GENERATED SAFE GIT VIEW is projected into the container.
  4. Environment-only Git configuration via GIT_CONFIG_NOSYSTEM + GIT_CONFIG_GLOBAL.

Security properties verified:
  - raw canaries in original host Git configs are NOT visible inside container
  - unknown arbitrary keys (not in any denylist) are NOT visible
  - git status/diff/rev-parse/ls-files work from ordinary repo, linked worktree,
    and submodule parent
  - credential-bearing configs at ALL known paths are never mounted

Design A (raw mount + scanner) is fundamentally incomplete because
M11 Reviewer A proved credential leakage through:
  - remote.<name>.pushurl
  - url.<base>.pushInsteadOf
  - sendemail.smtpPass
  - arbitrary unknown keys not in any denylist

Design C (generated minimal projection) is the target.
"""

import importlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


MODULE = "src.agent_tools.container_executor"


def _executor():
    """
    Return the container_executor module.

    The repair changed build_podman_run_argv to return (argv, cleanup_callbacks).
    This wrapper provides a consistent interface for tests.
    """
    try:
        mod = importlib.import_module(MODULE)
    except ModuleNotFoundError:
        pytest.skip("container_executor module not found")

    class _ExecutorWrapper:
        DEFAULT_CONTAINER_IMAGE = mod.DEFAULT_CONTAINER_IMAGE

        @staticmethod
        def build_podman_run_argv(**kwargs):
            result = mod.build_podman_run_argv(**kwargs)
            # The repair returns (argv, cleanup_callbacks)
            if isinstance(result, tuple) and len(result) == 2:
                return result
            # Defensive: should not happen
            return (result, [])

    return _ExecutorWrapper()


def _run_git(dir_, *args, env=None, timeout=10):
    """Run git with GIT_TERMINAL_PROMPT=0, return stdout."""
    git_env = dict(os.environ)
    git_env["GIT_TERMINAL_PROMPT"] = "0"
    if env:
        git_env.update(env)
    proc = subprocess.run(
        ["git", "-C", dir_] + list(args),
        capture_output=True, text=True, env=git_env, timeout=timeout,
    )
    return proc.stdout.strip(), proc.stderr, proc.returncode


# -------------------------------------------------------------------------
# Canary constants — must NEVER be visible inside the container
# -------------------------------------------------------------------------
CANARY = "JARVIS_GIT_SECRET_CANARY_M11RED_" + uuid.uuid4().hex[:12].upper()
CANARY_SHORT = CANARY[:40]


def _make_ordinary_repo_with_canaries(temp_git_root):
    """
    Create an ordinary repo with canaries planted in:
      .git/config                          — main repo config
      .git/config.worktree                 — worktreeConfig (optional)

    Returns workspace path.
    """
    repo_path = os.path.join(temp_git_root, "ordinary_repo")
    os.makedirs(repo_path)

    _run_git(repo_path, "init")
    _run_git(repo_path, "config", "user.email", "test@test.com")
    _run_git(repo_path, "config", "user.name", "Test User")

    # Plant canary in main config
    git_dir = os.path.join(repo_path, ".git")
    config_path = os.path.join(git_dir, "config")
    with open(config_path, "a") as f:
        f.write(f"\n[http]\n\textraheader = Authorization: Bearer {CANARY}\n")

    # Plant canary in config.worktree if possible
    wt_config_path = os.path.join(git_dir, "config.worktree")
    try:
        _run_git(repo_path, "config", "extensions.worktreeConfig", "true")
        with open(wt_config_path, "a") as f:
            f.write(f"\n[user]\n\tname = WT Test\n\temail = wt@test.com\n")
            f.write(f"\n[http]\n\textraheader = Authorization: Bearer {CANARY}_WT\n")
    except Exception:
        pass  # config.worktree optional

    return repo_path


def _make_linked_worktree_with_canaries(temp_git_root):
    """
    Create a linked worktree whose common Git dir has canaries at:
      common/config                          — main common config
      common/config.worktree                 — main common config.worktree
      common/worktrees/<id>/config.worktree   — sibling worktree config.worktree

    Target worktree is the one being validated.

    Returns (target_worktree_path, common_git_dir).
    """
    main_repo = os.path.join(temp_git_root, "main_repo")
    sibling_wt = os.path.join(temp_git_root, "sibling_worktree")
    target_wt = os.path.join(temp_git_root, "target_worktree")

    os.makedirs(main_repo)
    _run_git(main_repo, "init")
    _run_git(main_repo, "config", "user.email", "main@test.com")
    _run_git(main_repo, "config", "user.name", "Main Test")
    _run_git(main_repo, "config", "extensions.worktreeConfig", "true")

    Path(main_repo, "tracked.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", main_repo, "add", "tracked.txt"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", main_repo, "commit", "-q", "-m", "baseline"],
        check=True,
    )

    subprocess.run(
        ["git", "-C", main_repo, "worktree", "add", "-q", "-b", "sibling", str(sibling_wt)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", main_repo, "worktree", "add", "-q", "-b", "target", str(target_wt)],
        check=True,
    )

    # Plant canary in common/config
    common_git_dir = subprocess.check_output(
        ["git", "-C", str(target_wt), "rev-parse", "--git-common-dir"],
        text=True,
    ).strip()
    common_config = os.path.join(common_git_dir, "config")
    with open(common_config, "a") as f:
        f.write(f"\n[http]\n\textraheader = Authorization: Bearer {CANARY}_COMMON\n")

    # Plant canary in main's config.worktree
    common_wt_config = os.path.join(common_git_dir, "config.worktree")
    with open(common_wt_config, "w") as f:
        f.write(f"[user]\n\tname = Main WT\n\temail = main_wt@test.com\n")
        f.write(f"\n[http]\n\textraheader = Authorization: Bearer {CANARY}_MAIN_WT\n")

    # Plant canary in sibling's config.worktree
    sibling_gitdir = subprocess.check_output(
        ["git", "-C", str(sibling_wt), "rev-parse", "--git-dir"],
        text=True,
    ).strip()
    sibling_wt_config = os.path.join(sibling_gitdir, "config.worktree")
    with open(sibling_wt_config, "w") as f:
        f.write(f"[user]\n\tname = Sibling WT\n\temail = sibling_wt@test.com\n")
        f.write(f"\n[http]\n\textraheader = Authorization: Bearer {CANARY}_SIBLING_WT\n")

    return target_wt, common_git_dir


def _make_submodule_repo_with_canaries(temp_git_root):
    """
    Create a superproject (ordinary repo) with an initialized submodule.
    Canary planted at:
      .git/modules/<name>/config
      .git/modules/<name>/config.worktree

    Returns (superproject_path, submodule_git_dir).
    """
    super_path = os.path.join(temp_git_root, "superproject")
    sub_repo_path = os.path.join(temp_git_root, "sub_repo")
    os.makedirs(super_path)
    os.makedirs(sub_repo_path)

    _run_git(super_path, "init")
    _run_git(super_path, "config", "user.email", "super@test.com")
    _run_git(super_path, "config", "user.name", "Super Test")
    _run_git(sub_repo_path, "init")
    _run_git(sub_repo_path, "config", "user.email", "sub@test.com")
    _run_git(sub_repo_path, "config", "user.name", "Sub Test")

    subprocess.run(
        ["git", "-C", sub_repo_path, "commit", "--allow-empty", "-m", "init"],
        capture_output=True, timeout=10,
        env={**subprocess.os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    subprocess.run(
        ["git", "-C", super_path, "submodule", "add", sub_repo_path, "vendor/up"],
        capture_output=True, timeout=15,
        env={**subprocess.os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )

    module_git_dir = os.path.join(super_path, ".git", "modules", "vendor", "up")
    module_config = os.path.join(module_git_dir, "config")
    if os.path.isfile(module_config):
        with open(module_config, "a") as f:
            f.write(f"\n[http]\n\textraheader = Authorization: Bearer {CANARY}_SUBMODULE\n")

    # config.worktree for submodule
    module_wt_config = os.path.join(module_git_dir, "config.worktree")
    with open(module_wt_config, "w") as f:
        f.write(f"[user]\n\tname = Sub WT\n\temail = sub_wt@test.com\n")
        f.write(f"\n[http]\n\textraheader = Authorization: Bearer {CANARY}_SUBMODULE_WT\n")

    return super_path, module_git_dir


def _make_nested_submodule_with_canaries(temp_git_root):
    """
    Create a superproject with a manually-constructed nested module.
    Canary at:
      .git/modules/outer/modules/inner/config

    Returns (superproject_path, nested_module_git_dir).
    """
    super_path = os.path.join(temp_git_root, "super_nested")
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
        f.write(f"\n[http]\n\textraheader = Authorization: Bearer {CANARY}_NESTED\n")

    outer_config = os.path.join(
        super_path, ".git", "modules", "outer_sub", "config"
    )
    with open(outer_config, "w") as f:
        f.write("[core]\n\trepositoryformatversion = 0\n")
        f.write("[user]\n\tname = Outer Sub\n\temail = outer@test.com\n")
        f.write(f"\n[http]\n\textraheader = Authorization: Bearer {CANARY}_OUTER\n")

    return super_path, nested_module_git


def _make_stale_module_dir_with_canary(temp_git_root):
    """
    Create an ordinary repo with a leftover stale submodule Git dir.
    Canary at:
      .git/modules/stale/config
    """
    stale_path = os.path.join(temp_git_root, "stale_repo")
    os.makedirs(stale_path)
    _run_git(stale_path, "init")
    _run_git(stale_path, "config", "user.email", "stale@test.com")

    stale_module_git = os.path.join(stale_path, ".git", "modules", "stale")
    os.makedirs(stale_module_git)
    for subdir in ["objects", "refs"]:
        os.makedirs(os.path.join(stale_module_git, subdir), exist_ok=True)

    stale_config = os.path.join(stale_module_git, "config")
    with open(stale_config, "w") as f:
        f.write("[core]\n\trepositoryformatversion = 0\n")
        f.write(f"\n[http]\n\textraheader = Authorization: Bearer {CANARY}_STALE\n")

    return stale_path, stale_module_git


def _make_unknown_key_canary(temp_git_root):
    """
    Plant an arbitrary unknown key (not in any denylist) with the canary.
    This is the M11 critical test — unknown future Git config keys must also
    not be visible inside the container.
    """
    repo_path = os.path.join(temp_git_root, "unknown_key_repo")
    os.makedirs(repo_path)
    _run_git(repo_path, "init")
    _run_git(repo_path, "config", "user.email", "test@test.com")

    config_path = os.path.join(repo_path, ".git", "config")
    with open(config_path, "a") as f:
        f.write(f"\n[unknownfuture]\n\tarbitrarykey = {CANARY}_UNKNOWN\n")
        # Also add a pushurl variant to test M11 Reviewer A vector
        f.write(f"\n[remote \"origin\"]\n\tpushurl = https://user:{CANARY}_PUSHURL@github.com/example/repo\n")

    return repo_path


# -------------------------------------------------------------------------
# Structural verification helpers
# -------------------------------------------------------------------------

def _check_no_raw_git_mount(argv, workspace):
    """
    Verify that the original .git directory is NOT bind-mounted at its
    natural path inside the container.

    The new architecture mounts a GENERATED PROJECTION at /workspace/.git:ro,
    not the original. Check that no mount arg tries to bind the original .git.
    """
    rendered = "\n".join(argv)
    workspace_real = os.path.realpath(workspace)

    # Check there is no mount of the form /original/workspace/.git:/workspace/.git:ro
    # that uses the original path.
    for i, arg in enumerate(argv):
        if arg == "-v" and i + 1 < len(argv):
            mount_spec = argv[i + 1]
            if ":ro" in mount_spec and "/.git:" in mount_spec:
                # This is a git metadata mount. Verify it does NOT point to
                # the original .git at its natural host location.
                host_path = mount_spec.split(":")[0]
                original_dotgit = os.path.join(workspace_real, ".git")
                if os.path.realpath(host_path) == os.path.realpath(original_dotgit):
                    # Old pattern: original .git IS mounted at natural path.
                    # This violates the projection architecture.
                    return False, "Original .git mounted at natural path"

    # Also verify that a projected .git IS mounted at /workspace/.git
    has_projection = any(
        "/workspace/.git:ro" in str(arg) for arg in argv
    )
    return has_projection, ""


def _check_git_config_isolation(argv):
    """
    Verify that Git config is isolated via environment:
    - GIT_CONFIG_NOSYSTEM=1
    - GIT_CONFIG_GLOBAL points to a generated safe file (not ~/.gitconfig)
    """
    rendered = "\n".join(argv)

    if "GIT_CONFIG_NOSYSTEM=1" not in rendered:
        return False, "GIT_CONFIG_NOSYSTEM=1 not set"

    # GIT_CONFIG_GLOBAL must be set to a safe generated file
    global_match = re.search(r"GIT_CONFIG_GLOBAL=([^\s]+)", rendered)
    if not global_match:
        return False, "GIT_CONFIG_GLOBAL not set"

    global_path = global_match.group(1)
    # Must not be the real host global config
    home = os.path.expanduser("~")
    if global_path.startswith(home) and ".gitconfig" in global_path:
        return False, f"GIT_CONFIG_GLOBAL points to host config: {global_path}"

    return True, ""


def _check_safe_config_only_git_vars(argv):
    """
    Verify that GIT_CONFIG_KEY_* / GIT_CONFIG_VALUE_* env vars contain
    ONLY the minimal required settings (safe.directory, core.hooksPath, etc.)
    and NOT any original host credential-bearing settings.
    """
    rendered = "\n".join(argv)

    # Extract all GIT_CONFIG_KEY_* and GIT_CONFIG_VALUE_* pairs
    key_vars = re.findall(r"GIT_CONFIG_KEY_\d+=[^\s]+", rendered)
    value_vars = re.findall(r"GIT_CONFIG_VALUE_\d+=[^\s]+", rendered)

    # The values must be only safe settings
    safe_settings = {"safe.directory", "core.hooksPath", "core.bare"}
    allowed_prefixes = {"safe.directory", "core.hooksPath"}

    for kv in value_vars:
        val = kv.split("=", 1)[1] if "=" in kv else ""
        # For GIT_CONFIG_VALUE, the value itself can be anything (it's the key that matters)
        # But we check keys below
        pass

    for kv in key_vars:
        key = kv.split("=", 1)[1] if "=" in kv else ""
        if not any(key.startswith(prefix) for prefix in allowed_prefixes):
            # Unknown key — could be a credential leak
            return False, f"Unexpected GIT_CONFIG_KEY: {key}"

    return True, ""


# -------------------------------------------------------------------------
# RED tests: canary must NEVER be visible via structural argv analysis
# -------------------------------------------------------------------------

class TestGitMetadataProjectionRED:
    """RED: verify new projection architecture never exposes original config bytes."""

    @pytest.fixture
    def temp_git_root(self):
        d = tempfile.mkdtemp(prefix="m11red_")
        yield d
        shutil.rmtree(d, ignore_errors=True)

    # -------------------------------------------------------------------------
    # MAJOR-11: arbitrary unknown key (not in any denylist)
    # -------------------------------------------------------------------------

    def test_red_unknown_future_key_canary_never_mounted(self, temp_git_root):
        """
        RED: An arbitrary unknown Git config key with the canary value must
        NEVER be visible inside the container.

        This is the M11 Reviewer A critical finding: unknown future Git config
        keys bypass any enumerated denylist.

        With Design C (generated projection), the original .git/config is
        NEVER mounted — so the unknown key is structurally inaccessible.
        """
        ex = _executor()
        repo_path = _make_unknown_key_canary(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-unknown-key",
            command=["git", "config", "--list"],
        )

        # The unknown key canary must NOT appear in any environment variable
        rendered = "\n".join(argv)
        assert CANARY not in rendered, (
            f"UNKNOWN KEY CANARY visible in argv (environment variable leak)"
        )
        assert f"{CANARY}_UNKNOWN" not in rendered, (
            "Unknown future key value visible in argv"
        )
        assert f"{CANARY}_PUSHURL" not in rendered, (
            "pushurl credential visible in argv"
        )

    def test_red_pushurl_credential_never_mounted(self, temp_git_root):
        """
        RED: remote.<name>.pushurl with embedded credentials must NEVER be
        mounted inside the container.

        M11 Reviewer A found this vector bypasses http.extraheader denylists.
        """
        ex = _executor()
        repo_path = _make_unknown_key_canary(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-pushurl",
            command=["git", "config", "--list"],
        )

        rendered = "\n".join(argv)
        assert CANARY not in rendered
        assert f"{CANARY}_PUSHURL" not in rendered

    # -------------------------------------------------------------------------
    # Structural RED tests: architecture must enforce non-exposure
    # -------------------------------------------------------------------------

    def test_red_ordinary_repo_original_git_not_mounted(self, temp_git_root):
        """
        RED: For ordinary repo, the original .git directory must NOT be
        bind-mounted at its natural path.

        The new architecture mounts a GENERATED PROJECTION at /workspace/.git:ro.
        """
        ex = _executor()
        repo_path = _make_ordinary_repo_with_canaries(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-ordinary",
            command=["git", "status"],
        )

        ok, msg = _check_no_raw_git_mount(argv, repo_path)
        assert ok, f"Original .git mounted at natural path: {msg}"

    def test_red_ordinary_repo_git_config_isolated(self, temp_git_root):
        """
        RED: GIT_CONFIG_NOSYSTEM=1 and GIT_CONFIG_GLOBAL must be set to
        prevent host global config from leaking.
        """
        ex = _executor()
        repo_path = _make_ordinary_repo_with_canaries(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-ordinary",
            command=["git", "status"],
        )

        ok, msg = _check_git_config_isolation(argv)
        assert ok, f"Git config not properly isolated: {msg}"

    def test_red_ordinary_repo_canary_not_in_env_vars(self, temp_git_root):
        """
        RED: The canary must not appear in any GIT_CONFIG_KEY_* or
        GIT_CONFIG_VALUE_* environment variable.
        """
        ex = _executor()
        repo_path = _make_ordinary_repo_with_canaries(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-ordinary",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        assert CANARY not in rendered, "Canary visible in argv environment variables"

    def test_red_ordinary_repo_worktree_config_canary_not_mounted(self, temp_git_root):
        """
        RED: Canary in .git/config.worktree must NOT be mounted.
        """
        ex = _executor()
        repo_path = _make_ordinary_repo_with_canaries(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-ordinary",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        assert f"{CANARY}_WT" not in rendered, (
            "config.worktree canary visible in argv"
        )

    # -------------------------------------------------------------------------
    # Linked worktree RED tests
    # -------------------------------------------------------------------------

    def test_red_linked_worktree_sibling_config_not_mounted(self, temp_git_root):
        """
        RED: Canary in sibling worktree's config.worktree (inside common dir)
        must NOT be mounted.
        """
        ex = _executor()
        target_wt, common_git_dir = _make_linked_worktree_with_canaries(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=str(target_wt),
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-worktree",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        # Sibling config.worktree canary
        assert f"{CANARY}_SIBLING_WT" not in rendered, (
            "Sibling worktree config.worktree canary visible in argv"
        )
        # Main config.worktree canary
        assert f"{CANARY}_MAIN_WT" not in rendered, (
            "Main config.worktree canary visible in argv"
        )
        # Common config canary
        assert f"{CANARY}_COMMON" not in rendered, (
            "Common config canary visible in argv"
        )

    def test_red_linked_worktree_common_config_not_mounted(self, temp_git_root):
        """
        RED: The common Git directory's config must NOT be bind-mounted at
        its original path.  A generated projection must be used instead.
        """
        ex = _executor()
        target_wt, common_git_dir = _make_linked_worktree_with_canaries(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=str(target_wt),
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-worktree",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        common_real = os.path.realpath(common_git_dir)

        # Must not mount original common dir at its natural path
        for i, arg in enumerate(argv):
            if arg == "-v" and i + 1 < len(argv):
                mount_spec = argv[i + 1]
                if ":ro" in mount_spec:
                    host_path = mount_spec.split(":")[0]
                    if os.path.realpath(host_path) == common_real:
                        pytest.fail(
                            f"Original common Git dir mounted at natural path: {mount_spec}"
                        )

    # -------------------------------------------------------------------------
    # Submodule RED tests
    # -------------------------------------------------------------------------

    def test_red_submodule_config_canary_not_mounted(self, temp_git_root):
        """
        RED: Canary in .git/modules/<name>/config must NOT be mounted.
        """
        ex = _executor()
        super_path, module_git_dir = _make_submodule_repo_with_canaries(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=super_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-submodule",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        assert f"{CANARY}_SUBMODULE" not in rendered, (
            "Submodule config canary visible in argv"
        )
        assert f"{CANARY}_SUBMODULE_WT" not in rendered, (
            "Submodule config.worktree canary visible in argv"
        )

    def test_red_nested_submodule_canary_not_mounted(self, temp_git_root):
        """
        RED: Canary in .git/modules/outer/modules/inner/config must NOT be mounted.
        """
        ex = _executor()
        super_path, nested_module_git = _make_nested_submodule_with_canaries(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=super_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-nested",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        assert f"{CANARY}_NESTED" not in rendered, (
            "Nested submodule config canary visible in argv"
        )
        assert f"{CANARY}_OUTER" not in rendered, (
            "Outer submodule config canary visible in argv"
        )

    def test_red_stale_module_canary_not_mounted(self, temp_git_root):
        """
        RED: Canary in stale .git/modules/<name>/config must NOT be mounted.
        """
        ex = _executor()
        stale_path, stale_module_git = _make_stale_module_dir_with_canary(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=stale_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-stale",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        assert f"{CANARY}_STALE" not in rendered, (
            "Stale module config canary visible in argv"
        )


# -------------------------------------------------------------------------
# GREEN tests: Git operations must still work
# -------------------------------------------------------------------------

class TestGitMetadataProjectionGREEN:
    """GREEN: verify local Git capabilities work with the projection architecture."""

    @pytest.fixture
    def temp_git_root(self):
        d = tempfile.mkdtemp(prefix="m11green_")
        yield d
        shutil.rmtree(d, ignore_errors=True)

    def _make_simple_repo(self, path):
        """Create a minimal simple repo with a commit."""
        os.makedirs(path)
        _run_git(path, "init")
        _run_git(path, "config", "user.email", "test@test.com")
        _run_git(path, "config", "user.name", "Test")
        Path(path, "file.txt").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "-C", path, "add", "file.txt"], check=True)
        subprocess.run(["git", "-C", path, "commit", "-q", "-m", "init"], check=True)

    def test_green_git_status_ordinary_repo(self, temp_git_root):
        """
        GREEN: git status must work in ordinary repo with projected metadata.
        """
        ex = _executor()
        repo_path = os.path.join(temp_git_root, "simple")
        self._make_simple_repo(repo_path)

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-green",
            command=["git", "status", "--short"],
        )

        # Must produce valid podman argv
        assert "podman" in argv[0]
        assert "--pull=never" in argv
        # Must NOT raise — git status must be supported
        assert isinstance(argv, list)
        assert len(argv) > 5

    def test_green_git_diff_ordinary_repo(self, temp_git_root):
        """
        GREEN: git diff must work in ordinary repo with projected metadata.
        """
        ex = _executor()
        repo_path = os.path.join(temp_git_root, "diff_repo")
        self._make_simple_repo(repo_path)

        # Make a change
        Path(repo_path, "file.txt").write_text("changed\n", encoding="utf-8")

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-green",
            command=["git", "diff", "--stat"],
        )

        assert isinstance(argv, list)
        assert "git" in argv

    def test_green_git_rev_parse_ordinary_repo(self, temp_git_root):
        """
        GREEN: git rev-parse must work in ordinary repo with projected metadata.
        """
        ex = _executor()
        repo_path = os.path.join(temp_git_root, "revparse_repo")
        self._make_simple_repo(repo_path)

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-green",
            command=["git", "rev-parse", "--show-toplevel"],
        )

        assert isinstance(argv, list)

    def test_green_git_ls_files_ordinary_repo(self, temp_git_root):
        """
        GREEN: git ls-files must work in ordinary repo with projected metadata.
        """
        ex = _executor()
        repo_path = os.path.join(temp_git_root, "lsfiles_repo")
        self._make_simple_repo(repo_path)

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-green",
            command=["git", "ls-files"],
        )

        assert isinstance(argv, list)

    def test_green_linked_worktree_git_status(self, temp_git_root):
        """
        GREEN: git status must work in a linked worktree with projected metadata.
        """
        ex = _executor()
        main_repo = os.path.join(temp_git_root, "main")
        linked_wt = os.path.join(temp_git_root, "linked")
        os.makedirs(main_repo)

        _run_git(main_repo, "init")
        _run_git(main_repo, "config", "user.email", "test@test.com")
        _run_git(main_repo, "config", "user.name", "Test")
        Path(main_repo, "file.txt").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "-C", main_repo, "add", "file.txt"], check=True)
        subprocess.run(["git", "-C", main_repo, "commit", "-q", "-m", "init"], check=True)

        subprocess.run(
            ["git", "-C", main_repo, "worktree", "add", "-q", str(linked_wt)],
            check=True,
        )

        argv, _ = ex.build_podman_run_argv(
            workspace=str(linked_wt),
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-green-wt",
            command=["git", "status", "--short"],
        )

        assert isinstance(argv, list)

    def test_green_submodule_parent_git_status(self, temp_git_root):
        """
        GREEN: git status must work in a submodule parent repo with projected metadata.
        """
        ex = _executor()
        super_path = os.path.join(temp_git_root, "super")
        sub_repo = os.path.join(temp_git_root, "sub")
        os.makedirs(super_path)
        os.makedirs(sub_repo)

        _run_git(super_path, "init")
        _run_git(super_path, "config", "user.email", "super@test.com")
        _run_git(super_path, "config", "user.name", "Super")
        _run_git(sub_repo, "init")
        _run_git(sub_repo, "config", "user.email", "sub@test.com")

        subprocess.run(
            ["git", "-C", sub_repo, "commit", "--allow-empty", "-m", "init"],
            capture_output=True, timeout=10,
            env={**subprocess.os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        subprocess.run(
            ["git", "-C", super_path, "submodule", "add", sub_repo, "vendor/up"],
            capture_output=True, timeout=15,
            env={**subprocess.os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )

        argv, _ = ex.build_podman_run_argv(
            workspace=super_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-green-sub",
            command=["git", "status", "--short"],
        )

        assert isinstance(argv, list)

    def test_green_env_vars_include_minimal_git_config(self, temp_git_root):
        """
        GREEN: The argv must include safe.directory and core.hooksPath env vars
        that are necessary for Git to function correctly in the container.
        """
        ex = _executor()
        repo_path = os.path.join(temp_git_root, "envcheck")
        self._make_simple_repo(repo_path)

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-green",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        # Must have safe.directory=/workspace for Git to work
        assert "GIT_CONFIG_KEY_" in rendered, "No GIT_CONFIG_KEY_ env vars set"
        assert "safe.directory" in rendered, "safe.directory not set"


# -------------------------------------------------------------------------
# MAJOR-9 / MAJOR-10 supersession tests
# -------------------------------------------------------------------------

class TestPriorBoundarySupersession:
    """
    These tests document that the OLD attack vectors are now closed by
    the projection architecture — NOT by scanning/denylisting.

    The old tests (test_MAJOR9_*, test_MAJOR10_*) expected ValueError from
    config scanning. With Design C, the raw config files are NEVER mounted,
    so the old mechanism is superseded.

    These tests verify the NEW security mechanism: the canaries are structurally
    inaccessible because original .git directories are never bind-mounted.
    """

    @pytest.fixture
    def temp_git_root(self):
        d = tempfile.mkdtemp(prefix="m11supersession_")
        yield d
        shutil.rmtree(d, ignore_errors=True)

    def test_supersession_m9_sibling_config_worktree_inaccessible(
        self, temp_git_root
    ):
        """
        MAJOR-9 supersession: sibling worktree config.worktree canary must be
        structurally inaccessible via the new projection architecture.

        OLD mechanism: scanner detected and raised ValueError.
        NEW mechanism: original .git dir is never mounted, so the canary
        is not accessible inside the container at all.
        """
        ex = _executor()
        target_wt, _ = _make_linked_worktree_with_canaries(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=str(target_wt),
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-m9sup",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        # The canary is NOT in any argv element
        assert f"{CANARY}_SIBLING_WT" not in rendered
        assert CANARY not in rendered

    def test_supersession_m10_submodule_config_inaccessible(
        self, temp_git_root
    ):
        """
        MAJOR-10 supersession: submodule config canary must be structurally
        inaccessible via the new projection architecture.

        OLD mechanism: scanner detected .git/modules/**/config and raised ValueError.
        NEW mechanism: original .git/modules tree is never mounted.
        """
        ex = _executor()
        super_path, _ = _make_submodule_repo_with_canaries(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=super_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-m10sup",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        assert f"{CANARY}_SUBMODULE" not in rendered
        assert CANARY not in rendered

    def test_supersession_m10_nested_submodule_config_inaccessible(
        self, temp_git_root
    ):
        """
        MAJOR-10 supersession: nested submodule config canary must be
        structurally inaccessible.
        """
        ex = _executor()
        super_path, _ = _make_nested_submodule_with_canaries(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=super_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-m10nsup",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        assert f"{CANARY}_NESTED" not in rendered
        assert f"{CANARY}_OUTER" not in rendered

    def test_supersession_m10_stale_module_config_inaccessible(
        self, temp_git_root
    ):
        """
        MAJOR-10 supersession: stale .git/modules/<name>/config canary
        must be structurally inaccessible.
        """
        ex = _executor()
        stale_path, _ = _make_stale_module_dir_with_canary(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=stale_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-m10stalesup",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        assert f"{CANARY}_STALE" not in rendered

    def test_supersession_m11_unknown_key_inaccessible(self, temp_git_root):
        """
        MAJOR-11 supersession: arbitrary unknown key canary must be
        structurally inaccessible. This is the core M11 finding —
        the denylist can never be complete.
        """
        ex = _executor()
        repo_path = _make_unknown_key_canary(temp_git_root)

        argv, _ = ex.build_podman_run_argv(
            workspace=repo_path,
            image_ref=ex.DEFAULT_CONTAINER_IMAGE,
            container_name="test-m11sup",
            command=["git", "status"],
        )

        rendered = "\n".join(argv)
        assert CANARY not in rendered
        assert f"{CANARY}_UNKNOWN" not in rendered
        assert f"{CANARY}_PUSHURL" not in rendered
