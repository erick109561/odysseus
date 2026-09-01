"""
Rootless Podman execution boundary for untrusted agent subprocesses.

Policy/authority remains outside this module. This adapter only turns an
already-authorized workspace into a tightly bounded container invocation.

Security defaults:
- exact digest-pinned image only
- network disabled
- read-only root filesystem
- zero Linux capabilities
- no-new-privileges
- bounded CPU / memory / pids
- one writable workspace mount
- .git metadata over-mounted read-only when present
- ephemeral /tmp
- no host environment forwarded into the container
- explicit container teardown on timeout/cancellation
"""

import asyncio
import atexit
import collections
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from typing import Awaitable, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit


DEFAULT_CONTAINER_IMAGE = (
    "docker.io/library/python@"
    "sha256:0feb54d0096c86df7f3050e34563e07b"
    "2c156d38d0971d3c86cb0069f6be26e0"
)

_CONTAINER_NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
)

_DIGEST_IMAGE_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$"
)

_PROGRESS_INTERVAL_S = 2.0
_PROGRESS_TAIL_LINES = 12


def container_executor_enabled() -> bool:
    return os.environ.get(
        "ODYSSEUS_CONTAINER_EXECUTOR",
        "",
    ).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def configured_container_image() -> str:
    image = os.environ.get(
        "ODYSSEUS_CONTAINER_IMAGE",
        DEFAULT_CONTAINER_IMAGE,
    ).strip()

    _validate_image_ref(image)
    return image


def _validate_image_ref(image_ref: str) -> None:
    if not isinstance(image_ref, str):
        raise ValueError("container image must be a string")

    if not _DIGEST_IMAGE_RE.fullmatch(image_ref):
        raise ValueError(
            "container image must be pinned by exact sha256 digest"
        )


def _validate_container_name(container_name: str) -> None:
    if not _CONTAINER_NAME_RE.fullmatch(
        container_name or ""
    ):
        raise ValueError("invalid container name")


def _canonical_workspace(workspace: str) -> str:
    if not workspace or not str(workspace).strip():
        raise ValueError("workspace is required")

    resolved = os.path.realpath(
        os.path.expanduser(str(workspace).strip())
    )

    if not os.path.isdir(resolved):
        raise ValueError("workspace must be an existing directory")

    if os.path.dirname(resolved) == resolved:
        raise ValueError(
            "filesystem root cannot be used as workspace"
        )

    # Podman's -v source:destination syntax is ambiguous with ':'.
    if ":" in resolved or "\n" in resolved:
        raise ValueError(
            "workspace contains unsupported mount characters"
        )

    return resolved


def _git_env() -> dict:
    """
    Host-side Git probes must not inherit caller GIT_* overrides such as
    GIT_DIR, GIT_WORK_TREE, GIT_CONFIG_COUNT or credential helpers.
    """
    env = dict(os.environ)

    for key in tuple(env):
        if key.startswith("GIT_"):
            env.pop(key, None)

    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _run_git(
    workspace: str,
    *args: str,
    allowed_rc: tuple[int, ...] = (0,),
) -> str:
    git = shutil.which("git")

    if git is None:
        raise ValueError(
            "git metadata exists but host git is unavailable"
        )

    try:
        proc = subprocess.run(
            [git, "-C", workspace, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            env=_git_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(
            "unable to verify Git workspace identity"
        ) from exc

    if proc.returncode not in allowed_rc:
        raise ValueError(
            "unable to verify Git workspace identity"
        )

    return proc.stdout.strip()


# -------------------------------------------------------------------------
# Git metadata projection helpers
# (Design C: generated safe Git view instead of raw .git mount)
# -------------------------------------------------------------------------

def _generate_safe_git_config() -> str:
    """
    Generate the content of a minimal safe Git config for the container.

    This replaces ALL original host Git config bytes. The container sees only
    this generated config via GIT_CONFIG_GLOBAL.

    Settings preserved (proven necessary for local Git capability contract):
    - core.repositoryformatversion = 0 (standard repo format)
    - core.worktree = /workspace (container workdir)
    - core.bare = false
    - safe.directory and core.hooksPath are passed via GIT_CONFIG_KEY_*
      env vars for the local config scope, not the global scope.

    Settings explicitly NOT preserved (never needed inside container):
    - remote.* (no network access)
    - credential.* (no credential helpers)
    - http.* / url.* (no network)
    - user.* (identity not needed for read-only local ops)
    - sendemail.* (no email)
    - include.* / includeIf.* (no includes)
    - submodule.* (no submodule network ops)
    - Any unknown/arbitrary keys (M11: unknown keys bypass denylists)
    """
    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tworktree = /workspace\n"
        "\tbare = false\n"
        "\tfilemode = true\n"
        "\tsymlinks = false\n"
    )


def _safe_copy_file(src: str, dst: str) -> None:
    """
    Copy a single file safely: no symlinks, no special files.
    Creates parent directories as needed.
    """
    if os.path.islink(src):
        raise ValueError(f"symlink not allowed in Git metadata: {src}")
    if not os.path.isfile(src):
        raise ValueError(f"not a regular file in Git metadata: {src}")

    dst_dir = os.path.dirname(dst)
    if dst_dir:
        os.makedirs(dst_dir, exist_ok=True)

    shutil.copy2(src, dst)


def _copy_git_refs(src_git: str, dst_git: str) -> None:
    """
    Recursively copy the refs/ directory from src_git to dst_git.

    This is the minimal set needed for:
    - git rev-parse to resolve branch names to SHAs
    - git status to show branch name
    - git diff to show changed files

    We copy the entire refs/ tree since it's small and self-contained
    (no credential surface, no config files).

    Security: Reject ANY symlink anywhere in the refs/ tree, whether it
    points to a file or directory. A symlink ref could point to an arbitrary
    host path (e.g. refs/heads/main -> /etc/passwd or refs/heads/evil -> /etc).
    """
    src_refs = os.path.join(src_git, "refs")
    dst_refs = os.path.join(dst_git, "refs")

    if not os.path.isdir(src_refs):
        return

    # Use followlinks=False to not traverse symlink directories.
    # Check both files AND directories for symlinks.
    for root, dirs, files in os.walk(src_refs, followlinks=False):
        # Sort for deterministic ordering
        dirs.sort()
        files.sort()

        rel_root = os.path.relpath(root, src_refs)
        dst_root = os.path.join(dst_refs, rel_root) if rel_root != "." else dst_refs

        # Check all directory entries for symlinks BEFORE processing
        all_entries = list(dirs) + list(files)
        for name in all_entries:
            src_path = os.path.join(root, name)
            if os.path.islink(src_path):
                raise ValueError(
                    f"symlink not allowed in refs/ tree: "
                    f"{os.path.relpath(src_path, src_refs)}"
                )

        # Process regular files
        for name in files:
            src_file = os.path.join(root, name)
            dst_file = os.path.join(dst_root, name)
            os.makedirs(dst_root, exist_ok=True)
            _safe_copy_file(src_file, dst_file)


def _copy_packed_refs(src_git: str, dst_git: str) -> None:
    """Copy packed-refs if present."""
    src_packed = os.path.join(src_git, "packed-refs")
    if os.path.isfile(src_packed):
        dst_packed = os.path.join(dst_git, "packed-refs")
        _safe_copy_file(src_packed, dst_packed)


def _copy_shallow(src_git: str, dst_git: str) -> None:
    """Copy shallow if present (indicates shallow clone)."""
    src_shallow = os.path.join(src_git, "shallow")
    if os.path.isfile(src_shallow):
        dst_shallow = os.path.join(dst_git, "shallow")
        _safe_copy_file(src_shallow, dst_shallow)


def _copy_objects(src_git: str, dst_git: str) -> None:
    """
    Copy only the loose objects reachable from the current HEAD commit.

    This preserves confidentiality of historical objects that exist in the
    full object store but are not needed for current-state Git operations.

    Git needs: commit object -> tree object -> blob objects (file content).

    We use git rev-list --encoding=none --objects to enumerate only the
    objects reachable from HEAD without traversing the full history beyond
    the current snapshot. The --objects flag outputs all object names
    (commits, trees, blobs) in the full reachability graph from HEAD.
    This is MUCH faster than walking manually and avoids copying historical
    objects that are no longer referenced.
    """
    import subprocess

    src_objects = os.path.join(src_git, "objects")
    dst_objects = os.path.join(dst_git, "objects")

    if not os.path.isdir(src_objects):
        return

    # Resolve HEAD to get the current commit SHA
    # Use --verify to ensure it's a valid commit
    try:
        head_sha = subprocess.check_output(
            ["git", "-C", src_git, "rev-parse", "--verify", "HEAD"],
            text=True, stderr=subprocess.DEVNULL, env=_git_env(),
        ).strip()
    except subprocess.CalledProcessError:
        # No HEAD (empty repo) — nothing to copy
        return

    # Enumerate only the objects in the CURRENT commit snapshot (HEAD only,
    # not its ancestors). --max-count=1 limits to the tip commit.
    # --no-walk prevents following parent commits.
    # --objects outputs all object names in the commit's tree.
    # Result: exactly HEAD commit + tree + tree-entry blobs (current snapshot only).
    try:
        reachability_output = subprocess.check_output(
            [
                "git", "-C", src_git, "rev-list",
                "--objects",
                "--max-count=1",
                "--no-walk",
                "--encoding=none",
                head_sha,
            ],
            text=True, stderr=subprocess.DEVNULL, env=_git_env(),
        )
    except subprocess.CalledProcessError:
        return

    # Parse object SHAs from rev-list output
    # Each line is either: "<sha>" or "<sha> <path>"
    needed_shas = set()
    for line in reachability_output.splitlines():
        parts = line.strip().split()
        if parts:
            sha = parts[0]
            if len(sha) >= 2:
                needed_shas.add(sha)

    # Also include the HEAD commit itself if not in rev-list output
    needed_shas.add(head_sha)

    if not needed_shas:
        return

    # Build a fast SHA prefix -> filesystem path lookup
    # Loose objects: objects/<2>/<38>
    # We build a map of which prefixes we need
    src_objects_abs = os.path.abspath(src_objects)

    for sha in needed_shas:
        prefix = sha[:2]
        rest = sha[2:]
        prefix_dir = os.path.join(src_objects_abs, prefix)
        if not os.path.isdir(prefix_dir):
            continue
        src_file = os.path.join(prefix_dir, rest)
        if not os.path.isfile(src_file) or os.path.islink(src_file):
            # Not a loose object (may be packed) — skip
            continue
        dst_file = os.path.join(dst_objects, prefix, rest)
        dst_dir = os.path.dirname(dst_file)
        if not os.path.isdir(dst_dir):
            os.makedirs(dst_dir, exist_ok=True)
        shutil.copy2(src_file, dst_file)


def _copy_head(src_git: str, dst_git: str) -> None:
    """
    Copy HEAD (can be a file or a symlink to a ref).

    For an uninitialized .git directory (no HEAD yet), creates a minimal
    HEAD pointing to refs/heads/main so that Git commands can at least
    initialize the repository.
    """
    src_head = os.path.join(src_git, "HEAD")
    dst_head = os.path.join(dst_git, "HEAD")
    os.makedirs(dst_git, exist_ok=True)

    if os.path.islink(src_head):
        # Symlink HEAD (points to e.g. refs/heads/main) — copy as-is
        # but first verify the target doesn't escape the refs/ tree
        target = os.readlink(src_head)
        if target.startswith("refs/") and "/" not in target[5:]:
            # Safe: refs/heads/main style — copy as symlink
            os.symlink(target, dst_head)
            return
        else:
            raise ValueError(f"HEAD symlink has unexpected target: {target}")

    if os.path.isfile(src_head):
        _safe_copy_file(src_head, dst_head)
    else:
        # Uninitialized .git directory — create minimal HEAD.
        # This allows 'git init' to work inside the container if needed,
        # and is safe because there are no credentials in an uninitialized repo.
        with open(dst_head, "w") as f:
            f.write("ref: refs/heads/main\n")


def _copy_index(src_git: str, dst_git: str) -> None:
    """Copy the index file (required for git status, diff, ls-files)."""
    src_index = os.path.join(src_git, "index")
    if not os.path.isfile(src_index):
        # Some repos don't have an index yet
        return
    _safe_copy_file(src_index, os.path.join(dst_git, "index"))


def _copy_gitdir_file(src_git: str, dst_git: str) -> None:
    """
    Copy the .git file content if this is a linked worktree.
    The .git file contains 'gitdir: /absolute/path/to/gitdir'.
    We copy this as-is since it defines the gitdir location for the worktree.
    """
    if not os.path.isfile(src_git):
        return
    content = open(src_git).read()
    # Write as .git file in projection
    with open(os.path.join(dst_git, "gitdir"), "w") as f:
        f.write(content.strip())


def _build_minimal_git_projection(
    workspace: str,
    git_real: str,
    git_common: Optional[str] = None,
) -> tuple[str, List[str]]:
    """
    Build a minimal Git metadata projection for the container.

    The projection contains ONLY the files/dirs proven necessary for the
    bounded local Git capability contract (git status, diff, rev-parse, ls-files):
      - HEAD (from git_real, the worktree-specific gitdir)
      - index (from git_real, the worktree-specific gitdir)
      - refs/ (from git_common if provided, else git_real)
      - packed-refs (from git_common if provided, else git_real)
      - shallow (from git_common if provided, else git_real)
      - objects/ (from git_common if provided, else git_real)

    For LINKED WORKTREES:
      - git_real = worktree-specific gitdir (contains HEAD and index)
      - git_common = common/shared Git directory (contains refs/ and objects/)
      Both are REQUIRED for linked worktrees.

    For ORDINARY REPOS:
      - git_real = .git directory (contains everything)
      - git_common = None (use git_real for all sources)

    NEVER COPIED (credential surface):
      - config (contains host credentials)
      - config.worktree (contains host credentials)
      - any file under config.* patterns
      - COMMIT_EDITMSG (not needed for read-only local ops)
      - hooks/ (not needed for read-only local ops)
      - logs/ (not needed for read-only local ops)
      - info/ (not needed)
      - modules/ (submodule metadata with credential surface)

    Returns (projection_git_dir, cleanup_callbacks).
    The caller is responsible for calling cleanup callbacks when the
    projection is no longer needed.

    For linked worktrees, also copies the .git file (gitdir pointer).

    Raises ValueError on any unsafe filesystem type encountered.
    """
    import atexit

    # For ordinary repos: git_common is None, use git_real for everything.
    # For linked worktrees: git_common is the shared directory.
    common = git_common if git_common is not None else git_real

    # Create projection dir owned by this process
    proj_root = tempfile.mkdtemp(prefix="odysseus_git_proj_")
    proj_git = os.path.join(proj_root, ".git")
    os.makedirs(proj_git)

    # Register cleanup to run when process exits
    def _cleanup_proj():
        try:
            shutil.rmtree(proj_root, ignore_errors=True)
        except Exception:
            pass

    # Keep track of temp dirs for cleanup
    _projection_temp_dirs.append(proj_root)
    atexit.register(_cleanup_proj)

    # Copy essential files for read-only Git operations.
    # HEAD and index ALWAYS come from git_real (worktree-specific gitdir).
    # refs/, packed-refs, shallow, objects/ come from common (shared git dir).
    try:
        _copy_head(git_real, proj_git)
        _copy_index(git_real, proj_git)
        _copy_git_refs(common, proj_git)
        _copy_packed_refs(common, proj_git)
        _copy_shallow(common, proj_git)
        _copy_objects(common, proj_git)
    except ValueError:
        # Logging here would be circular; surface errors will be caught
        # by the caller and reported with proper context
        raise

    return proj_git, [_cleanup_proj]


def _make_git_config_tmpfs_mount() -> Tuple[List[str], str, List[Callable]]:
    """
    Create a tmpfs mount for the generated safe Git config, along with
    the GIT_CONFIG_GLOBAL env var pointing to it.

    Returns (mount_args, global_config_path, cleanup_callbacks) where mount_args
    is a list of podman-style -v mount arguments and global_config_path is
    the path inside the container where the safe config will be mounted.

    The cleanup callbacks must be invoked by the caller when the container
    execution completes.
    """
    # Create a tmpfs-backed directory for the safe config.
    cfg_tmp = tempfile.mkdtemp(prefix="odysseus_git_cfg_")

    def _cleanup_cfg():
        try:
            shutil.rmtree(cfg_tmp, ignore_errors=True)
        except Exception:
            pass

    _projection_temp_dirs.append(cfg_tmp)
    atexit.register(_cleanup_cfg)

    cfg_file = os.path.join(cfg_tmp, "gitconfig")

    # Write the safe config atomically
    content = _generate_safe_git_config()
    with open(cfg_file, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(cfg_file, 0o644)

    mount_args = [
        "-v",
        f"{cfg_file}:/tmp/odysseus_safe_gitconfig:ro",
    ]

    return mount_args, "/tmp/odysseus_safe_gitconfig", [_cleanup_cfg]


# Track projection temp directories for cleanup
_projection_temp_dirs: list[str] = []


def _get_projection_temp_dirs() -> list[str]:
    """Return list of active projection temp directories (for testing)."""
    return list(_projection_temp_dirs)


def _clear_projection_temp_dirs() -> None:
    """Clear and clean up all tracked projection temp directories."""
    for d in _projection_temp_dirs:
        try:
            shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass
    _projection_temp_dirs.clear()


def _run_git_config_file(
    config_path: str,
    *args: str,
    allowed_rc: tuple[int, ...] = (0,),
) -> str:
    git = shutil.which("git")

    if git is None:
        raise ValueError(
            "git config exists but host git is unavailable"
        )

    try:
        proc = subprocess.run(
            [git, "config", "--file", config_path, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            env=_git_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(
            "unable to inspect Git configuration"
        ) from exc

    if proc.returncode not in allowed_rc:
        raise ValueError(
            "unable to inspect Git configuration"
        )

    return proc.stdout.strip()


def _assert_git_config_safe(config_path: str) -> None:
    """
    Git metadata is exposed read-only for development introspection, but local
    repository credentials/config indirections are not allowed to cross the
    container boundary.
    """
    if not os.path.isfile(config_path):
        return

    names = _run_git_config_file(
        config_path,
        "--name-only",
        "--list",
        allowed_rc=(0, 1),
    )

    sensitive_patterns = (
        re.compile(r"^credential\.", re.I),
        # Catch bare http.extraheader / http.proxy AND URL-prefixed forms
        # (e.g. http.https://example.com.proxy).
        # Match bare (http.proxy) and URL-prefixed (http.https://example.com.proxy)
        # forms by consuming non-dot chars before the final .extraheader/.proxy suffix.
        # Catch bare (http.proxy) and URL-prefixed (http.https://example.com.proxy) forms.
        re.compile(
            r"^http\.(?:.*\.)?(?:extraheader|proxy)$",
            re.I,
        ),
        re.compile(r"^remote\..*\.proxy$", re.I),
        re.compile(
            r"^core\.(?:sshcommand|askpass)$",
            re.I,
        ),
        re.compile(r"^include\.path$", re.I),
        re.compile(r"^includeif\..*\.path$", re.I),
        re.compile(r"^url\..*\.insteadof$", re.I),
    )

    for name in names.splitlines():
        key = name.strip()

        if any(rx.search(key) for rx in sensitive_patterns):
            raise ValueError(
                "local Git config contains credential-sensitive settings"
            )

    remotes = _run_git_config_file(
        config_path,
        "--get-regexp",
        r"^remote\..*\.url$",
        allowed_rc=(0, 1),
    )

    for line in remotes.splitlines():
        parts = line.split(None, 1)

        if len(parts) != 2:
            continue

        url = parts[1].strip()

        if "://" not in url:
            continue

        parsed = urlsplit(url)

        if (
            parsed.scheme.lower() in {"http", "https"}
            and (
                parsed.username is not None
                or parsed.password is not None
            )
        ):
            raise ValueError(
                "Git remote URL contains embedded credentials"
            )



def _validate_mount_source(path: str) -> str:
    resolved = os.path.realpath(path)

    if not resolved:
        raise ValueError("empty mount source")

    if ":" in resolved or "\n" in resolved:
        raise ValueError(
            "Git metadata path contains unsupported mount characters"
        )

    if os.path.dirname(resolved) == resolved:
        raise ValueError(
            "filesystem root cannot be mounted as Git metadata"
        )

    return resolved


def _git_metadata_mount_args(workspace: str) -> Tuple[List[str], Optional[str], Optional[List[Callable]]]:
    """
    Returns (git_mount_args, git_dir_override, cleanup_callbacks).

    Design C (SAFE GIT CONFIG PROJECTION + MINIMAL GIT METADATA PROJECTION):
    - Original host .git/config and config.worktree are NEVER mounted.
    - Instead, a minimal projection is built containing only refs, HEAD, index.
    - Git config is provided via a generated safe file via GIT_CONFIG_GLOBAL.

    Normal repository:
        projected_git_dir -> /workspace/.git:ro

    Linked worktree:
        projected_git_dir -> /var/odysseus/gitdir:ro
        (GIT_DIR env var overrides to point to the projected gitdir)

    The projected git directory is created in a temp directory. The cleanup
    callbacks must be invoked by the caller when the container execution
    completes (success, failure, timeout, or cancellation).
    """
    dotgit = os.path.join(workspace, ".git")

    if not os.path.lexists(dotgit):
        return [], None, None

    if os.path.islink(dotgit):
        raise ValueError(
            ".git symlink is not allowed in container workspace"
        )

    # Ordinary repository: .git is local to the authorized workspace.
    if os.path.isdir(dotgit):
        git_real = _validate_mount_source(dotgit)

        try:
            if os.path.commonpath(
                [git_real, workspace]
            ) != workspace:
                raise ValueError
        except ValueError as exc:
            raise ValueError(
                ".git metadata resolves outside workspace"
            ) from exc

        # Build minimal projection — contains only refs, HEAD, index, packed-refs.
        # The original config (with credentials) is NEVER copied or mounted.
        try:
            proj_git, cleanup = _build_minimal_git_projection(workspace, git_real)
        except ValueError:
            # Security/integrity violations (symlink attacks, forbidden files)
            # must propagate — not be silently converted to "no git metadata".
            # Only non-git workspaces (missing HEAD/index) get skipped.
            raise

        return [
            "-v",
            f"{proj_git}:/workspace/.git:ro",
        ], None, cleanup

    # Linked worktree: fail closed unless host Git proves identity.
    if not os.path.isfile(dotgit):
        raise ValueError(
            ".git metadata has unsupported filesystem type"
        )

    top = os.path.realpath(
        _run_git(
            workspace,
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
        )
    )

    if top != workspace:
        raise ValueError(
            "Git worktree top does not match authorized workspace"
        )

    gitdir = _validate_mount_source(
        _run_git(
            workspace,
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
        )
    )

    common = _validate_mount_source(
        _run_git(
            workspace,
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        )
    )

    if not os.path.isdir(gitdir):
        raise ValueError(
            "verified Git worktree directory is missing"
        )

    if not os.path.isdir(common):
        raise ValueError(
            "verified Git common directory is missing"
        )

    try:
        if (
            gitdir != common
            and os.path.commonpath(
                [gitdir, common]
            ) != common
        ):
            raise ValueError
    except ValueError as exc:
        raise ValueError(
            "Git worktree metadata is outside common Git directory"
        ) from exc

    listed = _run_git(
        workspace,
        "worktree",
        "list",
        "--porcelain",
    )

    members = []

    for line in listed.splitlines():
        if line.startswith("worktree "):
            members.append(
                os.path.realpath(
                    line[len("worktree "):]
                )
            )

    if workspace not in members:
        raise ValueError(
            "workspace is not a registered Git worktree"
        )

    # Build minimal projection for linked worktree.
    # For linked worktrees: refs/ and objects/ are in the common dir,
    # but HEAD and index are in the worktree-specific gitdir.
    # Pass gitdir for HEAD/index and common for refs/objects.
    # The original config files (with credentials) are NEVER copied or mounted.
    proj_git, cleanup = _build_minimal_git_projection(workspace, gitdir, common)

    # Add the gitdir pointer file so Git knows where to find the repository.
    # The content must be the ABSOLUTE path to the projected gitdir.
    os.makedirs(proj_git, exist_ok=True)
    with open(os.path.join(proj_git, "gitdir"), "w") as f:
        f.write(f"gitdir: {os.path.abspath(proj_git)}\n")

    # For linked worktrees, .git is a FILE (gitdir pointer), so we cannot
    # bind-mount a directory over it at /workspace/.git.
    # Instead, mount to an internal path and use GIT_DIR env var.
    return [
        "-v",
        f"{proj_git}:/var/odysseus/gitdir:ro",
    ], "/var/odysseus/gitdir", cleanup


def build_podman_run_argv(
    *,
    workspace: str,
    image_ref: str,
    container_name: str,
    command: Sequence[str],
) -> Tuple[list[str], List[Callable]]:
    """
    Build the exact Podman argv for one bounded execution.

    Returns (argv, cleanup_callbacks). The caller MUST invoke cleanup_callbacks
    when the container execution completes.

    This function is intentionally deterministic, which makes the security
    contract directly unit-testable.
    """

    workspace = _canonical_workspace(workspace)
    _validate_image_ref(image_ref)
    _validate_container_name(container_name)

    git_mount_args, git_dir_override, git_cleanup = _git_metadata_mount_args(workspace)
    git_cfg_mount_args, git_cfg_global_path, git_cfg_cleanup = _make_git_config_tmpfs_mount()

    # Collect all cleanup callbacks; invoke when container completes
    cleanup_callbacks: List[Callable] = []
    if git_cleanup:
        cleanup_callbacks.extend(git_cleanup)
    if git_cfg_cleanup:
        cleanup_callbacks.extend(git_cfg_cleanup)

    if (
        not isinstance(command, (list, tuple))
        or not command
        or not all(
            isinstance(item, str) and item
            for item in command
        )
    ):
        raise ValueError("command must be a non-empty argv sequence")

    argv = [
        "podman",
        "run",
        "--rm",
        "--name",
        container_name,
        "--pull=never",
        "--init",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=256m",
        "--cpus=1",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=32m",
        "--workdir=/workspace",
        "--env=HOME=/tmp",
        "--env=TMPDIR=/tmp",
        "--env=PYTHONUNBUFFERED=1",
        "--env=GIT_TERMINAL_PROMPT=0",
        "--env=GIT_CONFIG_NOSYSTEM=1",
        "--env=GIT_CONFIG_GLOBAL=" + git_cfg_global_path,
        "--env=GIT_OPTIONAL_LOCKS=0",
        "--env=GIT_CONFIG_COUNT=2",
        "--env=GIT_CONFIG_KEY_0=safe.directory",
        "--env=GIT_CONFIG_VALUE_0=/workspace",
        "--env=GIT_CONFIG_KEY_1=core.hooksPath",
        "--env=GIT_CONFIG_VALUE_1=/dev/null",
        "--env=GIT_DIR=" + (git_dir_override if git_dir_override else "/workspace/.git"),
        "--env=GIT_WORK_TREE=" + ("/workspace" if git_dir_override else "/workspace"),
        "-v",
        f"{workspace}:/workspace:rw",
    ]

    argv.extend(git_cfg_mount_args)
    argv.extend(git_mount_args)

    argv.append(image_ref)
    argv.extend(command)

    return argv, cleanup_callbacks


async def _podman_control(
    *args: str,
    timeout: float = 8.0,
) -> Tuple[str, str, int]:
    proc = await asyncio.create_subprocess_exec(
        "podman",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        out_b, err_b = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass

        try:
            await proc.wait()
        except Exception:
            pass

        return "", "podman control timeout", 124

    return (
        out_b.decode("utf-8", errors="replace"),
        err_b.decode("utf-8", errors="replace"),
        proc.returncode or 0,
    )


async def _terminate_container(
    container_name: str,
    run_proc: asyncio.subprocess.Process,
) -> None:
    # Container lifecycle is the authority boundary. Kill it first.
    await _podman_control(
        "kill",
        "--signal",
        "KILL",
        container_name,
        timeout=5,
    )

    # Reap/terminate the local Podman client as a separate concern.
    try:
        await asyncio.wait_for(
            run_proc.wait(),
            timeout=5,
        )
    except asyncio.TimeoutError:
        try:
            run_proc.kill()
        except ProcessLookupError:
            pass

        try:
            await asyncio.wait_for(
                run_proc.wait(),
                timeout=2,
            )
        except Exception:
            pass

    # Handles both --rm races and partially-created containers.
    await _podman_control(
        "rm",
        "-f",
        container_name,
        timeout=5,
    )


async def run_container_command(
    *,
    workspace: str,
    command: Sequence[str],
    timeout: float,
    progress_cb: Optional[
        Callable[[Dict], Awaitable[None]]
    ] = None,
    image_ref: Optional[str] = None,
) -> Tuple[str, str, Optional[int], bool]:
    """
    Run one command inside the bounded Podman executor.

    Returns:
        stdout, stderr, returncode, timed_out

    On timeout or asyncio cancellation, the named container is explicitly
    destroyed so descendants that call setsid()/double-fork cannot retain
    workspace authority.
    """

    if shutil.which("podman") is None:
        raise RuntimeError(
            "container executor enabled but podman is unavailable"
        )

    image = image_ref or configured_container_image()

    container_name = (
        "odysseus-agent-"
        + uuid.uuid4().hex[:24]
    )

    argv, cleanup_callbacks = build_podman_run_argv(
        workspace=workspace,
        image_ref=image,
        container_name=container_name,
        command=command,
    )

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    started = time.monotonic()
    stdout_full: list[str] = []
    stderr_full: list[str] = []
    tail = collections.deque(
        maxlen=_PROGRESS_TAIL_LINES
    )

    async def _reader(stream, full_buf, label: str):
        if stream is None:
            return

        while True:
            line = await stream.readline()

            if not line:
                break

            decoded = line.decode(
                "utf-8",
                errors="replace",
            ).rstrip("\n")

            full_buf.append(decoded)

            if label == "err":
                tail.append(f"! {decoded}")
            else:
                tail.append(decoded)

    async def _progress_emitter():
        await asyncio.sleep(_PROGRESS_INTERVAL_S)

        while True:
            if progress_cb:
                try:
                    await progress_cb({
                        "elapsed_s": round(
                            time.monotonic() - started,
                            1,
                        ),
                        "tail": "\n".join(tail),
                        "executor": "podman",
                    })
                except Exception:
                    pass

            await asyncio.sleep(
                _PROGRESS_INTERVAL_S
            )

    rd_out = asyncio.create_task(
        _reader(
            proc.stdout,
            stdout_full,
            "out",
        )
    )

    rd_err = asyncio.create_task(
        _reader(
            proc.stderr,
            stderr_full,
            "err",
        )
    )

    prog_task = (
        asyncio.create_task(_progress_emitter())
        if progress_cb
        else None
    )

    timed_out = False

    try:
        await asyncio.wait_for(
            proc.wait(),
            timeout=timeout,
        )

    except asyncio.TimeoutError:
        timed_out = True

        await _terminate_container(
            container_name,
            proc,
        )

    except asyncio.CancelledError:
        await _terminate_container(
            container_name,
            proc,
        )

        for task in (rd_out, rd_err):
            task.cancel()

        if prog_task is not None:
            prog_task.cancel()

        raise

    finally:
        if (
            prog_task is not None
            and not prog_task.done()
        ):
            prog_task.cancel()

            try:
                await prog_task
            except (
                asyncio.CancelledError,
                Exception,
            ):
                pass

        for task in (rd_out, rd_err):
            try:
                await asyncio.wait_for(
                    task,
                    timeout=2,
                )
            except asyncio.TimeoutError:
                task.cancel()
            except Exception:
                pass

        # Idempotent cleanup. Normally --rm already removed it.
        await _podman_control(
            "rm",
            "-f",
            container_name,
            timeout=5,
        )

        # Invoke all projection cleanup callbacks (temp dir cleanup).
        # This runs on success, timeout, cancellation, and error paths,
        # preventing accumulation of temp directories during long-running workers.
        for cb in cleanup_callbacks:
            try:
                cb()
            except Exception:
                pass

    return (
        "\n".join(stdout_full),
        "\n".join(stderr_full),
        proc.returncode,
        timed_out,
    )
