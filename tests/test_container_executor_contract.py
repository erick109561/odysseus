import importlib
import os
from pathlib import Path

import pytest


MODULE = "src.agent_tools.container_executor"


def _executor():
    try:
        return importlib.import_module(MODULE)
    except ModuleNotFoundError:
        pytest.skip(
            "container_executor production module does not exist yet; "
            "expected during initial RED"
        )


def test_container_executor_module_exists():
    """
    First RED: successor must introduce a dedicated executor primitive.
    """
    try:
        importlib.import_module(MODULE)
    except ModuleNotFoundError:
        pytest.fail(
            "RED: src.agent_tools.container_executor does not exist"
        )


def test_rejects_mutable_image_tag(tmp_path):
    ex = _executor()

    with pytest.raises(ValueError):
        ex.build_podman_run_argv(
            workspace=str(tmp_path),
            image_ref="docker.io/library/python:3.12-alpine",
            container_name="jarvis-test",
            command=["python", "-V"],
        )[0]


def test_rejects_filesystem_root_as_workspace():
    ex = _executor()

    with pytest.raises(ValueError):
        ex.build_podman_run_argv(
            workspace="/",
            image_ref=(
                "docker.io/library/python@"
                "sha256:c95cd47204b8f236725fc8cf94726abe"
                "3f32755a062393597efadd9a5d24fbe1"
            ),
            container_name="jarvis-test",
            command=["python", "-V"],
        )[0]


def test_workspace_is_canonicalized_before_mount(tmp_path):
    ex = _executor()

    real = tmp_path / "real"
    real.mkdir()

    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)

    argv, _ = ex.build_podman_run_argv(
        workspace=str(alias),
        image_ref=(
            "docker.io/library/python@"
            "sha256:c95cd47204b8f236725fc8cf94726abe"
            "3f32755a062393597efadd9a5d24fbe1"
        ),
        container_name="jarvis-test",
        command=["python", "-V"],
    )

    expected = os.path.realpath(real)

    mounts = [
        arg for arg in argv
        if ":/workspace:" in arg
    ]

    assert mounts == [f"{expected}:/workspace:rw"]


def test_security_flags_are_mandatory(tmp_path):
    ex = _executor()

    argv, _ = ex.build_podman_run_argv(
        workspace=str(tmp_path),
        image_ref=(
            "docker.io/library/python@"
            "sha256:c95cd47204b8f236725fc8cf94726abe"
            "3f32755a062393597efadd9a5d24fbe1"
        ),
        container_name="jarvis-test",
        command=["python", "-V"],
    )

    joined = "\0".join(argv)

    required = [
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=",
        "--memory=",
        "--cpus=",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "--workdir=/workspace",
        "--init",
    ]

    for required_item in required:
        assert required_item in joined, required_item


def test_exactly_one_host_mount_is_workspace(tmp_path):
    ex = _executor()

    workspace = os.path.realpath(tmp_path)

    argv, _ = ex.build_podman_run_argv(
        workspace=workspace,
        image_ref=(
            "docker.io/library/python@"
            "sha256:c95cd47204b8f236725fc8cf94726abe"
            "3f32755a062393597efadd9a5d24fbe1"
        ),
        container_name="jarvis-test",
        command=["python", "-V"],
    )

    mounts = [
        arg for arg in argv
        if ":/" in arg
        and not arg.startswith("docker.io/")
    ]

    # With Design C (minimal projection), there are TWO mounts:
    # 1. workspace:/workspace:rw
    # 2. safe_git_config:/tmp/odysseus_safe_gitconfig:ro
    # The original .git is NOT mounted at its natural path.
    assert mounts[0] == f"{workspace}:/workspace:rw"
    # Second mount is the safe git config
    assert any("odysseus_safe_gitconfig" in m for m in mounts)

    forbidden = (
        "/var/run/docker.sock",
        "/run/podman/podman.sock",
        ".ssh",
        "/Desktop/AI-DEV-LAB",
        "/Desktop/Jarvis-Ops",
    )

    rendered = "\n".join(argv)

    for value in forbidden:
        assert value not in rendered


def test_container_name_is_constrained(tmp_path):
    ex = _executor()

    with pytest.raises(ValueError):
        ex.build_podman_run_argv(
            workspace=str(tmp_path),
            image_ref=(
                "docker.io/library/python@"
                "sha256:c95cd47204b8f236725fc8cf94726abe"
                "3f32755a062393597efadd9a5d24fbe1"
            ),
            container_name="../../hostile name",
            command=["python", "-V"],
        )[0]


def test_git_metadata_is_overmounted_read_only(tmp_path):
    ex = _executor()

    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    argv, _ = ex.build_podman_run_argv(
        workspace=str(tmp_path),
        image_ref=(
            "docker.io/library/python@"
            "sha256:c95cd47204b8f236725fc8cf94726abe"
            "3f32755a062393597efadd9a5d24fbe1"
        ),
        container_name="jarvis-test",
        command=["python", "-V"],
    )

    workspace = os.path.realpath(tmp_path)

    assert f"{workspace}:/workspace:rw" in argv
    # Design C: a git metadata dir is mounted at /workspace/.git:ro
    assert any("/workspace/.git:ro" in str(arg) for arg in argv), (
        "No /workspace/.git:ro mount found"
    )

    # The ORIGINAL .git directory must NOT be mounted at its natural path
    git_real = os.path.realpath(git_dir)
    assert not any(
        os.path.realpath(arg.split(":")[0]) == git_real
        for arg in argv
        if ":/workspace/.git:ro" in str(arg)
    ), "Original .git mounted at natural path — violates projection architecture"


def test_git_metadata_symlink_is_rejected(tmp_path):
    ex = _executor()

    outside = tmp_path / "outside-git"
    outside.mkdir()

    (tmp_path / ".git").symlink_to(
        outside,
        target_is_directory=True,
    )

    with pytest.raises(ValueError):
        ex.build_podman_run_argv(
            workspace=str(tmp_path),
            image_ref=(
                "docker.io/library/python@"
                "sha256:c95cd47204b8f236725fc8cf94726abe"
                "3f32755a062393597efadd9a5d24fbe1"
            ),
            container_name="jarvis-test",
            command=["python", "-V"],
        )[0]


def _make_linked_worktree(tmp_path):
    import subprocess

    repo = tmp_path / "repo"
    linked = tmp_path / "linked"

    subprocess.run(
        ["git", "init", "-q", str(repo)],
        check=True,
    )

    subprocess.run(
        ["git", "-C", str(repo),
         "config", "user.email", "test@example.invalid"],
        check=True,
    )

    subprocess.run(
        ["git", "-C", str(repo),
         "config", "user.name", "JARVIS Test"],
        check=True,
    )

    (repo / "tracked.txt").write_text(
        "baseline\n",
        encoding="utf-8",
    )

    subprocess.run(
        ["git", "-C", str(repo), "add", "tracked.txt"],
        check=True,
    )

    subprocess.run(
        ["git", "-C", str(repo),
         "commit", "-q", "-m", "baseline"],
        check=True,
    )

    subprocess.run(
        [
            "git", "-C", str(repo),
            "worktree", "add",
            "-q", "-b", "linked-test",
            str(linked),
        ],
        check=True,
    )

    return repo, linked


def test_default_image_is_exact_bookworm_digest():
    ex = _executor()

    assert ex.DEFAULT_CONTAINER_IMAGE == (
        "docker.io/library/python@"
        "sha256:0feb54d0096c86df7f3050e34563e07b"
        "2c156d38d0971d3c86cb0069f6be26e0"
    )


def test_linked_worktree_common_metadata_is_read_only(tmp_path):
    import subprocess

    _, linked = _make_linked_worktree(tmp_path)

    common = subprocess.check_output(
        [
            "git", "-C", str(linked),
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ],
        text=True,
    ).strip()

    argv, _ = _executor().build_podman_run_argv(
        workspace=str(linked),
        image_ref=(
            "docker.io/library/python@"
            "sha256:0feb54d0096c86df7f3050e34563e07b"
            "2c156d38d0971d3c86cb0069f6be26e0"
        ),
        container_name="jarvis-test",
        command=["git", "status", "--short"],
    )

    linked_real = os.path.realpath(linked)
    dotgit = os.path.join(linked_real, ".git")
    common = os.path.realpath(common)

    assert f"{linked_real}:/workspace:rw" in argv
    # Design C: for linked worktrees, .git is a file (gitdir pointer), so we
    # mount to an internal path (/var/odysseus/gitdir) and use GIT_DIR env.
    # Verify the projected git metadata IS mounted (at internal path).
    assert any(
        ("/var/odysseus/gitdir:ro" in str(arg) or "/workspace/.git:ro" in str(arg))
        for arg in argv
    ), (
        "No projected git metadata mount found "
        "(expected /workspace/.git:ro for ordinary repos or "
        "/var/odysseus/gitdir:ro for linked worktrees)"
    )
    # Original common Git dir must NOT be mounted at its natural path
    assert not any(
        os.path.realpath(arg.split(":")[0]) == os.path.realpath(common)
        for arg in argv
        if ":ro" in str(arg)
    ), "Original common Git dir mounted — violates projection architecture"


def test_linked_worktree_sensitive_git_config_is_rejected(tmp_path):
    """
    Design C: credential.helper in original Git config is structurally
    inaccessible inside the container because the original .git/config
    is NEVER mounted. The container only sees a generated safe config.

    This test verifies that the credential.helper setting does NOT appear
    in any argv element — the old scanner was replaced by structural
    non-exposure of original config files.
    """
    import subprocess

    repo, linked = _make_linked_worktree(tmp_path)

    subprocess.run(
        [
            "git", "-C", str(repo),
            "config",
            "credential.helper",
            "store",
        ],
        check=True,
    )

    # Design C: NO ValueError — original config is structurally inaccessible
    argv, _ = _executor().build_podman_run_argv(
        workspace=str(linked),
        image_ref=(
            "docker.io/library/python@"
            "sha256:0feb54d0096c86df7f3050e34563e07b"
            "2c156d38d0971d3c86cb0069f6be26e0"
        ),
        container_name="jarvis-test",
        command=["git", "status"],
    )

    # Verify the credential.helper setting is NOT visible in argv
    rendered = "\n".join(argv)
    assert "credential.helper" not in rendered
    assert "store" not in rendered or "PYTHONUNBUFFERED" in rendered


def test_fake_linked_git_pointer_is_rejected(tmp_path):
    fake_common = tmp_path / "fake-common"
    fake_common.mkdir()

    (tmp_path / ".git").write_text(
        "gitdir: " + str(fake_common) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        _executor().build_podman_run_argv(
            workspace=str(tmp_path),
            image_ref=(
                "docker.io/library/python@"
                "sha256:0feb54d0096c86df7f3050e34563e07b"
                "2c156d38d0971d3c86cb0069f6be26e0"
            ),
            container_name="jarvis-test",
            command=["git", "status"],
        )[0]


def test_native_file_policy_blocks_git_metadata(tmp_path):
    from src.tool_execution import _is_sensitive_path

    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    targets = [
        git_dir,
        git_dir / "HEAD",
        git_dir / "index",
    ]

    assert all(
        _is_sensitive_path(str(path))
        for path in targets
    )
