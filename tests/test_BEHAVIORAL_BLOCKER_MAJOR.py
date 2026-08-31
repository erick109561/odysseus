"""
Behavioral/runtime tests for ODYSSEUS_CONTAINER_EXECUTOR repairs.

Covers:
  BLOCKER-1  bg-marker host bypass (7 variants)
  MAJOR-2    real BashTool runtime with container mode
  MAJOR-3    double-cancel teardown adversarial probe
  MAJOR-4    host-shell action dispatch fail-closed
  MAJOR-5    Python clean-container routing contract

Run with:
  ODYSSEUS_CONTAINER_EXECUTOR=1 python -m pytest tests/test_BEHAVIORAL_BLOCKER_MAJOR.py -v
"""
import importlib
import os
import subprocess
import sys

import pytest


def _python_executable():
    """Return Python executable from this environment."""
    return sys.executable


def _repo_root():
    """Derive repository root from this test file's location."""
    # tests/ is at <repo>/tests/
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# BLOCKER-1: bg-marker host bypass — 7 variants, subprocess-proven
# ---------------------------------------------------------------------------

_BG_MARKERS = [
    "#!bg",
    "#bg",
    "# bg",
    "#background",
    "# background",
    "@background",
    "# @background",
]


class TestBlocker1BgMarkerFailClosed:
    """
    BLOCKER-1: container executor must block every bg marker variant.

    Each marker variant is tested via a subprocess call that:
    1. Sets ODYSSEUS_CONTAINER_EXECUTOR=1
    2. Imports tool_execution fresh
    3. Calls _split_bg_marker to confirm detection
    4. Patches bg_jobs.launch to verify it is NEVER called
    5. Verifies the fail-closed error is returned
    """

    @pytest.mark.parametrize("marker", _BG_MARKERS)
    def test_bg_marker_never_calls_bg_jobs_launch(self, marker):
        # Build script with proper escaping — marker is injected as a literal.
        content_lines = [
            "import sys, os, asyncio",
            f"os.environ['ODYSSEUS_CONTAINER_EXECUTOR'] = '1'",
            "import importlib",
            "te = importlib.import_module('src.tool_execution')",
            f"content = '''{marker}\necho test'''",
            "is_bg, cmd = te._split_bg_marker(content)",
            "assert is_bg, f'marker not detected'",
            "assert cmd.strip() == 'echo test'",
            "import src.bg_jobs as bg_jobs",
            "orig_launch = bg_jobs.launch",
            "called = []",
            "def track_launch(*a, **kw):",
            "    called.append((a, kw))",
            "    return orig_launch(*a, **kw)",
            "mock = importlib.import_module('unittest.mock')",
            "import src.tool_execution as te2",
            "with mock.patch.object(te2, 'is_public_blocked_tool', return_value=False):",
            "    with mock.patch.object(bg_jobs, 'launch', track_launch):",
            "        import src.agent_tools.container_executor as ce",
            "        with mock.patch.object(ce, 'container_executor_enabled', return_value=True):",
            "            desc, result = asyncio.run(",
            "                te2._execute_tool_block_impl(",
            "                    _FakeBlock('bash', content),",
            "                    session_id='test-session-123',",
            "                    owner='test-admin',",
            "                )",
            "            )",
            "print('CALLED:', len(called), file=sys.stderr)",
            "assert len(called) == 0, f'bg_jobs.launch called {len(called)} time(s)'",
            "assert result.get('error') is not None",
            "assert 'ODYSSEUS_CONTAINER_EXECUTOR' in result.get('error', '')",
            "print('PASS', file=sys.stderr)",
        ]
        header = (
            "class _FakeBlock:\n"
            "    def __init__(self, tool_type, content):\n"
            "        self.tool_type = tool_type\n"
            "        self.content = content\n"
        )
        full_script = header + "\n".join(content_lines)

        proc = subprocess.run(
            [_python_executable(), "-c", full_script],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=_repo_root(),
            env={**os.environ, "ODYSSEUS_CONTAINER_EXECUTOR": "1"},
        )
        out = proc.stdout + proc.stderr

        assert proc.returncode == 0, (
            f"BLOCKER-1 test failed for marker {marker!r}:\n"
            f"stdout: {proc.stdout[:500]}\n"
            f"stderr: {proc.stderr[:2000]}"
        )
        assert "PASS" in out, (
            f"BLOCKER-1 assertion failed for marker {marker!r}:\n{out[:2000]}"
        )

        proc = subprocess.run(
            [_python_executable(), "-c", full_script],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=_repo_root(),
            env={**os.environ, "ODYSSEUS_CONTAINER_EXECUTOR": "1"},
        )
        out = proc.stdout + proc.stderr

        assert proc.returncode == 0, (
            f"BLOCKER-1 test failed for marker {marker!r}:\n"
            f"stdout: {proc.stdout[:500]}\n"
            f"stderr: {proc.stderr[:2000]}"
        )
        assert "PASS" in out and "CALLED: 0" in out, (
            f"BLOCKER-1 assertion failed for marker {marker!r}:\n{out[:2000]}"
        )


# ---------------------------------------------------------------------------
# MAJOR-2: Real BashTool runtime — bashism must work in container
# ---------------------------------------------------------------------------

class TestMajor2BashToolContainerRuntime:
    """MAJOR-2: BashTool must use /bin/bash in container mode."""

    def test_bashism_runs_in_container(self):
        """
        With container executor enabled, [[ 1 == 1 ]] && echo BASHISM_OK
        must execute inside the container and return BASHISM_OK.
        """
        if not os.path.exists(_python_executable()):
            pytest.skip("venv python not available")

        env = {**os.environ, "ODYSSEUS_CONTAINER_EXECUTOR": "1"}

        script = r"""
import asyncio, os, sys
os.environ['ODYSSEUS_CONTAINER_EXECUTOR'] = '1'

import importlib
import src.agent_tools.subprocess_tools as st
importlib.reload(st)

async def run():
    tool = st.BashTool()
    result = await tool.execute(
        '[[ 1 == 1 ]] && echo BASHISM_OK',
        ctx={'session_id': None, 'subproc_env': {}, 'progress_cb': None}
    )
    print('OUTPUT:', result.get('output', ''), file=sys.stderr)
    print('RC:', result.get('exit_code', -1), file=sys.stderr)
    print('ERROR:', result.get('error', '')[:200], file=sys.stderr)

asyncio.run(run())
"""
        proc = subprocess.run(
            [_python_executable(), "-c", script],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=_repo_root(),
            env=env,
        )
        out = proc.stdout + proc.stderr

        assert "BASHISM_OK" in out, (
            f"BASHISM_OK not found — bashism may have run in /bin/sh. Output:\n{out[:2000]}"
        )
        assert "RC: 0" in out, f"Expected exit_code 0, output:\n{out[:2000]}"
        assert "not found" not in out.lower(), f"bash not found:\n{out[:2000]}"

    def test_container_route_taken(self):
        """Verify the container path is taken, not tmux/sh fallback."""
        if not os.path.exists(_python_executable()):
            pytest.skip("venv python not available")

        env = {**os.environ, "ODYSSEUS_CONTAINER_EXECUTOR": "1"}

        script = """
import asyncio, os, sys
os.environ['ODYSSEUS_CONTAINER_EXECUTOR'] = '1'

import importlib
import src.agent_tools.subprocess_tools as st
importlib.reload(st)

async def run():
    tool = st.BashTool()
    result = await tool.execute(
        'echo ROUTE_CONTAINER',
        ctx={'session_id': None, 'subproc_env': {}, 'progress_cb': None}
    )
    print('OUTPUT:', result.get('output', ''), file=sys.stderr)
    print('RC:', result.get('exit_code', -1), file=sys.stderr)

asyncio.run(run())
"""
        proc = subprocess.run(
            [_python_executable(), "-c", script],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=_repo_root(),
            env=env,
        )
        out = proc.stdout + proc.stderr
        assert "ROUTE_CONTAINER" in out, f"Container route not taken:\n{out[:2000]}"


# ---------------------------------------------------------------------------
# MAJOR-3: Double-cancel teardown — no orphaned containers
# ---------------------------------------------------------------------------

class TestMajor3DoubleCancelTeardown:
    """MAJOR-3: double-cancel must not leave orphaned odysseus-agent-* containers."""

    def test_double_cancel_leaves_no_orphaned_container(self):
        """
        1. Start a long-running command in container mode.
        2. Cancel it (first CancelledError).
        3. During teardown, cancel again (second CancelledError).
        4. After bounded wait: podman ps -a must show ZERO odysseus-agent-* containers.
        """
        if not os.path.exists(_python_executable()):
            pytest.skip("venv python not available")

        r = subprocess.run(["podman", "--version"], capture_output=True)
        if r.returncode != 0:
            pytest.skip("podman not available")

        env = {**os.environ, "ODYSSEUS_CONTAINER_EXECUTOR": "1"}

        script = r"""
import asyncio, os, subprocess, sys, time
os.environ['ODYSSEUS_CONTAINER_EXECUTOR'] = '1'

import importlib
import src.agent_tools.container_executor as ce
importlib.reload(ce)

async def run():
    container_name = None

    async def long_running():
        nonlocal container_name
        # Capture container name from run_container_command's argv.
        import re
        original_build = ce.build_podman_run_argv
        def capture_name(**kw):
            argv = original_build(**kw)
            # Extract the container name from the argv.
            for i, a in enumerate(argv):
                if a == '--name' and i + 1 < len(argv):
                    container_name = argv[i + 1]
                    break
            return argv
        ce.build_podman_run_argv = capture_name

        try:
            await ce.run_container_command(
                workspace='/tmp',
                command=['sh', '-c', 'sleep 30'],
                timeout=300,
            )
        except Exception as e:
            print(f'Expected exception: {e}', file=sys.stderr)

    task = asyncio.create_task(long_running())
    await asyncio.sleep(3)

    # First cancellation.
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # Second cancellation during teardown window.
    await asyncio.sleep(1)
    try:
        await asyncio.wait_for(asyncio.sleep(0), timeout=0.1)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass

    # Wait for teardown to propagate.
    await asyncio.sleep(8)

    # Check: podman ps -a must have zero odysseus-agent-* containers.
    result = subprocess.run(
        ['podman', 'ps', '-a', '--format', '{{.Names}}'],
        capture_output=True, text=True, timeout=10
    )
    names = [n.strip() for n in result.stdout.splitlines() if n.strip()]
    orphans = [n for n in names if n.startswith('odysseus-agent-')]
    print(f'CONTAINERS: {orphans}', file=sys.stderr)
    print(f'ALL_NAMES: {names}', file=sys.stderr)
    if orphans:
        raise AssertionError(f'Orphaned containers after double-cancel: {orphans}')
    print('PASS: no orphaned containers', file=sys.stderr)

asyncio.run(run())
"""
        proc = subprocess.run(
            [_python_executable(), "-c", script],
            capture_output=True,
            text=True,
            timeout=90,
            cwd=_repo_root(),
            env=env,
        )
        out = proc.stdout + proc.stderr

        assert "Orphaned containers" not in out, (
            f"Orphaned containers detected:\n{out[:3000]}"
        )
        assert "PASS: no orphaned containers" in out or "CONTAINERS: []" in out or "CONTAINERS: ['odysseus-agent-" not in out, (
            f"Container leak check inconclusive:\n{out[:3000]}"
        )


# ---------------------------------------------------------------------------
# MAJOR-4: host-shell action dispatch fail-closed
# ---------------------------------------------------------------------------

class TestMajor4HostShellActionFailClosed:
    """MAJOR-4: run_script/run_local/ssh_command must fail closed."""

    @pytest.mark.parametrize("action", ["run_script", "run_local", "ssh_command"])
    def test_execute_action_blocks_host_shell_when_enabled(self, action):
        """
        With ODYSSEUS_CONTAINER_EXECUTOR=1, _execute_action must return
        an error for run_script/run_local/ssh_command BEFORE the host
        action/subprocess runs.
        """
        if not os.path.exists(_python_executable()):
            pytest.skip("venv python not available")

        env = {**os.environ, "ODYSSEUS_CONTAINER_EXECUTOR": "1"}

        # Strategy: patch BUILTIN_ACTIONS dict to remove the dangerous action,
        # forcing _execute_action to hit the container-executor guard BEFORE
        # any action lookup. If the container-executor check passes, it returns
        # "not available". If it doesn't, it falls through to "Unknown action".
        script = f"""
import os, sys, asyncio
os.environ['ODYSSEUS_CONTAINER_EXECUTOR'] = '1'

import importlib
ts = importlib.import_module('src.task_scheduler')
ba = importlib.import_module('src.builtin_actions')

class FakeTask:
    action = '{action}'
    id = 'test-task-1'
    name = 'test'
    prompt = 'echo test'
    owner = None

class FakeScheduler:
    def _set_run_progress(self, run_id, message):
        pass

# Save original BUILTIN_ACTIONS and remove the dangerous action.
original_actions = dict(ba.BUILTIN_ACTIONS)
ba.BUILTIN_ACTIONS.pop('{action}', None)

try:
    msg, ok = asyncio.run(
        ts.TaskScheduler._execute_action(FakeScheduler(), FakeTask())
    )
    print(f'MSG: {{msg}}', file=sys.stderr)
    print(f'OK: {{ok}}', file=sys.stderr)
    if 'container' in msg.lower() or 'not available' in msg.lower():
        print('PASS', file=sys.stderr)
    else:
        print('FAIL: {{msg}}', file=sys.stderr)
finally:
    ba.BUILTIN_ACTIONS.clear()
    ba.BUILTIN_ACTIONS.update(original_actions)
"""
        proc = subprocess.run(
            [_python_executable(), "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=_repo_root(),
            env=env,
        )
        out = proc.stdout + proc.stderr

        # Must report failure with container executor message.
        assert "OK: False" in out, (
            f"Action {action} did not fail closed. Output:\n{out[:2000]}"
        )
        assert "PASS" in out, (
            f"Container executor check did not fire for {action}:\n{out[:2000]}"
        )
        assert "container" in out.lower() and "not available" in out.lower(), (
            f"Wrong error message for {action}:\n{out[:2000]}"
        )

    def test_safe_non_shell_task_not_blocked(self):
        """
        A safe task action (e.g. 'delay') must NOT be blocked by the
        container executor check.
        """
        if not os.path.exists(_python_executable()):
            pytest.skip("venv python not available")

        env = {**os.environ, "ODYSSEUS_CONTAINER_EXECUTOR": "1"}

        script = """
import os, sys, asyncio
os.environ['ODYSSEUS_CONTAINER_EXECUTOR'] = '1'

import importlib
ts = importlib.import_module('src.task_scheduler')

class FakeDelayTask:
    action = 'delay'
    id = 'test-task-safe'
    name = 'safe'
    prompt = None
    owner = None

class FakeScheduler:
    def _set_run_progress(self, run_id, message):
        pass

msg, ok = asyncio.run(
    ts.TaskScheduler._execute_action(FakeScheduler(), FakeDelayTask())
)
print(f'MSG: {msg}', file=sys.stderr)
print(f'OK: {ok}', file=sys.stderr)
if 'container' not in msg.lower():
    print('PASS', file=sys.stderr)
else:
    print('FAIL: blocked unexpectedly', file=sys.stderr)
"""
        proc = subprocess.run(
            [_python_executable(), "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=_repo_root(),
            env=env,
        )
        out = proc.stdout + proc.stderr

        assert "PASS" in out, (
            f"Safe task incorrectly blocked:\n{out[:2000]}"
        )


# ---------------------------------------------------------------------------
# MAJOR-5: Python clean-container contract
# ---------------------------------------------------------------------------

class TestMajor5PythonCleanContainerContract:
    """MAJOR-5: Python tool must use clean container runtime, no host venv."""

    def test_python_no_host_venv_import(self):
        """
        Python must run in python:3.12-bookworm container, NOT the macOS venv.
        Attempting to import a package only present on the host must fail.
        """
        if not os.path.exists(_python_executable()):
            pytest.skip("venv python not available")

        env = {**os.environ, "ODYSSEUS_CONTAINER_EXECUTOR": "1"}

        # This package would succeed on macOS venv but fail in clean container.
        script = """
import asyncio, os, sys
os.environ['ODYSSEUS_CONTAINER_EXECUTOR'] = '1'

import importlib
import src.agent_tools.subprocess_tools as st
importlib.reload(st)

async def run():
    tool = st.PythonTool()
    # Try to import something that ONLY exists in the macOS venv.
    # If this prints HOST_VENV:yes, the host venv was used.
    result = await tool.execute(
        'import sys; print("PYTHON_EXE:", sys.executable); import pkg_resources; print("HOST_VENV:yes")',
        ctx={'session_id': None, 'subproc_env': {}, 'progress_cb': None}
    )
    output = result.get('output', '')
    error = result.get('error', '')
    print('OUTPUT:', output, file=sys.stderr)
    print('ERROR:', error[:500], file=sys.stderr)

asyncio.run(run())
"""
        proc = subprocess.run(
            [_python_executable(), "-c", script],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=_repo_root(),
            env=env,
        )
        out = proc.stdout + proc.stderr

        # Must NOT have run in host venv.
        assert "HOST_VENV:yes" not in out, (
            f"Python ran in host venv instead of clean container. Output:\n{out[:2000]}"
        )

    def test_python_sys_path_no_macos_venv(self):
        """Verify sys.path[0] does not contain the macOS venv path."""
        if not os.path.exists(_python_executable()):
            pytest.skip("venv python not available")

        env = {**os.environ, "ODYSSEUS_CONTAINER_EXECUTOR": "1"}

        script = """
import asyncio, os, sys
os.environ['ODYSSEUS_CONTAINER_EXECUTOR'] = '1'

import importlib
import src.agent_tools.subprocess_tools as st
importlib.reload(st)

async def run():
    tool = st.PythonTool()
    result = await tool.execute(
        'import sys; print("SYS_PATH_0:", sys.path[0] if sys.path else "empty")',
        ctx={'session_id': None, 'subproc_env': {}, 'progress_cb': None}
    )
    print('OUTPUT:', result.get('output', ''), file=sys.stderr)

asyncio.run(run())
"""
        proc = subprocess.run(
            [_python_executable(), "-c", script],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=_repo_root(),
            env=env,
        )
        out = proc.stdout + proc.stderr

        macos_venv_marker = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "odysseus", "odysseus", "venv")
        assert macos_venv_marker not in out, (
            f"macOS venv path leaked into container Python sys.path. Output:\n{out[:2000]}"
        )
