"""
Shared path resolution helpers for RED/regression tests.

All tests MUST derive paths from __file__, not hardcoded paths.
This ensures tests work after repo relocation.
"""
import os
import sys
from pathlib import Path
from typing import Optional


def _find_repo_root(start: Path) -> Optional[Path]:
    """
    Search upward from start for a directory containing pyproject.toml or src/.
    Returns None if not found within reasonable depth.
    """
    for parent in [start] + list(start.parents):
        if (parent / "pyproject.toml").exists() and (parent / "src").exists():
            return parent
        # Also check for the git metadata repair repo marker
        if (parent / "src" / "agent_tools" / "container_executor.py").exists():
            return parent
        if parent == parent.parent:
            break  # Reached filesystem root
    return None


def get_repo_root() -> Path:
    """
    Derive the repository root from the location of this helper module.
    This helper is at: <repo>/tests/_repo_paths.py
    So parents[1] from here = repo root.
    """
    # This file is at <repo>/tests/_repo_paths.py
    return Path(__file__).resolve().parent.parent


def get_src_path() -> Path:
    """Derive the src/ directory path."""
    return get_repo_root() / "src"


def get_container_executor_path() -> Path:
    """Get the path to container_executor.py."""
    return get_src_path() / "agent_tools" / "container_executor.py"


def get_task_scheduler_path() -> Path:
    """Get the path to task_scheduler.py."""
    return get_src_path() / "task_scheduler.py"


def get_python_executable() -> str:
    """Return the current Python executable."""
    return sys.executable


def get_subprocess_tools_path() -> Path:
    """Get the path to subprocess_tools.py."""
    return get_src_path() / "agent_tools" / "subprocess_tools.py"
