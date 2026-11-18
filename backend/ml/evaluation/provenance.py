"""Small git provenance helpers shared by evaluation result writers."""
from __future__ import annotations

import subprocess
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parents[3]


def working_tree_is_dirty() -> bool:
    """Return whether the evaluation's repository has tracked or untracked changes."""
    try:
        status = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=REPO_DIR,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    return bool(status.strip())
