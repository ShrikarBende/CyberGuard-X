"""Default evaluation output path and isolated pytest-only override."""
from __future__ import annotations

import os
import sys
from pathlib import Path

DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent / "results"
TEST_RESULTS_ENV = "CYBERGUARDX_TEST_RESULTS_DIR"


def get_results_dir(*, test_mode: bool | None = None) -> Path:
    """Use a temporary output only when running under pytest; real runs use results/."""
    if test_mode is None:
        test_mode = "pytest" in sys.modules
    override = os.environ.get(TEST_RESULTS_ENV) if test_mode else None
    return Path(override).resolve() if override else DEFAULT_RESULTS_DIR
