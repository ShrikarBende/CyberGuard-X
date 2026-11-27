import sys
from pathlib import Path
import os
import shutil
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_pytest_evaluation_output = None


def pytest_addoption(parser):
    parser.addoption(
        "--write-results", action="store_true", default=False,
        help="Allow evaluation code called by tests to write into backend/ml/evaluation/results.",
    )


def pytest_configure(config):
    global _pytest_evaluation_output
    # Existing repository bundles in saved_models/ are unsigned until the operator
    # runs scripts/sign_existing_models.py; security tests override this explicitly.
    os.environ.setdefault("ALLOW_UNSIGNED_MODELS", "true")
    if config.getoption("--write-results"):
        os.environ.pop("CYBERGUARDX_TEST_RESULTS_DIR", None)
        return
    root = Path(config.rootpath).resolve()
    output = root / ".pytest-tmp" / f"evaluation-results-{os.getpid()}"
    output.mkdir(parents=True, exist_ok=True)
    _pytest_evaluation_output = output
    os.environ["CYBERGUARDX_TEST_RESULTS_DIR"] = str(output)


def pytest_unconfigure(config):
    if _pytest_evaluation_output is None:
        return
    root = Path(config.rootpath).resolve()
    target = _pytest_evaluation_output.resolve()
    expected_parent = (root / ".pytest-tmp").resolve()
    if target.parent == expected_parent and target.name.startswith("evaluation-results-"):
        shutil.rmtree(target, ignore_errors=True)


def pytest_collection_modifyitems(config, items):
    for item in items:
        linux_only = item.get_closest_marker("requires_linux")
        if linux_only and sys.platform == "win32":
            reason = linux_only.kwargs.get(
                "reason", "This API test requires a Linux asyncio event loop."
            )
            item.add_marker(pytest.mark.skip(reason=reason))
        requires_data = item.get_closest_marker("requires_data")
        if requires_data and os.getenv("CI", "").lower() == "true":
            reason = requires_data.kwargs.get(
                "reason", "Requires dataset/model files not provisioned in CI."
            )
            item.add_marker(pytest.mark.skip(reason=reason))
