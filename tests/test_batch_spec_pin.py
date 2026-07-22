"""Verify batch-spec submodule pin and generator drift."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BATCH_SPEC_DIR = _REPO_ROOT / "vendor" / "batch-spec"
_LOCK_PATH = _REPO_ROOT / "spec" / "batch-spec.lock"
_GENERATORS = (
    "scripts/spec/generate_parser.py",
    "scripts/spec/generate_expansion.py",
    "scripts/spec/generate_commands.py",
)


def _git_describe_tags(repo_dir: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "describe", "--tags", "--exact-match"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "describe", "--tags"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(
            f"Could not describe batch-spec checkout: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()


@pytest.mark.parametrize("generator", _GENERATORS)
def test_generators_check(generator: str) -> None:
    result = subprocess.run(
        [sys.executable, str(_REPO_ROOT / generator), "--check"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert (
        result.returncode == 0
    ), f"{generator} --check failed:\n{result.stdout}\n{result.stderr}"


def test_batch_spec_submodule_present() -> None:
    assert (
        _BATCH_SPEC_DIR.is_dir()
    ), "vendor/batch-spec is missing. Run: git submodule update --init --recursive"
    assert (_BATCH_SPEC_DIR / "grammar" / "BatchLexer.g4").is_file()
    assert (_BATCH_SPEC_DIR / "data" / "expansion.yaml").is_file()
    assert (_BATCH_SPEC_DIR / "data" / "commands.yaml").is_file()
    assert (_BATCH_SPEC_DIR / "VERSION").is_file()


def test_batch_spec_lock_matches_checkout() -> None:
    assert _LOCK_PATH.is_file(), "spec/batch-spec.lock is missing"
    lock = json.loads(_LOCK_PATH.read_text(encoding="utf-8"))
    expected_ref = lock["ref"]
    assert lock["path"] == "vendor/batch-spec"

    describe = _git_describe_tags(_BATCH_SPEC_DIR)
    assert describe == expected_ref or describe.startswith(
        f"{expected_ref}"
    ), f"Checked-out batch-spec ({describe}) does not match lock ref ({expected_ref})"
