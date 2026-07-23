"""Tests that hand-maintained documentation counts match live SSOT data."""

from __future__ import annotations

from pathlib import Path
import re

from scripts.spec.cmd_oracle import classify_corpus_cases
from tests.spec_corpus_support import discover_spec_corpus_cases

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_spec_readme_corpus_count_matches_discovery() -> None:
    """spec/README.md should state the live corpus case count."""
    corpus_count = len(discover_spec_corpus_cases())
    readme = (REPO_ROOT / "spec" / "README.md").read_text(encoding="utf-8")
    assert re.search(
        rf"\b{corpus_count}-case\b",
        readme,
    ), f"spec/README.md must state {corpus_count}-case corpus count"


def test_architecture_oracle_counts_match_classifier() -> None:
    """docs/Architecture.md should state live cmd.exe oracle classification counts."""
    runnable, skipped = classify_corpus_cases()
    architecture = (REPO_ROOT / "docs" / "Architecture.md").read_text(encoding="utf-8")
    runnable_match = re.search(r"\*\*(\d+) runnable\*\*", architecture)
    skipped_match = re.search(r"\*\*(\d+) skipped\*\*", architecture)
    assert (
        runnable_match is not None
    ), "docs/Architecture.md must document runnable oracle count"
    assert (
        skipped_match is not None
    ), "docs/Architecture.md must document skipped oracle count"
    assert int(runnable_match.group(1)) == len(
        runnable
    ), f"docs/Architecture.md runnable count must be {len(runnable)}"
    assert int(skipped_match.group(1)) == len(
        skipped
    ), f"docs/Architecture.md skipped count must be {len(skipped)}"
