"""Tests that hand-maintained documentation counts match live SSOT data."""

from __future__ import annotations

import json
from pathlib import Path
import re

from scripts.spec.cmd_oracle import classify_corpus_cases
from tests.spec_corpus_support import discover_spec_corpus_cases

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
_ARCHITECTURE_PATH = DOCS_DIR / "Architecture.md"
_SPEC_README_PATH = REPO_ROOT / "spec" / "README.md"
_BATCH_SPEC_LOCK_PATH = REPO_ROOT / "spec" / "batch-spec.lock"
_RELATIVE_LINK_PATTERN = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def _read_batch_spec_lock_ref() -> str:
    lock_data = json.loads(_BATCH_SPEC_LOCK_PATH.read_text(encoding="utf-8"))
    ref = lock_data.get("ref")
    assert isinstance(ref, str), "spec/batch-spec.lock must contain a string ref"
    return ref


def test_spec_readme_corpus_count_matches_discovery() -> None:
    """spec/README.md should state the live corpus case count."""
    corpus_count = len(discover_spec_corpus_cases())
    readme = _SPEC_README_PATH.read_text(encoding="utf-8")
    assert re.search(
        rf"\b{corpus_count}-case\b",
        readme,
    ), f"spec/README.md must state {corpus_count}-case corpus count"


def test_architecture_corpus_count_matches_discovery() -> None:
    """docs/Architecture.md should state the live corpus fixture count."""
    corpus_count = len(discover_spec_corpus_cases())
    architecture = _ARCHITECTURE_PATH.read_text(encoding="utf-8")
    assert re.search(
        rf"\b{corpus_count} committed fixtures\b",
        architecture,
    ), f"docs/Architecture.md must state {corpus_count} committed fixtures"


def test_spec_readme_batch_spec_pin_matches_lock() -> None:
    """spec/README.md should state the pinned batch-spec ref from batch-spec.lock."""
    pinned_ref = _read_batch_spec_lock_ref()
    readme = _SPEC_README_PATH.read_text(encoding="utf-8")
    assert (
        pinned_ref in readme
    ), f"spec/README.md must document batch-spec pin {pinned_ref}"


def test_architecture_oracle_counts_match_classifier() -> None:
    """docs/Architecture.md should state live cmd.exe oracle classification counts."""
    runnable, skipped = classify_corpus_cases()
    architecture = _ARCHITECTURE_PATH.read_text(encoding="utf-8")
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


def test_architecture_relative_links_resolve() -> None:
    """docs/Architecture.md relative links should resolve to existing repo paths."""
    architecture = _ARCHITECTURE_PATH.read_text(encoding="utf-8")
    missing: list[str] = []
    for match in _RELATIVE_LINK_PATTERN.finditer(architecture):
        target = match.group(1).strip()
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        target_path = target.split("#", maxsplit=1)[0]
        if not target_path:
            continue
        resolved = (DOCS_DIR / target_path).resolve()
        try:
            resolved.relative_to(REPO_ROOT.resolve())
        except ValueError:
            missing.append(f"{target} (escapes repo root)")
            continue
        if not resolved.exists():
            missing.append(target)
    assert not missing, "docs/Architecture.md has broken relative links:\n" + "\n".join(
        f"  - {link}" for link in missing
    )
