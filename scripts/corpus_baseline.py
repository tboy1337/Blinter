#!/usr/bin/env python3
"""Shared helpers for corpus baseline generation and verification."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import sys
from typing import TypedDict, cast

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_CORPUS_DIR = _REPO_ROOT / "batch-script-examples"
_DEFAULT_BASELINE = _REPO_ROOT / "tests" / "fixtures" / "corpus-baseline.json"

if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from blinter import (  # pylint: disable=wrong-import-position
    BlinterConfig,
    lint_batch_file,
)


class FileBaseline(TypedDict):
    """Per-file lint snapshot."""

    total: int
    rules: dict[str, int]


class ModeBaseline(TypedDict):
    """Lint snapshot for one configuration mode."""

    files: dict[str, FileBaseline]


class CorpusBaseline(TypedDict):
    """Full committed corpus baseline document."""

    version: int
    generated_from: str
    file_count: int
    modes: dict[str, ModeBaseline]


def collect_batch_files(root: Path) -> list[Path]:
    """Return sorted batch files under root."""
    return sorted(
        path
        for path in root.glob("**/*")
        if path.is_file() and path.suffix.lower() in {".bat", ".cmd"}
    )


def _lint_file(file_path: Path, *, follow_calls: bool, scan_root: Path) -> FileBaseline:
    if follow_calls:
        config = BlinterConfig(follow_calls=True, scan_root=str(scan_root.resolve()))
    else:
        config = BlinterConfig()
    issues = lint_batch_file(str(file_path), config=config)
    rule_counts: Counter[str] = Counter(issue.rule.code for issue in issues)
    return FileBaseline(
        total=len(issues),
        rules=dict(sorted(rule_counts.items())),
    )


def build_mode_baseline(
    corpus_dir: Path,
    *,
    follow_calls: bool,
) -> ModeBaseline:
    """Lint every corpus file for one mode."""
    files: dict[str, FileBaseline] = {}
    scan_root = corpus_dir.resolve()
    for file_path in collect_batch_files(corpus_dir):
        files[file_path.name] = _lint_file(
            file_path,
            follow_calls=follow_calls,
            scan_root=scan_root,
        )
    return ModeBaseline(files=files)


def build_corpus_baseline(corpus_dir: Path) -> CorpusBaseline:
    """Build a full baseline for default and follow-calls modes."""
    files = collect_batch_files(corpus_dir)
    return CorpusBaseline(
        version=1,
        generated_from="batch-script-examples",
        file_count=len(files),
        modes={
            "default": build_mode_baseline(corpus_dir, follow_calls=False),
            "follow_calls": build_mode_baseline(corpus_dir, follow_calls=True),
        },
    )


def load_baseline(path: Path) -> CorpusBaseline:
    """Load a committed baseline JSON document."""
    return cast(CorpusBaseline, json.loads(path.read_text(encoding="utf-8")))


def save_baseline(baseline: CorpusBaseline, path: Path) -> None:
    """Write baseline JSON with stable key ordering."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _compare_mode(
    mode_name: str,
    expected: ModeBaseline,
    actual: ModeBaseline,
) -> list[str]:
    diffs: list[str] = []
    expected_files = set(expected["files"])
    actual_files = set(actual["files"])
    missing = expected_files - actual_files
    extra = actual_files - expected_files
    if missing:
        diffs.append(f"{mode_name}: missing files: {sorted(missing)}")
    if extra:
        diffs.append(f"{mode_name}: unexpected files: {sorted(extra)}")

    for name in sorted(expected_files & actual_files):
        expected_entry = expected["files"][name]
        actual_entry = actual["files"][name]
        if expected_entry["total"] != actual_entry["total"]:
            diffs.append(
                f"{mode_name}/{name}: total {actual_entry['total']} != {expected_entry['total']}"
            )
        if expected_entry["rules"] != actual_entry["rules"]:
            diffs.append(f"{mode_name}/{name}: rule histogram mismatch")
    return diffs


def check_baseline(corpus_dir: Path, baseline_path: Path) -> list[str]:
    """Compare live corpus lint results to a committed baseline."""
    expected = load_baseline(baseline_path)
    actual = build_corpus_baseline(corpus_dir)
    diffs: list[str] = []
    if actual["file_count"] != expected["file_count"]:
        diffs.append(f"file_count {actual['file_count']} != {expected['file_count']}")
    for mode_name in ("default", "follow_calls"):
        if mode_name not in expected["modes"]:
            diffs.append(f"missing mode in baseline: {mode_name}")
            continue
        diffs.extend(
            _compare_mode(
                mode_name, expected["modes"][mode_name], actual["modes"][mode_name]
            )
        )
    return diffs
