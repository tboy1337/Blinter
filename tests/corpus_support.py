"""Shared helpers for optional local batch-script-examples regression tests."""

from __future__ import annotations

from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent.parent / "batch-script-examples"
CORPUS_BASELINE_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "corpus-baseline.json"
)
CORPUS_SKIP_REASON = "batch-script-examples not present"
CORPUS_BASELINE_SKIP_REASON = (
    "batch-script-examples or corpus-baseline.json not present"
)


def corpus_files() -> list[Path]:
    """Return sorted batch files from the local corpus folder, if present."""
    if not CORPUS_DIR.is_dir():
        return []
    return sorted(
        path
        for path in CORPUS_DIR.glob("**/*")
        if path.is_file() and path.suffix.lower() in {".bat", ".cmd"}
    )


def corpus_available() -> bool:
    """Return True when the local batch-script-examples corpus is available."""
    return bool(corpus_files())


def corpus_baseline_available() -> bool:
    """Return True when the committed corpus baseline snapshot is present."""
    return CORPUS_BASELINE_PATH.is_file()
