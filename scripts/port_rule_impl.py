#!/usr/bin/env python3
"""Port SST rule_impl modules into main checkers/ with import path fixes."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent

MAPPINGS: list[tuple[str, str, str]] = [
    (
        "experiment/sst-perf-w047",
        "src/blinter/parsing/visitors/rule_impl/warnings.py",
        "src/blinter/checkers/warnings.py",
    ),
    (
        "SST",
        "src/blinter/parsing/visitors/rule_impl/syntax.py",
        "src/blinter/checkers/syntax.py",
    ),
    (
        "SST",
        "src/blinter/parsing/visitors/rule_impl/advanced/vars_syntax.py",
        "src/blinter/checkers/advanced/vars_syntax.py",
    ),
    (
        "SST",
        "src/blinter/parsing/visitors/rule_impl/globals/analysis.py",
        "src/blinter/checkers/globals/analysis.py",
    ),
    (
        "SST",
        "src/blinter/parsing/visitors/rule_impl/globals/for_scope.py",
        "src/blinter/checkers/globals/for_scope.py",
    ),
    (
        "SST",
        "src/blinter/parsing/visitors/rule_impl/performance.py",
        "src/blinter/checkers/performance.py",
    ),
]

REPLACEMENTS = [
    ("blinter.parsing.visitors.rule_impl.globals.", "blinter.checkers.globals."),
    ("blinter.parsing.visitors.rule_impl.advanced.", "blinter.checkers.advanced."),
    ("blinter.parsing.visitors.rule_impl.", "blinter.checkers."),
]


def _git_show(branch: str, path: str) -> str:
    return subprocess.check_output(
        ["git", "show", f"{branch}:{path}"],
        text=True,
        cwd=REPO_ROOT,
    )


def _rewrite_imports(text: str) -> str:
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)
    return text


def main() -> int:
    for branch, source, dest in MAPPINGS:
        content = _rewrite_imports(_git_show(branch, source))
        dest_path = REPO_ROOT / dest
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_text(content, encoding="utf-8", newline="\n")
        print(f"Wrote {dest} from {branch}:{source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
