#!/usr/bin/env python3
"""Compare generated patterns.py tables against main's hand-written version."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

TABLES = [
    "DANGEROUS_COMMAND_NAMES",
    "DANGEROUS_COMMAND_PATTERNS",
    "COMMAND_CASING_KEYWORDS",
    "OLDER_WINDOWS_COMMANDS",
    "ARCHITECTURE_SPECIFIC_PATTERNS",
    "UNICODE_PROBLEMATIC_COMMANDS",
    "DEPRECATED_COMMANDS",
    "REMOVED_COMMANDS",
    "COMMON_COMMAND_TYPOS",
    "SENSITIVE_KEYWORDS",
    "BUILTIN_COMMANDS",
]


def _load_from_text(text: str, name: str) -> object:
    spec = importlib.util.spec_from_loader(name, loader=None)
    module = importlib.util.module_from_spec(spec)
    exec(text, module.__dict__)  # noqa: S102
    return module


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    main_text = subprocess.check_output(
        ["git", "show", "main:src/blinter/patterns.py"],
        text=True,
        cwd=repo_root,
    )
    gen_text = (repo_root / "src/blinter/patterns.py").read_text(encoding="utf-8")
    main_mod = _load_from_text(main_text, "main_patterns")
    gen_mod = _load_from_text(gen_text, "gen_patterns")
    diffs: list[str] = []
    for table in TABLES:
        main_value = getattr(main_mod, table)
        gen_value = getattr(gen_mod, table)
        if table in {"DEPRECATED_COMMANDS", "REMOVED_COMMANDS"}:
            main_cmp = set(main_value)
            gen_cmp = set(gen_value)
        else:
            main_cmp = main_value
            gen_cmp = gen_value
        if main_cmp != gen_cmp:
            diffs.append(table)
            print(f"DIFF {table}")
    if diffs:
        print("DIFF TABLES:", ", ".join(diffs))
        return 1
    print("ALL TABLES IDENTICAL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
