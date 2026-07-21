#!/usr/bin/env python3
"""Extract # Bad / # Good examples from Requirements.md into spec/corpus/."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys

_SCRIPTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPTS_DIR.parent.parent
CORPUS_DIR = _REPO_ROOT / "spec" / "corpus" / "syntax"
REQUIREMENTS = _REPO_ROOT / "docs" / "Batch-File-Linter-Requirements.md"


def main() -> None:
    text = REQUIREMENTS.read_text(encoding="utf-8")
    blocks = re.findall(
        r"```batch\n(.*?)```",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    created = 0
    for index, block in enumerate(blocks):
        lines = [
            line for line in block.splitlines() if not line.strip().startswith("#")
        ]
        if not lines:
            continue
        case_id = f"requirements-example-{index:03d}"
        case_dir = CORPUS_DIR / case_id
        if case_dir.exists():
            continue
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "input.cmd").write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
            newline="\r\n",
        )
        expect = {
            "description": f"Extracted Requirements.md example {index}",
            "rules": [],
            "lines": {},
            "must_not": [],
            "config": {},
            "tags": ["syntax", "extracted"],
        }
        (case_dir / "expect.json").write_text(
            json.dumps(expect, indent=2) + "\n",
            encoding="utf-8",
        )
        created += 1
    print(f"Created {created} new corpus cases under {CORPUS_DIR}")


if __name__ == "__main__":
    main()
