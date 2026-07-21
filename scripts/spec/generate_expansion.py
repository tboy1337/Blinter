#!/usr/bin/env python3
"""Generate src/blinter/rules/expansion_data.py from spec/data/expansion.yaml."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

import black
import yaml

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from _paths import EXPANSION_DATA_PY, EXPANSION_YAML  # noqa: E402

_HEADER = '''\
"""Batch expansion constants generated from spec/data/expansion.yaml.

THIS FILE IS GENERATED — edit spec/data/expansion.yaml and run:
  py scripts/spec/generate_expansion.py
"""

from __future__ import annotations

from typing import FrozenSet, Tuple

'''


def _load_expansion() -> dict[str, Any]:
    data = yaml.safe_load(EXPANSION_YAML.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("expansion.yaml must be a mapping")
    return data


def generate_expansion_text() -> str:
    data = _load_expansion()
    modifier_chars = str(data["valid_modifier_chars"])
    valid_modifiers = data.get("valid_modifiers", {})
    caret_counts = data["caret_escape"]["valid_caret_counts"]
    invalid = data.get("invalid_combinations", [])
    examples = data.get("valid_combined_examples", [])
    delayed = data.get("delayed_expansion", {})
    enable_keywords = delayed.get("enable_keywords", [])

    lines = [
        _HEADER,
        f'VALID_MODIFIER_CHARS: str = "{modifier_chars}"',
        f"VALID_MODIFIERS: FrozenSet[str] = frozenset({{",
    ]
    for key in sorted(valid_modifiers.keys()):
        lines.append(f'    "{key}",')
    lines.append("})")
    lines.append("")
    lines.append(f"VALID_CARET_COUNTS: Tuple[int, ...] = {tuple(caret_counts)}")
    lines.append("")
    lines.append(
        f'DELAYED_EXPANSION_PATTERN: str = "{delayed.get("pattern", "!VAR!")}"'
    )
    lines.append(
        f"DELAYED_EXPANSION_REQUIRES_SETLOCAL: bool = "
        f"{repr(bool(delayed.get('requires_setlocal', True)))}"
    )
    lines.append("DELAYED_EXPANSION_ENABLE_KEYWORDS: Tuple[str, ...] = (")
    for keyword in enable_keywords:
        lines.append(f'    "{keyword}",')
    lines.append(")")
    lines.append("")
    lines.append("VALID_COMBINED_TILDE_EXAMPLES: Tuple[str, ...] = (")
    for example in examples:
        escaped = str(example).replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    "{escaped}",')
    lines.append(")")
    lines.append("")
    lines.append("INVALID_TILDE_COMBINATION_REASONS: Tuple[str, ...] = (")
    for entry in invalid:
        reason = str(entry.get("reason", "")).replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    "{reason}",')
    lines.append(")")
    lines.append("")
    substring = data.get("string_operations", {}).get("substring_pattern", "%var:~0,1%")
    replacement = data.get("string_operations", {}).get(
        "replacement_pattern", "%var:old=new%"
    )
    lines.append(f'STRING_SUBSTRING_PATTERN: str = "{substring}"')
    lines.append(f'STRING_REPLACEMENT_PATTERN: str = "{replacement}"')
    lines.append("")
    source = "\n".join(lines)
    return black.format_str(source, mode=black.Mode(line_length=88))


def write_expansion_data() -> None:
    EXPANSION_DATA_PY.parent.mkdir(parents=True, exist_ok=True)
    EXPANSION_DATA_PY.write_text(
        generate_expansion_text(), encoding="utf-8", newline="\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate expansion_data.py")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = generate_expansion_text()
    if args.check:
        existing = (
            EXPANSION_DATA_PY.read_text(encoding="utf-8")
            if EXPANSION_DATA_PY.is_file()
            else ""
        )
        if existing != generated:
            print(
                f"{EXPANSION_DATA_PY} is out of date; run generate_expansion.py",
                file=sys.stderr,
            )
            raise SystemExit(1)
        print("expansion_data.py is up to date")
        return
    write_expansion_data()
    print(f"Wrote {EXPANSION_DATA_PY}")


if __name__ == "__main__":
    main()
