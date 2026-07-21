#!/usr/bin/env python3
"""Generate grammar-backed rule codes from spec/data/rules.yaml."""

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

from _paths import RULES_YAML  # noqa: E402

GRAMMAR_RULES_PY = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "blinter"
    / "parsing"
    / "grammar_rules.py"
)

_HEADER = '''\
"""Grammar-backed syntax rule codes (generated from rules.yaml grammar_nodes)."""

# THIS FILE IS GENERATED — edit spec/data/rules.yaml and run:
#   py scripts/spec/generate_grammar_rules.py

GRAMMAR_BACKED_RULE_CODES: frozenset[str] = frozenset({
'''


def _load_grammar_codes() -> list[str]:
    data = yaml.safe_load(RULES_YAML.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("rules.yaml must be a mapping")
    rules = data.get("rules")
    if not isinstance(rules, list):
        raise ValueError("rules.yaml must contain a rules list")
    codes: list[str] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("grammar_nodes"):
            codes.append(str(rule["code"]))
    return sorted(set(codes))


def generate_grammar_rules_text() -> str:
    codes = _load_grammar_codes()
    lines = [_HEADER]
    for code in codes:
        lines.append(f'    "{code}",')
    lines.append("})\n")
    source = "\n".join(lines)
    return black.format_str(source, mode=black.Mode(line_length=88))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate grammar_rules.py")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = generate_grammar_rules_text()
    if args.check:
        existing = (
            GRAMMAR_RULES_PY.read_text(encoding="utf-8")
            if GRAMMAR_RULES_PY.is_file()
            else ""
        )
        if existing != generated:
            print(f"{GRAMMAR_RULES_PY} is out of date", file=sys.stderr)
            raise SystemExit(1)
        print("grammar_rules.py is up to date")
        return
    GRAMMAR_RULES_PY.parent.mkdir(parents=True, exist_ok=True)
    GRAMMAR_RULES_PY.write_text(generated, encoding="utf-8", newline="\n")
    print(f"Wrote {GRAMMAR_RULES_PY}")


if __name__ == "__main__":
    main()
