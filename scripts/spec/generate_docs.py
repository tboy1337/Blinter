#!/usr/bin/env python3
"""Regenerate rule catalog sections in docs/Batch-File-Linter-Requirements.md."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

import yaml

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from _paths import REQUIREMENTS_MD, RULES_YAML  # noqa: E402

_START = "<!-- GENERATED:rule-catalog:start -->"
_END = "<!-- GENERATED:rule-catalog:end -->"


def _prefix_heading(prefix: str) -> str:
    mapping = {
        "E": "### Error Level Rules (E001-E999)",
        "W": "### Warning Level Rules (W001-W999)",
        "S": "### Style Level Rules (S001-S999)",
        "SEC": "### Security Level Rules (SEC001+)",
        "P": "### Performance Level Rules (P001-P999)",
    }
    return mapping[prefix]


def _rule_prefix(code: str) -> str:
    return "SEC" if code.startswith("SEC") else code[0]


def _rule_sort_key(rule: dict[str, object]) -> tuple[int, str]:
    code = str(rule["code"])
    prefix = _rule_prefix(code)
    order = {"E": 0, "W": 1, "S": 2, "SEC": 3, "P": 4}
    return (order.get(prefix, 99), code)


def _build_catalog(rules: list[dict[str, object]]) -> str:
    sections: list[str] = [_START, ""]
    current_prefix: str | None = None
    for rule in sorted(rules, key=_rule_sort_key):
        code = str(rule["code"])
        prefix = _rule_prefix(code)
        if prefix != current_prefix:
            sections.append(_prefix_heading(prefix))
            sections.append("**Auto-generated from spec/data/rules.yaml**")
            sections.append("")
            current_prefix = prefix
        name = str(rule["name"])
        severity = str(rule["severity"])
        note = ""
        if code == "E006" and severity == "WARNING":
            note = " (Warning severity despite E-prefix)"
        elif code == "SEC006" and severity == "STYLE":
            note = " (Style severity despite SEC-prefix)"
        sections.append(f"- **{code}**: {name}{note}")
    sections.append("")
    sections.append(_END)
    return "\n".join(sections)


def generate_docs_text() -> str:
    data = yaml.safe_load(RULES_YAML.read_text(encoding="utf-8"))
    rules = data["rules"]
    catalog = _build_catalog(rules)
    original = REQUIREMENTS_MD.read_text(encoding="utf-8")
    if _START in original and _END in original:
        updated = re.sub(
            rf"{re.escape(_START)}.*?{re.escape(_END)}",
            catalog,
            original,
            count=1,
            flags=re.DOTALL,
        )
    else:
        marker = "## Rule Categories Summary"
        if marker in original:
            parts = original.split(marker, 1)
            updated = parts[0] + marker + "\n\n" + catalog + "\n\n" + parts[1].lstrip()
        else:
            updated = original + "\n\n" + catalog + "\n"
    rule_count = len(rules)
    updated = re.sub(
        r"\(currently \*\*\d+\*\* rules; see `RULE_COUNT`[^)]*\)",
        f"(currently **{rule_count}** rules; see `RULE_COUNT` in that module)",
        updated,
        count=1,
    )
    updated = re.sub(
        r"\(see `RULE_COUNT` in that module for the current count\)",
        f"(currently **{rule_count}** rules; see `RULE_COUNT` in that module)",
        updated,
        count=1,
    )
    return updated


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate Requirements.md rule catalog"
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = generate_docs_text()
    if args.check:
        existing = REQUIREMENTS_MD.read_text(encoding="utf-8")
        if existing != generated:
            print(f"{REQUIREMENTS_MD} is out of date", file=sys.stderr)
            raise SystemExit(1)
        print("Requirements.md catalog is up to date")
        return
    REQUIREMENTS_MD.write_text(generated, encoding="utf-8", newline="\n")
    print(f"Updated {REQUIREMENTS_MD}")


if __name__ == "__main__":
    main()
