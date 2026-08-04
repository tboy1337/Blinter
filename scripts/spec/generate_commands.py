#!/usr/bin/env python3
"""Generate src/blinter/patterns.py from batch-spec commands.yaml + commands-linter.yaml."""

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

from _commands_data import builtin_commands_union, merged_commands_data  # noqa: E402
from _paths import PATTERNS_PY  # noqa: E402

_STATIC_FRAGMENT = _SCRIPTS_DIR / "patterns_static_fragment.py"

_HEADER = '''\
"""Regex patterns for dangerous commands and deprecated syntax.

SSOT tables (dangerous commands, builtins, typos) are generated from
vendor/batch-spec/data/commands.yaml and spec/data/commands-linter.yaml. Embedded-language detection patterns are maintained
in scripts/spec/patterns_static_fragment.py.

THIS FILE IS PARTIALLY GENERATED — run:
  py scripts/spec/generate_commands.py
"""

import re
from typing import List, Set, Tuple

'''


def _format_list(name: str, values: list[str]) -> str:
    lines = [f"{name}: List[str] = ["]
    for value in values:
        lines.append(f'    "{value}",')
    lines.append("]")
    return "\n".join(lines)


def _format_set(name: str, values: list[str]) -> str:
    lines = [f"{name}: Set[str] = {{"]
    for value in values:
        lines.append(f'    "{value}",')
    lines.append("}")
    return "\n".join(lines)


def _format_dict_str_str(name: str, values: dict[str, str]) -> str:
    lines = [f"{name} = {{"]
    for key in sorted(values.keys()):
        escaped = values[key].replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    "{key}": "{escaped}",')
    lines.append("}")
    return "\n".join(lines)


def _format_dangerous_patterns(patterns: list[dict[str, str]]) -> str:
    lines = ["DANGEROUS_COMMAND_PATTERNS: List[Tuple[str, str]] = ["]
    for entry in patterns:
        pattern = entry["pattern"]
        rule_code = entry["rule_code"]
        lines.append(f"    ({repr(pattern)}, {repr(rule_code)}),")
    lines.append("]")
    return "\n".join(lines)


def generate_patterns_text() -> str:
    data = merged_commands_data()
    sections = [_HEADER]
    sections.append(
        _format_list("DANGEROUS_COMMAND_NAMES", data["dangerous_command_names"])
    )
    sections.append("")
    sections.append('_DANGEROUS_CMDS_REGEX: str = "|".join(DANGEROUS_COMMAND_NAMES)')
    sections.append("")
    sections.append(_format_dangerous_patterns(data["dangerous_command_patterns"]))
    sections.append("")
    sections.append(
        _format_set("COMMAND_CASING_KEYWORDS", data["command_casing_keywords"])
    )
    sections.append("")
    sections.append(
        _format_set("OLDER_WINDOWS_COMMANDS", data["older_windows_commands"])
    )
    sections.append("")
    sections.append(
        "ARCHITECTURE_SPECIFIC_PATTERNS: List[str] = [\n"
        + "\n".join(f'    r"{v}",' for v in data["architecture_specific_patterns"])
        + "\n]"
    )
    sections.append("")
    sections.append(
        _format_set(
            "UNICODE_PROBLEMATIC_COMMANDS",
            data["unicode_problematic_commands"],
        )
    )
    sections.append("")
    sections.append(
        _format_dict_str_str("DEPRECATED_COMMANDS", data["deprecated_commands"])
    )
    sections.append("")
    sections.append(_format_dict_str_str("REMOVED_COMMANDS", data["removed_commands"]))
    sections.append("")
    sections.append(
        _format_dict_str_str("COMMON_COMMAND_TYPOS", data["common_command_typos"])
    )
    sections.append("")
    sections.append(_format_list("SENSITIVE_KEYWORDS", data["sensitive_keywords"]))
    sections.append("")
    sections.append(
        "CREDENTIAL_PATTERNS = [\n"
        '    rf"{keyword}\\s*=\\s*[\\"\\\']?[^\\s\\"\']+[\\"\\\']?" '
        "for keyword in SENSITIVE_KEYWORDS\n"
        "]"
    )
    sections.append("")
    sections.append(
        'SENSITIVE_ECHO_PATTERNS = [rf"echo.*{keyword}" for keyword in SENSITIVE_KEYWORDS]'
    )
    sections.append("")
    sections.append(_format_set("BUILTIN_COMMANDS", builtin_commands_union(data)))
    sections.append("")
    if _STATIC_FRAGMENT.is_file():
        sections.append(_STATIC_FRAGMENT.read_text(encoding="utf-8").strip())
        sections.append("")
    source = "\n".join(sections)
    return black.format_str(source, mode=black.Mode(line_length=88))


def write_patterns() -> None:
    PATTERNS_PY.write_text(generate_patterns_text(), encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate patterns.py from commands.yaml"
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = generate_patterns_text()
    if args.check:
        existing = (
            PATTERNS_PY.read_text(encoding="utf-8") if PATTERNS_PY.is_file() else ""
        )
        if existing != generated:
            print(
                f"{PATTERNS_PY} is out of date; run generate_commands.py",
                file=sys.stderr,
            )
            raise SystemExit(1)
        print("patterns.py is up to date")
        return
    write_patterns()
    print(f"Wrote {PATTERNS_PY}")


if __name__ == "__main__":
    main()
