#!/usr/bin/env python3
"""Build spec/data/commands-linter.yaml from src/blinter/patterns.py linter tables."""

from __future__ import annotations

from pathlib import Path
import sys

import yaml

_SCRIPTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPTS_DIR.parent.parent
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from _paths import COMMANDS_YAML  # noqa: E402

from blinter import patterns  # noqa: E402

if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))


def _set_to_reason_map(items: set[str], default_reason: str) -> dict[str, str]:
    return {name: default_reason for name in sorted(items)}


def main() -> None:
    payload = {
        "version": 1,
        "dangerous_command_names": patterns.DANGEROUS_COMMAND_NAMES,
        "dangerous_command_patterns": [
            {"pattern": pattern, "rule_code": rule_code}
            for pattern, rule_code in patterns.DANGEROUS_COMMAND_PATTERNS
        ],
        "command_casing_keywords": sorted(patterns.COMMAND_CASING_KEYWORDS),
        "builtin_commands": sorted(patterns.BUILTIN_COMMANDS),
        "deprecated_commands": _set_to_reason_map(
            patterns.DEPRECATED_COMMANDS,
            "Deprecated Windows command",
        ),
        "removed_commands": _set_to_reason_map(
            patterns.REMOVED_COMMANDS,
            "Removed Windows command",
        ),
        "older_windows_commands": sorted(patterns.OLDER_WINDOWS_COMMANDS),
        "common_command_typos": patterns.COMMON_COMMAND_TYPOS,
        "sensitive_keywords": patterns.SENSITIVE_KEYWORDS,
        "architecture_specific_patterns": patterns.ARCHITECTURE_SPECIFIC_PATTERNS,
        "unicode_problematic_commands": sorted(patterns.UNICODE_PROBLEMATIC_COMMANDS),
    }
    COMMANDS_YAML.parent.mkdir(parents=True, exist_ok=True)
    COMMANDS_YAML.write_text(
        yaml.dump(payload, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )
    print(f"Wrote {COMMANDS_YAML}")


if __name__ == "__main__":
    main()
