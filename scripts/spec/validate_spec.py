#!/usr/bin/env python3
"""Validate spec YAML files against JSON Schema."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import jsonschema
import yaml

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from _paths import (  # noqa: E402
    COMMANDS_YAML,
    DATA_DIR,
    EXPANSION_YAML,
    RULES_YAML,
    SCHEMA_DIR,
)

_PREFIX_SEVERITY_ALLOWLIST = {"E006", "SEC006"}


def _load_yaml(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _validate(path: Path, schema_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    data = _load_yaml(path)
    jsonschema.validate(instance=data, schema=schema)
    print(f"OK {path.name}")


def _validate_rule_integrity(rules_data: dict[str, object]) -> None:
    rules = rules_data.get("rules")
    if not isinstance(rules, list):
        raise ValueError("rules.yaml must contain a rules list")
    codes: list[str] = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Each rule must be a mapping")
        code = str(rule["code"])
        codes.append(code)
        severity = str(rule["severity"])
        if code.startswith("SEC"):
            prefix = "SEC"
        else:
            prefix = code[0]
        expected = {
            "E": "ERROR",
            "W": "WARNING",
            "S": "STYLE",
            "SEC": "SECURITY",
            "P": "PERFORMANCE",
        }.get(prefix)
        if expected and severity != expected and code not in _PREFIX_SEVERITY_ALLOWLIST:
            raise ValueError(
                f"Rule {code} has severity {severity}, expected {expected}"
            )
    if len(codes) != len(set(codes)):
        duplicates = sorted({c for c in codes if codes.count(c) > 1})
        raise ValueError(f"Duplicate rule codes in rules.yaml: {duplicates}")


def _validate_commands_rule_refs(
    commands_data: dict[str, object], valid_rules: set[str]
) -> None:
    patterns = commands_data.get("dangerous_command_patterns", [])
    if not isinstance(patterns, list):
        return
    for entry in patterns:
        if not isinstance(entry, dict):
            continue
        rule_code = str(entry.get("rule_code", ""))
        if rule_code and rule_code not in valid_rules:
            raise ValueError(f"commands.yaml references unknown rule_code {rule_code}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate spec YAML against schemas")
    parser.parse_args()
    _validate(RULES_YAML, SCHEMA_DIR / "rules.schema.json")
    rules_data = _load_yaml(RULES_YAML)
    if not isinstance(rules_data, dict):
        raise SystemExit("rules.yaml must be a mapping")
    _validate_rule_integrity(rules_data)
    valid_rules = {str(rule["code"]) for rule in rules_data["rules"]}

    _validate(COMMANDS_YAML, SCHEMA_DIR / "commands.schema.json")
    commands_data = _load_yaml(COMMANDS_YAML)
    if isinstance(commands_data, dict):
        _validate_commands_rule_refs(commands_data, valid_rules)

    if EXPANSION_YAML.is_file():
        _validate(EXPANSION_YAML, SCHEMA_DIR / "expansion.schema.json")
    else:
        raise SystemExit(f"Missing {EXPANSION_YAML}")

    if not DATA_DIR.is_dir():
        raise SystemExit(f"Missing {DATA_DIR}")
    print("Spec validation passed")


if __name__ == "__main__":
    main()
