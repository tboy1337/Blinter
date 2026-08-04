"""Shared merge of batch-spec commands.yaml and Blinter commands-linter.yaml."""

from __future__ import annotations

from typing import Any

from _paths import COMMANDS_LANGUAGE_YAML, COMMANDS_LINTER_YAML
import yaml


def merged_commands_data() -> dict[str, Any]:
    if not COMMANDS_LANGUAGE_YAML.is_file():
        raise FileNotFoundError("batch-spec commands.yaml missing")
    if not COMMANDS_LINTER_YAML.is_file():
        raise FileNotFoundError("commands-linter.yaml missing")
    language = yaml.safe_load(COMMANDS_LANGUAGE_YAML.read_text(encoding="utf-8"))
    linter = yaml.safe_load(COMMANDS_LINTER_YAML.read_text(encoding="utf-8"))
    if not isinstance(language, dict) or not isinstance(linter, dict):
        raise ValueError("commands YAML must be mappings")
    return {**language, **linter}


def builtin_commands_union(data: dict[str, Any]) -> list[str]:
    """Union of stock/cmd builtins and common external tools for E012/E014 suppression."""
    builtins = data.get("builtin_commands", [])
    externals = data.get("common_external_tools", [])
    if not isinstance(builtins, list) or not isinstance(externals, list):
        raise ValueError("builtin_commands and common_external_tools must be lists")
    return sorted(set(builtins) | set(externals))
