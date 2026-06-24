"""Fix missing cross-module imports in split package modules."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = ROOT / "src" / "blinter"

# Symbols defined in patterns.py
PATTERN_SYMBOLS = {
    "DANGEROUS_COMMAND_NAMES",
    "_DANGEROUS_CMDS_REGEX",
    "_COMPILED_IF_PATTERN",
    "_COMPILED_SETLOCAL_DISABLE",
    "_COMPILED_SET_PATTERN",
    "_COMPILED_GOTO_PATTERN",
    "_COMPILED_VAR_EXPANSION",
    "_COMPILED_ECHO_DOTS",
    "_COMPILED_NON_ASCII",
    "_COMPILED_NET_SESSION",
    "_COMPILED_NET_COMMAND",
    "_COMPILED_DELAYED_VAR",
    "DANGEROUS_COMMAND_PATTERNS",
    "COMMAND_CASING_KEYWORDS",
    "OLDER_WINDOWS_COMMANDS",
    "ARCHITECTURE_SPECIFIC_PATTERNS",
    "UNICODE_PROBLEMATIC_COMMANDS",
    "DEPRECATED_COMMANDS",
    "REMOVED_COMMANDS",
    "COMMON_COMMAND_TYPOS",
    "SENSITIVE_KEYWORDS",
    "CREDENTIAL_PATTERNS",
    "SENSITIVE_ECHO_PATTERNS",
    "BUILTIN_COMMANDS",
    "POWERSHELL_PATTERNS",
    "VBSCRIPT_PATTERNS",
    "CSHARP_PATTERNS",
    "BATCH_INDICATORS",
}

CONSTANT_SYMBOLS = {"BUILTIN_VARS", "MAGIC_NUMBER_EXCEPTIONS"}
RULE_SYMBOLS = {"RULES", "_add_issue", "_s011_rule", "_create_rule"}


def _collect_defined_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    import_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                import_names.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                import_names.add(alias.name)
    return names | import_names


def _collect_used_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    return used


def _has_import(text: str, symbol: str) -> bool:
    return bool(
        re.search(rf"from blinter\.[\w.]+ import [^\n]*\b{symbol}\b", text)
        or re.search(rf"import blinter", text)
    )


def fix_file(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    defined = _collect_defined_names(path)
    used = _collect_used_names(path)
    needed_patterns = sorted(
        symbol
        for symbol in PATTERN_SYMBOLS
        if symbol in used and symbol not in defined and not _has_import(text, symbol)
    )
    needed_constants = sorted(
        symbol
        for symbol in CONSTANT_SYMBOLS
        if symbol in used and symbol not in defined and not _has_import(text, symbol)
    )
    if not needed_patterns and not needed_constants:
        return False

    insert_lines: list[str] = []
    if needed_patterns:
        insert_lines.append("from blinter.patterns import (")
        for symbol in needed_patterns:
            insert_lines.append(f"    {symbol},")
        insert_lines.append(")")
    if needed_constants:
        insert_lines.append("from blinter.constants import (")
        for symbol in needed_constants:
            insert_lines.append(f"    {symbol},")
        insert_lines.append(")")

    lines = text.splitlines()
    insert_at = 0
    for index, line in enumerate(lines):
        if line.startswith('"""') and index == 0:
            continue
        if line.startswith("from ") or line.startswith("import "):
            insert_at = index + 1
        elif insert_at > 0 and line.strip() == "":
            break
    lines[insert_at:insert_at] = insert_lines
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


def main() -> None:
    changed = 0
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if path.name == "__init__.py":
            continue
        if fix_file(path):
            print(f"Fixed imports in {path.relative_to(ROOT)}")
            changed += 1
    print(f"Updated {changed} files")


if __name__ == "__main__":
    main()
