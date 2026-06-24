"""Add missing cross-module imports using split symbol map."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = ROOT / "src" / "blinter"
SPLIT_PATH = ROOT / "scripts" / "split_blinter.py"

SKIP_NAMES = {
    "True",
    "False",
    "None",
    "print",
    "len",
    "str",
    "int",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "type",
    "object",
    "staticmethod",
    "classmethod",
    "property",
    "super",
    "isinstance",
    "issubclass",
    "hasattr",
    "getattr",
    "setattr",
    "enumerate",
    "range",
    "min",
    "max",
    "sum",
    "any",
    "all",
    "sorted",
    "reversed",
    "zip",
    "map",
    "filter",
    "open",
    "Path",
    "Optional",
    "List",
    "Dict",
    "Set",
    "Tuple",
    "Union",
    "Callable",
    "DefaultDict",
    "NoReturn",
    "cast",
    "Enum",
    "dataclass",
    "defaultdict",
    "configparser",
    "logging",
    "re",
    "sys",
    "warnings",
    "Exception",
    "ValueError",
    "TypeError",
    "OSError",
    "FileNotFoundError",
    "PermissionError",
    "UnicodeDecodeError",
    "SystemExit",
}


def _load_symbol_map() -> dict[str, str]:
    spec = importlib.util.spec_from_file_location("split_blinter", SPLIT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load split_blinter.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return dict(module.SYMBOL_TO_MODULE)


def _module_path_for_file(path: Path) -> str:
    rel = path.relative_to(PACKAGE_ROOT).with_suffix("")
    return ".".join(rel.parts)


def _collect_defined(path: Path) -> set[str]:
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
    return names


def _collect_imported(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def _collect_used(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
    return names


def _insert_imports(path: Path, imports_by_module: dict[str, list[str]]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    import_lines: list[str] = []
    for module_key in sorted(imports_by_module):
        symbols = sorted(imports_by_module[module_key])
        if len(symbols) == 1:
            import_lines.append(f"from blinter.{module_key} import {symbols[0]}")
        else:
            import_lines.append(f"from blinter.{module_key} import (")
            for symbol in symbols:
                import_lines.append(f"    {symbol},")
            import_lines.append(")")
    insert_at = 0
    for index, line in enumerate(lines):
        if index == 0 and line.startswith('"""'):
            continue
        if line.startswith(("from ", "import ")):
            insert_at = index + 1
    lines[insert_at:insert_at] = import_lines
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def fix_file(path: Path, symbol_map: dict[str, str]) -> bool:
    if path.name == "__init__.py":
        return False
    module_key = _module_path_for_file(path)
    defined = _collect_defined(path)
    imported = _collect_imported(path)
    used = _collect_used(path)
    available = defined | imported | SKIP_NAMES
    needed: dict[str, list[str]] = {}
    for name in sorted(used):
        if name in available:
            continue
        target = symbol_map.get(name)
        if target is None or target == module_key:
            continue
        needed.setdefault(target, []).append(name)
    if not needed:
        return False
    _insert_imports(path, needed)
    return True


def main() -> None:
    symbol_map = _load_symbol_map()
    changed = 0
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if fix_file(path, symbol_map):
            print(f"Fixed {path.relative_to(ROOT)}")
            changed += 1
    print(f"Updated {changed} files")


if __name__ == "__main__":
    main()
