"""Verify src/blinter package contains all symbols from the original monolith."""

from __future__ import annotations

import ast
import importlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parent.parent
MONOLITH_PATH = ROOT / "blinter.py"
MONOLITH_FALLBACK = ROOT / "blinter.py.bak"
PACKAGE_ROOT = ROOT / "src" / "blinter"
SNAPSHOT_PATH = ROOT / "scripts" / "lint_behavior_snapshot.json"


@dataclass(frozen=True)
class SymbolInfo:
    """Metadata for a top-level symbol."""

    name: str
    kind: str
    lineno: int
    end_lineno: int
    source_lines: int


def _node_name(node: ast.AST) -> str | None:
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, ast.Assign):
        targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
        return targets[0] if len(targets) == 1 else None
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    return None


def _node_kind(node: ast.AST) -> str:
    if isinstance(node, ast.FunctionDef):
        return "function"
    if isinstance(node, ast.ClassDef):
        return "class"
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        return "assignment"
    return "other"


def collect_symbols_from_paths(paths: Sequence[Path]) -> dict[str, SymbolInfo]:
    """Collect top-level symbols from Python source files."""
    symbols: dict[str, SymbolInfo] = {}
    for path in paths:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in tree.body:
            name = _node_name(node)
            if name is None:
                continue
            start_line = node.lineno
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.decorator_list:
                start_line = node.decorator_list[0].lineno
            end_line = node.end_lineno or start_line
            symbols[name] = SymbolInfo(
                name=name,
                kind=_node_kind(node),
                lineno=start_line,
                end_lineno=end_line,
                source_lines=end_line - start_line + 1,
            )
    return symbols


def iter_package_python_files() -> Iterable[Path]:
    """Yield Python files under src/blinter."""
    if not PACKAGE_ROOT.is_dir():
        return
    yield from sorted(PACKAGE_ROOT.rglob("*.py"))


def compare_symbol_sets(
    baseline: dict[str, SymbolInfo],
    candidate: dict[str, SymbolInfo],
) -> list[str]:
    """Return human-readable parity errors."""
    errors: list[str] = []
    missing = sorted(set(baseline) - set(candidate))
    extra = sorted(set(candidate) - set(baseline))
    allowed_extra = {"__all__", "_logger", "_show_help", "_show_version"}
    extra = [name for name in extra if name not in allowed_extra]
    if missing:
        errors.append(f"Missing symbols ({len(missing)}): {', '.join(missing)}")
    if extra:
        errors.append(f"Unexpected extra symbols ({len(extra)}): {', '.join(extra)}")
    for name in sorted(set(baseline) & set(candidate)):
        base = baseline[name]
        cand = candidate[name]
        if base.kind != cand.kind:
            errors.append(f"{name}: kind mismatch {base.kind} vs {cand.kind}")
        line_delta = abs(base.source_lines - cand.source_lines)
        if line_delta > 5:
            errors.append(
                f"{name}: source line count delta {line_delta} "
                f"({base.source_lines} vs {cand.source_lines})"
            )
    return errors


def verify_importable_symbols(symbol_names: Sequence[str]) -> list[str]:
    """Ensure symbols are importable from the blinter package."""
    sys.path.insert(0, str(ROOT / "src"))
    errors: list[str] = []
    try:
        import blinter  # noqa: PLC0415

        for name in symbol_names:
            if not hasattr(blinter, name):
                errors.append(f"blinter.{name} is not exported from package root")
    finally:
        if str(ROOT / "src") in sys.path:
            sys.path.remove(str(ROOT / "src"))
    return errors


def capture_lint_snapshot() -> list[dict[str, object]]:
    """Capture lint results for canonical fixtures."""
    sys.path.insert(0, str(ROOT / "src"))
    try:
        import blinter  # noqa: PLC0415
        import tempfile

        fixtures = [
            "@echo off\r\necho hello\r\n",
            "@echo off\r\nif %ERRORLEVEL%==0 echo ok\r\n",
            "@echo off\r\nset VAR=value\r\necho %VAR%\r\n",
            "@echo off\r\ngoto :eof\r\n:label\r\necho test\r\n",
            "@echo off\r\nfor %%i in (*.txt) do echo %%i\r\n",
        ]
        results: list[dict[str, object]] = []
        for index, content in enumerate(fixtures):
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".bat",
                delete=False,
                encoding="utf-8",
                newline="",
            ) as handle:
                handle.write(content)
                temp_path = handle.name
            issues = blinter.lint_batch_file(temp_path)
            results.append(
                {
                    "fixture": index,
                    "issues": [
                        {
                            "line": issue.line_number,
                            "code": issue.rule.code,
                            "context": issue.context,
                        }
                        for issue in issues
                    ],
                }
            )
        return results
    finally:
        if str(ROOT / "src") in sys.path:
            sys.path.remove(str(ROOT / "src"))


def save_behavior_snapshot(path: Path | None = None) -> None:
    """Save lint behavior snapshot JSON."""
    target = path or SNAPSHOT_PATH
    snapshot = capture_lint_snapshot()
    target.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    print(f"Wrote behavior snapshot to {target}")


def compare_behavior_snapshot(path: Path | None = None) -> list[str]:
    """Compare current lint output to saved snapshot."""
    target = path or SNAPSHOT_PATH
    if not target.is_file():
        return [f"Snapshot file not found: {target}"]
    expected = json.loads(target.read_text(encoding="utf-8"))
    actual = capture_lint_snapshot()
    if expected != actual:
        return ["Lint behavior snapshot mismatch"]
    return []


def main() -> None:
    """Run parity verification."""
    baseline_path = MONOLITH_PATH if MONOLITH_PATH.is_file() else MONOLITH_FALLBACK
    if not PACKAGE_ROOT.is_dir():
        print(f"Package not found: {PACKAGE_ROOT}")
        sys.exit(1)

    errors: list[str] = []
    if baseline_path.is_file():
        baseline = collect_symbols_from_paths([baseline_path])
        candidate = collect_symbols_from_paths(list(iter_package_python_files()))
        errors.extend(compare_symbol_sets(baseline, candidate))
        module_names = [
            name
            for name, info in baseline.items()
            if info.kind in {"function", "class", "assignment"}
            and name not in {"__version__", "__author__", "__license__"}
        ]
        errors.extend(verify_importable_symbols(module_names))
    else:
        print("Skipping AST baseline comparison (monolith file not present).")

    if SNAPSHOT_PATH.is_file():
        errors.extend(compare_behavior_snapshot())

    if errors:
        print("Parity verification FAILED:")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)

    print(
        f"Parity verification passed ({len(list(iter_package_python_files()))} package files)"
    )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--save-snapshot":
        save_behavior_snapshot()
        sys.exit(0)
    main()
