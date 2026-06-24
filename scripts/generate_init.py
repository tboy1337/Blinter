"""Generate src/blinter/__init__.py re-exports from split mapping."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPLIT_PATH = ROOT / "scripts" / "split_blinter.py"
INIT_PATH = ROOT / "src" / "blinter" / "__init__.py"


def main() -> None:
    spec = importlib.util.spec_from_file_location("split_blinter", SPLIT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load split_blinter.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    symbol_map: dict[str, str] = module.SYMBOL_TO_MODULE

    lines = [
        '"""Blinter - batch file linter package."""',
        "",
    ]
    seen: set[str] = set()
    ordered = sorted(symbol_map.items(), key=lambda item: (item[1], item[0]))
    for name, module_key in ordered:
        if name in seen:
            continue
        seen.add(name)
        lines.append(f"from blinter.{module_key} import {name}")

    lines.extend(["", "__all__ = ["])
    all_names: list[str] = []
    for name, _ in ordered:
        if name not in all_names:
            all_names.append(name)
    for name in all_names:
        lines.append(f'    "{name}",')
    lines.append("]")
    INIT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {INIT_PATH} with {len(symbol_map)} symbols")


if __name__ == "__main__":
    main()
