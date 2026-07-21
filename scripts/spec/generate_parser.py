#!/usr/bin/env python3
"""Generate ANTLR Python parser from spec/grammar/*.g4."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from _paths import GENERATED_DIR, GRAMMAR_DIR  # noqa: E402

_GRAMMAR_FILES = ("BatchLexer.g4", "BatchParser.g4")
_STAMP_NAME = ".grammar-stamp"


def _grammar_fingerprint() -> str:
    digest = hashlib.sha256()
    for name in _GRAMMAR_FILES:
        content = (GRAMMAR_DIR / name).read_bytes()
        content = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        digest.update(content)
    return digest.hexdigest()


def _run_antlr() -> None:
    grammar_paths = [str(GRAMMAR_DIR / name) for name in _GRAMMAR_FILES]
    env_version = "4.13.2"
    cmd = [
        "antlr4",
        f"-Dlanguage=Python3",
        "-visitor",
        "-no-listener",
        "-o",
        str(GENERATED_DIR),
    ] + grammar_paths
    import os

    env = os.environ.copy()
    env.setdefault("ANTLR4_TOOLS_ANTLR_VERSION", env_version)
    subprocess.run(cmd, check=True, cwd=GRAMMAR_DIR, env=env)


def _write_package_init() -> None:
    init_path = GENERATED_DIR / "__init__.py"
    init_path.write_text(
        '"""ANTLR-generated batch parser (do not edit by hand)."""\n',
        encoding="utf-8",
    )


def _write_stamp() -> None:
    stamp_path = GENERATED_DIR / _STAMP_NAME
    stamp_path.write_text(_grammar_fingerprint(), encoding="utf-8")


def generate_parser() -> None:
    """Regenerate parser sources under src/blinter/generated/."""
    if GENERATED_DIR.exists():
        shutil.rmtree(GENERATED_DIR)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    _run_antlr()
    _write_package_init()
    _write_stamp()


def _generated_files() -> list[Path]:
    names = [
        "BatchLexer.py",
        "BatchParser.py",
        "BatchParserVisitor.py",
        "__init__.py",
        _STAMP_NAME,
    ]
    return [GENERATED_DIR / name for name in names]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ANTLR Python parser")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if generated files are missing or grammar changed",
    )
    args = parser.parse_args()
    if args.check:
        missing = [path for path in _generated_files() if not path.is_file()]
        if missing:
            print("Missing generated parser files:", file=sys.stderr)
            for path in missing:
                print(f"  {path}", file=sys.stderr)
            raise SystemExit(1)
        stamp_path = GENERATED_DIR / _STAMP_NAME
        expected = _grammar_fingerprint()
        actual = stamp_path.read_text(encoding="utf-8").strip()
        if actual != expected:
            print(
                "Generated parser is stale; run generate_parser.py",
                file=sys.stderr,
            )
            raise SystemExit(1)
        print("Generated parser is up to date")
        return
    generate_parser()
    print(f"Wrote ANTLR output to {GENERATED_DIR}")


if __name__ == "__main__":
    main()
