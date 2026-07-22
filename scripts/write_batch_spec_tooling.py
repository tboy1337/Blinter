#!/usr/bin/env python3
"""Write batch-spec repository tooling files (run after bootstrap_batch_spec_repo.py)."""

from __future__ import annotations

from pathlib import Path

BATCH_SPEC_ROOT = Path(__file__).resolve().parent.parent.parent / "batch-spec"


def write_files() -> None:
    root = BATCH_SPEC_ROOT
    (root / "scripts").mkdir(exist_ok=True)
    (root / "conformance").mkdir(exist_ok=True)
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)

    (root / ".gitignore").write_text(
        """__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.generated/
generated/python/*.interp
generated/python/*.tokens
.grammar-stamp
""",
        encoding="utf-8",
    )

    (root / "README.md").write_text(
        """# batch-spec

Single source of truth for the Windows batch/cmd.exe **language** structure used by
[Blinter](https://github.com/tboy1337/Blinter) and other conforming tools.

This repository defines grammar, expansion rules, and command catalogs. It does **not**
define linter rules (E/W/S/SEC/P codes) — those live in Blinter's `spec/` tree.

## Layout

| Path | Purpose |
|------|---------|
| `grammar/` | ANTLR 4 lexer/parser (`.g4`) |
| `data/commands.yaml` | Builtin, deprecated, removed commands and typos |
| `data/expansion.yaml` | `%` / `!` / `%~` expansion semantics |
| `schema/` | JSON Schema for YAML and parse corpus |
| `audit/cmd-help/` | Captured `cmd.exe /?` reference text |
| `corpus/parse/` | Parser conformance fixtures (parse-only `expect.json`) |
| `conformance/` | Implementation-agnostic conformance runner |
| `scripts/` | Validation and parser generation |

## Versioning

Releases are tagged with semver (`v0.1.0`, …). Consumers pin a tag via git submodule
or lock file. Do not depend on `main` directly in production CI.

## Validate

```bash
pip install pyyaml jsonschema antlr4-tools antlr4-python3-runtime
python scripts/validate.py
python scripts/generate_parser.py
python conformance/run_parser.py --impl antlr
```

## Add a parser implementation

1. Implement parsing for all cases under `corpus/parse/`.
2. Register the implementation in `conformance/run_parser.py`.
3. Run `python conformance/run_parser.py --impl <name>` locally and in CI.

## License

AGPL-3.0-or-later — see [COPYING](COPYING).
""",
        encoding="utf-8",
    )

    (root / "scripts" / "_paths.py").write_text(
        '''"""Shared paths for batch-spec tooling."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
SCHEMA_DIR = REPO_ROOT / "schema"
GRAMMAR_DIR = REPO_ROOT / "grammar"
CORPUS_DIR = REPO_ROOT / "corpus" / "parse"
GENERATED_DIR = REPO_ROOT / "generated" / "python"
COMMANDS_YAML = DATA_DIR / "commands.yaml"
EXPANSION_YAML = DATA_DIR / "expansion.yaml"
''',
        encoding="utf-8",
    )

    (root / "scripts" / "validate.py").write_text(
        '''#!/usr/bin/env python3
"""Validate batch-spec YAML files against JSON Schema."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import yaml

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from _paths import COMMANDS_YAML, EXPANSION_YAML, SCHEMA_DIR  # noqa: E402


def _validate(path: Path, schema_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    jsonschema.validate(instance=data, schema=schema)
    print(f"OK {path.name}")


def main() -> None:
    _validate(COMMANDS_YAML, SCHEMA_DIR / "commands.schema.json")
    _validate(EXPANSION_YAML, SCHEMA_DIR / "expansion.schema.json")
    print("batch-spec validation passed")


if __name__ == "__main__":
    main()
''',
        encoding="utf-8",
    )

    (root / "scripts" / "generate_parser.py").write_text(
        '''#!/usr/bin/env python3
"""Generate ANTLR Python parser from grammar/*.g4 into generated/python/."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

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
        content = content.replace(b"\\r\\n", b"\\n").replace(b"\\r", b"\\n")
        digest.update(content)
    return digest.hexdigest()


def _run_antlr() -> None:
    grammar_paths = [str(GRAMMAR_DIR / name) for name in _GRAMMAR_FILES]
    cmd = [
        "antlr4",
        "-Dlanguage=Python3",
        "-visitor",
        "-no-listener",
        "-o",
        str(GENERATED_DIR),
    ] + grammar_paths
    env = os.environ.copy()
    env.setdefault("ANTLR4_TOOLS_ANTLR_VERSION", "4.13.2")
    subprocess.run(cmd, check=True, cwd=GRAMMAR_DIR, env=env)


def generate_parser() -> None:
    if GENERATED_DIR.exists():
        shutil.rmtree(GENERATED_DIR)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    _run_antlr()
    (GENERATED_DIR / "__init__.py").write_text(
        '"""ANTLR-generated batch parser (do not edit by hand)."""\\n',
        encoding="utf-8",
    )
    (GENERATED_DIR / _STAMP_NAME).write_text(_grammar_fingerprint(), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ANTLR Python parser")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    names = ["BatchLexer.py", "BatchParser.py", "BatchParserVisitor.py", "__init__.py", _STAMP_NAME]
    if args.check:
        missing = [GENERATED_DIR / name for name in names if not (GENERATED_DIR / name).is_file()]
        if missing:
            for path in missing:
                print(f"Missing {path}", file=sys.stderr)
            raise SystemExit(1)
        stamp = (GENERATED_DIR / _STAMP_NAME).read_text(encoding="utf-8").strip()
        if stamp != _grammar_fingerprint():
            print("Generated parser is stale", file=sys.stderr)
            raise SystemExit(1)
        print("Generated parser is up to date")
        return
    generate_parser()
    print(f"Wrote ANTLR output to {GENERATED_DIR}")


if __name__ == "__main__":
    main()
''',
        encoding="utf-8",
    )

    (root / "conformance" / "run_parser.py").write_text(
        '''#!/usr/bin/env python3
"""Run parser conformance cases against a registered implementation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable, List

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "corpus" / "parse"
GENERATED_DIR = REPO_ROOT / "generated" / "python"


def _discover_cases() -> list[tuple[str, Path, dict[str, object]]]:
    cases: list[tuple[str, Path, dict[str, object]]] = []
    for expect_path in sorted(CORPUS_DIR.glob("**/expect.json")):
        case_dir = expect_path.parent
        input_path = case_dir / "input.cmd"
        if not input_path.is_file():
            continue
        expect = json.loads(expect_path.read_text(encoding="utf-8"))
        case_id = "/".join(case_dir.relative_to(CORPUS_DIR).parts)
        cases.append((case_id, input_path, expect))
    return cases


def _parse_antlr(lines: List[str]) -> tuple[object | None, list[str]]:
    if str(GENERATED_DIR) not in sys.path:
        sys.path.insert(0, str(GENERATED_DIR))
    from antlr4 import CommonTokenStream, InputStream  # noqa: PLC0415
    from BatchLexer import BatchLexer  # noqa: PLC0415
    from BatchParser import BatchParser  # noqa: PLC0415

    source = "\\n".join(lines)
    lexer = BatchLexer(InputStream(source))
    token_stream = CommonTokenStream(lexer)
    parser = BatchParser(token_stream)
    errors: list[str] = []

    class _Listener:  # noqa: D106
        def syntaxError(self, recognizer, offending_symbol, line, column, msg, e) -> None:  # noqa: ANN001
            del recognizer, offending_symbol, e
            errors.append(f"line {line}:{column} {msg}")

    lexer.removeErrorListeners()
    parser.removeErrorListeners()
    lexer.addErrorListener(_Listener())
    parser.addErrorListener(_Listener())
    tree = parser.script()
    return tree, errors


_IMPLEMENTATIONS: dict[str, Callable[[List[str]], tuple[object | None, list[str]]]] = {
    "antlr": _parse_antlr,
}


def _check_case(
    case_id: str,
    input_path: Path,
    expect: dict[str, object],
    impl: Callable[[List[str]], tuple[object | None, list[str]]],
) -> str | None:
    lines = input_path.read_text(encoding="utf-8").splitlines()
    tree, errors = impl(lines)
    parse_meta = expect.get("parse", {})
    if not isinstance(parse_meta, dict):
        parse_meta = {}
    if parse_meta.get("expect_syntax_errors"):
        if not errors:
            return f"{case_id}: expected syntax errors, got none"
        return None
    if parse_meta.get("should_parse") is False:
        if tree is not None and not errors:
            return f"{case_id}: expected parse failure"
        return None
    if tree is None:
        return f"{case_id}: parser returned no tree"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="batch-spec parser conformance")
    parser.add_argument("--impl", default="antlr", choices=sorted(_IMPLEMENTATIONS))
    args = parser.parse_args()
    impl = _IMPLEMENTATIONS[args.impl]
    failures: list[str] = []
    for case_id, input_path, expect in _discover_cases():
        message = _check_case(case_id, input_path, expect, impl)
        if message:
            failures.append(message)
    if failures:
        for message in failures:
            print(message, file=sys.stderr)
        return 1
    print(f"All {len(_discover_cases())} parse cases passed ({args.impl})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''',
        encoding="utf-8",
    )

    (root / ".github" / "workflows" / "ci.yml").write_text(
        """name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.14"
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install pyyaml jsonschema antlr4-tools antlr4-python3-runtime
      - name: Validate YAML schemas
        run: python scripts/validate.py
      - name: Generate parser
        run: python scripts/generate_parser.py
      - name: Parser conformance
        run: python conformance/run_parser.py --impl antlr
""",
        encoding="utf-8",
    )

    print(f"Wrote tooling files under {root}")


if __name__ == "__main__":
    write_files()
