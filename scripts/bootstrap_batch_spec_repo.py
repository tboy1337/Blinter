#!/usr/bin/env python3
"""One-time bootstrap for the batch-spec repository (run from Blinter SST branch)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

BLINTER_ROOT = Path(__file__).resolve().parent.parent
BATCH_SPEC_ROOT = BLINTER_ROOT.parent / "batch-spec"

PARSE_CASES: list[tuple[str, dict[str, object]]] = [
    ("if-else-block", {"description": "IF block with ELSE", "parse": {"should_parse": True}, "tags": ["if", "blocks"]}),
    ("for-in-parens-valid", {"description": "FOR IN parenthesized list", "parse": {"should_parse": True}, "tags": ["for"]}),
    ("percent-tilde-dp0-valid", {"description": "Percent-tilde dp0 expansion", "parse": {"should_parse": True}, "tags": ["expansion"]}),
    ("e003-if-format", {"description": "IF command format", "parse": {"should_parse": True}, "tags": ["if"]}),
    ("conditional-exec-valid", {"description": "Conditional command chaining", "parse": {"should_parse": True}, "tags": ["operators"]}),
    ("if-defined-var", {"description": "IF DEFINED variable", "parse": {"should_parse": True}, "tags": ["if"]}),
    ("if-errorlevel-ge", {"description": "IF ERRORLEVEL GE comparison", "parse": {"should_parse": True}, "tags": ["if", "errorlevel"]}),
    ("for-case-distinct-valid", {"description": "FOR case consistency valid", "parse": {"should_parse": True}, "tags": ["for"]}),
    ("else-if-valid", {"description": "ELSE IF chain", "parse": {"should_parse": True}, "tags": ["if"]}),
    ("exit-shift-smoke-valid", {"description": "EXIT and SHIFT smoke", "parse": {"should_parse": True}, "tags": ["exit", "shift"]}),
    ("e021-string-substring-valid", {"description": "String substring expansion", "parse": {"should_parse": True}, "tags": ["expansion"]}),
    ("e036-if-exist-valid", {"description": "IF EXIST valid", "parse": {"should_parse": True}, "tags": ["if", "exist"]}),
    ("e040-for-do-paren-sameline-valid", {"description": "FOR DO paren same line", "parse": {"should_parse": True}, "tags": ["for"]}),
    ("e038-for-f-valid", {"description": "FOR /F valid", "parse": {"should_parse": True}, "tags": ["for"]}),
    ("e039-if-paren-sameline-valid", {"description": "IF paren same line", "parse": {"should_parse": True}, "tags": ["if"]}),
    ("w051-for-loop-valid", {"description": "FOR loop valid", "parse": {"should_parse": True}, "tags": ["for"]}),
    ("w057-bat-with-call-valid", {"description": "CALL .bat valid", "parse": {"should_parse": True}, "tags": ["call"]}),
    ("w061-pushd-popd-valid", {"description": "PUSHD POPD valid", "parse": {"should_parse": True}, "tags": ["pushd"]}),
    ("w062-cd-d-valid", {"description": "CD /D valid", "parse": {"should_parse": True}, "tags": ["cd"]}),
    ("w058-ren-valid", {"description": "REN valid", "parse": {"should_parse": True}, "tags": ["ren"]}),
    ("e041-set-p-valid", {"description": "SET /P valid", "parse": {"should_parse": True}, "tags": ["set"]}),
    ("e016-errorlevel-syntax", {"description": "ERRORLEVEL syntax", "parse": {"should_parse": True}, "tags": ["if", "errorlevel"]}),
    ("e010-for-missing-do", {"description": "FOR missing DO", "parse": {"expect_syntax_errors": True}, "tags": ["for", "negative"]}),
    ("e009-mismatched-quotes", {"description": "Mismatched quotes", "parse": {"should_parse": True}, "tags": ["quotes", "negative"]}),
    ("e001-nested-parens", {"description": "Nested parentheses", "parse": {"should_parse": True}, "tags": ["blocks"]}),
    ("e012-missing-call", {"description": "CALL label", "parse": {"should_parse": True}, "tags": ["call"]}),
    ("e017-invalid-modifier", {"description": "Invalid percent-tilde modifier", "parse": {"should_parse": True}, "tags": ["expansion", "negative"]}),
    ("e030-improper-caret", {"description": "Improper caret escape", "parse": {"should_parse": True}, "tags": ["caret", "negative"]}),
    ("e031-multilevel-caret", {"description": "Multilevel caret", "parse": {"should_parse": True}, "tags": ["caret"]}),
    ("e032-continuation-trailing-space", {"description": "Caret continuation trailing space", "parse": {"should_parse": True}, "tags": ["continuation"]}),
    ("e033-double-percent", {"description": "Double percent escaping", "parse": {"should_parse": True}, "tags": ["percent"]}),
    ("w034-useback-synonym-valid", {"description": "FOR /F usebackq", "parse": {"should_parse": True}, "tags": ["for"]}),
    ("w056-if-orange-valid", {"description": "IF OR/AND valid", "parse": {"should_parse": True}, "tags": ["if"]}),
    ("w063-for-f-token-valid", {"description": "FOR /F tokens valid", "parse": {"should_parse": True}, "tags": ["for"]}),
    ("w050-shift-valid-boundaries", {"description": "SHIFT valid boundaries", "parse": {"should_parse": True}, "tags": ["shift"]}),
    ("w044-set-a-spacing-valid", {"description": "SET /A spacing valid", "parse": {"should_parse": True}, "tags": ["set"]}),
]


def _split_commands() -> tuple[dict[str, object], dict[str, object]]:
    data = yaml.safe_load(
        (BLINTER_ROOT / "spec" / "data" / "commands.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(data, dict)
    language_keys = {
        "version",
        "builtin_commands",
        "deprecated_commands",
        "removed_commands",
        "older_windows_commands",
        "common_command_typos",
        "builtin_overlap_deprecated_notes",
    }
    linter_keys = {
        "version",
        "dangerous_command_names",
        "dangerous_command_patterns",
        "command_casing_keywords",
        "sensitive_keywords",
        "architecture_specific_patterns",
        "unicode_problematic_commands",
    }
    language = {key: data[key] for key in language_keys}
    linter = {key: data[key] for key in linter_keys}
    return language, linter


def _copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def bootstrap() -> None:
    if BATCH_SPEC_ROOT.exists():
        shutil.rmtree(BATCH_SPEC_ROOT)
    BATCH_SPEC_ROOT.mkdir(parents=True)

    (BATCH_SPEC_ROOT / "data").mkdir(parents=True, exist_ok=True)
    _copy_tree(BLINTER_ROOT / "spec" / "grammar", BATCH_SPEC_ROOT / "grammar")
    shutil.copy2(
        BLINTER_ROOT / "spec" / "data" / "expansion.yaml",
        BATCH_SPEC_ROOT / "data" / "expansion.yaml",
    )
    _copy_tree(BLINTER_ROOT / "spec" / "audit" / "cmd-help", BATCH_SPEC_ROOT / "audit" / "cmd-help")

    language_commands, linter_commands = _split_commands()
    (BATCH_SPEC_ROOT / "data" / "commands.yaml").write_text(
        yaml.safe_dump(language_commands, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
        newline="\n",
    )
    (BLINTER_ROOT / "spec" / "data" / "commands-linter.yaml").write_text(
        yaml.safe_dump(linter_commands, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
        newline="\n",
    )

    schema_dir = BATCH_SPEC_ROOT / "schema"
    schema_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        BLINTER_ROOT / "spec" / "schema" / "expansion.schema.json",
        schema_dir / "expansion.schema.json",
    )

    commands_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://batch-spec.dev/schema/commands.schema.json",
        "title": "Batch command language catalog",
        "type": "object",
        "required": ["version"],
        "properties": {
            "version": {"type": "integer", "minimum": 1},
            "builtin_commands": {"type": "array", "items": {"type": "string"}},
            "deprecated_commands": {"type": "object", "additionalProperties": {"type": "string"}},
            "removed_commands": {"type": "object", "additionalProperties": {"type": "string"}},
            "older_windows_commands": {"type": "array", "items": {"type": "string"}},
            "common_command_typos": {"type": "object", "additionalProperties": {"type": "string"}},
            "builtin_overlap_deprecated_notes": {"type": "object", "additionalProperties": {"type": "string"}},
        },
        "additionalProperties": False,
    }
    (schema_dir / "commands.schema.json").write_text(
        json.dumps(commands_schema, indent=2) + "\n", encoding="utf-8"
    )
    parse_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://batch-spec.dev/schema/parse-expect.schema.json",
        "title": "batch-spec parse corpus expect.json",
        "type": "object",
        "required": ["description"],
        "properties": {
            "description": {"type": "string", "minLength": 1},
            "tags": {"type": "array", "items": {"type": "string"}},
            "parse": {
                "type": "object",
                "properties": {
                    "should_parse": {"type": "boolean"},
                    "expect_syntax_errors": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }
    (schema_dir / "parse-expect.schema.json").write_text(
        json.dumps(parse_schema, indent=2) + "\n", encoding="utf-8"
    )

    corpus_root = BATCH_SPEC_ROOT / "corpus" / "parse"
    syntax_root = BLINTER_ROOT / "spec" / "corpus" / "syntax"
    for case_id, expect in PARSE_CASES:
        src = syntax_root / case_id / "input.cmd"
        if not src.is_file():
            print(f"WARNING: missing source case {case_id}", file=sys.stderr)
            continue
        case_dir = corpus_root / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, case_dir / "input.cmd")
        (case_dir / "expect.json").write_text(
            json.dumps(expect, indent=2) + "\n", encoding="utf-8"
        )

    shutil.copy2(BLINTER_ROOT / "COPYING", BATCH_SPEC_ROOT / "COPYING")
    (BATCH_SPEC_ROOT / "VERSION").write_text("0.1.0\n", encoding="utf-8")
    print(f"Bootstrapped {BATCH_SPEC_ROOT}")


if __name__ == "__main__":
    bootstrap()
