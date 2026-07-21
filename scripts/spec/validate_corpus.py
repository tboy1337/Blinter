#!/usr/bin/env python3
"""Validate every spec/corpus expect.json fixture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

import jsonschema
import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))
if str(_REPO_ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "tests"))

from blinter import lint_batch_file  # noqa: E402
from spec_corpus_support import (  # noqa: E402
    CORPUS_DIR,
    assert_issues_match,
    discover_spec_corpus_cases,
)

_SCHEMA = json.loads(
    (_REPO_ROOT / "spec" / "schema" / "corpus-expect.schema.json").read_text(
        encoding="utf-8"
    )
)
_RULES_YAML = yaml.safe_load(
    (_REPO_ROOT / "spec" / "data" / "rules.yaml").read_text(encoding="utf-8")
)
_VALID_RULES = {entry["code"] for entry in _RULES_YAML["rules"]}
_CORPUS_INDEX = _REPO_ROOT / "spec" / "corpus" / "meta" / "corpus-index.yaml"


def _validate_rule_refs(expect: dict[str, object], expect_path: Path) -> None:
    for rule in expect.get("rules", []):
        if rule not in _VALID_RULES:
            raise ValueError(f"Unknown rule {rule} in {expect_path}")
    lines = expect.get("lines", {})
    if isinstance(lines, dict):
        for codes in lines.values():
            for rule in codes:
                if rule not in _VALID_RULES:
                    raise ValueError(f"Unknown rule {rule} in {expect_path}")
    for rule in expect.get("must_not", []):
        if rule not in _VALID_RULES:
            raise ValueError(f"Unknown must_not rule {rule} in {expect_path}")
    config = expect.get("config", {})
    if isinstance(config, dict):
        for key in ("disabled_rules", "enabled_rules"):
            values = config.get(key)
            if values:
                for rule in values:
                    if rule not in _VALID_RULES:
                        raise ValueError(
                            f"Unknown config.{key} rule {rule} in {expect_path}"
                        )


def _validate_case_naming(expect: dict[str, object], expect_path: Path) -> None:
    case_id = expect_path.parent.name
    if case_id.endswith("-valid"):
        return
    match = re.match(r"^e(\d{3})-", case_id, re.IGNORECASE)
    if not match:
        return
    expected_rule = f"E{match.group(1)}"
    asserted: set[str] = set(expect.get("rules", []))
    lines = expect.get("lines", {})
    if isinstance(lines, dict):
        for codes in lines.values():
            if isinstance(codes, list):
                asserted.update(str(code) for code in codes)
    if expected_rule not in asserted:
        raise ValueError(
            f"{expect_path} is named for {expected_rule} but expect.json does not assert it"
        )


def _validate_corpus_index_tags(expect: dict[str, object], expect_path: Path) -> None:
    if not _CORPUS_INDEX.is_file():
        return
    index = yaml.safe_load(_CORPUS_INDEX.read_text(encoding="utf-8"))
    if not isinstance(index, dict):
        return
    allowed_tags: set[str] = set()
    tags_section = index.get("tags", {})
    if isinstance(tags_section, dict):
        allowed_tags.update(tags_section.keys())
        for values in tags_section.values():
            if isinstance(values, list):
                allowed_tags.update(str(v) for v in values)
    for tag in expect.get("tags", []):
        if allowed_tags and tag not in allowed_tags:
            raise ValueError(f"Unknown corpus tag {tag!r} in {expect_path}")
    max_total = index.get("aggregate_limits", {}).get("max_total_issues_per_case")
    if max_total is not None and expect.get("total") is not None:
        if int(expect["total"]) > int(max_total):
            raise ValueError(
                f"total {expect['total']} exceeds corpus max {max_total} in {expect_path}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate SSOT corpus fixtures")
    parser.add_argument(
        "--lint-only",
        action="store_true",
        help="Only run live lint assertions, skip schema",
    )
    args = parser.parse_args()

    cases = discover_spec_corpus_cases()
    if not cases:
        raise SystemExit(f"No corpus cases under {CORPUS_DIR}")

    for case in cases:
        expect_path = case.case_dir / "expect.json"
        if not args.lint_only:
            jsonschema.validate(instance=case.expect, schema=_SCHEMA)
            _validate_rule_refs(case.expect, expect_path)
            _validate_case_naming(case.expect, expect_path)
            _validate_corpus_index_tags(case.expect, expect_path)
        issues = lint_batch_file(str(case.input_path), config=case.config)
        assert_issues_match(issues, case.expect)
        print(f"OK {case.id}")

    print(f"Validated {len(cases)} corpus cases")


if __name__ == "__main__":
    main()
