#!/usr/bin/env python3
"""Generate expect.json for spec corpus cases from live lint output."""

from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import sys

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from blinter import BlinterConfig, lint_batch_file  # noqa: E402

CORPUS_DIR = _REPO_ROOT / "spec" / "corpus"


def _discover_cases() -> list[Path]:
    cases: list[Path] = []
    for expect_path in sorted(CORPUS_DIR.glob("**/expect.json")):
        cases.append(expect_path.parent)
    for input_path in sorted(CORPUS_DIR.glob("**/input.cmd")):
        if not (input_path.parent / "expect.json").is_file():
            cases.append(input_path.parent)
    for input_path in sorted(CORPUS_DIR.glob("**/input.bat")):
        if not (input_path.parent / "expect.json").is_file():
            cases.append(input_path.parent)
    for cmd_path in sorted(CORPUS_DIR.glob("**/*.cmd")):
        if (
            cmd_path.name != "input.cmd"
            and not (cmd_path.parent / "expect.json").is_file()
        ):
            cases.append(cmd_path.parent)
    return sorted(set(cases))


def _primary_cmd(case_dir: Path) -> Path:
    input_cmd = case_dir / "input.cmd"
    if input_cmd.is_file():
        return input_cmd
    input_bat = case_dir / "input.bat"
    if input_bat.is_file():
        return input_bat
    scripts = sorted(case_dir.glob("*.cmd")) + sorted(case_dir.glob("*.bat"))
    if not scripts:
        raise FileNotFoundError(f"No .cmd/.bat in {case_dir}")
    return scripts[0]


def main() -> None:
    for case_dir in _discover_cases():
        cmd_path = _primary_cmd(case_dir)
        config_data: dict[str, object] = {}
        if "follow-calls" in case_dir.name:
            config_data = {
                "follow_calls": True,
                "scan_root": str(case_dir.resolve()),
            }
        config = BlinterConfig(
            follow_calls=bool(config_data.get("follow_calls", False)),
            scan_root=(
                str(config_data["scan_root"]) if config_data.get("scan_root") else None
            ),
        )
        issues = lint_batch_file(str(cmd_path), config=config)
        by_line: dict[str, list[str]] = defaultdict(list)
        rules: set[str] = set()
        for issue in issues:
            rules.add(issue.rule.code)
            by_line[str(issue.line_number)].append(issue.rule.code)
        for line, codes in by_line.items():
            by_line[line] = sorted(set(codes))
        category = (
            case_dir.parent.name
            if case_dir.parent.name in {"syntax", "integration"}
            else "syntax"
        )
        payload = {
            "description": case_dir.name.replace("-", " "),
            "rules": sorted(rules),
            "lines": dict(sorted(by_line.items(), key=lambda item: int(item[0]))),
            "must_not": [],
            "config": config_data,
            "tags": [category],
        }
        if "no-p026" in case_dir.name:
            payload["must_not"] = ["P026"]
        if case_dir.name == "unreachable-goto-flow":
            payload["must_not"] = ["E008"]
        expect_path = case_dir / "expect.json"
        expect_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {expect_path}")


if __name__ == "__main__":
    main()
