"""Tests for rules.yaml SSOT and registry codegen."""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
import sys
from types import ModuleType

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_YAML = REPO_ROOT / "spec" / "data" / "rules.yaml"


def test_rules_yaml_matches_registry() -> None:
    """rules.yaml must round-trip to the generated RULES dict."""
    data = yaml.safe_load(RULES_YAML.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    yaml_rules = data["rules"]

    if str(REPO_ROOT / "src") not in sys.path:
        sys.path.insert(0, str(REPO_ROOT / "src"))
    registry = importlib.import_module("blinter.rules.registry")
    importlib.reload(registry)

    assert len(yaml_rules) == registry.RULE_COUNT
    for entry in yaml_rules:
        code = entry["code"]
        rule = registry.RULES[code]
        assert rule.name == entry["name"]
        assert rule.severity.name == entry["severity"]
        assert rule.explanation == entry["explanation"]
        assert rule.recommendation == entry["recommendation"]


def _load_cmd_oracle_module() -> ModuleType:
    path = REPO_ROOT / "scripts" / "spec" / "cmd_oracle.py"
    spec = importlib.util.spec_from_file_location("cmd_oracle", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cmd_oracle_blocks_unsafe_fixture_content() -> None:
    """cmd_oracle must never execute fork bombs or interactive fixtures."""
    oracle = _load_cmd_oracle_module()
    case_dir = REPO_ROOT / "spec" / "corpus" / "syntax" / "e001-nested-parens"
    fork_bomb = '@echo off\n:loop\nstart "" %0\ngoto loop\n'
    assert oracle._content_unsafe_reason(fork_bomb, case_dir) is not None
    assert oracle._content_unsafe_reason("@echo off\necho ok\n", case_dir) is None


def test_cmd_oracle_allows_safe_call_and_wmic() -> None:
    """Refined heuristics allow internal CALL, co-located scripts, and read-only wmic."""
    oracle = _load_cmd_oracle_module()
    case_dir = REPO_ROOT / "spec" / "corpus" / "integration" / "call-subroutine-e012"
    call_sub = "@echo off\nCALL :sub\necho ok\n"
    assert oracle._content_unsafe_reason(call_sub, case_dir) is None

    follow_dir = REPO_ROOT / "spec" / "corpus" / "integration" / "follow-calls-e006"
    follow = "@echo off\ncall helper.cmd\n"
    assert oracle._content_unsafe_reason(follow, follow_dir) is None

    wmic_dir = REPO_ROOT / "spec" / "corpus" / "syntax" / "w024-deprecated-wmic"
    wmic = "@echo off\nwmic os get caption\n"
    assert oracle._content_unsafe_reason(wmic, wmic_dir) is None


def test_cmd_oracle_allows_specific_del() -> None:
    """del without wildcards on a single file is safe for oracle."""
    oracle = _load_cmd_oracle_module()
    case_dir = REPO_ROOT / "spec" / "corpus" / "integration" / "p001-redundant-exist"
    text = "@echo off\nif exist file.txt del file.txt\n"
    assert oracle._content_unsafe_reason(text, case_dir) is None


def test_cmd_oracle_skips_denylisted_cases() -> None:
    """Denylisted fixtures must not run even when content looks benign."""
    oracle = _load_cmd_oracle_module()
    skip_ids = oracle._load_skip_ids()
    case_id = "integration/sec021-fork-bomb"
    input_path = REPO_ROOT / "spec" / "corpus" / case_id / "input.cmd"
    reason = oracle._skip_reason(input_path, case_id, skip_ids)
    assert reason is not None
    assert "fork" in reason.lower() or "start" in reason.lower()


def test_cmd_oracle_runs_safe_security_echo_fixture() -> None:
    """Echo-only security fixtures are runnable after denylist refactor."""
    oracle = _load_cmd_oracle_module()
    skip_ids = oracle._load_skip_ids()
    case_id = "integration/sec010-sensitive-echo"
    input_path = REPO_ROOT / "spec" / "corpus" / case_id / "input.cmd"
    reason = oracle._skip_reason(input_path, case_id, skip_ids)
    assert reason is None


def test_cmd_oracle_run_mode_bypasses_heuristics(tmp_path: Path) -> None:
    """expect.json oracle=run bypasses content heuristics."""
    oracle = _load_cmd_oracle_module()
    case_dir = tmp_path / "syntax" / "taskkill-case"
    case_dir.mkdir(parents=True)
    (case_dir / "input.cmd").write_text(
        "@echo off\ntaskkill /im notepad.exe\n", encoding="utf-8"
    )
    (case_dir / "expect.json").write_text(
        '{"description": "test", "oracle": "run"}', encoding="utf-8"
    )
    input_path = case_dir / "input.cmd"
    reason = oracle._skip_reason(input_path, "syntax/taskkill-case", {})
    assert reason is None
