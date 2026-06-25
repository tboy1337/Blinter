"""Golden corpus tests for batch-script-examples (optional local folder)."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from blinter import BlinterConfig, lint_batch_file

_CORPUS_DIR = Path(__file__).resolve().parent.parent / "batch-script-examples"


def _corpus_files() -> list[Path]:
    if not _CORPUS_DIR.is_dir():
        return []
    return sorted(
        path
        for path in _CORPUS_DIR.glob("**/*")
        if path.is_file() and path.suffix.lower() in {".bat", ".cmd"}
    )


@pytest.fixture(scope="module")
def corpus_available() -> bool:
    return _CORPUS_DIR.is_dir() and bool(_corpus_files())


@pytest.mark.skipif(not _corpus_files(), reason="batch-script-examples not present")
class TestBatchScriptExamplesCorpus:
    """Regression limits from real-world admin script corpus."""

    def test_all_corpus_files_lint_without_exception(self) -> None:
        for file_path in _corpus_files():
            lint_batch_file(str(file_path))

    def test_corpus_noise_limits(self) -> None:
        rule_counts: Counter[str] = Counter()
        overlap_lines = 0

        for file_path in _corpus_files():
            issues = lint_batch_file(str(file_path))
            rule_counts.update(issue.rule.code for issue in issues)
            by_line: dict[int, set[str]] = {}
            for issue in issues:
                if issue.rule.code in {"S011", "S020"}:
                    by_line.setdefault(issue.line_number, set()).add(issue.rule.code)
            overlap_lines += sum(
                1 for codes in by_line.values() if codes == {"S011", "S020"}
            )

        assert rule_counts.get("S012", 0) < 500
        assert overlap_lines == 0
        assert rule_counts.get("E009", 0) <= 3
        assert rule_counts.get("E022", 0) == 0
        assert rule_counts.get("E006", 0) < 5
        assert sum(rule_counts.values()) < 14_000

    def test_acopy_s012_not_per_line_spam(self) -> None:
        file_path = _CORPUS_DIR / "aCopy.BAT"
        if not file_path.is_file():
            pytest.skip("aCopy.BAT not in corpus")
        issues = lint_batch_file(str(file_path))
        s012 = [issue for issue in issues if issue.rule.code == "S012"]
        assert len(s012) <= 1


class TestNamingRuleRegression:
    """S022 global naming and S017 per-line case checks."""

    def test_global_mixed_naming_emits_single_s022(self, tmp_path: Path) -> None:
        content = "@echo off\n" "set MY_VAR=1\n" "set other_var=2\n" "set Another=3\n"
        batch_file = tmp_path / "mixed.cmd"
        batch_file.write_text(content, encoding="utf-8")
        issues = lint_batch_file(str(batch_file))
        s022 = [issue for issue in issues if issue.rule.code == "S022"]
        s006 = [issue for issue in issues if issue.rule.code == "S006"]
        assert len(s022) == 1
        assert len(s006) == 0

    def test_per_line_case_mismatch_emits_s017(self, tmp_path: Path) -> None:
        content = "@echo off\n" "set MYVAR=1\n" "set myvar=2\n"
        batch_file = tmp_path / "case.cmd"
        batch_file.write_text(content, encoding="utf-8")
        issues = lint_batch_file(str(batch_file))
        s017 = [issue for issue in issues if issue.rule.code == "S017"]
        assert len(s017) >= 1

    def test_disabled_s022_suppresses_global_naming(self, tmp_path: Path) -> None:
        content = "@echo off\n" "set MY_VAR=1\n" "set other_var=2\n" "set Another=3\n"
        batch_file = tmp_path / "mixed.cmd"
        batch_file.write_text(content, encoding="utf-8")
        config = BlinterConfig(disabled_rules={"S022"})
        issues = lint_batch_file(str(batch_file), config=config)
        assert not [issue for issue in issues if issue.rule.code == "S022"]


class TestRuleRegistryCoverage:
    """Every registered rule must be referenced by a checker or pattern."""

    def test_all_rules_referenced_in_implementation(self) -> None:
        from blinter.rules.registry import RULES  # noqa: PLC0415

        src_root = Path(__file__).resolve().parent.parent / "src" / "blinter"
        search_paths = [
            src_root / "checkers",
            src_root / "patterns.py",
            src_root / "parsing",
            src_root / "rules",
        ]
        combined_source = ""
        for path in search_paths:
            if path.is_file():
                combined_source += path.read_text(encoding="utf-8")
                continue
            for py_file in path.rglob("*.py"):
                combined_source += py_file.read_text(encoding="utf-8")

        orphans = [
            code
            for code in RULES
            if f'"{code}"' not in combined_source
            and f'RULES["{code}"]' not in combined_source
            and f"RULES['{code}']" not in combined_source
        ]
        assert not orphans, f"Orphan rules without checker references: {orphans}"
