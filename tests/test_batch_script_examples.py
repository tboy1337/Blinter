"""Golden corpus tests for batch-script-examples (optional local folder)."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any, cast

import pytest

from blinter import BlinterConfig, find_batch_files, lint_batch_file

_CORPUS_DIR = Path(__file__).resolve().parent.parent / "batch-script-examples"
_BASELINE_PATH = Path(__file__).resolve().parent / "fixtures" / "corpus-baseline.json"


def _corpus_files() -> list[Path]:
    if not _CORPUS_DIR.is_dir():
        return []
    return sorted(
        path
        for path in _CORPUS_DIR.glob("**/*")
        if path.is_file() and path.suffix.lower() in {".bat", ".cmd"}
    )


_CORPUS_PATHS = _corpus_files()
_BASELINE_AVAILABLE = _BASELINE_PATH.is_file()


def _follow_calls_config() -> BlinterConfig:
    return BlinterConfig(follow_calls=True, scan_root=str(_CORPUS_DIR.resolve()))


def _load_baseline() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_BASELINE_PATH.read_text(encoding="utf-8")))


def _collect_noise_metrics(
    file_paths: list[Path],
    *,
    follow_calls: bool,
) -> tuple[Counter[str], int]:
    rule_counts: Counter[str] = Counter()
    overlap_lines = 0
    config = _follow_calls_config() if follow_calls else BlinterConfig()
    for file_path in file_paths:
        issues = lint_batch_file(str(file_path), config=config)
        rule_counts.update(issue.rule.code for issue in issues)
        by_line: dict[int, set[str]] = {}
        for issue in issues:
            if issue.rule.code in {"S011", "S020"}:
                by_line.setdefault(issue.line_number, set()).add(issue.rule.code)
        overlap_lines += sum(
            1 for codes in by_line.values() if codes == {"S011", "S020"}
        )
    return rule_counts, overlap_lines


def _assert_noise_limits(rule_counts: Counter[str], overlap_lines: int) -> None:
    assert rule_counts.get("S012", 0) < 500
    assert overlap_lines == 0
    assert rule_counts.get("E009", 0) <= 3
    assert rule_counts.get("E022", 0) == 0
    assert rule_counts.get("E006", 0) < 5
    assert sum(rule_counts.values()) < 14_000


@pytest.fixture(scope="module")
def corpus_available() -> bool:
    return _CORPUS_DIR.is_dir() and bool(_corpus_files())


@pytest.fixture(scope="module")
def corpus_baseline() -> dict[str, Any]:
    if not _BASELINE_AVAILABLE:
        pytest.skip("corpus-baseline.json not present")
    return _load_baseline()


@pytest.mark.skipif(not _CORPUS_PATHS, reason="batch-script-examples not present")
class TestBatchScriptExamplesCorpus:
    """Regression limits from real-world admin script corpus."""

    def test_all_corpus_files_lint_without_exception(self) -> None:
        for file_path in _corpus_files():
            lint_batch_file(str(file_path))

    def test_corpus_noise_limits(self) -> None:
        rule_counts, overlap_lines = _collect_noise_metrics(
            _corpus_files(),
            follow_calls=False,
        )
        _assert_noise_limits(rule_counts, overlap_lines)

    def test_corpus_noise_limits_follow_calls(self) -> None:
        rule_counts, overlap_lines = _collect_noise_metrics(
            _corpus_files(),
            follow_calls=True,
        )
        _assert_noise_limits(rule_counts, overlap_lines)

    def test_acopy_s012_not_per_line_spam(self) -> None:
        file_path = _CORPUS_DIR / "aCopy.BAT"
        if not file_path.is_file():
            pytest.skip("aCopy.BAT not in corpus")
        issues = lint_batch_file(str(file_path))
        s012 = [issue for issue in issues if issue.rule.code == "S012"]
        assert len(s012) <= 1


@pytest.mark.skipif(
    not _CORPUS_PATHS or not _BASELINE_AVAILABLE,
    reason="batch-script-examples or corpus-baseline.json not present",
)
class TestCorpusBaselineSnapshot:
    """Compare live corpus lint results to a local baseline snapshot."""

    @pytest.mark.slow
    def test_corpus_matches_baseline_default(
        self, corpus_baseline: dict[str, Any]
    ) -> None:
        expected = corpus_baseline["modes"]["default"]["files"]
        assert corpus_baseline["file_count"] == len(_corpus_files())
        for file_path in _corpus_files():
            issues = lint_batch_file(str(file_path))
            rule_counts = Counter(issue.rule.code for issue in issues)
            entry = expected[file_path.name]
            assert len(issues) == entry["total"], file_path.name
            assert dict(sorted(rule_counts.items())) == entry["rules"], file_path.name

    @pytest.mark.slow
    def test_corpus_matches_baseline_follow_calls(
        self, corpus_baseline: dict[str, Any]
    ) -> None:
        expected = corpus_baseline["modes"]["follow_calls"]["files"]
        config = _follow_calls_config()
        for file_path in _corpus_files():
            issues = lint_batch_file(str(file_path), config=config)
            rule_counts = Counter(issue.rule.code for issue in issues)
            entry = expected[file_path.name]
            assert len(issues) == entry["total"], file_path.name
            assert dict(sorted(rule_counts.items())) == entry["rules"], file_path.name


@pytest.mark.skipif(not _CORPUS_PATHS, reason="batch-script-examples not present")
@pytest.mark.parametrize(
    "file_path", _CORPUS_PATHS, ids=[path.name for path in _CORPUS_PATHS]
)
@pytest.mark.slow
class TestCorpusPerFileSmoke:
    """Per-file smoke tests for default and follow-calls lint modes."""

    def test_lint_default_without_exception(self, file_path: Path) -> None:
        lint_batch_file(str(file_path))

    def test_lint_follow_calls_without_exception(self, file_path: Path) -> None:
        lint_batch_file(str(file_path), config=_follow_calls_config())


@pytest.mark.skipif(not _CORPUS_PATHS, reason="batch-script-examples not present")
class TestCorpusTargetedFiles:
    """High-value corpus files with specific regression assertions."""

    def test_mas_aio_no_p026_false_positive(self) -> None:
        file_path = _CORPUS_DIR / "MAS_AIO.cmd"
        if not file_path.is_file():
            pytest.skip("MAS_AIO.cmd not in corpus")
        issues = lint_batch_file(str(file_path))
        p026 = [issue for issue in issues if issue.rule.code == "P026"]
        assert len(p026) == 0

    def test_ops_logs_no_unreachable_false_positive(self) -> None:
        file_path = _CORPUS_DIR / "OpsLogs.BAT"
        if not file_path.is_file():
            pytest.skip("OpsLogs.BAT not in corpus")
        issues = lint_batch_file(str(file_path))
        e008 = [issue for issue in issues if issue.rule.code == "E008"]
        assert len(e008) == 0

    def test_percent_mm_cmd_lints_without_error(self) -> None:
        file_path = _CORPUS_DIR / "%MM%.cmd"
        if not file_path.is_file():
            pytest.skip("%MM%.cmd not in corpus")
        issues = lint_batch_file(str(file_path))
        assert isinstance(issues, list)

    def test_setdrive_callers_bounded_e006_with_follow_calls(self) -> None:
        config = _follow_calls_config()
        for name in ("BackupDHCP.BAT", "aCopy.BAT", "SetDrive.BAT"):
            file_path = _CORPUS_DIR / name
            if not file_path.is_file():
                pytest.skip(f"{name} not in corpus")
            issues = lint_batch_file(str(file_path), config=config)
            e006 = [issue for issue in issues if issue.rule.code == "E006"]
            assert len(e006) == 0, name

    def test_find_batch_files_includes_special_filenames(self) -> None:
        discovered = find_batch_files(str(_CORPUS_DIR), recursive=True)
        names = {Path(path).name for path in discovered}
        assert len(names) == len(_corpus_files())
        assert "%MM%.cmd" in names


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
