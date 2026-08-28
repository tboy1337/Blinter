"""Conformance tests for committed spec/corpus fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from blinter import lint_batch_file
from tests.spec_corpus_support import (
    SpecCorpusCase,
    assert_issues_match,
    discover_spec_corpus_cases,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    "case",
    discover_spec_corpus_cases(),
    ids=lambda case: case.id,
)
def test_spec_corpus_case(case: object) -> None:
    """Each spec/corpus case must match its expect.json oracle."""
    assert isinstance(case, SpecCorpusCase)
    issues = lint_batch_file(str(case.input_path), config=case.config)
    assert_issues_match(issues, case.expect)


def test_documented_corpus_count_matches_fixtures() -> None:
    """Docs and funding copy must track the committed corpus size."""
    count = len(discover_spec_corpus_cases())
    architecture = (_REPO_ROOT / "docs" / "Architecture.md").read_text(encoding="utf-8")
    spec_readme = (_REPO_ROOT / "spec" / "README.md").read_text(encoding="utf-8")
    funding = (_REPO_ROOT / "funding.json").read_text(encoding="utf-8")
    assert f"{count} committed fixtures" in architecture
    assert f"{count}-case conformance corpus" in spec_readme
    assert f"{count}-case conformance corpus" in funding


def test_wmic_read_only_corpus_is_oracle_runnable() -> None:
    """Read-only WMIC queries still ship on Windows 10 and must be executable.

    Absence on Windows 11 is a fast cmd.exe error (oracle-acceptable). Skip
    only interactive or mutating WMIC, not ``wmic os get``.
    """
    skip_text = (
        _REPO_ROOT / "spec" / "corpus" / "meta" / "oracle-skip.yaml"
    ).read_text(encoding="utf-8")
    expect = (
        _REPO_ROOT
        / "spec"
        / "corpus"
        / "syntax"
        / "w024-deprecated-wmic"
        / "expect.json"
    ).read_text(encoding="utf-8")
    oracle_src = (_REPO_ROOT / "scripts" / "spec" / "cmd_oracle.py").read_text(
        encoding="utf-8"
    )
    assert "syntax/w024-deprecated-wmic" not in skip_text
    assert '"oracle": "run"' in expect
    assert "interactive wmic prompt" in oracle_src
    assert "mutating wmic" in oracle_src
    assert "hangs or is absent on modern Windows" not in oracle_src
