"""Parity tests between fast syntax scanning and ANTLR-backed visitor."""

from __future__ import annotations

import pytest

from blinter.parsing.fast_syntax import check_grammar_backed_syntax_fast
from blinter.parsing.grammar_rules import GRAMMAR_BACKED_RULE_CODES
from blinter.parsing.visitors.syntax_visitor import check_ast_syntax_rules_antlr
from tests.spec_corpus_support import SpecCorpusCase, discover_spec_corpus_cases


def _issue_keys(issues: object) -> set[tuple[int, str]]:
    from blinter.models import LintIssue

    assert isinstance(issues, list)
    keys: set[tuple[int, str]] = set()
    for issue in issues:
        assert isinstance(issue, LintIssue)
        if issue.rule.code in GRAMMAR_BACKED_RULE_CODES:
            keys.add((issue.line_number, issue.rule.code))
    return keys


@pytest.mark.parametrize(
    "case",
    [
        case
        for case in discover_spec_corpus_cases()
        if isinstance(case, SpecCorpusCase)
        and any(
            rule in GRAMMAR_BACKED_RULE_CODES
            for rule in case.expect.get("rules", [])
            if isinstance(rule, str)
        )
    ],
    ids=lambda case: case.id if isinstance(case, SpecCorpusCase) else str(case),
)
def test_fast_syntax_matches_antlr_on_grammar_corpus_cases(case: object) -> None:
    """Fast scanner should emit the same grammar-backed issues as ANTLR visitor."""
    assert isinstance(case, SpecCorpusCase)
    lines = case.input_path.read_text(encoding="utf-8").splitlines()
    fast_keys = _issue_keys(check_grammar_backed_syntax_fast(lines))
    antlr_keys = _issue_keys(check_ast_syntax_rules_antlr(lines))
    assert fast_keys == antlr_keys, (
        f"Mismatch for {case.id}: fast-only={fast_keys - antlr_keys}, "
        f"antlr-only={antlr_keys - fast_keys}"
    )


def test_fast_syntax_matches_antlr_with_delayed_expansion_enabled() -> None:
    """Fast and ANTLR paths should agree when delayed expansion is active."""
    lines = [
        "@echo off",
        "setlocal enabledelayedexpansion",
        "echo !notclosed",
    ]
    fast_keys = _issue_keys(check_grammar_backed_syntax_fast(lines))
    antlr_keys = _issue_keys(check_ast_syntax_rules_antlr(lines))
    assert fast_keys == antlr_keys
    assert fast_keys == {(3, "E011")}


def test_bang_e011_requires_active_delayed_expansion() -> None:
    """Incomplete bang variables should not raise E011 when DE is inactive."""
    lines = ["@echo off", "echo !notclosed"]
    keys = _issue_keys(check_grammar_backed_syntax_fast(lines))
    assert "E011" not in {code for _, code in keys}


def test_bang_e011_after_disable_region() -> None:
    """Incomplete bang variables after disable should not raise E011."""
    lines = [
        "setlocal enabledelayedexpansion",
        "echo !ok!",
        "setlocal disabledelayedexpansion",
        "echo !literal_open",
    ]
    keys = _issue_keys(check_grammar_backed_syntax_fast(lines))
    assert "E011" not in {code for _, code in keys}


def test_bang_e011_ignores_rem_only_enable_hint() -> None:
    """REM mentions of enabledelayedexpansion must not enable bang E011."""
    lines = ["rem setlocal enabledelayedexpansion", "echo !notclosed"]
    keys = _issue_keys(check_grammar_backed_syntax_fast(lines))
    assert "E011" not in {code for _, code in keys}


def test_bang_e011_flags_incomplete_var_when_delayed_expansion_active() -> None:
    """Incomplete delayed-expansion spans should raise E011 when DE is active."""
    lines = ["setlocal enabledelayedexpansion", "echo !notclosed"]
    keys = _issue_keys(check_grammar_backed_syntax_fast(lines))
    assert keys == {(2, "E011")}


def test_bang_e011_allows_special_char_vars_when_delayed_expansion_active() -> None:
    """Special-character delayed expansion variables must not raise grammar E011."""
    lines = [
        "setlocal enabledelayedexpansion",
        "echo !@DEBUG_MODE!",
    ]
    keys = _issue_keys(check_grammar_backed_syntax_fast(lines))
    assert "E011" not in {code for _, code in keys}
