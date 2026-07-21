"""Parser tests for spec corpus inputs."""

from __future__ import annotations

import pytest

from blinter.parsing.antlr_bridge import parse_batch_lines
from tests.spec_corpus_support import discover_spec_corpus_cases


@pytest.mark.parametrize(
    "case",
    discover_spec_corpus_cases(),
    ids=lambda case: case.id,
)
def test_spec_corpus_parses(case: object) -> None:
    """Every corpus input.cmd should parse without fatal ANTLR failure."""
    from tests.spec_corpus_support import SpecCorpusCase

    assert isinstance(case, SpecCorpusCase)
    lines = case.input_path.read_text(encoding="utf-8").splitlines()
    result = parse_batch_lines(lines)
    assert result.tree is not None
    parse_meta = case.expect.get("parse", {})
    if isinstance(parse_meta, dict) and parse_meta.get("expect_syntax_errors"):
        assert result.errors, "Expected ANTLR syntax errors"
    elif isinstance(parse_meta, dict) and parse_meta.get("should_parse") is False:
        assert result.errors
    else:
        # Non-fatal: tree is produced even with lexer/parser messages
        assert result.preprocessed.lines
