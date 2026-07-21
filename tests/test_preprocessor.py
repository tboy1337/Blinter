"""Tests for line preprocessor."""

from __future__ import annotations

from blinter.parsing.preprocessor import map_line_number, preprocess_lines


def test_preprocess_joins_caret_continuation() -> None:
    lines = ["echo hello ^", "world", "echo done"]
    result = preprocess_lines(lines)
    assert len(result.lines) == 2
    assert result.lines[0] == "echo hello world"
    assert map_line_number(result, 1) == 1


def test_preprocess_flags_trailing_space_after_caret() -> None:
    lines = ["echo part1 ^ ", "part2"]
    result = preprocess_lines(lines)
    assert any(code == "E032" for _, code in result.continuation_issues)
