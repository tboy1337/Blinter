"""Conformance tests for committed spec/corpus fixtures."""

from __future__ import annotations

import pytest

from blinter import lint_batch_file
from tests.spec_corpus_support import (
    assert_issues_match,
    discover_spec_corpus_cases,
)


@pytest.mark.parametrize(
    "case",
    discover_spec_corpus_cases(),
    ids=lambda case: case.id,
)
def test_spec_corpus_case(case: object) -> None:
    """Each spec/corpus case must match its expect.json oracle."""
    from tests.spec_corpus_support import SpecCorpusCase

    assert isinstance(case, SpecCorpusCase)
    issues = lint_batch_file(str(case.input_path), config=case.config)
    assert_issues_match(issues, case.expect)
