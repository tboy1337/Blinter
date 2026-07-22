"""Performance smoke tests for Blinter lint throughput."""

from __future__ import annotations

import os
import tempfile

import pytest

from blinter import lint_batch_file


def _build_thousand_line_batch() -> str:
    lines = ["@echo off", "setlocal"]
    for index in range(498):
        lines.append(f'set "VAR{index}=value{index}"')
        lines.append(f"echo %VAR{index}%")
    lines.extend(["endlocal", "exit /b 0"])
    return "\n".join(lines)


class TestLintPerformance:
    """Guard against major lint throughput regressions."""

    @pytest.mark.slow
    @pytest.mark.timeout(10)
    def test_thousand_line_file_lints_within_ceiling(self) -> None:
        """A ~1000-line script should lint within a generous time ceiling."""
        content = _build_thousand_line_batch()
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".bat",
            delete=False,
            encoding="utf-8",
        ) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            issues = lint_batch_file(temp_path)
            assert isinstance(issues, list)
        finally:
            os.unlink(temp_path)
