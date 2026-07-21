"""Line preprocessing for batch parsing (continuations, source mapping)."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import List


@dataclass(frozen=True)
class SourceSpan:
    """Maps a position in preprocessed text back to an original line number."""

    original_line: int
    preprocessed_line: int
    column: int = 0


@dataclass
class PreprocessedScript:
    """Result of joining continuation lines while preserving line mapping."""

    lines: List[str]  # logical lines after joining continuations
    original_lines: List[str]
    line_map: List[int]  # preprocessed line index -> original 1-based line number
    continuation_issues: List[tuple[int, str]]  # E032 during preprocess


_CONTINUATION_PATTERN = re.compile(r"\^\s*$")


def preprocess_lines(lines: List[str]) -> PreprocessedScript:
    """
    Join caret-continued lines and build a line-number map.

    Trailing whitespace after ``^`` is flagged for E032 (handled by caller).
    """
    original_lines = list(lines)
    logical: List[str] = []
    line_map: List[int] = []
    continuation_issues: List[tuple[int, str]] = []

    index = 0
    while index < len(lines):
        original_line_no = index + 1
        current = lines[index].rstrip("\r\n")
        stripped = current.rstrip()

        if stripped.endswith("^"):
            line_no_newline = lines[index].rstrip("\r\n")
            if not line_no_newline.endswith("^"):
                continuation_issues.append((original_line_no, "E032"))

            merged = stripped[:-1]
            next_index = index + 1
            while next_index < len(lines):
                next_line = lines[next_index].rstrip("\r\n")
                merged += next_line.lstrip()
                next_stripped = next_line.rstrip()
                if not next_stripped.endswith("^"):
                    index = next_index
                    break
                line_no_newline = lines[next_index].rstrip("\r\n")
                if not line_no_newline.endswith("^"):
                    continuation_issues.append((next_index + 1, "E032"))
                merged = merged + next_stripped[:-1]
                next_index += 1
            else:
                index = next_index - 1 if next_index > index + 1 else index

            logical.append(merged)
            line_map.append(original_line_no)
            index += 1
            continue

        logical.append(current)
        line_map.append(original_line_no)
        index += 1

    return PreprocessedScript(
        lines=logical,
        original_lines=original_lines,
        line_map=line_map,
        continuation_issues=continuation_issues,
    )


def map_line_number(preprocessed: PreprocessedScript, preprocessed_line: int) -> int:
    """Map a 1-based preprocessed line number to original source line."""
    if preprocessed_line < 1:
        return 1
    if preprocessed_line > len(preprocessed.line_map):
        return preprocessed.line_map[-1] if preprocessed.line_map else preprocessed_line
    return preprocessed.line_map[preprocessed_line - 1]
