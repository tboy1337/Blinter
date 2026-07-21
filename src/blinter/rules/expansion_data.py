"""Batch expansion constants generated from spec/data/expansion.yaml.

THIS FILE IS GENERATED — edit spec/data/expansion.yaml and run:
  py scripts/spec/generate_expansion.py
"""

from __future__ import annotations

from typing import FrozenSet, Tuple

VALID_MODIFIER_CHARS: str = "nxfpdstaz"
VALID_MODIFIERS: FrozenSet[str] = frozenset(
    {
        "$",
        "a",
        "d",
        "f",
        "n",
        "p",
        "s",
        "t",
        "x",
        "z",
    }
)

VALID_CARET_COUNTS: Tuple[int, ...] = (1, 3, 7, 15, 31)

DELAYED_EXPANSION_PATTERN: str = "!VAR!"
DELAYED_EXPANSION_REQUIRES_SETLOCAL: bool = True
DELAYED_EXPANSION_ENABLE_KEYWORDS: Tuple[str, ...] = (
    "setlocal enabledelayedexpansion",
    "setlocal enableextensions enabledelayedexpansion",
)

VALID_COMBINED_TILDE_EXAMPLES: Tuple[str, ...] = (
    "%~dpnx1%",
    "%~f1%",
    "%~nx1%",
    "%~dp0%",
    "%~z0%",
    "%~ftza1%",
)

INVALID_TILDE_COMBINATION_REASONS: Tuple[str, ...] = (
    "%~ modifiers may not be used with %* (CALL /?)",
    "Percent-tilde requires parameter 0-9 or single FOR loop letter",
)

STRING_SUBSTRING_PATTERN: str = "%var:~start,length%"
STRING_REPLACEMENT_PATTERN: str = "%var:old=new%"
