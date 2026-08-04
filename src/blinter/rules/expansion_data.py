"""Batch expansion constants generated from vendor/batch-spec/data/expansion.yaml.

THIS FILE IS GENERATED — edit vendor/batch-spec/data/expansion.yaml and run:
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

DELAYED_EXPANSION_PATTERN: str = "!VAR!"
DELAYED_EXPANSION_REQUIRES_SETLOCAL: bool = False
DELAYED_EXPANSION_ENABLE_KEYWORDS: Tuple[str, ...] = (
    "setlocal enabledelayedexpansion",
    "setlocal enableextensions enabledelayedexpansion",
)

VALID_COMBINED_TILDE_EXAMPLES: Tuple[str, ...] = (
    "%~1",
    "%~dpnx1",
    "%~f1",
    "%~nx1",
    "%~fs1",
    "%~dp0",
    "%~z0",
    "%~ftza1",
    "%~dp$PATH:1",
)

INVALID_TILDE_COMBINATION_REASONS: Tuple[str, ...] = (
    "%~ modifiers may not be used with %* (CALL /?)",
    "Percent-tilde letter modifiers must be from nxfpdstaz (case-insensitive; CALL /?, FOR /?); the parameter must be 0-9, *, or a path-search $ENV: form",
)

STRING_SUBSTRING_PATTERN: str = "%var:~start,length%"
STRING_REPLACEMENT_PATTERN: str = "%var:old=new%"
