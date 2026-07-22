"""Shared delayed-expansion token checks for fast and ANTLR syntax paths."""

from __future__ import annotations

import re
from typing import List

from blinter.models import LintIssue
from blinter.parsing.antlr_bridge import _detect_delayed_expansion
from blinter.rules.registry import RULES

# Any delayed-expansion span between exclamation marks (substitution, !@var!, etc.).
_ANY_BANG_SPAN_RE = re.compile(r"![^!]+!", re.IGNORECASE)


def resolve_delayed_expansion(
    has_delayed_expansion: bool,
    lines: List[str],
) -> bool:
    """Return whether delayed expansion is active for grammar token checks."""
    return has_delayed_expansion or _detect_delayed_expansion(lines)


def check_delayed_expansion_bang_var_tokens(
    stripped: str,
    line_number: int,
    *,
    effective_delayed_expansion: bool,
) -> List[LintIssue]:
    """
    Grammar-token checks for delayed-expansion ``!...!`` references.

    When delayed expansion is disabled, well-formed ``!ident!`` tokens are left
    to W022/P008 enablement rules. When enabled, flag leftover ``!`` markers
    that indicate incomplete or malformed expansion after valid spans are removed.
    """
    issues: List[LintIssue] = []
    if not effective_delayed_expansion:
        return issues

    scratch = _ANY_BANG_SPAN_RE.sub("", stripped)
    if "!" not in scratch:
        return issues

    if re.search(r"![A-Za-z0-9_@]+(?:[^!]|$)", scratch, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["E011"],
                context="Invalid delayed expansion token syntax",
            )
        )
    return issues
