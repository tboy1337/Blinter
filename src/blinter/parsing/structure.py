"""Label collection, script structure, and subroutine detection."""

import re
from typing import (
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)

from blinter.constants import BUILTIN_VARS
from blinter.models import LintIssue
from blinter.patterns import (
    _COMPILED_SETLOCAL_DISABLE,
)
from blinter.rules.helpers import _add_issue

_LABEL_TARGET_PATTERN = re.compile(
    r"\b(?:call|goto)\s+(:[^\s]+)",
    re.IGNORECASE,
)


def _collect_labels(lines: List[str]) -> Tuple[Dict[str, int], List[LintIssue]]:
    """Collect all labels and detect duplicates."""
    labels: Dict[str, int] = {}
    issues: List[LintIssue] = []

    for i, line in enumerate(lines, start=1):
        stripped_line = line.strip()
        if stripped_line.startswith(":"):
            # Skip comment-style lines that start with :: (double colon)
            if stripped_line.startswith("::"):
                continue

            label = stripped_line.lower()

            # Skip comment-style labels (like :::) that contain no alphanumeric characters
            # These are commonly used as decorative comments and should not be flagged as duplicates
            label_content = label[1:]  # Remove the leading ":"
            if not re.search(r"[a-zA-Z0-9]", label_content):
                # This is a comment-style label like ::::::, skip it
                continue

            if label in labels:
                _add_issue(
                    issues,
                    line_number=i,
                    rule_code="W013",
                    context=f"Label '{label}' already defined on line {labels[label]}",
                )
            else:
                labels[label] = i

    return labels, issues


def _normalize_label_target(raw_target: str) -> str:
    """Normalize CALL/GOTO label targets to match ``labels`` dict keys."""
    target = raw_target.strip().lower()
    if not target.startswith(":"):
        target = f":{target}"
    return target


_INVOCATION_PREFIX_CACHE: Dict[int, List[Set[str]]] = {}


def clear_invocation_prefix_cache() -> None:
    """Clear cached invocation-prefix data between lint passes."""
    _INVOCATION_PREFIX_CACHE.clear()


def _build_invocation_prefix(lines: List[str]) -> List[Set[str]]:
    """
    For each line index, return labels invoked on all prior lines.

    ``prefix[i]`` contains CALL/GOTO targets from lines ``0..i-1`` (0-based).
    """
    prefix: List[Set[str]] = []
    targeted: Set[str] = set()
    for line in lines:
        prefix.append(set(targeted))
        for match in _LABEL_TARGET_PATTERN.finditer(line):
            targeted.add(_normalize_label_target(match.group(1)))
    return prefix


def _invocation_prefix_for_lines(lines: List[str]) -> List[Set[str]]:
    """Return cached invocation prefix for ``lines`` within a single lint pass."""
    lines_id = id(lines)
    cached = _INVOCATION_PREFIX_CACHE.get(lines_id)
    if cached is None:
        cached = _build_invocation_prefix(lines)
        _INVOCATION_PREFIX_CACHE[lines_id] = cached
    return cached


def _labels_targeted_before(lines: List[str], before_line: int) -> Set[str]:
    """Collect label names referenced by CALL/GOTO before ``before_line``."""
    if before_line <= 1:
        return set()
    prefix = _invocation_prefix_for_lines(lines)
    return prefix[before_line - 1]


def _label_block_for_line(
    line_number: int, sorted_labels: List[Tuple[str, int]], total_lines: int
) -> Optional[Tuple[str, int]]:
    """
    Return (label_name, label_line) for the block containing ``line_number``.

    Label bodies span from the line after the label until the next label (exclusive).
    """
    for index, (label_name, label_line) in enumerate(sorted_labels):
        next_label_line = (
            sorted_labels[index + 1][1]
            if index + 1 < len(sorted_labels)
            else total_lines + 1
        )
        if label_line < line_number < next_label_line:
            return label_name, label_line
    return None


def _label_sort_key(item: tuple[str, int]) -> int:
    """Sort label entries by line number."""
    return item[1]


def _is_in_subroutine_context(
    lines: List[str], line_number: int, labels: Dict[str, int]
) -> bool:
    """
    Determine if a line is within an invoked subroutine context.

    A line is in subroutine context when it falls inside a label block that was
    reached via an earlier ``CALL :label`` or ``GOTO :label``. Main-line fall-through
    into a label without a prior transfer is not treated as subroutine context.
    """
    if not labels or line_number < 1:
        return False

    sorted_labels = sorted(labels.items(), key=_label_sort_key)
    block = _label_block_for_line(line_number, sorted_labels, len(lines))
    if block is None:
        return False

    label_name, label_line = block
    return label_name in _labels_targeted_before(lines, line_number)


_SET_VAR_NAME = r"[A-Za-z0-9_@]+"
# CALL :label varname — first argument names a variable set via SET "%1=" in :label
_CALL_LABEL_VAR_PATTERN = re.compile(
    rf"\bcall\s+:\w+\s+({_SET_VAR_NAME})\b",
    re.IGNORECASE,
)


def _collect_set_variables(lines: List[str]) -> Set[str]:
    """Collect all variables that are set in the script."""
    set_vars: Set[str] = set()
    vn = _SET_VAR_NAME
    for line in lines:
        # Match different SET patterns, including quoted variable names
        # Use re.search instead of re.match to find SET commands anywhere in the line
        # This handles cases like: if not defined VAR set "VAR=value"
        patterns = [
            rf"\bset\s+({vn})=",  # Regular set: set VAR=value
            rf'\bset\s+"({vn})=',  # Quoted set: set "VAR=value"
            rf"\bset\s+/p\s+({vn})=",  # Set with prompt: set /p VAR=
            rf'\bset\s+/p\s+"({vn})=',  # Quoted set with prompt: set /p "VAR="
            rf"\bset\s+/a\s+({vn})=",  # Arithmetic set: set /a VAR=
            rf'\bset\s+/a\s+"({vn})=',  # Quoted arithmetic set: set /a "VAR="
            rf"\bset\s+/a\s+({vn})[+\-*/%]?=",  # Compound: set /a VAR+=1
            rf'\bset\s+/a\s+"({vn})[+\-*/%]?=',  # Quoted compound set /a
        ]

        stripped_line = line.strip()
        for pattern in patterns:
            for set_match in re.finditer(pattern, stripped_line, re.IGNORECASE):
                var_name_text: str = set_match.group(1)
                set_vars.add(var_name_text.upper())

        for call_match in _CALL_LABEL_VAR_PATTERN.finditer(stripped_line):
            set_vars.add(str(call_match.group(1)).upper())

        # Handle dynamic variable assignments in FOR loops: set "%%~b=value"
        # Example: for %%a in (list) do (set "%%~a=value")
        dynamic_set_match = re.search(
            r'\bset\s+"%%~[a-zA-Z]=', line.strip(), re.IGNORECASE
        )
        if dynamic_set_match:
            # When we see dynamic variable assignment, we need to look for what values
            # the FOR loop might iterate over to determine variable names
            # For now, mark this as a script that uses dynamic variables
            # and be more lenient with undefined variable warnings
            set_vars.add("__DYNAMIC_VARS__")

    set_vars.update(BUILTIN_VARS)

    return set_vars


def _parse_suppression_comments(lines: List[str]) -> Dict[int, Set[str]]:
    """
    Parse inline suppression comments from batch file lines.

    Supports formats:
    - REM LINT:IGNORE <code> - Suppress code on the next line
    - REM LINT:IGNORE - Suppress all issues on the next line
    - REM LINT:IGNORE-LINE <code> - Suppress code on the same line
    - REM LINT:IGNORE-LINE - Suppress all issues on the same line

    Args:
        lines: List of lines from the batch file

    Returns:
        Dictionary mapping line numbers to set of rule codes to suppress.
        An empty set means suppress all rules for that line.

    Example:
        REM LINT:IGNORE E009
        ECHO '' .... Represents a " character
    """
    suppressions: Dict[int, Set[str]] = {}

    for i, line in enumerate(lines, start=1):
        stripped = line.strip().upper()

        # Check for IGNORE comment (affects next line)
        if stripped.startswith("REM ") or stripped.startswith("::"):
            # Remove REM or :: prefix
            comment_text = (
                stripped[3:].strip()
                if stripped.startswith("REM")
                else stripped[2:].strip()
            )

            # Check for LINT:IGNORE-LINE (same line suppression)
            if comment_text.startswith("LINT:IGNORE-LINE"):
                rest = comment_text[16:].strip()
                if rest:
                    # Specific rules to suppress
                    codes = {code.strip() for code in rest.split(",") if code.strip()}
                    suppressions.setdefault(i, set()).update(codes)
                else:
                    # Suppress all rules on this line
                    suppressions[i] = set()

            # Check for LINT:IGNORE (next line suppression)
            elif comment_text.startswith("LINT:IGNORE"):
                rest = comment_text[11:].strip()
                if rest:
                    # Specific rules to suppress on next line
                    codes = {code.strip() for code in rest.split(",") if code.strip()}
                    suppressions.setdefault(i + 1, set()).update(codes)
                else:
                    # Suppress all rules on next line
                    suppressions[i + 1] = set()

    return suppressions


def _analyze_script_structure(
    lines: List[str],
) -> Tuple[bool, bool, bool, bool, bool, bool, bool]:
    """Analyze script structure for context-aware checking.

    Returns:
        Tuple of (has_setlocal, has_set_commands, has_delayed_expansion, uses_delayed_vars,
                  has_disable_delayed_expansion, has_literal_exclamations, disable_expansion_lines)
    """
    has_setlocal = any("setlocal" in line.lower() for line in lines)
    has_set_commands = any(
        re.match(r"\s*set\s+[^=]+=.*", line, re.IGNORECASE) for line in lines
    )
    has_delayed_expansion = any(
        re.search(r"setlocal\s+enabledelayedexpansion", line, re.IGNORECASE)
        for line in lines
    )
    # Match any content between exclamation marks, including special chars like @, -, #, $, etc.
    # that are commonly used in batch variable names (e.g., !@DEBUG_MODE!, !@CRLF-%~1!)
    uses_delayed_vars = any(re.search(r"![^!]+!", line) for line in lines)

    # Check for SETLOCAL DISABLEDELAYEDEXPANSION usage
    has_disable_delayed_expansion = any(
        _COMPILED_SETLOCAL_DISABLE.search(line) for line in lines
    )

    # Check for literal ! characters in strings (not delayed expansion variables)
    # Look for ! characters that are NOT part of delayed expansion !var! patterns
    # Use negative lookbehind (?<![^\s]) and negative lookahead (?![^\s!]) to match standalone !
    has_literal_exclamations = False
    for line in lines:
        # Remove all delayed expansion patterns first
        cleaned = re.sub(r"![^!\s]+!", "", line)
        # Now check if there are any remaining ! characters in echo/set statements
        if re.search(r"(echo|set\s+\w+=).*!", cleaned, re.IGNORECASE):
            has_literal_exclamations = True
            break

    # Track whether any line uses disabledelayedexpansion
    has_disable_expansion_lines = any(
        _COMPILED_SETLOCAL_DISABLE.search(line) for line in lines
    )

    return (
        has_setlocal,
        has_set_commands,
        has_delayed_expansion,
        uses_delayed_vars,
        has_disable_delayed_expansion,
        has_literal_exclamations,
        has_disable_expansion_lines,
    )
