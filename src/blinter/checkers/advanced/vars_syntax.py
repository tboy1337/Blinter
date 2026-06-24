"""FOR-loop, variable, and string-operation syntax checks."""

import re
from typing import List

from blinter.models import LintIssue
from blinter.rules.registry import RULES


def _check_advanced_for_rules(line: str, line_number: int) -> List[LintIssue]:
    """Check for advanced FOR command patterns."""
    issues: List[LintIssue] = []
    stripped = line.strip().lower()

    if not stripped.startswith("for"):
        return issues

    # W034: FOR /F missing usebackq option
    if "/f" in stripped and " " in stripped and '"' in stripped:
        if "usebackq" not in stripped and (
            "(" in stripped.split('"')[0] or "`" in stripped
        ):
            issues.append(
                LintIssue(
                    line_number,
                    RULES["W034"],
                    context="FOR /F with spaces in filename needs usebackq",
                )
            )

    # W035: FOR /F tokenizing without proper delimiters
    # Skip if tokens=* is used (means take entire line, no tokenization needed)
    if (
        "/f" in stripped
        and "delims=" not in stripped
        and "tokens=" in stripped
        and "tokens=*" not in stripped
    ):
        issues.append(
            LintIssue(
                line_number,
                RULES["W035"],
                context="FOR /F tokenizing should specify delimiters",
            )
        )

    # W036: FOR /F missing skip option for headers
    if (
        "/f" in stripped
        and "skip=" not in stripped
        and ("file" in stripped or ".txt" in stripped or ".csv" in stripped)
    ):
        issues.append(
            LintIssue(
                line_number,
                RULES["W036"],
                context="FOR /F on data files should consider skip= for headers",
            )
        )

    # W037: FOR /F missing eol option for comments
    if "/f" in stripped and "eol=" not in stripped and ".txt" in stripped:
        issues.append(
            LintIssue(
                line_number,
                RULES["W037"],
                context="FOR /F should specify eol= for comment handling",
            )
        )

    # W038: FOR /R with explicit filename needs wildcard
    if "/r" in stripped and not ("*" in stripped or "?" in stripped):
        # Check if there's a specific filename pattern
        filename_match = re.search(r"\b\w+\.\w+\b", stripped)
        if filename_match:
            issues.append(
                LintIssue(
                    line_number,
                    RULES["W038"],
                    context=f"FOR /R with '{filename_match.group()}' needs wildcard",
                )
            )

    return issues


def _check_advanced_process_mgmt(line: str, line_number: int) -> List[LintIssue]:
    """Check for process management best practices."""
    issues: List[LintIssue] = []
    stripped = line.strip().lower()

    # W042: Timeout command without /NOBREAK option
    if (
        stripped.startswith("timeout")
        and "/nobreak" not in stripped
        and "/t" in stripped
    ):
        issues.append(
            LintIssue(
                line_number,
                RULES["W042"],
                context="TIMEOUT should use /NOBREAK for uninterruptible delays",
            )
        )

    # W043: Process management without proper verification
    if stripped.startswith("taskkill") and "tasklist" not in stripped:
        issues.append(
            LintIssue(
                line_number,
                RULES["W043"],
                context="TASKKILL should verify process existence first",
            )
        )

    # SEC015: Process killing without authentication
    if "taskkill" in stripped and "/f" in stripped and "/fi" not in stripped:
        issues.append(
            LintIssue(
                line_number,
                RULES["SEC015"],
                context="TASKKILL /F should include filters to avoid system processes",
            )
        )

    return issues


def _check_percent_tilde_syntax(stripped: str, line_number: int) -> List[LintIssue]:
    """Check for percent-tilde syntax issues (E017, E019)."""
    issues: List[LintIssue] = []
    tilde_pattern = r"%~([a-zA-Z]+)([0-9]+|[a-zA-Z])%"
    valid_modifiers = set("nxfpdstaz")

    for match in re.finditer(tilde_pattern, stripped):
        modifiers = str(match.group(1)).lower()
        parameter = str(match.group(2))

        # Check for invalid modifiers
        if not all(m in valid_modifiers for m in modifiers):
            issues.append(
                LintIssue(
                    line_number=line_number,
                    rule=RULES["E017"],
                    context=f"Invalid modifier in %~{modifiers}{parameter}%",
                )
            )

        # Check if used on non-parameter variable (not 0-9 or FOR variable)
        if not (parameter.isdigit() or (len(parameter) == 1 and parameter.isalpha())):
            issues.append(
                LintIssue(
                    line_number=line_number,
                    rule=RULES["E019"],
                    context=f"Percent-tilde syntax used on invalid parameter: {parameter}",
                )
            )

    return issues


def _check_for_loop_var_syntax(stripped: str, line_number: int) -> List[LintIssue]:
    """Check FOR loop variable syntax (E020)."""
    issues: List[LintIssue] = []
    for_pattern = r"for\s+%%?([a-zA-Z])\s+in\s*\("

    for match in re.finditer(for_pattern, stripped, re.IGNORECASE):
        # In batch files, should use %%i, on command line %i
        var_syntax = match.group(0)
        if "%%" not in var_syntax:
            issues.append(
                LintIssue(
                    line_number=line_number,
                    rule=RULES["E020"],
                    context="FOR loop variable should use %% in batch files",
                )
            )

    return issues


def _check_string_operation_syntax(stripped: str, line_number: int) -> List[LintIssue]:
    """Check string operations syntax (E021)."""
    issues: List[LintIssue] = []
    # Use non-greedy matching and more specific patterns to avoid false positives
    # Match valid substring operations: %var:~start,length% or %var:~start%
    # Match valid replacement operations: %var:old=new%
    string_ops = [
        r"%[a-zA-Z_][a-zA-Z0-9_]*:~-?[0-9]+(?:,-?[0-9]+)?%",  # Substring with numbers
        r"%[a-zA-Z_][a-zA-Z0-9_]*:(?!~)[^=]+=[^%]*?%",  # Replacement (not substring)
    ]

    for pattern in string_ops:
        for match in re.finditer(pattern, stripped):
            matched_text = match.group(0)
            # Basic validation - should have exactly 2 percent signs
            if matched_text.count("%") != 2:
                issues.append(
                    LintIssue(
                        line_number=line_number,
                        rule=RULES["E021"],
                        context=f"Malformed string operation: {matched_text}",
                    )
                )

    return issues


def _check_set_a_quoting(stripped: str, line_number: int) -> List[LintIssue]:
    """Check SET /A syntax (E023)."""
    issues: List[LintIssue] = []

    if re.match(r"\s*set\s+/a\s+", stripped, re.IGNORECASE):
        # Check for special characters that need quoting
        if any(char in stripped for char in "^&|<>()"):
            if not ('"' in stripped or "'" in stripped):
                issues.append(
                    LintIssue(
                        line_number=line_number,
                        rule=RULES["E023"],
                        context="SET /A with special characters should be quoted",
                    )
                )

    return issues


def _check_advanced_vars(lines: List[str]) -> List[LintIssue]:
    """Check for advanced variable expansion syntax issues (E017-E022)."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        issues.extend(_check_percent_tilde_syntax(stripped, i))
        issues.extend(_check_for_loop_var_syntax(stripped, i))
        issues.extend(_check_string_operation_syntax(stripped, i))
        issues.extend(_check_set_a_quoting(stripped, i))
        issues.extend(_check_set_a_arithmetic(stripped, i))

    return issues


def _check_set_a_arithmetic(stripped: str, line_number: int) -> List[LintIssue]:
    """Check SET /A arithmetic syntax (E022)."""
    issues: List[LintIssue] = []
    seta_match = re.match(r"set\s+/a\s+(.+)", stripped, re.IGNORECASE)
    if not seta_match:
        return issues

    expression = seta_match.group(1)
    expr_match = re.match(r"^([^&|]*?)(?:\s*(?:[^\\^]|^)[&|]|$)", expression)
    if expr_match:
        expression = expr_match.group(1).strip()

    if re.search(r"[=+\-*/%<>!][=+\-*/%<>!]", expression):
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["E022"],
                context="Invalid operator sequence in SET /A expression",
            )
        )

    if re.search(r"[a-zA-Z_]", expression) and not re.search(
        r"0x[0-9a-fA-F]+", expression
    ):
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["E022"],
                context="SET /A expression contains invalid alphabetic tokens",
            )
        )

    return issues
