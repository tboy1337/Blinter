"""Advanced style, security, and performance rules."""

import re
from typing import (
    Dict,
    List,
    Optional,
    Tuple,
    cast,
)

from blinter.constants import MAGIC_NUMBER_EXCEPTIONS
from blinter.models import LintIssue
from blinter.parsing.context import _is_comment_line
from blinter.parsing.structure import _is_in_subroutine_context
from blinter.rules.registry import RULES


def _check_advanced_security(
    line: str, line_number: int, lines: List[str], labels: Dict[str, int]
) -> List[LintIssue]:
    """Check for advanced security patterns."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # SEC014: Unescaped user input in command execution
    # Only check if we're NOT in a subroutine context
    # In subroutines, %1, %2, etc. refer to subroutine parameters, not user input
    if "%1" in stripped or "%2" in stripped or "%*" in stripped:
        # Skip this check if we're inside a subroutine
        if not _is_in_subroutine_context(lines, line_number, labels):
            # Check for user parameters used without proper escaping
            special_chars = ["&", "|", ">", "<", "^"]
            if any(char in stripped for char in special_chars):
                if not re.search(r"\^[&|><^]", stripped):
                    issues.append(
                        LintIssue(
                            line_number,
                            RULES["SEC014"],
                            context="User input parameters should be escaped",
                        )
                    )

    # SEC017: Temporary file creation in predictable location
    if "temp" in stripped.lower() and (".tmp" in stripped or ".temp" in stripped):
        if "%random%" not in stripped.lower() and "%time%" not in stripped.lower():
            issues.append(
                LintIssue(
                    line_number,
                    RULES["SEC017"],
                    context="Temp files should use %RANDOM% or timestamp",
                )
            )

    # SEC018: Command output redirection to insecure location
    redirection_patterns = [
        r">\s*c:\\temp",
        r">\s*c:\\windows\\temp",
        r">\s*\\\\.*\\share",
    ]
    for pattern in redirection_patterns:
        if re.search(pattern, stripped.lower()):
            issues.append(
                LintIssue(
                    line_number,
                    RULES["SEC018"],
                    context="Output redirected to potentially insecure location",
                )
            )

    return issues


def _check_advanced_performance(
    lines: List[str], line_number: int, line: str
) -> List[LintIssue]:
    """Check for performance patterns."""
    issues: List[LintIssue] = []
    stripped = line.strip().lower()

    # P017: Repeated file existence checks
    if stripped.startswith("if exist"):
        filename_match = re.search(r'if exist\s+(["\']?)([^"\'\s]+)\1', stripped)
        if filename_match:
            filename = filename_match.group(2)
            # Count occurrences of the same file check in surrounding lines
            check_range = max(0, line_number - 5), min(len(lines), line_number + 5)
            same_checks = 0
            for i in range(check_range[0], check_range[1]):
                if i != line_number - 1 and filename in lines[i].lower():
                    same_checks += 1
            if same_checks >= 2:
                issues.append(
                    LintIssue(
                        line_number,
                        RULES["P017"],
                        context=f"File '{filename}' checked multiple times",
                    )
                )

    # P020: Redundant command echoing suppression
    if stripped.startswith("@echo off") and line_number > 1:
        issues.append(
            LintIssue(
                line_number,
                RULES["P020"],
                context="@ECHO OFF should only appear once at script start",
            )
        )

    # P021: Inefficient process checking pattern
    if stripped.startswith("tasklist") and "/fi" not in stripped:
        issues.append(
            LintIssue(
                line_number,
                RULES["P021"],
                context="TASKLIST should use /FI filters for efficiency",
            )
        )

    return issues


def _check_advanced_style_patterns(
    line: str, line_number: int, lines: List[str]
) -> List[LintIssue]:
    """Check for advanced style patterns."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # S023: Magic timeout values without explanation
    timeout_match = re.search(r"timeout\s+/t\s+(\d+)", stripped.lower())
    if timeout_match:
        timeout_value = int(timeout_match.group(1))
        if timeout_value > 10:  # Arbitrary values > 10 seconds
            # Check if there's a comment explaining the value
            has_explanation = False
            check_lines = [line_number - 2, line_number - 1, line_number]
            for check_line in check_lines:
                if 0 <= check_line - 1 < len(lines):
                    if _is_comment_line(lines[check_line - 1]):
                        has_explanation = True
                        break
            if not has_explanation:
                issues.append(
                    LintIssue(
                        line_number,
                        RULES["S023"],
                        context=f"Timeout value {timeout_value} needs explanation",
                    )
                )

    # S024: Complex one-liner should be split
    if len(stripped) > 80 and ("&&" in stripped or "||" in stripped):
        if "^" not in stripped:  # No continuation used
            issues.append(
                LintIssue(
                    line_number,
                    RULES["S024"],
                    context="Complex command should be split using continuation character",
                )
            )

    # S026: Inconsistent continuation character usage
    if "^" in stripped and not stripped.endswith("^"):
        # Check for improper continuation usage (exclude escape sequences)
        # In batch files, ^ is used for both line continuation AND escaping special chars
        # Only flag if it appears to be a continuation character, not an escape character
        if stripped.count("^") == 1 and not re.search(r"\^\s*$", line):
            # Check if ^ is used as escape character (followed by special char)
            # Special chars that can be escaped: & | ( ) < > ^ " space tab
            if not re.search(r"\^[&|()<>^\"\s]", stripped):
                issues.append(
                    LintIssue(
                        line_number,
                        RULES["S026"],
                        context="Continuation character should be at line end",
                    )
                )

    return issues


def _check_variable_naming(
    line: str, line_number: int, variables_seen: Dict[str, str]
) -> List[LintIssue]:
    """Check variable naming consistency (S017)."""
    issues: List[LintIssue] = []
    # Find SET commands with both quoted and unquoted variable names
    var_matches: List[re.Match[str]] = []
    set_patterns = [
        r"set\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=",  # Regular set: set VAR=value
        r'set\s+"([a-zA-Z_][a-zA-Z0-9_]*)\s*=',  # Quoted set: set "VAR=value"
    ]
    for pattern in set_patterns:
        matches = list(re.finditer(pattern, line, re.IGNORECASE))
        var_matches.extend(matches)

    for match in var_matches:
        var_name = str(match.group(1))
        if var_name.isupper():
            case_style = "upper"
        elif var_name.islower():
            case_style = "lower"
        else:
            case_style = "mixed"

        if var_name.upper() in variables_seen:
            if variables_seen[var_name.upper()] != case_style:
                issues.append(
                    LintIssue(
                        line_number=line_number,
                        rule=RULES["S017"],
                        context=f"Inconsistent case for variable {var_name}",
                    )
                )
        else:
            variables_seen[var_name.upper()] = case_style

    return issues


def _check_function_docs(
    line: str, line_number: int, lines: List[str]
) -> List[LintIssue]:
    """Check for function documentation (S018) - hybrid implementation."""
    issues: List[LintIssue] = []

    stripped = line.strip()
    # Match all labels (subroutines) - pattern: :LabelName
    if re.match(r"\s*:[a-zA-Z_][a-zA-Z0-9_]*\s*$", stripped):
        # Found a label that might be a subroutine
        # Check if previous 3 lines have documentation (more focused than 5)
        doc_found = False
        for j in range(max(0, line_number - 3), line_number - 1):
            if j < len(lines) and _is_comment_line(lines[j]):
                doc_found = True
                break

        if not doc_found:
            issues.append(
                LintIssue(
                    line_number=line_number,
                    rule=RULES["S018"],
                    context="Function/subroutine lacks documentation",
                )
            )

    return issues


def _find_set_exclusion_ranges(line: str) -> List[Tuple[int, int]]:
    """
    Find exclusion ranges for SET statements in a line.

    Args:
        line: The line to analyze

    Returns:
        List of (start, end) tuples representing character ranges to exclude from checks
    """
    # Pattern matches: SET VAR=value, SET /A VAR=value, including in IF statements
    # We want to skip checking the value part after the = sign
    set_pattern = r"\bSET\s+(?:/A\s+)?([A-Z_@#$][A-Z0-9_@#$]*)\s*="

    # Find all SET statement positions to create exclusion zones
    exclusion_ranges: List[Tuple[int, int]] = []
    for set_match in re.finditer(set_pattern, line, re.IGNORECASE):
        # Find the equals sign position
        equals_pos = set_match.end() - 1

        # The exclusion zone starts right after the equals sign and goes to:
        # 1. End of line
        # 2. Next SET statement
        # 3. Closing parenthesis (for IF statements)
        # 4. Start of next command (via & or |)

        search_start = equals_pos + 1
        end_pos = len(line)

        # Look for terminators after the equals sign
        remainder = line[search_start:]

        # Find the earliest terminator
        # Check for command separators (but not in quoted strings)
        # Simple heuristic: look for & or | that aren't inside quotes
        for i, char in enumerate(remainder):
            if char in ("&", "|", ")"):
                # Check if we're inside quotes (simple check)
                before = remainder[:i]
                if before.count('"') % 2 == 0:  # Even number of quotes = not in string
                    end_pos = search_start + i
                    break

        exclusion_ranges.append((search_start, end_pos))

    return exclusion_ranges


def _is_number_in_special_context(
    immediate_before: str, immediate_after: str, context_before: str, context_after: str
) -> bool:
    """
    Check if a number is in a special context (GUID, path, math expr) and should be skipped.

    Args:
        immediate_before: Last 2 chars before number (stripped)
        immediate_after: First 2 chars after number (stripped)
        context_before: Full text before number
        context_after: Full text after number

    Returns:
        True if number should be skipped, False otherwise
    """
    # Check for GUID or identifier pattern: dash/brace immediately adjacent
    has_guid_before = immediate_before and immediate_before[-1] in ["-", "{"]
    has_guid_after = immediate_after and immediate_after[0] in ["-", "}"]

    # Check for file path: backslash or forward slash immediately adjacent
    has_path_before = immediate_before and immediate_before[-1] in ["\\", "/"]
    has_path_after = immediate_after and immediate_after[0] in ["\\", "/"]

    # Check if it's in a PowerShell math expression context
    context_lower = context_before.lower()
    in_math_round = "round(" in context_lower and ")" in context_after
    in_math_class = "[math]::" in context_lower

    return (
        has_guid_before
        or has_guid_after
        or has_path_before
        or has_path_after
        or in_math_round
        or in_math_class
    )


def _check_magic_numbers(line: str, line_number: int) -> List[LintIssue]:
    """Check for magic numbers (S019)."""
    # Skip comment lines - magic numbers in comments are documentation, not code
    if _is_comment_line(line):
        return []

    issues: List[LintIssue] = []
    number_pattern = r"\b(?<!%)\d{2,}\b(?!%)"

    # Find SET statement exclusion zones
    exclusion_ranges = _find_set_exclusion_ranges(line)

    for match in re.finditer(number_pattern, line):
        number = match.group(0)
        match_start = match.start()

        # Skip if this number is within a SET statement's value assignment
        if any(start <= match_start < end for start, end in exclusion_ranges):
            continue

        # Get context around the number
        context_before = line[: match.start()]
        context_after = line[match.end() :]
        immediate_before = context_before[-2:].strip()
        immediate_after = context_after[:2].strip()

        # Skip if in special context (GUID, path, math expression)
        if _is_number_in_special_context(
            immediate_before, immediate_after, context_before, context_after
        ):
            continue

        # Check if number is a common exception
        if number not in MAGIC_NUMBER_EXCEPTIONS:
            issues.append(
                LintIssue(
                    line_number=line_number,
                    rule=RULES["S019"],
                    context=f"Magic number {number} should be defined as constant",
                )
            )

    return issues


def _check_line_length(
    line: str, line_number: int, max_line_length: int = 100
) -> List[LintIssue]:
    """Check for long lines (S020)."""
    issues: List[LintIssue] = []

    line_length = len(line.rstrip("\n"))
    if line_length > max_line_length and not line.rstrip().endswith("^"):
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["S020"],
                context=f"Line length {line_length} exceeds {max_line_length} characters",
            )
        )

    return issues


def _check_advanced_style_rules(
    lines: List[str], max_line_length: int = 100
) -> List[LintIssue]:
    """Check for advanced style and best practice issues (S017-S020)."""
    issues: List[LintIssue] = []
    variables_seen: Dict[str, str] = {}  # var_name -> case_style

    for i, line in enumerate(lines, start=1):
        issues.extend(_check_variable_naming(line, i, variables_seen))
        issues.extend(_check_function_docs(line, i, lines))
        issues.extend(_check_magic_numbers(line, i))
        issues.extend(_check_line_length(line, i, max_line_length))

    return issues


def _get_safe_system_variables() -> List[str]:
    """Return list of safe system variables that don't pose injection risks."""
    return [
        "SystemDrive",
        "SystemRoot",
        "Windows",
        "WinDir",
        "ProgramFiles",
        "ProgramData",
        "CommonProgramFiles",
        "UserProfile",
        "AppData",
        "LocalAppData",
        "Temp",
        "TMP",
        "ComSpec",
        "Path",
        "PathExt",
        "Processor_Architecture",
        "Number_Of_Processors",
        "OS",
        "HomeDrive",
        "HomePath",
        "Public",
        "AllUsersProfile",
        "CommonProgramW6432",
        "ProgramFiles(x86)",
        "CommonProgramFiles(x86)",
    ]


def _get_safe_command_patterns() -> List[str]:
    """Return list of safe command patterns for SEC013 rule."""
    return [
        r'cd\s+/d\s+"%[a-zA-Z_][a-zA-Z0-9_]*%"',  # Standard drive change
        r"echo\s+.*>\s*nul",  # Output redirection to nul
        r'echo\s+.*>>\s*"[^"]*"',  # Safe file append
        r'echo\s+.*>\s*"[^"]*"',  # Safe file write
        r'%[a-zA-Z_][a-zA-Z0-9_]*%"\s*>[^&|]*$',  # Variable in quotes followed by redirection
        # Safe file operations with variables (no command chaining)
        r"^[^&|]*\b(del|copy|move|type|xcopy)\s+[^&|]*%[a-zA-Z_][a-zA-Z0-9_]*%[^&|]*>[^&|]*$",
        r"^[^&|]*\b(rd|md|mkdir|rmdir)\s+[^&|]*%[a-zA-Z_][a-zA-Z0-9_]*%[^&|]*>[^&|]*$",
        # Safe operations with multiple variables but no chaining
        r"^[^&|]*%[a-zA-Z_][a-zA-Z0-9_]*%[^&|]*%[a-zA-Z_][a-zA-Z0-9_]*%[^&|]*>[^&|]*$",
    ]


def _is_safe_command_injection(stripped: str) -> bool:
    """Check if a command with variables is safe from injection attacks."""
    system_variables = _get_safe_system_variables()

    # Check if only system variables are used
    variables_in_line: List[str] = cast(
        List[str], re.findall(r"%([a-zA-Z_][a-zA-Z0-9_()]*)%", stripped)
    )
    uses_only_system_vars = all(
        var in system_variables or var.startswith("~") or var.isdigit()
        for var in variables_in_line
    )

    # If only system variables are used, be more lenient
    if uses_only_system_vars:
        return True

    # Check against safe patterns
    safe_patterns = _get_safe_command_patterns()
    if any(re.search(pattern, stripped, re.IGNORECASE) for pattern in safe_patterns):
        return True

    # Additional safety check for file operations with only redirection
    potential_chaining: List[str] = cast(List[str], re.findall(r"[&|]", stripped))
    has_command_chaining = False
    for match in potential_chaining:
        match_pos = stripped.find(match)
        context = stripped[max(0, match_pos - 3) : match_pos + 3]
        if "2>&1" not in context and ">&1" not in context:
            has_command_chaining = True
            break

    is_file_operation = bool(
        re.search(
            r"\b(del|copy|move|type|xcopy|rd|md|mkdir|rmdir)\b", stripped, re.IGNORECASE
        )
    )
    has_only_redirection = bool(re.search(r">.*$", stripped))

    return is_file_operation and has_only_redirection and not has_command_chaining


def _check_enhanced_security_rules(lines: List[str]) -> List[LintIssue]:
    """Check for enhanced security issues (SEC011-SEC013)."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Check for path traversal (SEC011)
        if ".." in stripped and any(
            op in stripped for op in ["cd", "copy", "move", "del"]
        ):
            issues.append(
                LintIssue(
                    line_number=i,
                    rule=RULES["SEC011"],
                    context="Path contains .. which may allow directory traversal",
                )
            )

        # Check for unsafe temp file creation (SEC012)
        temp_pattern = r"[^%]temp[^%].*\.(tmp|bat|cmd|exe)"
        if re.search(temp_pattern, stripped, re.IGNORECASE):
            if "%random%" not in stripped.lower():
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["SEC012"],
                        context="Temp file creation without random component",
                    )
                )

        # Check for command injection via variables (SEC013)
        # Exclude echo statements as they are generally safe for output
        if re.search(r"%[a-zA-Z_][a-zA-Z0-9_]*%.*[&|<>]", stripped):
            # Skip echo statements - they are safe for variable expansion
            if not re.match(r"\s*echo\s+", stripped, re.IGNORECASE):
                if not _is_safe_command_injection(stripped):
                    issues.append(
                        LintIssue(
                            line_number=i,
                            rule=RULES["SEC013"],
                            context="Variable used with shell operators may allow injection",
                        )
                    )

    return issues


def _check_unnecessary_output_p014(
    lines: List[str], i: int, stripped: str
) -> Optional[LintIssue]:
    """Check for unnecessary output in non-interactive context (P014)."""
    # Only flag TYPE and DIR commands - ECHO is typically intentional user communication
    noisy_commands = ["type", "dir"]

    for cmd in noisy_commands:
        if re.match(rf"\s*{cmd}\s+", stripped, re.IGNORECASE):
            if ">nul" not in stripped.lower() and ">" not in stripped:
                # Check if nearby lines suggest interactive context
                nearby_interactive = _has_nearby_interactive_cmds(lines, i)

                if not nearby_interactive:
                    return LintIssue(
                        line_number=i,
                        rule=RULES["P014"],
                        context=(
                            f"{cmd.upper()} output may be unnecessary in "
                            "non-interactive context"
                        ),
                    )
    return None


def _has_nearby_interactive_cmds(lines: List[str], line_index: int) -> bool:
    """Check if there are interactive commands near the given line."""
    interactive_keywords = ["pause", "timeout", "set /p", "choice"]

    for j in range(max(0, line_index - 3), min(len(lines), line_index + 4)):
        nearby_line = lines[j].lower() if j < len(lines) else ""
        if any(keyword in nearby_line for keyword in interactive_keywords):
            return True
    return False


def _check_enhanced_performance(lines: List[str]) -> List[LintIssue]:
    """Check for enhanced performance issues (P012-P014)."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Check DIR without /B for performance (P013)
        if re.match(r"\s*dir\s+(?!.*\/b)", stripped, re.IGNORECASE):
            if "|" in stripped or ">" in stripped:  # Output is being processed
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["P013"],
                        context="DIR output processed - consider /B flag for performance",
                    )
                )

        # Check for unnecessary output (P014)
        p014_issue = _check_unnecessary_output_p014(lines, i, stripped)
        if p014_issue:
            issues.append(p014_issue)

    return issues
