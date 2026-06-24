"""Blinter package module."""

import re
from typing import (
    List,
    Optional,
    Set,
    Tuple,
)
from blinter.models import LintIssue
from blinter.patterns import (
    ARCHITECTURE_SPECIFIC_PATTERNS,
    OLDER_WINDOWS_COMMANDS,
    UNICODE_PROBLEMATIC_COMMANDS,
)
from blinter.rules.registry import RULES
from blinter.patterns import (
    _COMPILED_IF_PATTERN,
)

def _check_unicode_handling_issue(stripped: str, line_num: int) -> Optional[LintIssue]:
    """Check for Unicode handling issues in commands (W011)."""
    for cmd in UNICODE_PROBLEMATIC_COMMANDS:
        if re.match(rf"{cmd}\s", stripped, re.IGNORECASE):
            has_unicode_risk = False

            # For echo command, only flag if it contains potentially problematic content
            if cmd == "echo":
                has_unicode_risk = _check_echo_unicode_risk(stripped)
            elif cmd in ["findstr", "find"]:
                has_unicode_risk = _check_search_unicode_risk(stripped)
            else:
                has_unicode_risk = _check_general_unicode_risk(stripped)

            if has_unicode_risk:
                return LintIssue(
                    line_number=line_num,
                    rule=RULES["W011"],
                    context=f"Command '{cmd}' may have Unicode handling issues",
                )
            break
    return None

def _check_echo_unicode_risk(stripped: str) -> bool:
    """Check for Unicode risks in echo commands."""
    # Extract the actual echo content (text after the command)
    echo_content = ""
    match = re.match(r"echo\s+(.*)", stripped, re.IGNORECASE)
    if match:
        echo_content = match.group(1)

    # Check for complex variable expansions within individual variables
    complex_vars: List[str] = []
    # Match %VARNAME% patterns and extract variable names
    # This will match: %red%, %under%, etc., and also false positives like %a % from %%a %%b
    variables: List[str] = re.findall(r"%([^%]+)%", echo_content)
    for var_content in variables:
        # Filter out false positives from FOR loop variables (%%a %%b matches as %a %)
        # These will contain spaces or be very short with spaces
        if " " in var_content or "\t" in var_content:
            continue  # Skip false matches across FOR loop variables

        # var_content is the variable name without % signs
        # Allow: alphanumeric, underscore, tilde, @ (common for internal vars), and # (also used)
        # Strip trailing non-alphanumeric characters that might be adjacent literals
        # e.g., %@DIVIDER-% should be treated as %@DIVIDER% followed by a literal -
        var_name = re.match(r"^([A-Z0-9_~@#]+)", var_content, re.IGNORECASE)
        if var_name:
            # This is a valid simple variable name, not complex
            continue

        # Check for parameter expansions like %~n1, %~dp0
        if re.match(r"^~[a-z]*\d*$", var_content, re.IGNORECASE):
            continue

        # If we get here, it's a complex/unusual variable expansion
        complex_vars.append(var_content)

    # Check if this is safe file redirection (output to files, not complex shell operations)
    has_safe_redirection = bool(
        re.search(
            r">\s*(nul|\"[^\"]*\"|[^\s&|<>]+)(\s*2>&1)?\s*$", stripped, re.IGNORECASE
        )
    )

    # Check for escaped angle brackets (^< or ^>) which are safe
    has_escaped_brackets = bool(re.search(r"\^[<>]", stripped))

    # Only flag echo if it has real Unicode issues
    return (
        not all(
            ord(c) < 128 for c in echo_content if c.strip()
        )  # Contains non-ASCII in actual content
        or (
            bool(re.search(r"[<>]", stripped))
            and not has_safe_redirection
            and not has_escaped_brackets
        )  # Has unsafe redirection (not escaped)
        or len(complex_vars) > 0  # Has truly complex variable expansion
        or bool(
            re.search(r"[\x00-\x1f\x7f-\xff]", echo_content)
        )  # Control chars in content
    )

def _check_search_unicode_risk(stripped: str) -> bool:
    """Check for Unicode risks in findstr/find commands."""
    return (
        not all(ord(c) < 128 for c in stripped)  # Contains non-ASCII
        or bool(
            re.search(r"/[a-z]", stripped, re.IGNORECASE)
        )  # Uses flags affecting Unicode
        or ">" in stripped
        or "<" in stripped  # File redirection
    )

def _check_general_unicode_risk(stripped: str) -> bool:
    """Check for general Unicode risks in other commands."""
    return not all(ord(c) < 128 for c in stripped) or bool(
        re.search(r"[\x00-\x1f\x7f-\xff]", stripped)  # Contains non-ASCII
    )

def _check_compatibility_warnings(  # pylint: disable=unused-argument
    line: str, line_num: int, stripped: str
) -> List[LintIssue]:
    """Check for compatibility-related warning issues."""
    issues: List[LintIssue] = []

    # W009: Windows version compatibility
    for cmd in OLDER_WINDOWS_COMMANDS:
        if re.match(rf"{cmd}\s", stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W009"],
                    context=f"Command '{cmd}' may not be available on older Windows versions",
                )
            )
            break

    # W010: Architecture-specific operation
    for pattern in ARCHITECTURE_SPECIFIC_PATTERNS:
        if pattern in stripped:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W010"],
                    context=f"Architecture-specific reference: {pattern}",
                )
            )
            break

    # W011: Unicode handling issue - only flag when actually problematic
    unicode_issue = _check_unicode_handling_issue(stripped, line_num)
    if unicode_issue:
        issues.append(unicode_issue)

    # W027: Command behavior differs between interpreters
    interpreter_diff_commands = ["append", "dpath", "ftype", "assoc", "path"]
    first_word = stripped.split()[0].lower() if stripped.split() else ""
    if first_word in interpreter_diff_commands:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W027"],
                context=f"Command '{first_word}' behaves differently in COMMAND.COM vs cmd.exe",
            )
        )

    # W029: 16-bit command in 64-bit context
    # Only match .COM files being executed as commands, not domain names
    # Match patterns like: command.com, call something.com, start program.com
    # But not: ping google.com, http://site.com, etc.
    if re.search(
        r"^\s*(?:call\s+|start\s+)?[\w-]+\.com(?:\s|$)", stripped, re.IGNORECASE
    ):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W029"],
                context="16-bit .COM file may not work in 64-bit Windows",
            )
        )

    return issues

def _check_command_warnings(  # pylint: disable=unused-argument
    line: str, line_num: int, stripped: str
) -> List[LintIssue]:
    """Check for command-specific warning issues."""
    issues: List[LintIssue] = []

    # W006: Network operation without timeout
    if re.match(r"ping\s+[^-]*$", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W006"],
                context="PING command without timeout parameter",
            )
        )

    # W008: Permanent PATH modification
    if re.match(r"setx\s+path", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W008"],
                context="SETX modifies PATH permanently",
            )
        )

    # W015: Deprecated command usage - Now handled by W024 in _check_deprecated_commands()
    # (Removed duplicate check - W024 provides more comprehensive deprecated command detection)

    return issues

def _check_unquoted_variables(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for unquoted variables with spaces (W005).

    Only flags genuinely problematic cases:
    - IF string comparisons (==) with unquoted variables
    """
    issues: List[LintIssue] = []

    # Only check IF string comparisons with == operator
    # These are the most common source of issues with unquoted variables
    if_string_comp = re.search(
        r"\bif\s+(?:not\s+)?%[A-Z0-9_]+%\s*==\s*", stripped, re.IGNORECASE
    )
    if if_string_comp:
        # Don't flag if already quoted properly elsewhere in the comparison
        if not re.search(
            r'\bif\s+(?:not\s+)?"[^"]*%[A-Z0-9_]+%[^"]*"', stripped, re.IGNORECASE
        ):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W005"],
                    context=(
                        "IF string comparison with unquoted variable "
                        "may fail if variable contains spaces"
                    ),
                )
            )

    return issues

def _check_non_ascii_chars(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for non-ASCII characters (W012)."""
    issues: List[LintIssue] = []
    if not all(ord(c) < 128 for c in stripped):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W012"],
                context="Line contains non-ASCII characters",
            )
        )
    return issues

def _check_errorlevel_comparison(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for errorlevel comparison semantic difference (W017)."""
    issues: List[LintIssue] = []
    w017_if_match = _COMPILED_IF_PATTERN.match(stripped)
    if not w017_if_match:
        return issues

    w017_group_result = w017_if_match.group(1)
    if w017_group_result is None:
        return issues

    w017_if_content: str = w017_group_result.strip()
    # Only warn about the specific problematic pattern: %ERRORLEVEL% NEQ 1
    if re.search(r"%errorlevel%\s+neq\s+1\b", w017_if_content, re.IGNORECASE):
        # Don't warn if it's in a complex condition with && or ||
        if not re.search(r"&&|\|\|", w017_if_content):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W017"],
                    context=(
                        "IF %ERRORLEVEL% NEQ 1 behaves differently than "
                        "IF NOT ERRORLEVEL 1"
                    ),
                )
            )
    return issues

def _check_inefficient_modifiers(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for inefficient parameter modifier usage (W026)."""
    issues: List[LintIssue] = []
    inefficient_param_match: List[Tuple[str, str]] = re.findall(
        r"(%~[fdpnx][0-9]+%)\s*(%~[fdpnx][0-9]+%)", stripped, re.IGNORECASE
    )
    if inefficient_param_match:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W026"],
                context="Multiple parameter modifiers can be combined for efficiency",
            )
        )
    return issues

def _check_extended_non_ascii(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for extended non-ASCII characters (W030)."""
    issues: List[LintIssue] = []
    if any(ord(char) > 127 for char in stripped):
        # Check if it's not just typical CP437 characters
        non_ascii_chars = [char for char in stripped if ord(char) > 127]
        if non_ascii_chars:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W030"],
                    context=f"Non-ASCII characters detected: {''.join(set(non_ascii_chars))}",
                )
            )
    return issues

def _check_unicode_filenames(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for Unicode filename in batch operation (W031)."""
    issues: List[LintIssue] = []
    unicode_file_ops = ["copy", "move", "del", "type", "ren", "rename"]
    first_word = stripped.split()[0].lower() if stripped.split() else ""
    if first_word in unicode_file_ops:
        # Look for non-ASCII characters in file paths
        if re.search(r"[^\x00-\x7F]", stripped):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W031"],
                    context="File operation with Unicode filename may cause issues",
                )
            )
    return issues

def _check_call_ambiguity(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for command execution ambiguity (W033)."""
    issues: List[LintIssue] = []
    call_match = re.match(r"call\s+([^:\s]+)", stripped, re.IGNORECASE)
    if call_match:
        call_target: str = call_match.group(1)
        # Check if it's a filename without extension
        if not re.search(
            r"\.[a-z]{1,4}$", call_target.lower()
        ) and not call_target.startswith(":"):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W033"],
                    context=f"CALL '{call_target}' without extension may be ambiguous with PATHEXT",
                )
            )
    return issues

def _check_warning_issues(  # pylint: disable=unused-argument
    line: str, line_num: int, set_vars: Set[str], delayed_expansion_enabled: bool
) -> List[LintIssue]:
    """Check for warning level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # Use helper functions to check for various warning issues
    issues.extend(_check_unquoted_variables(stripped, line_num))
    issues.extend(_check_non_ascii_chars(stripped, line_num))
    issues.extend(_check_errorlevel_comparison(stripped, line_num))
    issues.extend(_check_inefficient_modifiers(stripped, line_num))
    issues.extend(_check_extended_non_ascii(stripped, line_num))
    issues.extend(_check_unicode_filenames(stripped, line_num))
    issues.extend(_check_call_ambiguity(stripped, line_num))
    issues.extend(_check_compatibility_warnings(line, line_num, stripped))
    issues.extend(_check_command_warnings(line, line_num, stripped))

    return issues
