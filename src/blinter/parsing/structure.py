"""Label collection, script structure, and subroutine detection."""

import re
from typing import (
    Dict,
    List,
    Set,
    Tuple,
)

from blinter.models import LintIssue
from blinter.patterns import (
    _COMPILED_SETLOCAL_DISABLE,
)
from blinter.rules.helpers import _add_issue


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


def _is_in_subroutine_context(  # pylint: disable=unused-argument
    lines: List[str], line_number: int, labels: Dict[str, int]
) -> bool:
    """
    Determine if a line is within a subroutine context.

    A line is considered to be in a subroutine if:
    1. There is a label defined before it (indicating start of a subroutine)
    2. The line comes after the first label in the file (main script is before any labels)

    Args:
        lines: All lines in the batch file (reserved for future enhancement)
        line_number: The current line number (1-indexed)
        labels: Dictionary mapping label names to line numbers

    Returns:
        True if the line is within a subroutine context
    """
    if not labels:
        return False

    # Find the minimum label line number (first subroutine starts after this)
    min_label_line = min(labels.values())

    # If we're before the first label, we're in the main script
    if line_number < min_label_line:
        return False

    # Check if there's a label defined before the current line
    # This indicates we're inside a subroutine
    for label_line in labels.values():
        if label_line < line_number:
            # Found a label before this line, so we're in a subroutine
            return True

    return False


_SET_VAR_NAME = r"[A-Za-z0-9_@]+"
_CALL_SETS_FIRST_ARG_PATTERNS: tuple[str, ...] = (
    r"\bcall\s+:getrepairsetup\s+([A-Za-z0-9_]+)",
    r"\bcall\s+:getc2rrepair\s+([A-Za-z0-9_]+)",
    r"\bcall\s+:_taskgetids\s+([A-Za-z0-9_]+)",
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

        for call_pattern in _CALL_SETS_FIRST_ARG_PATTERNS:
            for call_match in re.finditer(call_pattern, stripped_line, re.IGNORECASE):
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

    # Add common environment variables that are typically available
    common_env_vars = {
        "PATH",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "USERNAME",
        "COMPUTERNAME",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_ARCHITEW6432",  # WOW64 - native architecture on 64-bit when running 32-bit
        "PROCESSOR_IDENTIFIER",
        "ERRORLEVEL",
        "CD",
        "DATE",
        "TIME",
        "RANDOM",
        "CMDEXTVERSION",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOGONSERVER",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATHEXT",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",  # 32-bit program files on 64-bit systems
        "PROGRAMW6432",  # 64-bit program files folder on 64-bit systems
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "WINDIR",
        "ALLUSERSPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PUBLIC",
        # Additional commonly used environment variables
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "USERDOMAIN",
        "USERDNSDOMAIN",
        "SESSIONNAME",
        "CLIENTNAME",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        # Optional environment variables that may or may not be set
        "SUDO_USER",  # Set by newer Windows sudo command
        "ORIGINAL_USER",  # Sometimes set by scripts for elevation tracking
        "DRIVERDATA",  # Driver data directory (Windows 10+)
        "ONEDRIVE",  # OneDrive directory if configured
        "ONEDRIVECONSUMER",  # Consumer OneDrive
        "ONEDRIVECOMMERCIAL",  # Business OneDrive
        "DEBUG",  # Optional script-control flag from callers
        "COMMONPROGRAMW6432",  # 64-bit common files on 64-bit Windows
        "SAFEBOOT_OPTION",  # Set when Windows is in Safe Mode
    }
    set_vars.update(common_env_vars)

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
