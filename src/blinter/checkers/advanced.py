"""Blinter package module."""

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
from blinter.patterns import DEPRECATED_COMMANDS, REMOVED_COMMANDS
from blinter.rules.registry import RULES
from blinter.parsing.context import _is_comment_line
from blinter.parsing.structure import _is_in_subroutine_context

def _should_flag_caret_escape(stripped: str, caret_pos: int, line: str = "") -> bool:
    """Check if a caret escape sequence should be flagged as improper."""
    # Check if this is within a FOR loop command string (within single quotes)
    # In FOR loops, command strings like 'command 2^>nul ^| filter' use single caret correctly
    if re.search(r"\bfor\s+", stripped, re.IGNORECASE):
        # Find all single-quoted strings in FOR commands
        # Look for patterns like FOR ... IN ('...') where carets inside quotes are valid
        for_match = re.search(r"\bin\s*\('([^']*)'\)", stripped, re.IGNORECASE)
        if for_match:
            # Check if the caret is within the quoted string
            quote_start = for_match.start(1)
            quote_end = for_match.end(1)
            if quote_start <= caret_pos < quote_end:
                return False

    # Check if this is an ECHO statement (likely ASCII art)
    if re.match(r"echo\s+", stripped, re.IGNORECASE):
        # ECHO statements often contain ASCII art with carets - don't flag these
        return False

    # Check if this is a SET statement (storing escaped commands)
    # SET commands often store command strings with escaped special characters
    # Example: SET @PRINT_IF_DEBUG=ECHO:^& SET @^& ECHO:^& TIMEOUT 5
    # Also check for SET inside IF statements: IF ... (SET VAR=value^&...)
    if re.search(r"\bset\s+", stripped, re.IGNORECASE):
        # SET statements commonly use single carets to store command strings - don't flag these
        return False

    # Check if this line is within a parenthesized command block (FOR DO block, IF block, etc.)
    # Lines inside blocks are typically indented and need carets for proper redirection
    # Pattern: line starts with whitespace/tabs (indented) and contains command with redirection
    if line and re.match(r"^\s+", line):
        # This is an indented line, likely inside a block
        # Carets for redirection (2^>NUL, ^|, etc.) are necessary in blocks
        # to prevent premature evaluation
        return False

    # Check if this line is a DO block on the same line as FOR
    # Pattern: FOR ... DO ( command with carets )
    if re.search(r"\bdo\s*\(", stripped, re.IGNORECASE):
        # This is a FOR DO block, carets are necessary
        return False

    return True

def _check_improper_caret_escape(
    stripped: str, line_number: int, line: str = ""
) -> List[LintIssue]:
    """Check for E030: Improper caret escape sequence."""
    issues: List[LintIssue] = []
    # Look for single caret attempting to escape special chars
    # But exclude FOR loop command strings, ECHO statements (ASCII art), and SET commands
    caret_matches = re.finditer(r"\^[&|><](?!\^)", stripped)
    for match in caret_matches:
        caret_pos = match.start()
        if _should_flag_caret_escape(stripped, caret_pos, line):
            issues.append(LintIssue(line_number, RULES["E030"], context=stripped))
    return issues

def _check_multilevel_escaping(stripped: str, line_number: int) -> List[LintIssue]:
    """Check for E031: Invalid multilevel escaping."""
    issues: List[LintIssue] = []
    # Check for incorrect caret counts in multilevel escaping
    caret_sequences: List[str] = re.findall(r"\^+[&|><]", stripped)
    for seq in caret_sequences:
        caret_count = len(seq) - 1  # -1 for the target character
        # Valid counts follow 2^n-1 pattern: 1, 3, 7, 15...
        valid_counts: List[int] = [1, 3, 7, 15, 31]  # 2^n-1 pattern for n=1 to 5
        if caret_count > 0 and caret_count not in valid_counts:
            issues.append(LintIssue(line_number, RULES["E031"], context=seq))
    return issues

def _check_continuation_spaces(
    line: str, stripped: str, line_number: int
) -> List[LintIssue]:
    """Check for E032: Continuation character with trailing spaces."""
    issues: List[LintIssue] = []
    # Check if line ends with ^ followed by spaces/tabs (before the line ending)
    if stripped.endswith("^"):
        # Get the line without line endings
        line_no_newline = line.rstrip("\r\n")
        # If the line doesn't end with ^ after removing spaces,
        # then there are trailing spaces after ^
        if not line_no_newline.endswith("^"):
            issues.append(
                LintIssue(
                    line_number, RULES["E032"], context="Caret with trailing spaces"
                )
            )
    return issues

def _check_double_percent_escaping(stripped: str, line_number: int) -> List[LintIssue]:
    """Check for E033: Double percent escaping error."""
    issues: List[LintIssue] = []
    # Look for single % in echo statements that should be %%
    if stripped.lower().startswith("echo") and "%" in stripped:
        # Only flag if there's a literal percentage (like "50%") not a variable reference
        # Variable references like %var% are fine
        # Check for percentage signs that might need escaping (number followed by %)
        # But exclude variable references %VAR%
        line_without_vars = re.sub(r"%[A-Za-z_][A-Za-z0-9_]*%", "", stripped)
        if re.search(r"\b\d+%(?!%)\b", line_without_vars):
            issues.append(
                LintIssue(
                    line_number,
                    RULES["E033"],
                    context="Percentage needs double escaping",
                )
            )
    return issues

def _check_advanced_escaping_rules(line: str, line_number: int) -> List[LintIssue]:
    """Check for advanced escaping technique issues."""
    # Multiple escaping rules (E030-E033) require checking various patterns
    issues: List[LintIssue] = []
    stripped = line.strip()

    # E030: Improper caret escape sequence
    issues.extend(_check_improper_caret_escape(stripped, line_number, line))

    # E031: Invalid multilevel escaping
    issues.extend(_check_multilevel_escaping(stripped, line_number))

    # E032: Continuation character with trailing spaces
    issues.extend(_check_continuation_spaces(line, stripped, line_number))

    # E033: Double percent escaping error
    issues.extend(_check_double_percent_escaping(stripped, line_number))

    return issues

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

    return issues

def _check_for_f_options(stripped: str, line_number: int) -> Optional[LintIssue]:
    """Check FOR /F without proper options (W020)."""
    if re.match(
        r'\s*for\s+/f\s+(?!.*"[^"]*tokens[^"]*")[^(]*\(', stripped, re.IGNORECASE
    ):
        return LintIssue(
            line_number=line_number,
            rule=RULES["W020"],
            context="FOR /F without explicit tokens/delims options",
        )
    return None

def _check_if_comparison_quotes(stripped: str, line_number: int) -> Optional[LintIssue]:
    """Check IF comparisons without quotes (W021)."""
    if_pattern = r'\s*if\s+(?:not\s+)?%\w+%\s*==\s*[^"\']\w+'
    if re.search(if_pattern, stripped, re.IGNORECASE):
        return LintIssue(
            line_number=line_number,
            rule=RULES["W021"],
            context="IF comparison should be quoted",
        )
    return None

def _check_deprecated_commands(stripped: str, line_number: int) -> List[LintIssue]:
    """Check for deprecated commands (W024) and removed commands (E034)."""
    issues: List[LintIssue] = []

    # Skip comment lines (REM or ::)
    if stripped.lower().startswith("rem ") or stripped.startswith("::"):
        return issues

    # First check for removed commands (more severe - Error level)
    # Special handling for "NET PRINT" (just NET PRINT is removed, not NET itself)
    if re.search(r"\bnet\s+print\b", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["E034"],
                context="NET PRINT has been removed - use PowerShell Print cmdlets instead",
            )
        )

    # Check other removed commands
    first_word = stripped.split()[0].lower() if stripped.split() else ""
    if first_word in REMOVED_COMMANDS:
        replacement_map = {
            "caspol": "Code Access Security Policy Tool from SDK",
            "diskcomp": "FC (file comparison)",
            "append": "modify PATH or use full paths",
            "browstat": "NET VIEW or PowerShell",
            "inuse": "HANDLE.EXE from Sysinternals",
            "diskcopy": "ROBOCOPY or XCOPY",
            "streams": "PowerShell Get-Item -Stream",
        }
        replacement = replacement_map.get(first_word, "a modern alternative")
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["E034"],
                context=(
                    f"Command '{first_word.upper()}' has been removed "
                    f"from Windows - use {replacement}"
                ),
            )
        )

    # Check for deprecated commands (Warning level)
    # Special case for NET SEND
    if re.search(r"\bnet\s+send\b", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["W024"],
                context="Use MSG command instead of deprecated 'NET SEND'",
            )
        )

    # Special case for AT command (needs special handling because AT is a common word)
    # Only flag if it looks like the scheduling command (e.g., "at 14:00" or "at \\computer")
    if re.search(r"\bat\s+(\d|\\\\)", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["W024"],
                context="Use SCHTASKS command instead of deprecated 'AT'",
            )
        )

    # Check single-word deprecated commands
    if first_word in DEPRECATED_COMMANDS:
        replacement_map = {
            "wmic": "PowerShell WMI cmdlets (Get-WmiObject/Get-CimInstance)",
            "cacls": "ICACLS command",
            "winrm": "PowerShell Remoting (Enter-PSSession/Invoke-Command)",
            "bitsadmin": "PowerShell BitsTransfer module",
            "nbtstat": "PowerShell Get-NetAdapter cmdlets",
            "dpath": "PATH environment variable modification",
            "keys": "CHOICE or SET /P commands",
            "assign": "drive mounting with modern tools",
            "backup": "modern backup tools",
            "comp": "FC command",
            "edlin": "modern text editors",
            "join": "drive mounting with modern tools",
            "subst": "persistent drive mappings or UNC paths",
        }
        replacement = replacement_map.get(first_word, "a modern alternative")
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["W024"],
                context=f"Command '{first_word.upper()}' is deprecated - use {replacement}",
            )
        )

    return issues

def _check_cmd_error_handling(
    stripped: str, line_number: int, lines: List[str]
) -> Optional[LintIssue]:
    """Check for missing error handling (W025)."""
    commands_needing_handling = ["del", "copy", "move", "mkdir", "rmdir"]

    for cmd in commands_needing_handling:
        if re.match(rf"\s*{cmd}\s+", stripped, re.IGNORECASE):
            # Check if next 3 lines have error handling
            for j in range(line_number, min(line_number + 3, len(lines) + 1)):
                if j <= len(lines) and (
                    "errorlevel" in lines[j - 1].lower()
                    or "if " in lines[j - 1].lower()
                ):
                    return None

            return LintIssue(
                line_number=line_number,
                rule=RULES["W025"],
                context=f"{cmd.upper()} command without error checking",
            )

    return None

def _check_enhanced_commands(lines: List[str]) -> List[LintIssue]:
    """Check for enhanced command validation issues (W020-W025)."""
    issues: List[LintIssue] = []
    uses_delayed_expansion = False

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Check for delayed expansion usage
        if re.search(r"!\w+!", stripped):
            uses_delayed_expansion = True

        # Run all line-level checks
        issue = _check_for_f_options(stripped, i)
        if issue:
            issues.append(issue)

        issue = _check_if_comparison_quotes(stripped, i)
        if issue:
            issues.append(issue)

        issues.extend(_check_deprecated_commands(stripped, i))

        issue = _check_cmd_error_handling(stripped, i, lines)
        if issue:
            issues.append(issue)

    # Check for missing SETLOCAL EnableDelayedExpansion (W022)
    if uses_delayed_expansion:
        has_setlocal = any(
            re.search(r"setlocal.*enabledelayedexpansion", line, re.IGNORECASE)
            for line in lines
        )
        if not has_setlocal:
            issues.append(
                LintIssue(
                    line_number=1,
                    rule=RULES["W022"],
                    context="Script uses !var! but missing SETLOCAL EnableDelayedExpansion",
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
