"""Blinter package module."""

from collections import defaultdict
from pathlib import Path
import re
from typing import (
    DefaultDict,
    Dict,
    List,
    Optional,
    Tuple,
)
from blinter.models import LintIssue
from blinter.patterns import COMMAND_CASING_KEYWORDS
from blinter.parsing.context import _is_comment_line
from blinter.rules.helpers import _add_issue
from blinter.rules.registry import RULES
from blinter.parsing.context import _is_safe_ctx_for_privilege

def _check_global_style_rules(lines: List[str], file_path: str) -> List[LintIssue]:
    """Check global style rules that apply to the entire file."""
    issues: List[LintIssue] = []

    if not lines:
        return issues
    # S001: Missing @ECHO OFF at file start
    if not lines[0].strip().lower().startswith("@echo off"):
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["S001"],
                context="Script should start with @ECHO OFF",
            )
        )

    # S002: ECHO OFF without @ prefix
    first_line = lines[0].strip().lower()
    if first_line.startswith("echo off") and not first_line.startswith("@echo off"):
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["S002"],
                context="Use @ECHO OFF instead of ECHO OFF",
            )
        )

    # S007: File extension recommendation
    if file_path.lower().endswith(".bat"):
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["S007"],
                context="Consider using .cmd extension instead of .bat for scripts "
                "targeting Windows 2000 and newer",
            )
        )

    # S015: Inconsistent colon usage in GOTO statements
    issues.extend(_check_goto_colon_consistency(lines))

    return issues

def _check_goto_colon_consistency(  # pylint: disable=too-many-locals
    lines: List[str],
) -> List[LintIssue]:
    """Check for consistent colon usage in GOTO statements throughout the script (S015)."""
    issues: List[LintIssue] = []

    goto_statements: List[Tuple[int, str, bool]] = []

    # Collect all GOTO statements (excluding GOTO :EOF which has special rules)
    for i, line in enumerate(lines, start=1):
        stripped = line.strip().lower()
        goto_match = re.match(r"goto\s+(:?\S+)", stripped, re.IGNORECASE)
        if goto_match:
            label_text: str = goto_match.group(1).lower()
            # Skip GOTO :EOF and GOTO EOF as they have special handling
            if label_text not in [":eof", "eof"]:
                # Skip dynamic labels (containing variables)
                if not re.search(r"%[^%]+%|!\w+!", label_text):
                    uses_colon: bool = label_text.startswith(":")
                    goto_statements.append((i, label_text, uses_colon))

    if len(goto_statements) < 2:
        # Need at least 2 GOTO statements to check consistency
        return issues

    # Check if there's inconsistency in colon usage
    first_uses_colon = goto_statements[0][2]
    inconsistent_lines = []

    for line_num, _label, uses_colon in goto_statements[1:]:
        if uses_colon != first_uses_colon:
            inconsistent_lines.append(line_num)

    # Flag all inconsistent occurrences
    for line_num in inconsistent_lines:
        first_line = goto_statements[0][0]
        first_style = "with colon" if first_uses_colon else "without colon"
        current_style = "without colon" if first_uses_colon else "with colon"
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["S015"],
                context=(
                    f"GOTO statement uses {current_style} but first GOTO (line {first_line}) "
                    f"uses {first_style}"
                ),
            )
        )

    return issues

def _check_global_priv_security(lines: List[str]) -> List[LintIssue]:
    """Check for SEC005 privilege issues globally across the entire script."""
    issues: List[LintIssue] = []

    # Check if there's a privilege check (net session) in the script
    has_privilege_check = False
    for line in lines:
        stripped = line.strip().lower()
        if re.search(r"net\s+session\s*(>|$)", stripped):
            has_privilege_check = True
            break

    # If no privilege check found, flag all commands that need privileges
    if not has_privilege_check:
        for i, line in enumerate(lines, start=1):
            # Skip commands in safe contexts (comments, ECHO, SET statements)
            # Note: Uses privilege-specific safe context check that excludes IF DEFINED
            if _is_safe_ctx_for_privilege(line):
                continue

            stripped = line.strip().lower()

            # Check for admin commands
            admin_commands = ["reg add hklm", "reg delete hklm", "sc "]
            for cmd in admin_commands:
                if cmd in stripped:
                    issues.append(
                        LintIssue(
                            line_number=i,
                            rule=RULES["SEC005"],
                            context=f"Command '{cmd.strip()}' may require administrator privileges",
                        )
                    )
                    break

            # Check for net commands that aren't privilege checks
            # Use word boundary to match "net" as a command, not as part of words like "internet"
            if re.search(r"\bnet\s+", stripped):
                net_privilege_check_patterns = [
                    r"net\s+session\s*>",  # net session redirected (used for checking)
                    r"net\s+session\s*$",  # net session at end of line (used for checking)
                ]
                is_privilege_check = any(
                    re.search(pattern, stripped)
                    for pattern in net_privilege_check_patterns
                )
                if not is_privilege_check:
                    issues.append(
                        LintIssue(
                            line_number=i,
                            rule=RULES["SEC005"],
                            context="NET command may require administrator privileges",
                        )
                    )

    return issues

def _check_new_global_rules(lines: List[str], file_path: str) -> List[LintIssue]:
    """Check for new global rules that require full file context."""
    issues: List[LintIssue] = []

    # Split complex function into smaller focused functions
    issues.extend(_check_bat_cmd_differences(lines, file_path))
    issues.extend(_check_advanced_global_patterns(lines, file_path))
    issues.extend(_check_code_documentation(lines))
    issues.extend(_check_setlocal_redundancy(lines))

    # Global security checks
    issues.extend(_check_global_priv_security(lines))

    return issues

def _check_bat_cmd_differences(lines: List[str], file_path: str) -> List[LintIssue]:
    """Check for .bat/.cmd specific issues."""
    issues: List[LintIssue] = []

    # W028: .bat/.cmd errorlevel handling difference
    file_extension = Path(file_path).suffix.lower()
    errorlevel_commands = ["append", "dpath", "ftype", "set", "path", "assoc", "prompt"]

    if file_extension == ".bat":
        for i, line in enumerate(lines, start=1):
            stripped = line.strip().lower()
            first_word = stripped.split()[0] if stripped.split() else ""
            if first_word in errorlevel_commands:
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["W028"],
                        context=f"Command '{first_word}' handles errorlevel differently in "
                        f".bat vs .cmd files",
                    )
                )
                break  # Only flag once per file

    # W032: Missing character set declaration
    has_non_ascii = False
    has_chcp = False

    for line in lines:
        # Check for non-ASCII characters
        if any(ord(char) > 127 for char in line):
            has_non_ascii = True

        # Check for CHCP command
        if re.match(r"@?chcp\s", line.strip(), re.IGNORECASE):
            has_chcp = True

    if has_non_ascii and not has_chcp:
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["W032"],
                context="File contains non-ASCII characters but no character set "
                "declaration (CHCP)",
            )
        )

    return issues

def _check_advanced_global_patterns(
    lines: List[str], file_path: str
) -> List[LintIssue]:
    """Check advanced patterns of Batch Scripting."""
    issues: List[LintIssue] = []

    # W039: Nested FOR loops without call optimization
    issues.extend(_check_nested_for_loops(lines))

    # W041: Missing error handling for external commands
    issues.extend(_check_external_error_handling(lines))

    # SEC016: Automatic restart without failure limits
    issues.extend(_check_restart_limits(lines))

    # SEC019: Batch self-modification vulnerability
    issues.extend(_check_self_modification(lines, file_path))

    return issues

def _check_nested_for_loops(lines: List[str]) -> List[LintIssue]:
    """Check for nested FOR loops that should use CALL optimization."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip().lower()
        if not stripped.startswith("for "):
            continue

        # Found a FOR loop, check for nested FORs
        nested_for_issue = _find_nested_for_issue(lines, i)
        if nested_for_issue:
            issues.append(nested_for_issue)

    return issues

def _find_nested_for_issue(lines: List[str], start_line: int) -> Optional[LintIssue]:
    """Find nested FOR loop issues starting from given line."""
    brace_count = 0
    in_for_block = False

    for j in range(start_line, min(start_line + 20, len(lines))):
        check_line = lines[j].strip()
        brace_count += check_line.count("(") - check_line.count(")")

        if brace_count > 0:
            in_for_block = True

        # Check for nested FOR loop
        if in_for_block and check_line.lower().strip().startswith("for "):
            if j != start_line - 1:  # Not the same line
                if "call :" not in check_line.lower():
                    return LintIssue(
                        line_number=j + 1,
                        rule=RULES["W039"],
                        context="Nested FOR loop should use CALL :subroutine",
                    )
                break

        if brace_count <= 0 and in_for_block:
            break

    return None

def _check_external_error_handling(lines: List[str]) -> List[LintIssue]:
    """Check for missing error handling on external commands."""
    issues: List[LintIssue] = []
    external_commands = ["xcopy", "robocopy", "reg", "sc", "net", "wmic", "powershell"]

    for i, line in enumerate(lines, start=1):
        stripped = line.strip().lower()
        for cmd in external_commands:
            if stripped.startswith(cmd):
                # Check if next few lines have error handling
                has_error_check = False
                for j in range(i, min(i + 3, len(lines))):
                    if "errorlevel" in lines[j].lower() or "if not" in lines[j].lower():
                        has_error_check = True
                        break
                if not has_error_check:
                    issues.append(
                        LintIssue(
                            line_number=i,
                            rule=RULES["W041"],
                            context=f"External command '{cmd}' needs error handling",
                        )
                    )
                break

    return issues

def _check_restart_limits(lines: List[str]) -> List[LintIssue]:
    """Check for restart patterns without proper limits."""
    issues: List[LintIssue] = []
    restart_patterns = ["goto", ":retry", ":restart", "call :retry"]

    for i, line in enumerate(lines, start=1):
        stripped = line.strip().lower()
        for pattern in restart_patterns:
            if pattern in stripped and ("retry" in stripped or "restart" in stripped):
                # Look for counter or limit logic
                has_limit = False
                check_range = max(0, i - 10), min(len(lines), i + 10)
                for j in range(check_range[0], check_range[1]):
                    check_line = lines[j].lower()
                    limit_words = ["counter", "attempt", "limit", "max", "count"]
                    if any(word in check_line for word in limit_words):
                        has_limit = True
                        break
                if not has_limit:
                    issues.append(
                        LintIssue(
                            line_number=i,
                            rule=RULES["SEC016"],
                            context="Restart logic should have failure attempt limits",
                        )
                    )
                break

    return issues

def _check_self_modification(lines: List[str], file_path: str) -> List[LintIssue]:
    """Check for batch self-modification vulnerabilities."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip().lower()
        if (
            "echo" in stripped
            and (".bat" in stripped or ".cmd" in stripped)
            and (">" in stripped or ">>" in stripped)
        ):
            # Check if writing to same file or generating batch files
            if any(
                keyword in stripped for keyword in ["%~f0", "%0", file_path.lower()]
            ):
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["SEC019"],
                        context="Script appears to modify itself - potential security risk",
                    )
                )

    return issues

def _check_code_documentation(lines: List[str]) -> List[LintIssue]:
    """Check for code documentation and style issues."""
    issues: List[LintIssue] = []

    # S022: Inconsistent variable naming convention
    issues.extend(_check_var_naming(lines))

    return issues

def _categorize_variable_style(var_name: str) -> str:
    """
    Determine the naming style of a variable.

    Args:
        var_name: Variable name to analyze

    Returns:
        Style name: "snake_case", "PascalCase", "camelCase", "UPPERCASE", or "lowercase"
    """
    if "_" in var_name and var_name.islower():
        return "snake_case"
    if var_name[0].isupper() and any(c.islower() for c in var_name[1:]):
        return "PascalCase"
    if var_name[0].islower() and any(c.isupper() for c in var_name[1:]):
        return "camelCase"
    if var_name.isupper():
        return "UPPERCASE"
    if var_name.islower():
        return "lowercase"
    return "unknown"

def _should_skip_line_for_var_check(stripped: str) -> bool:
    """
    Check if line should be skipped for variable name checking.

    Args:
        stripped: Stripped line content

    Returns:
        True if line should be skipped
    """
    skip_prefixes = ("echo ", "rem ", "::")
    skip_chars = (">", ">>")

    if any(stripped.startswith(prefix) for prefix in skip_prefixes):
        return True
    if any(char in stripped for char in skip_chars):
        return True
    return False

def _check_var_naming(lines: List[str]) -> List[LintIssue]:
    """Check for inconsistent variable naming conventions."""
    issues: List[LintIssue] = []
    variable_names = set()
    naming_styles: DefaultDict[str, int] = defaultdict(int)

    # Combined pattern for efficiency
    set_pattern = re.compile(
        r'^\s*set\s+(?:")?([a-zA-Z_][a-zA-Z0-9_]*)\s*=', re.IGNORECASE
    )

    for line in lines:
        stripped = line.strip()
        if _should_skip_line_for_var_check(stripped):
            continue

        # Extract variable names from SET commands
        match = set_pattern.search(line)
        if match:
            var_name = match.group(1)
            variable_names.add(var_name)
            style = _categorize_variable_style(var_name)
            naming_styles[style] += 1

    # Check for mixed styles (only if we have enough variables to analyze)
    if len(variable_names) >= 3:
        used_styles = sum(1 for count in naming_styles.values() if count > 0)
        if used_styles > 1:
            dominant_style = max(naming_styles, key=naming_styles.get)  # type: ignore[arg-type]
            _add_issue(
                issues,
                line_number=1,
                rule_code="S022",
                context=f"Mixed variable naming styles detected. "
                f"Consider using {dominant_style} consistently",
            )

    return issues

def _check_setlocal_redundancy(lines: List[str]) -> List[LintIssue]:
    """Check for redundant SETLOCAL/ENDLOCAL pairs."""
    issues: List[LintIssue] = []
    setlocal_count = sum(1 for line in lines if "setlocal" in line.lower())
    endlocal_count = sum(1 for line in lines if "endlocal" in line.lower())

    if setlocal_count > 1 or endlocal_count > 1:
        for i, line in enumerate(lines, start=1):
            if "setlocal" in line.lower() and i > 5:  # Not at beginning
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["P024"],
                        context="Multiple SETLOCAL commands create unnecessary overhead",
                    )
                )
                break

    return issues

def _check_missing_exit_statement(  # pylint: disable=too-many-branches
    lines: List[str],
) -> List[LintIssue]:
    """Check if script can reach EOF without an explicit EXIT statement (W001).

    This function performs control flow analysis to determine if the main execution
    path can fall through to end-of-file without encountering an EXIT statement.

    Smart detection includes:
    - Allows scripts where all paths lead to EXIT or GOTO :EOF
    - Allows pure subroutine libraries (scripts that start with a label before any executable code)
    - Allows scripts with only @echo off and comments (essentially setup-only scripts)
    - Flags scripts where main execution can fall through to EOF
    - Understands GOTO, labels, and conditional branches
    """
    issues: List[LintIssue] = []

    # Empty script or comments-only script doesn't need exit
    has_meaningful_code = False
    first_executable_line = -1
    first_label_line = -1

    # Find first executable code and first label
    for i, line in enumerate(lines):
        stripped = line.strip().lower()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("rem") or stripped.startswith("::"):
            continue

        # Check for labels (but not comment-style labels)
        if stripped.startswith(":") and not stripped.startswith("::"):
            if first_label_line == -1:
                first_label_line = i
            continue

        # Check for executable code
        if _is_truly_executable_command(stripped):
            if first_executable_line == -1:
                first_executable_line = i
            # @echo off is a setup command, not meaningful executable code
            # Only count as meaningful if it's not just @echo off/on
            if not re.match(r"^@?echo\s+(off|on)$", stripped):
                has_meaningful_code = True

    # If no meaningful executable code, no issue
    if not has_meaningful_code:
        return issues

    # If first label comes before first executable code, this is a subroutine library
    # These scripts are meant to be CALLed, not executed directly
    if (
        first_label_line != -1
        and first_executable_line != -1
        and first_label_line < first_executable_line
    ):
        return issues

    # Now check if the main execution path reaches EOF without EXIT
    # Scan backwards from end of file to find if we can reach EOF
    can_reach_eof = _can_main_execution_reach_eof(lines)

    if can_reach_eof:
        # Find the last line of executable code to report the issue there
        last_executable_line = -1
        for i in range(len(lines) - 1, -1, -1):
            stripped = lines[i].strip().lower()
            if _is_truly_executable_command(stripped):
                last_executable_line = i + 1  # Convert to 1-indexed
                break

        if last_executable_line > 0:
            issues.append(
                LintIssue(
                    line_number=last_executable_line,
                    rule=RULES["W001"],
                    context="Script can reach end of file without explicit EXIT statement",
                )
            )

    return issues

def _can_main_execution_reach_eof(lines: List[str]) -> bool:
    """Determine if the main execution path can reach end-of-file without EXIT.

    This performs a forward scan through the script tracking whether we can
    reach EOF. It considers:
    - EXIT statements (blocks path to EOF)
    - GOTO statements (may redirect control flow)
    - Labels (can be jumped to)
    - Conditional blocks (IF/FOR with parentheses)
    """
    # Track whether we're in reachable code
    reachable = True
    paren_depth = 0

    for line in lines:
        stripped = line.strip().lower()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("rem") or stripped.startswith("::"):
            continue

        # Labels make code reachable again
        if stripped.startswith(":") and not stripped.startswith("::"):
            reachable = True
            continue

        # Update parentheses depth for IF/FOR blocks
        paren_depth = _update_paren_depth(stripped, paren_depth)

        # Check for EXIT statements
        if re.match(r"exit\b", stripped):
            # EXIT makes code unreachable
            # But only if we're at the top level (not inside IF/FOR blocks)
            if paren_depth == 0:
                reachable = False
                continue

        # Check for unconditional GOTO (not inside IF statement)
        # GOTO at top level redirects control flow
        if paren_depth == 0 and re.match(r"goto\s+", stripped):
            # Check if it's GOTO :EOF (which is like EXIT)
            if re.match(r"goto\s+:eof\b", stripped):
                reachable = False
                continue
            # Other GOTO statements redirect flow, making subsequent code unreachable
            # until we hit a label
            reachable = False
            continue

    # If we finished the scan and code is still reachable, we can reach EOF
    return reachable

def _check_unreachable_code(lines: List[str]) -> List[LintIssue]:
    """Check for unreachable code after EXIT or GOTO statements."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        if re.match(r"(exit\s|goto\s)", stripped):
            # Find unreachable code after this EXIT/GOTO
            unreachable_line = _find_truly_unreachable_code(lines, i)
            if unreachable_line is not None:
                command = stripped.split()[0].upper()
                issues.append(
                    LintIssue(
                        line_number=unreachable_line + 1,
                        rule=RULES["E008"],
                        context=(
                            f"Code after {command} on line {i + 1} will never execute"
                        ),
                    )
                )

    return issues

def _find_truly_unreachable_code(
    lines: List[str], exit_line_index: int
) -> Optional[int]:
    """Find truly unreachable code, considering batch file control flow properly."""
    exit_paren_depth = _calculate_exit_paren_depth(lines, exit_line_index)
    return _scan_for_unreachable_code(lines, exit_line_index, exit_paren_depth)

def _calculate_exit_paren_depth(lines: List[str], exit_line_index: int) -> int:
    """Calculate the parentheses depth at the EXIT statement."""
    current_paren_depth = 0

    for i in range(exit_line_index + 1):
        line = lines[i].strip().lower()
        current_paren_depth = _update_paren_depth(line, current_paren_depth)

    return current_paren_depth

def _scan_for_unreachable_code(
    lines: List[str], exit_line_index: int, exit_paren_depth: int
) -> Optional[int]:
    """Scan forward from EXIT to find unreachable code."""
    current_paren_depth = exit_paren_depth

    for j in range(exit_line_index + 1, len(lines)):
        line = lines[j].strip().lower()

        # Skip empty lines and comments
        if not line or line.startswith("rem") or line.startswith("::"):
            continue

        # Check if this line makes code reachable again
        if _line_makes_code_reachable(line):
            return None

        # Update parentheses depth
        current_paren_depth = _update_paren_depth(line, current_paren_depth)

        # Handle closing parentheses specially
        if line == ")":
            if current_paren_depth < exit_paren_depth:
                return None
            continue

        # Skip certain structural elements
        if line in {"endlocal", "setlocal"}:
            continue

        # Check for executable code
        if _is_truly_executable_command(line):
            if exit_paren_depth == 0 or current_paren_depth >= exit_paren_depth:
                return j
            return None

    return None

def _update_paren_depth(line: str, current_depth: int) -> int:
    """Update parentheses depth based on the line content."""
    # Match IF or FOR statements with opening parentheses
    if re.search(r"\b(?:if|for)\b.*\(", line):
        return current_depth + 1
    # Match closing parenthesis even with redirect operators
    # Examples: ), ) >>file.txt, ) 2>&1, ) >>file.log 2>&1, ) >nul 2>&1
    # Pattern: ) followed by optional whitespace and optional redirects
    # Order matters: >> must be checked before > to avoid partial match
    if re.match(r"^\)(?:\s*(?:>>|[12]>|[<>]))?", line):
        return current_depth - 1
    return current_depth

def _line_makes_code_reachable(line: str) -> bool:
    """Check if a line makes code reachable again."""
    # Labels make code reachable
    if line.startswith(":") and not line.startswith("::"):
        return True

    # ') else' creates a new reachable path
    if re.match(r"^\)\s*else\b", line):
        return True

    return False

def _is_truly_executable_command(line: str) -> bool:
    """Check if a line is truly executable code (not structural)."""
    line = line.strip().lower()

    # Skip empty, comments, labels
    if (
        not line
        or line.startswith("rem")
        or line.startswith("::")
        or line.startswith(":")
    ):
        return False

    # Skip pure structural elements
    if line in {")", "endlocal", "setlocal"}:
        return False

    # Skip ') else' patterns
    if re.match(r"^\)\s*(else\b.*)?$", line):
        return False

    # Skip closing parenthesis with redirection operators
    # These are part of block I/O redirection, not executable code
    # Examples: ) >>file.txt 2>&1, ) >output.log, ) 2>nul
    if re.match(r"^\)\s*(?:>>?|<|[12]>&?[12]?)", line):
        return False

    return True

def _check_redundant_operations(lines: List[str]) -> List[LintIssue]:
    """Check for redundant file operations."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        # Look for repeated IF EXIST checks on the same file
        exist_match = re.search(r"if\s+exist\s+(\S+)", stripped)
        if exist_match:
            filename_result = exist_match.group(1)
            if filename_result is not None:
                filename: str = filename_result
                # Check subsequent lines for same file
                for j in range(i + 1, min(i + 5, len(lines))):
                    next_stripped = lines[j].strip().lower()
                    if f"if exist {filename}" in next_stripped:
                        issues.append(
                            LintIssue(
                                line_number=j + 1,
                                rule=RULES["P001"],
                                context=f"Redundant existence check for {filename} "
                                f"(first check on line {i + 1})",
                            )
                        )
                        break

    return issues

def _check_code_duplication(lines: List[str]) -> List[LintIssue]:
    """Check for code duplication that could be refactored."""
    issues: List[LintIssue] = []

    # Simple heuristic: look for repeated command patterns
    command_blocks: Dict[str, List[int]] = defaultdict(list)

    # Commands that are commonly repeated for user interaction and don't need refactoring
    ui_commands = [
        r"timeout\s+/t\s+\d+",  # timeout commands
        r"pause\s*$",  # pause commands
        r"echo\s+\.?\s*$",  # echo blank lines
        r"^\s*echo\s+",  # echo commands in general
        r"^\s*if\s+",  # if statements
        r"^\s*set\s+",  # set commands
        r"^\s*call\s+",  # call commands
        r"^\s*goto\s+",  # goto commands
        r"^\s*for\s+",  # for loops
    ]

    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        if stripped and not stripped.startswith(":") and not stripped.startswith("rem"):
            # Skip common user interface commands that are legitimately repeated
            is_ui_command = any(re.search(pattern, stripped) for pattern in ui_commands)
            if is_ui_command:
                continue

            # Normalize the command for comparison
            normalized = re.sub(r"\S+\.(txt|log|bat|cmd)", "FILE", stripped)
            normalized = re.sub(r"%\w+%", "VAR", normalized)

            if (
                len(normalized) > 40
            ):  # Only consider substantial commands (increased from 20)
                command_blocks[normalized].append(i + 1)

    # Calculate appropriate threshold based on script size
    # For larger scripts, allow more repetition before flagging
    script_size = len(lines)
    if script_size < 100:
        threshold = 3  # Small scripts: flag 3+ occurrences
    elif script_size < 500:
        threshold = 5  # Medium scripts: flag 5+ occurrences
    elif script_size < 2000:
        threshold = 10  # Large scripts: flag 10+ occurrences
    else:
        threshold = 20  # Very large scripts: flag 20+ occurrences

    for _normalized_cmd, line_numbers in command_blocks.items():
        if len(line_numbers) >= threshold:  # Found threshold+ similar commands
            # Only flag if occurrences are close together (within 100 lines)
            # This catches actual duplication that should be refactored
            for i in range(len(line_numbers) - 1):
                if line_numbers[i + 1] - line_numbers[i] < 100:
                    # Found close duplicates, flag this group
                    issues.append(
                        LintIssue(
                            line_number=line_numbers[i + 1],
                            rule=RULES["P002"],
                            context=f"Similar command pattern repeated "
                            f"(also on lines {line_numbers[i]})",
                        )
                    )

    return issues

def _check_missing_pause(lines: List[str]) -> List[LintIssue]:
    """Check for missing PAUSE in interactive scripts (W014)."""
    issues: List[LintIssue] = []

    has_user_input = any(
        re.search(r"set\s+/p\s+", line, re.IGNORECASE)
        or re.search(r"choice\s+", line, re.IGNORECASE)
        for line in lines
    )

    has_pause = any(re.search(r"pause", line, re.IGNORECASE) for line in lines)

    if has_user_input and not has_pause:
        # Find an appropriate line number (near the end)
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].strip() and not lines[i].strip().startswith("rem"):
                issues.append(
                    LintIssue(
                        line_number=i + 1,
                        rule=RULES["W014"],
                        context="Interactive script should include PAUSE to prevent window closing",
                    )
                )
                break

    return issues

def _collect_indented_lines(lines: List[str]) -> List[Tuple[int, str]]:
    """Collect all indented lines with their leading whitespace."""
    indented_lines = []
    for i, line in enumerate(lines, start=1):
        if line.startswith(("\t", " ")):
            leading_whitespace = ""
            for char in line:
                if char in ("\t", " "):
                    leading_whitespace += char
                else:
                    break
            indented_lines.append((i, leading_whitespace))
    return indented_lines

def _find_single_line_mixed_indent(
    indented_lines: List[Tuple[int, str]],
) -> List[LintIssue]:
    """Check for mixed tabs and spaces within single lines."""
    issues: List[LintIssue] = []
    for line_num, whitespace in indented_lines:
        if "\t" in whitespace and " " in whitespace:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["S012"],
                    context="Line mixes tabs and spaces for indentation",
                )
            )
    return issues

def _find_file_mixed_indent(
    indented_lines: List[Tuple[int, str]],
) -> Optional[LintIssue]:
    """Check for inconsistent indentation across the entire file."""
    uses_tabs = False
    uses_spaces = False
    first_tab_line = 0
    first_space_line = 0

    for line_num, whitespace in indented_lines:
        if "\t" in whitespace:
            uses_tabs = True
            if first_tab_line == 0:
                first_tab_line = line_num
        if " " in whitespace:
            uses_spaces = True
            if first_space_line == 0:
                first_space_line = line_num

    if uses_tabs and uses_spaces:
        later_line = max(first_tab_line, first_space_line)
        if first_tab_line < first_space_line:
            context = (
                f"File mixes tabs (line {first_tab_line}) and spaces "
                f"(line {first_space_line}) for indentation"
            )
        else:
            context = (
                f"File mixes spaces (line {first_space_line}) and tabs "
                f"(line {first_tab_line}) for indentation"
            )
        return LintIssue(line_number=later_line, rule=RULES["S012"], context=context)
    return None

def _check_inconsistent_indentation(
    lines: List[str],
) -> List[LintIssue]:
    """Check for inconsistent indentation patterns across the file (S012)."""
    issues: List[LintIssue] = []

    indented_lines = _collect_indented_lines(lines)
    if len(indented_lines) < 2:
        return issues

    # Check for mixed patterns within single lines first
    single_line_issues = _find_single_line_mixed_indent(indented_lines)
    issues.extend(single_line_issues)

    # Check for inconsistent indentation across file only if no single-line mixing found
    if not single_line_issues:
        file_issue = _find_file_mixed_indent(indented_lines)
        if file_issue:
            issues.append(file_issue)

    return issues

def _check_missing_header_doc(lines: List[str]) -> List[LintIssue]:
    """Check for missing file header documentation (S013)."""
    issues: List[LintIssue] = []

    # Skip short files (under 30 lines) - likely simple utilities
    # Increased threshold to be less aggressive
    if len(lines) < 30:
        return issues

    # Check first 15 lines for meaningful comments (expanded from 10)
    meaningful_comments = 0
    general_comments = 0

    for line in lines[:15]:
        stripped = line.strip().lower()
        if _is_comment_line(line) and len(stripped) > 6:
            general_comments += 1
            # Look for formal documentation indicators (strict)
            if any(
                keyword in stripped
                for keyword in [
                    "script:",
                    "purpose:",
                    "author:",
                    "date:",
                    "description:",
                    "usage:",
                    "function:",
                    "does:",
                    "created:",
                    "modified:",
                    "version:",
                ]
            ):
                meaningful_comments += 1
            # Also accept descriptive comments about what the script does
            elif any(
                keyword in stripped
                for keyword in [
                    "this script",
                    "this batch",
                    "this file",
                    "repairs",
                    "fixes",
                    "cleans",
                    "updates",
                    "installs",
                    "configures",
                    "enables",
                    "disables",
                    "resets",
                    "restores",
                    "optimizes",
                    "removes",
                    "deletes",
                    "creates",
                    "sets up",
                    "flushes",
                ]
            ):
                meaningful_comments += 1

    # Only flag if there are NO meaningful comments AND very few general comments
    # Increased threshold to 3 to be even more lenient
    if meaningful_comments == 0 and general_comments < 3:
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["S013"],
                context="Script lacks header documentation (purpose, author, date)",
            )
        )

    return issues

def _collect_cmd_cases(lines: List[str]) -> Dict[str, List[Tuple[int, str]]]:
    """Collect command casing patterns from file lines."""
    command_cases: Dict[str, List[Tuple[int, str]]] = {}

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("rem ") or stripped.startswith("::"):
            continue

        # Skip lines where commands appear in contexts that aren't actual batch commands
        # (e.g., within echo statements, comments, or file output)
        if (
            stripped.lower().startswith("echo ")
            or ">" in stripped  # File redirection (content being written to file)
            or ">>" in stripped
        ):
            continue

        # Find commands in this line - only at the start or after common batch separators
        for keyword in COMMAND_CASING_KEYWORDS:
            # Only match commands at line start or after certain separators
            pattern = rf"(^|\s+|&|\||\()\s*({keyword})\b"
            matches = re.finditer(pattern, stripped, re.IGNORECASE)

            for match in matches:
                actual_case = match.group(2)  # Group 2 is the keyword itself
                if keyword not in command_cases:
                    command_cases[keyword] = []
                command_cases[keyword].append((line_num, actual_case))

    return command_cases

def _find_most_common_case(
    occurrences: List[Tuple[int, str]],
) -> Tuple[str, Dict[str, List[int]]]:
    """Find the most common case variant and return case counts."""
    case_counts: Dict[str, List[int]] = {}
    for line_num, actual_case in occurrences:
        if actual_case not in case_counts:
            case_counts[actual_case] = []
        case_counts[actual_case].append(line_num)

    def _get_count(case_variant: str) -> int:
        return len(case_counts[case_variant])

    most_common_case = max(case_counts.keys(), key=_get_count)
    return most_common_case, case_counts

def _check_cmd_case_consistency(lines: List[str]) -> List[LintIssue]:
    """Check for consistent command capitalization within the file (S003)."""
    issues: List[LintIssue] = []

    if len(lines) < 2:  # Skip very short files
        return issues

    command_cases = _collect_cmd_cases(lines)

    # Check for inconsistency within each command
    for _, occurrences in command_cases.items():
        if len(occurrences) < 2:  # Need at least 2 occurrences to check consistency
            continue

        most_common_case, case_counts = _find_most_common_case(occurrences)

        if len(case_counts) > 1:  # Inconsistent casing found
            # Report inconsistencies
            for case_variant, line_numbers in case_counts.items():
                if case_variant != most_common_case:
                    for line_num in line_numbers:
                        issues.append(
                            LintIssue(
                                line_number=line_num,
                                rule=RULES["S003"],
                                context=f"Command '{case_variant}' should be "
                                f"'{most_common_case}' for consistency "
                                f"(most common in this file)",
                            )
                        )

    return issues
