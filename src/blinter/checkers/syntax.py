"""Blinter package module."""

import re
from typing import (
    Dict,
    List,
    Set,
    Tuple,
)
from blinter.models import LintIssue
from blinter.patterns import (
    BUILTIN_COMMANDS,
    COMMON_COMMAND_TYPOS,
    _COMPILED_IF_PATTERN,
)
from blinter.rules.registry import RULES

def _check_goto_labels(
    stripped: str, line_num: int, labels: Dict[str, int]
) -> List[LintIssue]:
    """Check for GOTO label issues (E002, E015)."""
    issues: List[LintIssue] = []
    goto_match = re.match(r"goto\s+(:?\S+)", stripped, re.IGNORECASE)
    if not goto_match:
        return issues

    label_text: str = goto_match.group(1)
    target_label: str = label_text.lower()

    # E015: GOTO EOF must use colon (GOTO :EOF is required, GOTO EOF is invalid)
    if target_label == "eof":
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E015"],
                context="GOTO EOF should be GOTO :EOF (colon is mandatory for EOF)",
            )
        )
    elif target_label == ":eof":
        # :eof is a built-in construct, always valid with colon
        pass
    # Check for dynamic labels (containing variables)
    elif re.search(r"%[^%]+%|!\w+!", label_text):
        # Dynamic labels like "label.%errorlevel%" or "label[%variable%]" can't be
        # statically validated
        pass
    else:
        # Static label - check if it exists
        if not target_label.startswith(":"):
            target_label = ":" + target_label
        if target_label not in labels:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E002"],
                    context=f"GOTO points to non-existent label '{label_text}'",
                )
            )
    return issues

def _check_call_labels(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for CALL label issues (E014)."""
    issues: List[LintIssue] = []
    call_match = re.match(r"call\s+([^:\s]\S*)", stripped, re.IGNORECASE)
    if not call_match:
        return issues

    call_label_text: str = call_match.group(1)

    # Skip if the call target contains environment variables (runtime expansion)
    # Pattern matches %VAR%, %@VAR%, and similar variable syntax
    if re.search(r"%[@\w]+%", call_label_text):
        return issues

    # Check if this looks like a label call (not an external program)
    # Skip if it contains path separators, extensions, or is a known command
    if (
        not re.search(r"[\\/.:]|\.(?:bat|cmd|exe|com)$", call_label_text.lower())
        and call_label_text.lower() not in BUILTIN_COMMANDS
    ):
        # This appears to be a label call without colon
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E014"],
                context=(
                    f"CALL to label '{call_label_text}' should use colon: "
                    f"CALL :{call_label_text}"
                ),
            )
        )
    return issues

def _check_if_statement_formatting(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for IF statement formatting issues (E003)."""
    issues: List[LintIssue] = []
    if_match = _COMPILED_IF_PATTERN.match(stripped)
    if not if_match:
        return issues

    if_group_result = if_match.group(1)
    if if_group_result is None:
        return issues

    if_content: str = if_group_result.strip()

    # Valid IF patterns to check for:
    valid_if_patterns = [
        r"exist\s+",  # IF EXIST
        r"defined\s+",  # IF DEFINED
        r"errorlevel\s+\d+",  # IF ERRORLEVEL n
        r"/i\s+",  # IF /I (case insensitive)
        r"not\s+",  # IF NOT
        r".*\s*(==|equ|neq|lss|leq|gtr|geq)\s*",  # Comparison operators
    ]

    # Check if this IF statement matches any valid pattern
    is_valid_if = any(
        re.search(pattern, if_content, re.IGNORECASE) for pattern in valid_if_patterns
    )

    # If it doesn't match any valid pattern and seems incomplete, flag it
    if not is_valid_if and not re.search(
        r"[&|()]", if_content
    ):  # Not a complex conditional
        # Only flag if it looks like an incomplete comparison (has words but no operators)
        if re.match(r"[\"']?%?\w+%?[\"']?\s*$", if_content):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E003"],
                    context=(
                        "IF statement appears to be missing comparison operator "
                        "or condition"
                    ),
                )
            )
    return issues

def _check_errorlevel_syntax(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for invalid errorlevel comparison syntax (E016)."""
    issues: List[LintIssue] = []
    errorlevel_if_match = _COMPILED_IF_PATTERN.match(stripped)
    if not errorlevel_if_match:
        return issues

    errorlevel_group_result = errorlevel_if_match.group(1)
    if errorlevel_group_result is None:
        return issues

    errorlevel_content: str = errorlevel_group_result.strip()

    # Check for invalid "if not %errorlevel% number" pattern (missing operator)
    if re.match(r"not\s+%errorlevel%\s+\d+", errorlevel_content, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E016"],
                context=(
                    "Invalid 'IF NOT %ERRORLEVEL% number' syntax - "
                    "missing comparison operator"
                ),
            )
        )
    # Check for other invalid errorlevel patterns
    elif re.match(
        r"not\s+%errorlevel%\s+[^\s]+(?:\s|$)", errorlevel_content, re.IGNORECASE
    ):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E016"],
                context=(
                    "Invalid 'IF NOT %ERRORLEVEL%' syntax - use 'IF NOT ERRORLEVEL n' "
                    "or add comparison operator"
                ),
            )
        )
    return issues

def _check_if_exist_mixing(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for IF EXIST syntax mixing (E004)."""
    issues: List[LintIssue] = []
    if not re.match(r"if\s+exist\s+\S+\s+==", stripped, re.IGNORECASE):
        return issues

    # Check if there's another "if" between "exist" and "=="
    exist_to_equals = re.search(r"if\s+exist\s+(.*?)==", stripped, re.IGNORECASE)
    if exist_to_equals:
        between_text = exist_to_equals.group(1)
        # If there's no "if" keyword between exist and ==, then it's mixing
        if not re.search(r"\bif\b", between_text, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E004"],
                    context="Mixing IF EXIST with comparison operators",
                )
            )
    return issues

def _check_path_syntax(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for invalid path syntax (E005)."""
    issues: List[LintIssue] = []
    # Check if line contains PowerShell, VBScript, or other scripting commands
    # Now also checks for common PowerShell variable patterns (%psc%, %ps%, etc.)
    has_script_command = re.search(
        r"(for\s+|powershell\s+|cscript\s+|wscript\s+|msiexec\s+|%ps[c]?%|%powershell%)",
        stripped,
        re.IGNORECASE,
    )

    if has_script_command:
        return issues

    # Skip lines that look like they're part of PowerShell/C#/VBScript code
    # or output commands (echo, Write-Output, etc.)
    script_indicators = [
        r"\$\w+\s*=",  # PowerShell variable assignment
        r"-match\s+",  # PowerShell match operator
        r"\.Matches\(",  # Regex.Matches
        r"IndexOf\(",  # Array.IndexOf
        r"foreach\s*\(",  # foreach loops
        r"\[regex\]::",  # PowerShell [regex]::
        r"\[System\.",  # .NET class references
        r"Get-Content",  # PowerShell cmdlets
        r"ToArray\(\)",  # .ToArray() method calls
        r"Write-Output\s+",  # PowerShell Write-Output
        r"Write-Host\s+",  # PowerShell Write-Host
        r"^echo\s+",  # echo command at line start
        r"^\s*\$\w+",  # PowerShell variable at line start
    ]

    for indicator in script_indicators:
        if re.search(indicator, stripped, re.IGNORECASE):
            return issues

    # Check for XML/HTML content - must be at start of string or after whitespace/quote
    # to avoid false positives with paths like "file<test>"
    if re.search(r"<\?xml|^\s*<\w+[\s>]|['\"]<\w+\s", stripped, re.IGNORECASE):
        return issues

    path_patterns = [r'"([^"]*[<>|*?][^"]*)",', r"'([^']*[<>|*?][^']*)'"]
    for pattern in path_patterns:
        match = re.search(pattern, stripped)
        if match:
            path_content = match.group(1)
            # Allow escaped redirections like ^> ^| ^< in command strings
            escaped_content = re.sub(r"\^[<>|]", "", path_content)
            # Skip if this looks like a PowerShell or script command string
            # (contains :: for regex, scriptblock syntax, etc.)
            if re.search(
                r"(::|scriptblock|split\s|regex)", escaped_content, re.IGNORECASE
            ):
                continue
            # Wildcards (* and ?) are VALID in file paths for pattern matching
            # Only flag < > | as truly invalid
            if re.search(r"[<>|]", escaped_content):
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["E005"],
                        context="Path contains invalid characters",
                    )
                )
                break
    return issues

def _check_quotes(line: str, line_num: int) -> List[LintIssue]:
    """Check for mismatched quotes (E009)."""
    issues: List[LintIssue] = []

    # Skip REM comments and :: documentation comments - they can contain any characters
    stripped = line.strip()
    if (
        stripped.lower().startswith("rem ")
        or stripped.lower().startswith("rem\t")
        or stripped.startswith("::")
    ):
        return issues

    # Skip echo statements that are displaying documentation/help text
    # about special characters. These often contain unmatched quotes as examples.
    # Pattern: ECHO followed by spaces and text containing "Represents" or "...."
    if re.match(r"\s*echo\s+.*\.\.\.\.", stripped, re.IGNORECASE) or re.match(
        r"\s*echo\s+.*represents", stripped, re.IGNORECASE
    ):
        # This is documentation text explaining special characters
        return issues

    # Count quotes with comprehensive handling of batch file quoting rules
    # Handle: escaped quotes (""), caret escaping (^"), continuation lines,
    # and context-aware parsing
    quote_count = 0
    i = 0
    in_parentheses = 0  # Track parentheses depth for FOR/IF blocks

    while i < len(line):
        char = line[i]

        # Track parentheses depth to understand context
        if char == "(":
            in_parentheses += 1
        elif char == ")":
            in_parentheses = max(0, in_parentheses - 1)

        # Handle quote characters
        elif char == '"':
            # Check if this is a caret-escaped quote (^")
            if i > 0 and line[i - 1] == "^":
                # This is an escaped quote, skip it
                i += 1
                continue

            # Check if this is an escaped quote ("")
            if i + 1 < len(line) and line[i + 1] == '"':
                # Skip both quotes in the pair
                i += 2
                continue

            # Check for line continuation (^ at end)
            # If the quote is followed by ^ at end of line, it may be incomplete
            remaining = line[i + 1 :].strip()
            if remaining == "^":
                # Line continuation - don't count as unmatched
                i += 1
                continue

            # This is a regular quote
            quote_count += 1

        i += 1

    # Only report unmatched quotes if we're not in a complex parentheses block
    # and the line doesn't end with continuation character
    line_continues = line.rstrip().endswith("^")

    if quote_count % 2 != 0 and not line_continues:
        # Additional check: verify this isn't a special case like delayed expansion
        # or variable substitution that might have intentional single quotes
        has_delayed_expansion = "!" in line and re.search(
            r"\bset\s", stripped, re.IGNORECASE
        )
        has_call_substitution = re.search(r"call\s+:[^:]+", stripped, re.IGNORECASE)
        # Check for string replacement syntax like !VAR:"=! or %VAR:"=%
        # Delayed expansion: !VAR:"=! or !VAR:searchString=replaceString!
        has_delayed_string_replacement = re.search(
            r"![^!]+:[^=]*\"[^=]*=[^!]*!", line
        ) or re.search(r"![^!]+:[^=]*=[^!]*\"[^!]*!", line)
        # Old-style expansion: %VAR:"=% or %VAR:searchString=replaceString%
        has_percent_string_replacement = re.search(
            r"%[^%]+:[^=]*\"[^=]*=[^%]*%", line
        ) or re.search(r"%[^%]+:[^=]*=[^%]*\"[^%]*%", line)

        if not (
            has_delayed_expansion
            or has_call_substitution
            or has_delayed_string_replacement
            or has_percent_string_replacement
        ):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E009"],
                    context="Unmatched double quotes detected",
                )
            )
    return issues

def _check_for_loop_syntax(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for malformed FOR loop (E010)."""
    issues: List[LintIssue] = []
    if (
        re.match(r"for\s+.*", stripped, re.IGNORECASE)
        and " do " not in stripped.lower()
    ):
        # Don't flag multiline FOR loops (those ending with opening parenthesis)
        # or those that appear to continue on next line
        if not re.search(r"\(\s*$", stripped):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E010"],
                    context="FOR loop is missing required DO keyword",
                )
            )
    return issues

def _has_special_variable_patterns(stripped: str) -> bool:
    """Check if line contains special variable patterns that should skip E011 checks."""
    # Check for indirect variable expansion patterns like !%1!, !%var%!, or !%~n1!
    if re.search(r"!([^!]*%[^%!]+%?[^!]*|%~?[a-z0-9]+)!", stripped, re.IGNORECASE):
        return True

    # Check for dynamic variable assignment like set "%1=value" or set "%%~a=value"
    if re.search(r'set\s+"[^"]*%%?~?[a-z0-9][^"]*=', stripped, re.IGNORECASE):
        return True

    # Check for wildcard patterns with variables
    if re.search(
        r"(?:\*+%%?[A-Z0-9_@-]+(?::[^%]*=[^%]*)?%%?|\b%%?[A-Z0-9_@-]+(?::[^%]*=[^%]*)?%%?\*+)",
        stripped,
        re.IGNORECASE,
    ):
        return True

    # Check for escaped percent signs, string replacement, or variables with suffixes
    return (
        "%%%%" in stripped
        or bool(re.search(r"%%?[A-Z0-9_@-]+:.+=.+%%?", stripped, re.IGNORECASE))
        or bool(re.search(r"%[A-Z0-9_@-]+%[\w.*\\/:]+", stripped, re.IGNORECASE))
    )

def _check_variable_expansion(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for invalid variable expansion syntax (E011)."""
    issues: List[LintIssue] = []

    # Skip checking if line has special patterns
    if _has_special_variable_patterns(stripped):
        return issues

    # Remove FOR loop variables with modifiers (%%~a, %%~nx1, etc.)
    temp_stripped = re.sub(r"%%~[a-zA-Z]+", "", stripped)
    temp_stripped = re.sub(r"%%[a-zA-Z]", "", temp_stripped)

    # Remove command-line parameters with modifiers (%~nx1, %~dp0, etc.)
    temp_stripped = re.sub(
        r"%~?[fdpnxsatz]*[0-9*](?![0-9])", "", temp_stripped, flags=re.IGNORECASE
    )

    # Remove all valid variable expansion patterns (including @ prefix)
    temp_no_percent = re.sub(
        r"%[A-Z0-9_~@]+[^%]*%", "", temp_stripped, flags=re.IGNORECASE
    )
    temp_no_exclaim = re.sub(
        r"![A-Z0-9_@]+[^!]*!", "", temp_stripped, flags=re.IGNORECASE
    )

    # Look for incomplete variable patterns that suggest mismatched delimiters
    if re.search(r"%[A-Z0-9_@]+(?:[^%]|$)", temp_no_percent, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E011"],
                context="Variable reference may have mismatched % delimiters",
            )
        )

    if re.search(r"![A-Z0-9_@]+(?:[^!]|$)", temp_no_exclaim, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E011"],
                context="Delayed expansion variable may have mismatched ! delimiters",
            )
        )
    return issues

def _check_subroutine_call(
    stripped: str, line_num: int, labels: Dict[str, int]
) -> List[LintIssue]:
    """Check for missing CALL for subroutine invocation (E012).

    Detects when a user tries to invoke a defined label/subroutine without using
    CALL or GOTO, which won't work in batch files.

    Example:
        :MyFunction         <- Label definition
        MyFunction arg1     <- ERROR: Should be CALL :MyFunction arg1
    """
    issues: List[LintIssue] = []

    # Skip empty lines, comments, and label definitions
    if not stripped or stripped.startswith(("rem ", "rem\t", "::", ":")):
        return issues

    # Skip lines that already use CALL or GOTO
    if re.match(r"^(call|goto)\s+", stripped, re.IGNORECASE):
        return issues

    # Extract the first word (command/potential label invocation)
    first_word_match = re.match(r"^([a-z0-9_-]+)\b", stripped, re.IGNORECASE)
    if not first_word_match:
        return issues

    first_word: str = first_word_match.group(1).lower()

    # Skip if it's a known builtin command or external program
    if first_word in BUILTIN_COMMANDS:
        return issues

    # Skip if it looks like a file path or has an extension
    if re.search(r"[\\/.:]|\.(?:bat|cmd|exe|com|ps1)$", first_word):
        return issues

    # Check if this word matches any defined label (case-insensitive)
    # Labels are stored with colon prefix in lowercase (e.g., ":mylabel")
    potential_label = ":" + first_word

    # Check if this matches a defined label
    if potential_label in labels:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E012"],
                context=f"Attempting to call label '{first_word}' without CALL or GOTO",
            )
        )

    return issues

def _check_command_typos(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for invalid command syntax / typos (E013)."""
    issues: List[LintIssue] = []
    first_word = stripped.split()[0].lower() if stripped.split() else ""
    if first_word in COMMON_COMMAND_TYPOS:
        correct_command = COMMON_COMMAND_TYPOS[first_word]
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E013"],
                context=(
                    f"Command '{first_word}' appears to be a typo, "
                    f"did you mean '{correct_command}'?"
                ),
            )
        )
    return issues

def _check_parameter_modifiers(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for invalid parameter modifier combinations (E024, E025)."""
    issues: List[LintIssue] = []

    # E024: Invalid parameter modifier combination
    param_modifier_match: List[Tuple[str, str]] = re.findall(
        r"%~([a-zA-Z]+)([0-9]+|[a-zA-Z])%", stripped, re.IGNORECASE
    )
    if param_modifier_match:
        valid_modifiers: Set[str] = {"f", "d", "p", "n", "x", "s", "a", "t", "z"}
        for modifier, param in param_modifier_match:
            invalid_chars: Set[str] = set(modifier.lower()) - valid_modifiers
            if invalid_chars:
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["E024"],
                        context=f"Invalid parameter modifier characters: "
                        f"{', '.join(invalid_chars)} in %~{modifier}{param}%",
                    )
                )

    # E025: Parameter modifier on wrong context
    # First, remove FOR loop variables with modifiers (%%~a) - these are VALID
    temp_stripped = re.sub(r"%%~[a-zA-Z]", "", stripped)

    # Also remove batch file parameter modifiers like %~dp0, %~f1, etc. - these are VALID
    # %0 refers to the batch file itself, %1-%9 are command line arguments
    temp_stripped = re.sub(r"%~[a-zA-Z]+[0-9]", "", temp_stripped)

    # Now check for parameter modifiers used in wrong context (single % only)
    # This catches things like %~dVARIABLE% which are invalid
    wrong_context_match: List[str] = re.findall(
        r"%~[a-zA-Z]+([^0-9%\s][^%\s]*|[A-Z_][A-Z0-9_]*)%", temp_stripped
    )
    if wrong_context_match:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E025"],
                context="Parameter modifiers should only be used with batch parameters "
                "(%1, %2, etc.) or FOR variables (%%i)",
            )
        )
    return issues

def _check_unc_path(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for UNC path used as working directory (E027)."""
    issues: List[LintIssue] = []
    if re.match(r"cd\s+\\\\[^\\]+\\", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E027"],
                context="CD command cannot use UNC paths as working directory",
            )
        )
    return issues

def _is_legitimate_quote_pattern(stripped: str) -> bool:
    """
    Check if a line contains legitimate quote patterns that should be excluded.

    Args:
        stripped: The stripped line to check

    Returns:
        True if the line contains legitimate quote patterns, False otherwise
    """
    # Check all legitimate patterns
    legitimate_patterns = [
        # ECHO statements displaying documentation/help text
        # Pattern: ECHO followed by spaces and text containing "Represents" or "...."
        re.match(r"\s*echo\s+.*\.\.\.\.", stripped, re.IGNORECASE) is not None,
        re.match(r"\s*echo\s+.*represents", stripped, re.IGNORECASE) is not None,
        # Comparisons with empty string: neq "", equ "", == "", != ""
        re.search(r'\b(neq|equ|==|!=|lss|leq|gtr|geq)\s+""', stripped, re.IGNORECASE)
        is not None,
        # START command with triple-quote escaping: start ... /c ""!var!" ...
        re.search(r'\bstart\b.*\s+/c\s+""[^"]+!"', stripped, re.IGNORECASE) is not None,
        # START command with empty window title: start "" command
        re.search(r'\bstart\s+""\s+', stripped, re.IGNORECASE) is not None,
        # Properly formatted triple-quote patterns: """text"""
        re.match(r'.*"""[^"]*""".*', stripped) is not None,
        # Empty string as function/subroutine parameter: CALL :label param1 "" param2
        re.search(r'\bcall\s+:[^\s]+.*\s+""\s+', stripped, re.IGNORECASE) is not None,
        # Empty string as command parameter (not just in CALL): command param "" param
        re.search(r'\s+""\s+[^\s]', stripped) is not None,
    ]

    return any(legitimate_patterns)

def _check_quote_escaping(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for complex quote escaping errors (E028)."""
    issues: List[LintIssue] = []
    if '"""' not in stripped and not re.search(r'["\s]""[^"]', stripped):
        return issues

    if _is_legitimate_quote_pattern(stripped):
        return issues

    # Look for potentially problematic quote patterns
    quote_context = ""
    if '"""' in stripped:
        quote_context = "Triple quote pattern found"
    elif re.search(r'["\s]""[^"]', stripped):
        quote_context = "Complex quote escaping detected"

    issues.append(
        LintIssue(line_number=line_num, rule=RULES["E028"], context=quote_context)
    )
    return issues

def _check_set_a_expression(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for complex SET /A expression errors (E029)."""
    issues: List[LintIssue] = []
    seta_match = re.match(r"set\s+/a\s+(.+)", stripped, re.IGNORECASE)
    if not seta_match:
        return issues

    expression: str = seta_match.group(1)

    # Extract only the arithmetic expression, stopping at command separators
    # Command separators: & | && || (but not when escaped with ^)
    # Stop at the first unescaped command separator
    expr_match = re.match(r"^([^&|]*?)(?:\s*(?:[^\\^]|^)[&|]|$)", expression)
    if expr_match:
        expression = expr_match.group(1).strip()

    # Check for unbalanced parentheses in arithmetic expressions
    paren_count: int = expression.count("(") - expression.count(")")
    if paren_count != 0:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E029"],
                context=f"Unbalanced parentheses in SET /A expression: {paren_count} unclosed",
            )
        )

    # Check for unquoted expressions with special characters that might cause issues
    if not (expression.startswith('"') and expression.endswith('"')):
        if re.search(r"[&|<>^]", expression):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E029"],
                    context="SET /A expression with special characters should be quoted",
                )
            )
    return issues

def _check_syntax_errors(
    line: str, line_num: int, labels: Dict[str, int]
) -> List[LintIssue]:
    """Check for syntax error level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # Use helper functions to check for various syntax errors
    issues.extend(_check_goto_labels(stripped, line_num, labels))
    issues.extend(_check_call_labels(stripped, line_num))
    issues.extend(_check_if_statement_formatting(stripped, line_num))
    issues.extend(_check_errorlevel_syntax(stripped, line_num))
    issues.extend(_check_if_exist_mixing(stripped, line_num))
    issues.extend(_check_path_syntax(stripped, line_num))
    issues.extend(_check_quotes(line, line_num))
    issues.extend(_check_for_loop_syntax(stripped, line_num))
    issues.extend(_check_variable_expansion(stripped, line_num))
    issues.extend(_check_subroutine_call(stripped, line_num, labels))
    issues.extend(_check_command_typos(stripped, line_num))
    issues.extend(_check_parameter_modifiers(stripped, line_num))
    issues.extend(_check_unc_path(stripped, line_num))
    issues.extend(_check_quote_escaping(stripped, line_num))
    issues.extend(_check_set_a_expression(stripped, line_num))

    return issues
