"""Comment detection and safe-context helpers for checkers."""

import re
from typing import cast

from blinter.patterns import (
    _DANGEROUS_CMDS_REGEX,
)


def _is_comment_line(line: str) -> bool:
    """
    Check if a line is a comment (REM or ::).

    Args:
        line: The line to check

    Returns:
        True if the line is a comment
    """
    stripped = line.strip().lower()
    return (
        stripped.startswith("rem ")
        or stripped.startswith("rem\t")
        or stripped.startswith("::")
    )


def _is_command_in_safe_context(line: str) -> bool:
    """
    Check if a potentially dangerous command is in a safe context.

    Safe contexts include REM comments, ECHO statements, labels, GOTO statements,
    or IF DEFINED variable checks. SET statements are generally safe UNLESS they
    contain dangerous commands in command substitution contexts (e.g., WHERE FORMAT,
    WHERE SHUTDOWN, etc.).

    Args:
        line: The line to check

    Returns:
        True if the command is in a safe context and shouldn't be flagged as dangerous
    """
    stripped = line.strip().lower()

    # Check if line is a comment (REM or ::)
    if _is_comment_line(line):
        return True

    # Check if line is a label definition (starts with :)
    if stripped.startswith(":"):
        return True

    # Check if line starts with ECHO or @ECHO (output statements)
    if stripped.startswith(("echo ", "echo\t", "@echo ", "@echo\t")):
        return True

    # Check if line contains GOTO statement (navigation to labels)
    # or IF DEFINED for variable checks
    if re.search(r"\bgoto\s+:", stripped) or re.search(r"\bif\s+defined\s+", stripped):
        return True

    # Check if line is a SET statement (environment variable assignment)
    # But NOT if it contains dangerous commands in command substitution
    if stripped.startswith(("set ", "set\t")):
        # Check for any dangerous command pattern in command substitution
        # Common patterns: WHERE <dangerous_cmd>, or the dangerous command itself in quotes
        dangerous_in_substitution = re.search(
            rf"where\s+({_DANGEROUS_CMDS_REGEX})", stripped
        ) or re.search(rf"['\(]\s*({_DANGEROUS_CMDS_REGEX})\s+", stripped)
        if not dangerous_in_substitution:
            return True

    return False


def _is_safe_ctx_for_privilege(line: str) -> bool:
    """
    Check if a command is in a safe context for privilege (SEC005) checks.

    This is similar to _is_command_in_safe_context but EXCLUDES IF DEFINED
    because privilege-requiring commands still need admin rights even when
    wrapped in an IF DEFINED conditional.

    For example:
    - IF DEFINED @DLETTER NET USE %@DLETTER% /D /Y  <- Still needs admin rights
    - IF DEFINED @MSSHUTDOWN echo Variable defined   <- Truly safe (just echo)
    - IF DEFINED @MORECMDS ECHO Other NET USER Options <- Truly safe (just echo)
    - IF DEFINED *SERVICE_SC (                         <- Truly safe (just variable check)

    Safe contexts for privilege checks include REM comments, ECHO statements,
    labels, GOTO statements, and SET statements (without dangerous commands).
    IF DEFINED is NOT considered safe for privilege checks UNLESS the actual
    command after the condition is ECHO or there's just a variable name check.

    Args:
        line: The line to check

    Returns:
        True if the command is in a safe context for privilege checks
    """
    stripped = line.strip().lower()

    # Check if line is a comment (REM or ::) or label definition (starts with :)
    if _is_comment_line(line) or stripped.startswith(":"):
        return True

    # Check if line starts with ECHO or @ECHO (output statements)
    if stripped.startswith(("echo ", "echo\t", "@echo ", "@echo\t")):
        return True

    # Check if line contains IF/IF DEFINED with ECHO as the actual command
    # Pattern: IF [/I] [NOT] [DEFINED] <condition> ECHO <text>
    # Examples:
    #   IF DEFINED @VAR ECHO text with NET USER <- ECHO is the command (SAFE)
    #   IF DEFINED @VAR NET USE <- NET USE is the command (NOT SAFE)
    if_match = re.match(
        r"^@?if\s+(?:/i\s+)?(?:not\s+)?(?:defined\s+\S+\s+)?(.+)", stripped
    )
    if if_match:
        # Extract the command portion after the condition
        command_portion: str = cast(str, if_match.group(1)).strip()
        # Check if the command is ECHO or if it's IF DEFINED with just a variable check
        # Pattern: IF DEFINED <varname> ( or IF DEFINED <varname> THEN or just IF DEFINED <varname>
        is_echo_command: bool = command_portion.startswith(("echo ", "echo\t"))
        is_variable_check: bool = bool(
            re.match(r"^@?if\s+(?:/i\s+)?defined\s+\S+\s*(?:\(|then)?$", stripped)
        )
        if is_echo_command or is_variable_check:
            return True

    # Check if line contains GOTO statement (navigation to labels)
    # NOTE: IF DEFINED is NOT included here for privilege checks
    if re.search(r"\bgoto\s+:", stripped):
        return True

    # Check if line is a SET statement (environment variable assignment)
    # But NOT if it contains dangerous commands in command substitution
    if stripped.startswith(("set ", "set\t")):
        # Check for any dangerous command pattern in command substitution
        # Common patterns: WHERE <dangerous_cmd>, or the dangerous command itself in quotes
        dangerous_in_substitution = re.search(
            rf"where\s+({_DANGEROUS_CMDS_REGEX})", stripped
        ) or re.search(rf"['\(]\s*({_DANGEROUS_CMDS_REGEX})\s+", stripped)
        if not dangerous_in_substitution:
            return True

    return False
