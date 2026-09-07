"""Comment detection and safe-context helpers for checkers."""

import re
from typing import Iterator, cast

from blinter.logging_config import logger
from blinter.patterns import (
    _DANGEROUS_CMDS_REGEX,
)

_GOTO_LABEL_RE = re.compile(r"\bgoto\s+(:?)([a-zA-Z_][\w]*)", re.IGNORECASE)
_CALL_LABEL_RE = re.compile(r"\bcall\s+:([a-zA-Z_][\w]*)", re.IGNORECASE)


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


def _is_comment_or_label(line: str) -> bool:
    """Return True when the line is a comment or label definition."""
    stripped = line.strip().lower()
    return _is_comment_line(line) or stripped.startswith(":")


def _is_echo_statement(stripped: str) -> bool:
    """Return True when the line is an ECHO output statement."""
    return stripped.startswith(("echo ", "echo\t", "@echo ", "@echo\t"))


def _command_body(line: str) -> str:
    """Return command text after whitespace and a leading @, or empty for comments."""
    if _is_comment_line(line):
        return ""
    stripped = line.strip()
    if stripped.startswith("@"):
        stripped = stripped[1:].lstrip()
    return stripped


def _first_command_token(line: str) -> str:
    """Return the first command token, ignoring comments and a leading @."""
    body = _command_body(line)
    if not body:
        return ""
    return body.split()[0].lower()


def _is_setlocal_command(line: str) -> bool:
    """Return True when the line's command token is SETLOCAL."""
    if _is_comment_line(line) and "setlocal" in line.lower():
        logger.debug("Ignoring SETLOCAL mention in comment: %s", line.strip())
        return False
    return _first_command_token(line) == "setlocal"


def _is_endlocal_command(line: str) -> bool:
    """Return True when the line's command token is ENDLOCAL."""
    if _is_comment_line(line) and "endlocal" in line.lower():
        logger.debug("Ignoring ENDLOCAL mention in comment: %s", line.strip())
        return False
    return _first_command_token(line) == "endlocal"


def _executable_jump_text(line: str) -> str:
    """Return the executable portion of a line for GOTO/CALL reference scans.

    Full-line comments are excluded. ECHO output is excluded unless a command
    separator (``&``, ``&&``, ``||``) starts a later command such as
    ``echo x || goto :label``.
    """
    if _is_comment_line(line):
        return ""
    body = _command_body(line)
    lowered = body.lower()
    if lowered.startswith(("echo ", "echo\t")):
        separator = re.search(r"&&|\|\||&", body)
        if separator is None:
            logger.debug(
                "Ignoring GOTO/CALL mention inside echo output: %s", line.strip()
            )
            return ""
        return body[separator.end() :]
    return body


def _iter_goto_label_refs(line: str) -> Iterator[tuple[str, str]]:
    """Yield (raw_target, label_name) for executable GOTO destinations."""
    text = _executable_jump_text(line)
    if not text:
        return
    for match in _GOTO_LABEL_RE.finditer(text):
        colon = str(match.group(1) or "")
        name = str(match.group(2))
        yield colon + name, name.lower()


def _goto_and_call_label_names(line: str) -> set[str]:
    """Return label names referenced by GOTO or CALL :label on an executable line."""
    text = _executable_jump_text(line)
    if not text:
        return set()
    names = {name for _raw, name in _iter_goto_label_refs(line)}
    for match in _CALL_LABEL_RE.finditer(text):
        names.add(str(match.group(1)).lower())
    return names


def _call_subroutine_label_names(line: str) -> set[str]:
    """Return label names invoked via CALL :label on an executable line."""
    text = _executable_jump_text(line)
    if not text:
        return set()
    return {str(match.group(1)).lower() for match in _CALL_LABEL_RE.finditer(text)}


def _set_line_without_dangerous_substitution(stripped: str) -> bool:
    """Return True when a SET line has no dangerous command substitution."""
    if not stripped.startswith(("set ", "set\t")):
        return False
    dangerous_in_substitution = re.search(
        rf"where\s+({_DANGEROUS_CMDS_REGEX})", stripped
    ) or re.search(rf"['\(]\s*({_DANGEROUS_CMDS_REGEX})\s+", stripped)
    return dangerous_in_substitution is None


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

    if _is_comment_or_label(line):
        return True

    if _is_echo_statement(stripped):
        return True

    if re.search(r"\bgoto\s+:", stripped) or re.search(r"\bif\s+defined\s+", stripped):
        return True

    if _set_line_without_dangerous_substitution(stripped):
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

    if _is_comment_or_label(line):
        return True

    if _is_echo_statement(stripped):
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

    if re.search(r"\bgoto\s+:", stripped):
        return True

    if _set_line_without_dangerous_substitution(stripped):
        return True

    return False
