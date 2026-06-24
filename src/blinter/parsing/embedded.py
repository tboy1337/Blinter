"""Embedded script block detection within batch files."""
from dataclasses import dataclass
import re
from typing import (
    Dict,
    List,
    Set,
    Tuple,
)
from blinter.logging_config import logger
from blinter.patterns import (
    BATCH_INDICATORS,
    CSHARP_PATTERNS,
    POWERSHELL_PATTERNS,
    VBSCRIPT_PATTERNS,
)

def _is_script_language_line(line: str, patterns: List[str]) -> bool:
    """
    Check if a line matches any pattern from a script language.

    Args:
        line: The line to check
        patterns: List of regex patterns to match against

    Returns:
        True if the line matches any pattern
    """
    for pattern in patterns:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False

def _is_batch_code_line(line: str, stripped: str) -> bool:
    """
    Check if a line looks like batch code rather than embedded script.

    Args:
        line: The full line to check
        stripped: The stripped version of the line

    Returns:
        True if the line appears to be batch code
    """
    for pattern in BATCH_INDICATORS:
        if re.match(pattern, stripped, re.IGNORECASE):
            # Additional check: make sure it's not PowerShell
            if not any(re.search(p, line, re.IGNORECASE) for p in POWERSHELL_PATTERNS):
                return True
    return False

@dataclass
class ScriptBlockState:
    """State information for script block detection."""

    is_script_line: bool
    in_current_block: bool
    in_other_blocks: bool
    script_type: str
    line_num: int
    last_label_line: int

def _handle_script_block_start(state: ScriptBlockState) -> Tuple[bool, int]:
    """
    Handle the start of a script block.

    Args:
        state: Script block state information

    Returns:
        Tuple of (should_enter_block, block_start_line)
    """
    if state.is_script_line and not state.in_other_blocks:
        if not state.in_current_block:
            logger.debug(
                "Detected %s block starting at line %d (after label on line %d)",
                state.script_type,
                state.line_num,
                state.last_label_line,
            )
            return True, state.line_num
    return state.in_current_block, 0

def _handle_script_block_end(
    is_batch_line: bool,
    block_type: str,
    line_num: int,
    block_start: int,
) -> bool:
    """
    Handle the end of a script block.

    Args:
        is_batch_line: Whether the current line looks like batch code
        block_type: Type of block being ended
        line_num: Current line number
        block_start: Line where the block started

    Returns:
        False to indicate the block has ended
    """
    if is_batch_line:
        logger.debug(
            "%s block ended at line %d (lasted %d lines)",
            block_type,
            line_num - 1,
            line_num - block_start,
        )
        return False
    return True

def _process_heredoc_block(
    stripped: str,
    i: int,
    in_heredoc: bool,
    block_start: int,
    skip_lines: Set[int],
) -> Tuple[bool, int, bool]:
    """
    Process PowerShell heredoc blocks (<# ... #>).

    Returns:
        Tuple of (in_heredoc, block_start, should_continue)
    """
    # Check for heredoc start
    if re.search(r"<#", stripped) and not in_heredoc:
        skip_lines.add(i)
        logger.debug("Detected PowerShell heredoc block starting at line %d", i)
        return True, i, True

    # Check for heredoc end
    if in_heredoc:
        skip_lines.add(i)
        if re.search(r"#>", stripped):
            logger.debug(
                "PowerShell heredoc block ended at line %d (lasted %d lines)",
                i,
                i - block_start + 1,
            )
            return False, 0, True
        return True, block_start, True

    return False, block_start, False

@dataclass
class ScriptProcessingContext:
    """Context information for script block processing."""

    line: str
    stripped: str
    line_num: int
    last_label_line: int
    block_states: Dict[str, bool]
    block_start_line: int
    skip_lines: Set[int]

def _process_script_blocks(
    ctx: ScriptProcessingContext,
) -> Tuple[Dict[str, bool], int, bool]:
    """
    Process script language blocks (PowerShell, VBScript, C#).

    Args:
        ctx: Script processing context

    Returns:
        Tuple of (updated_block_states, block_start_line, should_continue)
    """
    # Check for script patterns
    script_patterns = {
        "powershell": _is_script_language_line(ctx.line, POWERSHELL_PATTERNS),
        "vbscript": _is_script_language_line(ctx.line, VBSCRIPT_PATTERNS),
        "csharp": _is_script_language_line(ctx.line, CSHARP_PATTERNS),
    }

    # Handle block starts for each script type
    for script_type, is_script_line in script_patterns.items():
        other_blocks = any(
            ctx.block_states[other]
            for other in ctx.block_states
            if other != script_type
        )
        ctx.block_states[script_type], start = _handle_script_block_start(
            ScriptBlockState(
                is_script_line,
                ctx.block_states[script_type],
                other_blocks,
                script_type.capitalize(),
                ctx.line_num,
                ctx.last_label_line,
            )
        )
        if start:
            ctx.skip_lines.add(ctx.line_num)
            return ctx.block_states, start, True

    # Handle block ends if in any block
    if any(ctx.block_states.values()):
        is_batch_line = _is_batch_code_line(ctx.line, ctx.stripped)
        for script_type in ctx.block_states:
            if ctx.block_states[script_type]:
                ended = _handle_script_block_end(
                    is_batch_line,
                    script_type.capitalize(),
                    ctx.line_num,
                    ctx.block_start_line,
                )
                ctx.block_states[script_type] = not ended
        if not is_batch_line:
            ctx.skip_lines.add(ctx.line_num)

    return ctx.block_states, ctx.block_start_line, False

def _detect_embedded_script_blocks(  # pylint: disable=too-many-locals
    lines: List[str],
) -> Set[int]:
    """
    Detect embedded PowerShell, VBScript, C#, or other script blocks within batch files.

    These embedded scripts are common in advanced batch files and should be skipped
    during batch-specific linting to avoid false positives.

    Detection strategies:
    1. PowerShell blocks: Lines with $variable syntax, PowerShell cmdlets, operators
    2. VBScript blocks: Lines with VBScript syntax (Dim, Set, WScript, etc.)
    3. C# blocks: Lines with C# syntax (foreach with types, int/uint, using statements)
    4. Context-based: Script blocks typically appear after labels

    Args:
        lines: List of lines from the batch file

    Returns:
        Set of line numbers (1-indexed) that should be skipped during linting
    """
    skip_lines: Set[int] = set()
    block_states = {"powershell": False, "vbscript": False, "csharp": False}
    in_powershell_heredoc = False
    block_start_line = 0
    last_label_line = 0

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Skip empty lines and batch comments
        if (
            not stripped
            or stripped.startswith("::")
            or stripped.upper().startswith("REM ")
        ):
            continue

        # Handle heredoc blocks
        in_powershell_heredoc, block_start_line, should_continue = (
            _process_heredoc_block(
                stripped, i, in_powershell_heredoc, block_start_line, skip_lines
            )
        )
        if should_continue:
            continue

        # Track labels (potential start of embedded script block)
        if re.match(r"^:[a-zA-Z_][\w]*:", stripped):
            last_label_line = i
            block_states = {"powershell": False, "vbscript": False, "csharp": False}
            continue

        # Process script blocks
        block_states, block_start_line, should_continue = _process_script_blocks(
            ScriptProcessingContext(
                line,
                stripped,
                i,
                last_label_line,
                block_states,
                block_start_line,
                skip_lines,
            )
        )
        if should_continue:
            continue

    if skip_lines:
        logger.info(
            "Detected and skipping %d lines of embedded PowerShell/VBScript/C# code",
            len(skip_lines),
        )

    return skip_lines
