"""Security vulnerability line checks (SEC-prefix rules)."""

import re
from typing import (
    List,
    Optional,
)

from blinter.models import LintIssue
from blinter.parsing.context import (
    _is_command_in_safe_context,
    _is_comment_line,
    _is_safe_ctx_for_privilege,
)
from blinter.patterns import (
    _DANGEROUS_CMDS_REGEX,
    CREDENTIAL_PATTERNS,
    DANGEROUS_COMMAND_PATTERNS,
    SENSITIVE_ECHO_PATTERNS,
)
from blinter.rules.registry import RULES


def _check_input_validation_sec(
    line: str, line_num: int, stripped: str
) -> List[LintIssue]:
    """Check for input validation and command security issues (SEC001-SEC003)."""
    issues: List[LintIssue] = []

    # SEC001: Potential command injection vulnerability
    if re.search(r"set\s+/p\s+[^=]+=.*%.*%", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC001"],
                context="User input used in command without validation",
            )
        )

    # SEC002: Unsafe SET command usage - only flag unquoted SET commands
    # Skip ANSI escape sequences, color definitions, and constant declarations
    set_match = re.match(r"set\s+([A-Za-z0-9_]+)=(.+)", stripped, re.IGNORECASE)
    if set_match:
        var_name: str = set_match.group(1)
        var_val_text: str = set_match.group(2)
        var_val: str = var_val_text.strip()

        # Skip if it's an ANSI escape sequence or color definition
        is_ansi_or_color = (
            "ESC" in var_name.upper()
            or "COLOR" in var_name.upper()
            or "%ESC%" in var_val
            or var_val.startswith("(")  # Skip tuple/list definitions like colors=(...)
            or re.match(
                r"^[\w.]+$", var_val
            )  # Skip simple constants like filename.ext, VARNAME
        )

        if not is_ansi_or_color and not (
            var_val.startswith('"') and var_val.endswith('"')
        ):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC002"],
                    context="SET command value should be quoted for safety",
                )
            )

    # SEC003: Dangerous command without confirmation
    if not _is_command_in_safe_context(line):
        for pattern, rule_code in DANGEROUS_COMMAND_PATTERNS:
            if re.search(pattern, stripped, re.IGNORECASE):
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES[rule_code],
                        context="Destructive command should have user confirmation",
                    )
                )
                break

    # SEC003: Special check for WHERE with dangerous commands in command substitution
    # This checks for dangerous command existence and should be flagged
    # But skip if it's in a comment line
    if not _is_comment_line(line):
        where_match = re.search(
            rf"where\s+({_DANGEROUS_CMDS_REGEX})", stripped, re.IGNORECASE
        )
        if where_match:
            cmd = str(where_match.group(1)).upper()
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC003"],
                    context=f"Checking for {cmd} command should have user confirmation",
                )
            )

    return issues


def _has_priv_check_before(lines: List[str], target_line_num: int) -> bool:
    """Check if there's a privilege check (net session) before the target line."""
    for _, line in enumerate(lines[: target_line_num - 1], start=1):
        stripped = line.strip().lower()
        if re.search(r"net\s+session\s*(>|$)", stripped):
            return True
    return False


def _check_privilege_security(
    stripped: str, line_num: int, lines: Optional[List[str]] = None, line: str = ""
) -> List[LintIssue]:
    """Check for privilege escalation security issues (SEC005)."""
    issues: List[LintIssue] = []

    # Skip commands in safe contexts (comments, ECHO, SET statements)
    # Note: Uses privilege-specific safe context check that excludes IF DEFINED
    if line and _is_safe_ctx_for_privilege(line):
        return issues

    # SEC005: Missing privilege check for admin operations
    admin_commands = ["reg add hklm", "reg delete hklm", "sc "]
    net_privilege_check_patterns = [
        r"net\s+session\s*>",  # net session redirected (used for checking)
        r"net\s+session\s*$",  # net session at end of line (used for checking)
    ]

    for cmd in admin_commands:
        if cmd in stripped.lower():
            # Check if there's already a privilege check earlier in the script
            if lines and _has_priv_check_before(lines, line_num):
                # Privilege check already performed, skip this check
                pass
            else:
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["SEC005"],
                        context=f"Command '{cmd.strip()}' may require administrator privileges",
                    )
                )
            break

    # Check for net commands that aren't privilege checks
    # Use word boundary to match "net" as a command, not as part of words like "internet"
    if re.search(r"\bnet\s+", stripped.lower()):
        is_privilege_check = any(
            re.search(pattern, stripped.lower())
            for pattern in net_privilege_check_patterns
        )
        if not is_privilege_check:
            # Check if there's already a privilege check earlier in the script
            if lines and _has_priv_check_before(lines, line_num):
                # Privilege check already performed, skip this check
                pass
            else:
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["SEC005"],
                        context="NET command may require administrator privileges",
                    )
                )

    return issues


def _check_path_security(line: str, stripped: str, line_num: int) -> List[LintIssue]:
    """Check for path-related security issues (SEC006-SEC007, SEC014)."""
    issues: List[LintIssue] = []

    # Skip ECHO statements, REM comments, and :: comments as these are typically
    # used for documentation/help text and don't perform actual file operations
    if _is_command_in_safe_context(line):
        return issues

    # SEC006: Hardcoded absolute path
    hardcoded_paths = [r"C:\\", r"D:\\", r"E:\\", r"/Users/", r"/home/"]
    for path_pattern in hardcoded_paths:
        if re.search(path_pattern, stripped):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC006"],
                    context="Hardcoded absolute path may not exist on other systems",
                )
            )
            break

    # SEC007: Hardcoded temporary directory (patterns scanned by this rule, not runtime paths)
    temp_paths = [r"C:\temp", r"C:\tmp", r"/tmp"]  # nosec B108
    for temp_path in temp_paths:
        if temp_path in stripped:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC007"],
                    context="Use %TEMP% instead of hardcoded temporary paths",
                )
            )
            break

    # SEC020: UNC path without UAC elevation check
    unc_operations = ["pushd", "copy", "xcopy", "robocopy", "move"]
    first_word = stripped.split()[0].lower() if stripped.split() else ""
    if first_word in unc_operations or re.search(r"\\\\[^\\]+\\", stripped):
        if "\\\\" in stripped:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC020"],
                    context="UNC path operation may fail under UAC without elevation check",
                )
            )

    return issues


def _check_info_disclosure_sec(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for information disclosure security issues (SEC008-SEC010)."""
    issues: List[LintIssue] = []

    # SEC008: Plain text credentials detected
    for pattern in CREDENTIAL_PATTERNS:
        if re.search(pattern, stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC008"],
                    context="Potential hardcoded credentials detected",
                )
            )
            break

    # SEC009: PowerShell execution policy bypass
    if re.search(r"powershell.*-executionpolicy\s+bypass", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC009"],
                context="PowerShell execution policy bypass detected",
            )
        )

    # SEC010: Sensitive information in ECHO output
    for pattern in SENSITIVE_ECHO_PATTERNS:
        if re.search(pattern, stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC010"],
                    context="ECHO statement may display sensitive information",
                )
            )
            break

    return issues


def _check_malware_security(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for malware-like behavior security issues (SEC021-SEC024)."""
    issues: List[LintIssue] = []

    # SEC021: Fork bomb pattern detected
    if (
        re.search(r'start\s+""\s*%0', stripped, re.IGNORECASE)
        or re.search(r"start\s+%0", stripped, re.IGNORECASE)
        or re.search(r"start\s+cmd\s*/c\s*%0", stripped, re.IGNORECASE)
    ):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC021"],
                context="Fork bomb pattern detected: recursive self-execution",
            )
        )

    # SEC022: Potential hosts file modification
    if re.search(r">>.*hosts", stripped, re.IGNORECASE) or re.search(
        r"echo.*>>.*drivers.*etc.*hosts", stripped, re.IGNORECASE
    ):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC022"],
                context="Hosts file modification detected - potential DNS poisoning",
            )
        )

    # SEC023: Autorun.inf creation detected
    if re.search(r"echo.*>.*autorun\.inf", stripped, re.IGNORECASE) or re.search(
        r"copy.*autorun\.inf", stripped, re.IGNORECASE
    ):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC023"],
                context="Autorun.inf creation detected - potential malware vector",
            )
        )

    # SEC024: Batch file copying itself to removable media
    if re.search(r"copy\s+%0\s+[a-z]:", stripped, re.IGNORECASE) or re.search(
        r"xcopy.*%0.*[a-z]:", stripped, re.IGNORECASE
    ):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC024"],
                context="Batch file copying itself to other drives - potential virus behavior",
            )
        )

    return issues


def _check_security_issues(line: str, line_num: int) -> List[LintIssue]:
    """Check for security level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # Check different categories of security issues
    issues.extend(_check_input_validation_sec(line, line_num, stripped))
    # Include line-by-line privilege checks for backward compatibility with tests
    issues.extend(_check_privilege_security(stripped, line_num, line=line))
    issues.extend(_check_path_security(line, stripped, line_num))
    issues.extend(_check_info_disclosure_sec(stripped, line_num))
    issues.extend(_check_malware_security(stripped, line_num))

    return issues
