"""Blinter - A professional-grade batch file linter for Windows.

This module provides comprehensive functionality to lint Windows batch files (.bat and .cmd)
for common syntax errors, style issues, security vulnerabilities and performance problems.

Features:
- 150+ built-in rules across 5 severity levels
- Thread-safe operations for concurrent processing
- Robust encoding detection and handling
- Comprehensive error handling for production use
- Performance optimized for large files
- Extensible architecture for custom rules

Usage:
    import blinter
    issues = blinter.lint_batch_file("script.bat")

Author: tboy1337
Version: 1.0.33
License: CRL
"""

# pylint: disable=too-many-lines

from collections import defaultdict
import configparser
from dataclasses import dataclass
from enum import Enum
import logging
from pathlib import Path
import re
import sys
from typing import DefaultDict, Dict, List, Optional, Set, Tuple, Union, cast
import warnings

__version__ = "1.0.33"
__author__ = "tboy1337"
__license__ = "CRL"

# Configure module-level logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class RuleSeverity(Enum):
    """Rule severity levels."""

    ERROR = "Error"
    WARNING = "Warning"
    STYLE = "Style"
    SECURITY = "Security"
    PERFORMANCE = "Performance"


@dataclass
class Rule:
    """Represents a linting rule with code, explanation and recommendation."""

    code: str
    name: str
    severity: RuleSeverity
    explanation: str
    recommendation: str

    def __post_init__(self) -> None:
        """Validate rule after initialization."""
        if not self.code or not isinstance(self.code, str):
            raise ValueError("Rule code must be a non-empty string")
        if not self.name or not isinstance(self.name, str):
            raise ValueError("Rule name must be a non-empty string")
        if not isinstance(self.severity, RuleSeverity):
            raise ValueError("Rule severity must be a RuleSeverity enum")
        if not self.explanation or not isinstance(self.explanation, str):
            raise ValueError("Rule explanation must be a non-empty string")
        if not self.recommendation or not isinstance(self.recommendation, str):
            raise ValueError("Rule recommendation must be a non-empty string")


@dataclass
class LintIssue:
    """Represents a linting issue found in a batch file."""

    line_number: int
    rule: Rule
    context: str = ""  # Additional context about the issue

    def __post_init__(self) -> None:
        """Validate issue after initialization."""
        if self.line_number < 1:
            raise ValueError("Line number must be positive")
        if not isinstance(self.rule, Rule):
            raise ValueError("Rule must be a Rule instance")


@dataclass
class BlinterConfig:
    """Configuration settings for blinter."""

    # General settings
    recursive: bool = True
    show_summary: bool = False
    max_line_length: int = 150

    # Rule enablement - all rules enabled by default
    enabled_rules: Optional[Set[str]] = None
    disabled_rules: Optional[Set[str]] = None

    # Severity filtering
    min_severity: Optional[RuleSeverity] = None

    def __post_init__(self) -> None:
        """Initialize default values after creation."""
        if self.enabled_rules is None:
            self.enabled_rules = set()
        if self.disabled_rules is None:
            self.disabled_rules = set()

    def is_rule_enabled(self, rule_code: str) -> bool:
        """Check if a rule is enabled based on configuration."""
        # If rule is explicitly disabled, return False
        if self.disabled_rules and rule_code in self.disabled_rules:
            return False

        # If enabled_rules is empty, all rules are enabled by default
        # If enabled_rules has items, only those rules are enabled
        if self.enabled_rules:
            return rule_code in self.enabled_rules

        return True

    def should_include_severity(self, severity: RuleSeverity) -> bool:
        """Check if issues of this severity should be included."""
        if self.min_severity is None:
            return True

        # Define severity order (higher values = more severe)
        severity_order = {
            RuleSeverity.STYLE: 1,
            RuleSeverity.PERFORMANCE: 2,
            RuleSeverity.WARNING: 3,
            RuleSeverity.SECURITY: 4,
            RuleSeverity.ERROR: 5,
        }

        return severity_order.get(severity, 0) >= severity_order.get(self.min_severity, 0)


# Comprehensive rule definitions
RULES: Dict[str, Rule] = {
    # Error Level Rules (E001-E999)
    "E001": Rule(
        code="E001",
        name="Nested parentheses mismatch",
        severity=RuleSeverity.ERROR,
        explanation="Batch scripts have improper nesting or mismatched "
        "parentheses which will cause syntax errors",
        recommendation="Ensure all opening parentheses have matching "
        "closing parentheses and are properly nested",
    ),
    "E002": Rule(
        code="E002",
        name="Missing label for GOTO statement",
        severity=RuleSeverity.ERROR,
        explanation="GOTO statement points to a label that does not exist, "
        "which will cause runtime errors",
        recommendation="Create the missing label or correct the GOTO "
        "statement to point to an existing label",
    ),
    "E003": Rule(
        code="E003",
        name="IF statement improper formatting",
        severity=RuleSeverity.ERROR,
        explanation="IF statement has improper spacing or syntax that "
        "will prevent correct execution",
        recommendation='Use proper spacing: IF "condition" operator "value" command',
    ),
    "E004": Rule(
        code="E004",
        name="IF EXIST syntax mixing",
        severity=RuleSeverity.ERROR,
        explanation="Mixing IF EXIST syntax with comparison operators " "creates invalid syntax",
        recommendation="Use either 'IF EXIST filename' or "
        '\'IF "variable"=="value"\' but not both together',
    ),
    "E005": Rule(
        code="E005",
        name="Invalid path syntax",
        severity=RuleSeverity.ERROR,
        explanation="Path contains invalid characters or exceeds " "system length limits",
        recommendation='Remove invalid characters (<>|"*?) and ensure '
        "path length is under 260 characters",
    ),
    "E006": Rule(
        code="E006",
        name="Potentially undefined variable reference",
        # Note: Despite "E" prefix, this is WARNING severity due to common use of
        # environment variables set by system or parent processes (false positive risk)
        severity=RuleSeverity.WARNING,
        explanation="Script references variables that were never set in this script. "
        "This may be intentional if using environment variables, but could cause "
        "runtime errors if the variable is not set by parent process or system",
        recommendation="If this is an environment variable, this warning can be ignored. "
        "Otherwise, define the variable using SET before referencing it, "
        "or add IF DEFINED checks to handle undefined cases",
    ),
    "E007": Rule(
        code="E007",
        name="Empty variable check syntax error",
        severity=RuleSeverity.ERROR,
        explanation="Incorrect syntax for checking if variables are empty "
        "will cause comparison errors",
        recommendation='Use proper syntax: IF "%%VAR%%"=="" for ' "empty variable checks",
    ),
    "E008": Rule(
        code="E008",
        name="Unreachable code after EXIT or GOTO",
        severity=RuleSeverity.ERROR,
        explanation="Code after EXIT or GOTO statements will never execute",
        recommendation="Remove unreachable code or restructure script logic",
    ),
    "E009": Rule(
        code="E009",
        name="Mismatched quotes",
        severity=RuleSeverity.ERROR,
        explanation="Lines with unmatched quotes will cause syntax errors or unexpected behavior",
        recommendation="Ensure all quotes are properly paired and closed",
    ),
    "E010": Rule(
        code="E010",
        name="Malformed FOR loop missing DO",
        severity=RuleSeverity.ERROR,
        explanation="FOR loops must contain the DO keyword for proper execution",
        recommendation="Add DO keyword: FOR %%i IN (items) DO command",
    ),
    "E011": Rule(
        code="E011",
        name="Invalid variable expansion syntax",
        severity=RuleSeverity.ERROR,
        explanation=(
            "Variable references must use proper %VAR% or !VAR! syntax with matching delimiters"
        ),
        recommendation=(
            "Ensure variables use matching % or ! delimiters: %VAR% for standard, "
            "!VAR! for delayed expansion"
        ),
    ),
    "E012": Rule(
        code="E012",
        name="Missing CALL for subroutine invocation",
        severity=RuleSeverity.ERROR,
        explanation=(
            "Subroutines should be invoked using CALL :label_name to ensure proper "
            "return handling"
        ),
        recommendation="Use CALL :subroutine_name instead of direct label jumps for subroutines",
    ),
    "E013": Rule(
        code="E013",
        name="Invalid command syntax detected",
        severity=RuleSeverity.ERROR,
        explanation=(
            "Command appears to have typos or invalid syntax that will cause " "execution errors"
        ),
        recommendation="Check command spelling and syntax: IF not IFF, ECHO not ECKO, FOR not FORx",
    ),
    "E014": Rule(
        code="E014",
        name="Missing colon in CALL statement",
        severity=RuleSeverity.ERROR,
        explanation=(
            "CALL statements to labels require a colon (unlike GOTO where colon is optional)"
        ),
        recommendation="Use CALL :label_name with colon when calling internal subroutines",
    ),
    "E015": Rule(
        code="E015",
        name="Missing colon in GOTO :EOF statement",
        severity=RuleSeverity.ERROR,
        explanation=(
            "GOTO :EOF requires a colon as it's a special built-in construct, not a "
            "user-defined label"
        ),
        recommendation="Use GOTO :EOF (with colon) to jump to end of file",
    ),
    # Warning Level Rules (W001-W999)
    "W001": Rule(
        code="W001",
        name="Missing exit code",
        severity=RuleSeverity.WARNING,
        explanation="Script doesn't set appropriate exit codes to indicate success or failure",
        recommendation="Add EXIT /b 0 for success or EXIT /b 1 for errors at script end",
    ),
    "W002": Rule(
        code="W002",
        name="Missing ERRORLEVEL check",
        severity=RuleSeverity.WARNING,
        explanation="Critical operations should check %%ERRORLEVEL%% to handle failures properly",
        recommendation="Add IF ERRORLEVEL 1 checks after operations that might fail",
    ),
    "W003": Rule(
        code="W003",
        name="Operation without error handling",
        severity=RuleSeverity.WARNING,
        explanation="Operations that commonly fail lack proper error checking",
        recommendation="Add error checking and appropriate responses for failed operations",
    ),
    "W004": Rule(
        code="W004",
        name="Potential infinite loop",
        severity=RuleSeverity.WARNING,
        explanation="Loop construct may run infinitely without proper exit conditions",
        recommendation="Add counter variables or proper exit conditions to prevent infinite loops",
    ),
    "W005": Rule(
        code="W005",
        name="Unquoted variable with spaces",
        severity=RuleSeverity.WARNING,
        explanation="Variables that may contain spaces should be quoted to prevent parsing errors",
        recommendation='Use quotes around variables: IF "%%VARIABLE%%"=="value"',
    ),
    "W006": Rule(
        code="W006",
        name="Network operation without timeout",
        severity=RuleSeverity.WARNING,
        explanation="Network operations may hang indefinitely without proper timeout settings",
        recommendation="Add timeout parameters to network commands like PING -n 4",
    ),
    "W007": Rule(
        code="W007",
        name="File operation on potentially locked file",
        severity=RuleSeverity.WARNING,
        explanation="Operations on files that may be in use by other programs can fail",
        recommendation="Check if applications are using the file before attempting operations",
    ),
    "W008": Rule(
        code="W008",
        name="Permanent PATH modification",
        severity=RuleSeverity.WARNING,
        explanation="SETX modifies PATH permanently, which may not be desired",
        recommendation="Use SET for temporary changes or confirm permanent changes are intended",
    ),
    "W009": Rule(
        code="W009",
        name="Windows version compatibility",
        severity=RuleSeverity.WARNING,
        explanation="Command may not be available in older Windows versions",
        recommendation="Use version checks or provide alternative commands for older Windows",
    ),
    "W010": Rule(
        code="W010",
        name="Architecture-specific operation",
        severity=RuleSeverity.WARNING,
        explanation="Operation is specific to 32-bit or 64-bit architecture",
        recommendation="Add architecture detection and appropriate handling for both architectures",
    ),
    "W011": Rule(
        code="W011",
        name="Unicode handling issue",
        severity=RuleSeverity.WARNING,
        explanation=(
            "Command contains non-ASCII characters or complex operations "
            "that may not handle Unicode properly. "
            "Note: Only flags lines with actual Unicode content or unsafe operations, "
            "not all echo/type/find commands"
        ),
        recommendation=(
            "Consider using commands with better Unicode support, "
            "or ensure proper code page (chcp 65001 for UTF-8)"
        ),
    ),
    "W012": Rule(
        code="W012",
        name="Non-ASCII characters detected",
        severity=RuleSeverity.WARNING,
        explanation="Non-ASCII characters may cause issues in some environments",
        recommendation="Use ASCII-only characters or ensure proper encoding handling",
    ),
    "W013": Rule(
        code="W013",
        name="Duplicate label",
        severity=RuleSeverity.WARNING,
        explanation="Multiple labels with the same name can cause unpredictable GOTO behavior",
        recommendation="Rename duplicate labels to have unique names",
    ),
    "W014": Rule(
        code="W014",
        name="Missing PAUSE for user interaction",
        severity=RuleSeverity.WARNING,
        explanation=(
            "Interactive scripts should include PAUSE to prevent window from " "closing immediately"
        ),
        recommendation="Add PAUSE before EXIT to allow user to see script output",
    ),
    "W015": Rule(
        code="W015",
        name="Deprecated command usage",
        severity=RuleSeverity.WARNING,
        explanation="Command is deprecated and may not be available in newer Windows versions",
        recommendation="Replace deprecated commands with modern alternatives",
    ),
    "E016": Rule(
        code="E016",
        name="Invalid errorlevel comparison syntax",
        severity=RuleSeverity.ERROR,
        explanation="Invalid syntax in errorlevel comparison will cause script failure",
        recommendation=(
            "Use proper errorlevel syntax: 'IF ERRORLEVEL n', 'IF NOT ERRORLEVEL n', "
            "or 'IF %ERRORLEVEL% operator value'"
        ),
    ),
    "W017": Rule(
        code="W017",
        name="Errorlevel comparison semantic difference",
        severity=RuleSeverity.WARNING,
        explanation=(
            "IF %ERRORLEVEL% NEQ 1 has different behavior than IF NOT ERRORLEVEL 1 - "
            "NEQ 1 matches any value except 1 (0,2,3...), while NOT ERRORLEVEL 1 "
            "only matches values less than 1 (i.e., 0)"
        ),
        recommendation=(
            "Use 'IF NOT ERRORLEVEL 1' for traditional errorlevel checking, or "
            "'IF %ERRORLEVEL% EQU 0' if you specifically want to check for success"
        ),
    ),
    "W018": Rule(
        code="W018",
        name="Multi-byte characters with potential line ending risks",
        severity=RuleSeverity.WARNING,
        explanation=(
            "Multi-byte UTF-8 characters combined with non-CRLF line endings "
            "can cause buffer parsing errors in batch files due to "
            "parser boundary misalignment"
        ),
        recommendation=(
            "Either remove non-ASCII characters OR ensure file uses CRLF line endings. "
            "Consider using ASCII alternatives or environment variables "
            "for special characters"
        ),
    ),
    "W019": Rule(
        code="W019",
        name="GOTO/CALL with potential line ending risks",
        severity=RuleSeverity.WARNING,
        explanation=(
            "GOTO and CALL statements may fail to find labels when file uses "
            "Unix line endings, especially near 512-byte boundaries due to "
            "Windows batch parser bugs"
        ),
        recommendation=(
            "Ensure file uses CRLF line endings, or duplicate critical labels " "as a workaround"
        ),
    ),
    # Style Level Rules (S001-S999)
    "S001": Rule(
        code="S001",
        name="Missing @ECHO OFF at file start",
        severity=RuleSeverity.STYLE,
        explanation="Batch scripts usually start with @ECHO OFF to prevent "
        "command echoing during execution",
        recommendation="Add '@ECHO OFF' as the first line of your script",
    ),
    "S002": Rule(
        code="S002",
        name="ECHO OFF without @ prefix",
        severity=RuleSeverity.STYLE,
        explanation="ECHO OFF should use @ prefix to prevent the command "
        "itself from being displayed",
        recommendation="Use '@ECHO OFF' instead of 'ECHO OFF'",
    ),
    "S003": Rule(
        code="S003",
        name="Inconsistent command capitalization",
        severity=RuleSeverity.STYLE,
        explanation="Batch commands should follow consistent casing conventions "
        "within the same file for readability",
        recommendation="Use consistent casing for batch commands throughout "
        "the file (either uppercase or lowercase)",
    ),
    "S004": Rule(
        code="S004",
        name="Trailing whitespace",
        severity=RuleSeverity.STYLE,
        explanation="Trailing spaces at line end can cause subtle errors and should be removed",
        recommendation="Remove trailing spaces and tabs from line endings",
    ),
    "E018": Rule(
        code="E018",
        name="Unix line endings detected",
        severity=RuleSeverity.ERROR,
        explanation=(
            "Batch file uses Unix line endings (LF-only) which can cause GOTO/CALL "
            "label parsing failures and script malfunction due to Windows batch parser "
            "512-byte boundary bugs"
        ),
        recommendation=(
            "Convert file to Windows line endings (CRLF). Use tools like dos2unix, "
            "notepad++, or configure git with 'git config core.autocrlf true'"
        ),
    ),
    "S005": Rule(
        code="S005",
        name="Mixed line endings",
        severity=RuleSeverity.STYLE,
        explanation=(
            "File contains mixed line ending types (CRLF and LF) which can cause "
            "parsing inconsistencies"
        ),
        recommendation=(
            "Use consistent CRLF line endings throughout the file " "for Windows batch files"
        ),
    ),
    "S006": Rule(
        code="S006",
        name="Inconsistent variable naming",
        severity=RuleSeverity.STYLE,
        explanation="Variable names should follow consistent naming conventions",
        recommendation="Use consistent naming: either ALL_CAPS or camelCase throughout",
    ),
    "S007": Rule(
        code="S007",
        name="BAT extension used instead of CMD for newer Windows",
        severity=RuleSeverity.STYLE,
        explanation="The .cmd file extension is recommended over .bat for Windows NT "
        "and newer versions (Windows 2000+). CMD files support additional "
        "features and have better error handling in newer Windows environments",
        recommendation="Consider renaming .bat files to .cmd for scripts intended for "
        "Windows 2000 and newer versions. CMD files provide better "
        "compatibility with modern Windows features and improved error reporting",
    ),
    "S008": Rule(
        code="S008",
        name="Missing comments for complex code",
        severity=RuleSeverity.STYLE,
        explanation="Complex sections should have comments explaining their purpose",
        recommendation="Add REM comments to explain complex logic and operations",
    ),
    "S009": Rule(
        code="S009",
        name="Magic numbers used",
        severity=RuleSeverity.STYLE,
        explanation="Hardcoded numeric values should be defined as named variables",
        recommendation="Define constants using SET before using numeric values",
    ),
    "S010": Rule(
        code="S010",
        name="Dead code detected",
        severity=RuleSeverity.STYLE,
        explanation="Unused labels or unreferenced subroutines make code harder to maintain",
        recommendation="Remove unused labels and unreferenced code sections",
    ),
    "S011": Rule(
        code="S011",
        name="Line exceeds maximum length",
        severity=RuleSeverity.STYLE,
        explanation="Lines longer than 150 characters are hard to read and maintain",
        recommendation="Break long lines into multiple shorter lines for better readability",
    ),
    "S012": Rule(
        code="S012",
        name="Inconsistent indentation",
        severity=RuleSeverity.STYLE,
        explanation="Inconsistent indentation makes code harder to read and maintain",
        recommendation="Use consistent indentation (4 spaces or 1 tab) for nested blocks",
    ),
    "S013": Rule(
        code="S013",
        name="Missing file header documentation",
        severity=RuleSeverity.STYLE,
        explanation="Scripts should include header documentation for maintainability",
        recommendation="Add REM comments at the top describing script purpose, author and date",
    ),
    "S014": Rule(
        code="S014",
        name="Long parameter list affects readability",
        severity=RuleSeverity.STYLE,
        explanation="Functions with many parameters are hard to read and maintain",
        recommendation="Group related parameters into variables or reduce parameter count",
    ),
    "S015": Rule(
        code="S015",
        name="Inconsistent colon usage in GOTO statements",
        severity=RuleSeverity.STYLE,
        explanation=(
            "GOTO statements should use consistent colon style throughout the script "
            "for better readability"
        ),
        recommendation=(
            "Choose either 'GOTO label' or 'GOTO :label' style and use consistently "
            "throughout the script"
        ),
    ),
    "S016": Rule(
        code="S016",
        name="Potentially unsafe double-colon comment",
        severity=RuleSeverity.STYLE,
        explanation=(
            "Double-colon comments (::) may be misinterpreted as labels when using "
            "non-CRLF line endings due to batch parser buffer alignment issues"
        ),
        recommendation=(
            "Use 'REM' for comments instead of '::' for maximum compatibility, "
            "or ensure CRLF line endings are used throughout the file"
        ),
    ),
    # Security Level Rules (SEC001-SEC999)
    "SEC001": Rule(
        code="SEC001",
        name="Potential command injection vulnerability",
        severity=RuleSeverity.SECURITY,
        explanation="User input used in commands without validation could "
        "allow malicious code execution",
        recommendation="Validate and sanitize all user input before using in commands",
    ),
    "SEC002": Rule(
        code="SEC002",
        name="Unsafe SET command usage",
        severity=RuleSeverity.SECURITY,
        explanation="SET commands without proper validation or quoting can cause security issues",
        recommendation='Always quote SET values and validate input: SET "var=safe value"',
    ),
    "SEC003": Rule(
        code="SEC003",
        name="Dangerous command without confirmation",
        severity=RuleSeverity.SECURITY,
        explanation="Destructive commands should require user confirmation "
        "to prevent accidental execution",
        recommendation="Add confirmation prompts before destructive operations",
    ),
    "SEC004": Rule(
        code="SEC004",
        name="Dangerous registry operation",
        severity=RuleSeverity.SECURITY,
        explanation="Registry modifications can damage system functionality "
        "and should be carefully reviewed",
        recommendation="Backup registry before modifications and use specific "
        "keys rather than broad deletions",
    ),
    "SEC005": Rule(
        code="SEC005",
        name="Missing privilege check",
        severity=RuleSeverity.SECURITY,
        explanation="Operations requiring admin rights should check for proper privileges",
        recommendation="Use NET SESSION >nul 2>&1 to check for administrator privileges",
    ),
    "SEC006": Rule(
        code="SEC006",
        name="Hardcoded absolute path",
        # Note: This is a STYLE/portability issue, not a security issue
        # Keeping SEC prefix for backward compatibility but severity is STYLE
        severity=RuleSeverity.STYLE,
        explanation=(
            "Hardcoded absolute paths may not exist on other systems, "
            "reducing script portability. "
            "This is a portability concern, not a security issue"
        ),
        recommendation=(
            "Use environment variables like %%USERPROFILE%%, %%PROGRAMFILES%%, etc. "
            "instead of hardcoded paths for better portability across different systems"
        ),
    ),
    "SEC007": Rule(
        code="SEC007",
        name="Hardcoded temporary directory",
        severity=RuleSeverity.SECURITY,
        explanation="Hardcoded temp paths may not exist and could create security vulnerabilities",
        recommendation="Use %%TEMP%% environment variable instead of hardcoded temporary paths",
    ),
    "SEC008": Rule(
        code="SEC008",
        name="Plain text credentials detected",
        severity=RuleSeverity.SECURITY,
        explanation="Hardcoded passwords and credentials in scripts pose serious security risks",
        recommendation="Use secure credential storage or prompt for credentials at runtime",
    ),
    "SEC009": Rule(
        code="SEC009",
        name="PowerShell execution policy bypass",
        severity=RuleSeverity.SECURITY,
        explanation="Bypassing PowerShell execution policy can allow malicious scripts to run",
        recommendation="Avoid using -ExecutionPolicy Bypass unless absolutely necessary",
    ),
    "SEC010": Rule(
        code="SEC010",
        name="Sensitive information in ECHO output",
        severity=RuleSeverity.SECURITY,
        explanation="ECHO statements may display sensitive information in console or log files",
        recommendation="Avoid echoing passwords, API keys, or other sensitive data",
    ),
    # Performance Level Rules (P001-P999)
    "P001": Rule(
        code="P001",
        name="Redundant file existence check",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Unnecessary repeated file existence checks reduce script performance",
        recommendation="Combine existence checks or store result in variable for reuse",
    ),
    "P002": Rule(
        code="P002",
        name="Code duplication detected",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Repeated code blocks should be refactored into "
        "subroutines for better maintainability",
        recommendation="Create subroutines using CALL :function_name for repeated code",
    ),
    "P003": Rule(
        code="P003",
        name="Unnecessary SETLOCAL",
        severity=RuleSeverity.PERFORMANCE,
        explanation="SETLOCAL is not needed if there are no SET commands in the script",
        recommendation="Remove SETLOCAL if no local variables are set",
    ),
    "P004": Rule(
        code="P004",
        name="Unnecessary ENABLEDELAYEDEXPANSION",
        severity=RuleSeverity.PERFORMANCE,
        explanation="ENABLEDELAYEDEXPANSION is not needed if no !VARIABLES! are used",
        recommendation="Remove ENABLEDELAYEDEXPANSION if delayed expansion is not used",
    ),
    "P005": Rule(
        code="P005",
        name="ENDLOCAL without SETLOCAL",
        severity=RuleSeverity.PERFORMANCE,
        explanation="ENDLOCAL is not needed without a corresponding SETLOCAL",
        recommendation="Remove unnecessary ENDLOCAL commands",
    ),
    "P006": Rule(
        code="P006",
        name="Missing ENDLOCAL before exit",
        severity=RuleSeverity.PERFORMANCE,
        explanation="SETLOCAL should be paired with ENDLOCAL before every exit point",
        recommendation="Add ENDLOCAL before all EXIT statements when SETLOCAL is used",
    ),
    "P007": Rule(
        code="P007",
        name="Temporary file without random name",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Temporary files should use %%RANDOM%% to prevent file collisions",
        recommendation="Use %%RANDOM%% in temporary filenames: temp_%%RANDOM%%.txt",
    ),
    "P008": Rule(
        code="P008",
        name="Delayed expansion without enablement",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Using !VARIABLES! requires SETLOCAL "
        "ENABLEDELAYEDEXPANSION for proper functionality",
        recommendation="Add SETLOCAL ENABLEDELAYEDEXPANSION before using !variable! syntax",
    ),
    "P009": Rule(
        code="P009",
        name="Inefficient FOR loop pattern",
        severity=RuleSeverity.PERFORMANCE,
        explanation="FOR loop could be optimized for better performance with large data sets",
        recommendation="Use 'tokens=*' parameter for better performance: FOR /f \"tokens=*\" %%i",
    ),
    "P010": Rule(
        code="P010",
        name="Missing optimization flags for directory operations",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Directory operations can be faster with appropriate flags",
        recommendation="Use /F flag for large directory operations: DIR /F",
    ),
    # Advanced Variable Expansion Rules (E017-E030)
    "E017": Rule(
        code="E017",
        name="Invalid percent-tilde syntax",
        severity=RuleSeverity.ERROR,
        explanation="Percent-tilde expansion syntax is malformed and will cause errors",
        recommendation=(
            "Use correct syntax: %~n1 (name), %~f1 (full path), "
            "%~d1 (drive), %~p1 (path), %~x1 (extension)"
        ),
    ),
    "E019": Rule(
        code="E019",
        name="Percent-tilde on non-parameter variable",
        severity=RuleSeverity.ERROR,
        explanation=(
            "Percent-tilde syntax only works with command-line parameters "
            "(%1-%9) and FOR loop variables"
        ),
        recommendation=(
            "Use percent-tilde only with %1-%9 parameters or FOR loop " "variables like %%i"
        ),
    ),
    "E020": Rule(
        code="E020",
        name="Invalid FOR loop variable syntax",
        severity=RuleSeverity.ERROR,
        explanation="FOR loop variables must use %% in batch files and % on command line",
        recommendation="Use %%i in batch files, %i on command line for FOR loop variables",
    ),
    "E021": Rule(
        code="E021",
        name="Invalid string operation syntax",
        severity=RuleSeverity.ERROR,
        explanation="String operations have incorrect syntax and will fail",
        recommendation=(
            "Use correct syntax: %var:~start,length% for substring, "
            "%var:old=new% for replacement"
        ),
    ),
    "E022": Rule(
        code="E022",
        name="Invalid arithmetic expression in SET /A",
        severity=RuleSeverity.ERROR,
        explanation="Arithmetic expression contains invalid syntax or operators",
        recommendation="Use valid operators: + - * / % & | ^ << >> and proper parentheses",
    ),
    "E023": Rule(
        code="E023",
        name="Missing quotes in SET /A with special characters",
        severity=RuleSeverity.ERROR,
        explanation=(
            "Special characters in SET /A expressions need quoting to " "prevent parsing errors"
        ),
        recommendation=(
            'Quote expressions with special chars: SET /A "result=5^2" ' "not SET /A result=5^2"
        ),
    ),
    # Enhanced Command Validation Rules (W020-W035)
    "W020": Rule(
        code="W020",
        name="FOR loop missing /F options for complex parsing",
        severity=RuleSeverity.WARNING,
        explanation=("FOR /F should specify tokens and delims options for reliable parsing"),
        recommendation=(
            'Use explicit options: FOR /F "tokens=1,2 delims=," ' "instead of default behavior"
        ),
    ),
    "W021": Rule(
        code="W021",
        name="IF comparison without quotes",
        severity=RuleSeverity.WARNING,
        explanation="IF comparisons should be quoted to handle spaces and special characters",
        recommendation='Use quotes: IF "%var%"=="value" instead of IF %var%==value',
    ),
    "W022": Rule(
        code="W022",
        name="Missing SETLOCAL EnableDelayedExpansion",
        severity=RuleSeverity.WARNING,
        explanation="Scripts using !var! syntax should enable delayed expansion",
        recommendation=(
            "Add SETLOCAL EnableDelayedExpansion at script start when using !var! expansion"
        ),
    ),
    "W023": Rule(
        code="W023",
        name="Inefficient nested FOR loops",
        severity=RuleSeverity.WARNING,
        explanation="Nested FOR loops can be performance bottlenecks with large data sets",
        recommendation="Consider alternative approaches or add progress indicators for large loops",
    ),
    "W024": Rule(
        code="W024",
        name="Deprecated command detected",
        severity=RuleSeverity.WARNING,
        explanation="Command is deprecated in modern Windows versions and may not be available",
        recommendation=(
            "Replace with modern equivalent: "
            "NET SEND->MSG, AT->SCHTASKS, CACLS->ICACLS, etc. "
            "Note: XCOPY is NOT deprecated despite ROBOCOPY being recommended "
            "for advanced scenarios"
        ),
    ),
    "W025": Rule(
        code="W025",
        name="Missing error handling",
        severity=RuleSeverity.WARNING,
        explanation="Command may produce errors that should be checked",
        recommendation="Add error checking: IF ERRORLEVEL 1 to handle failures. "
        "Only use 2>nul if you genuinely want to ignore expected errors",
    ),
    # Advanced Style and Best Practice Rules (S017-S025)
    "S017": Rule(
        code="S017",
        name="Inconsistent variable naming convention",
        severity=RuleSeverity.STYLE,
        explanation="Variable names should follow consistent naming conventions",
        recommendation=(
            "Use consistent case and naming: UPPERCASE for globals, lowercase for locals"
        ),
    ),
    "S018": Rule(
        code="S018",
        name="Missing subroutine documentation",
        severity=RuleSeverity.STYLE,
        explanation="Subroutines (callable labels) should have documentation comments",
        recommendation=(
            "Add REM comments describing subroutine purpose, parameters, and return values"
        ),
    ),
    "S019": Rule(
        code="S019",
        name="Magic numbers in code",
        severity=RuleSeverity.STYLE,
        explanation="Numeric literals should be replaced with named constants for clarity",
        recommendation="Define constants: SET MAX_RETRIES=3 instead of using raw numbers",
    ),
    "S020": Rule(
        code="S020",
        name="Long line without continuation",
        severity=RuleSeverity.STYLE,
        explanation="Very long lines reduce readability and should be split",
        recommendation="Use ^ for line continuation: command parameter1 ^ parameter2 ^ parameter3",
    ),
    # Enhanced Security Rules (SEC011-SEC015)
    "SEC011": Rule(
        code="SEC011",
        name="Unvalidated path traversal",
        severity=RuleSeverity.SECURITY,
        explanation="Path operations may allow directory traversal attacks with .. sequences",
        recommendation="Validate paths and remove .. sequences before file operations",
    ),
    "SEC012": Rule(
        code="SEC012",
        name="Unsafe temporary file creation",
        severity=RuleSeverity.SECURITY,
        explanation="Temporary files created predictably may be security vulnerabilities",
        recommendation="Use %RANDOM% in temp file names or check file existence before creation",
    ),
    "SEC013": Rule(
        code="SEC013",
        name="Command injection via variable substitution",
        severity=RuleSeverity.SECURITY,
        explanation="Variables containing user input used in commands may allow code injection",
        recommendation=("Validate and sanitize variables before use in command execution"),
    ),
    # Performance Enhancement Rules (P012-P020)
    "P012": Rule(
        code="P012",
        name="Inefficient string operations",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Multiple string operations on same variable can be combined",
        recommendation=("Combine operations: %var:~0,5:old=new% instead of multiple assignments"),
    ),
    "P013": Rule(
        code="P013",
        name="Missing /B flag for large DIR operations",
        severity=RuleSeverity.PERFORMANCE,
        explanation="DIR without /B produces verbose output that may be inefficient",
        recommendation="Use DIR /B for bare format when only filenames are needed",
    ),
    "P014": Rule(
        code="P014",
        name="Unnecessary command output",
        severity=RuleSeverity.PERFORMANCE,
        explanation=(
            "Commands producing unwanted output should be redirected to improve performance"
        ),
        recommendation="Redirect unwanted output: command >nul 2>&1",
    ),
    # Enhanced Parameter Validation Rules (E024-E026)
    "E024": Rule(
        code="E024",
        name="Invalid parameter modifier combination",
        severity=RuleSeverity.ERROR,
        explanation="Parameter modifier contains invalid or non-existent modifiers",
        recommendation="Use valid modifiers: %~n1% (name), %~f1% (full path), %~d1% (drive), "
        "%~p1% (path), %~x1% (extension), %~s1% (short names), %~a1% (attributes), "
        "%~t1% (time), %~z1% (size)",
    ),
    "E025": Rule(
        code="E025",
        name="Parameter modifier on wrong context",
        severity=RuleSeverity.ERROR,
        explanation="Parameter modifier used in inappropriate context or with wrong variable type",
        recommendation="Use parameter modifiers only with batch parameters (%1, %2, etc.) "
        "or FOR variables (%%i)",
    ),
    "E027": Rule(
        code="E027",
        name="UNC path used as working directory",
        severity=RuleSeverity.ERROR,
        explanation="UNC paths cannot be used as working directories with CD command",
        recommendation="Use PUSHD \\server\\share\\ ... POPD pattern instead of CD for UNC paths",
    ),
    "E028": Rule(
        code="E028",
        name="Complex quote escaping error",
        severity=RuleSeverity.ERROR,
        explanation="Complex quote patterns may not be handled correctly by the command "
        "interpreter",
        recommendation='Use triple-quote pattern """text""" for quotes within quoted strings, '
        "or escape properly with variables",
    ),
    "E029": Rule(
        code="E029",
        name="Complex SET /A expression errors",
        severity=RuleSeverity.ERROR,
        explanation="Arithmetic expression contains syntax errors or unbalanced operators",
        recommendation="Check operator precedence, balance parentheses, and quote complex "
        'expressions: SET /A "result=(value1+value2)*3"',
    ),
    # Enhanced Warning Rules (W026-W033)
    "W026": Rule(
        code="W026",
        name="Inefficient parameter modifier usage",
        severity=RuleSeverity.WARNING,
        explanation="Multiple separate parameter modifiers can be combined for efficiency",
        recommendation="Use combined modifiers: %~dpnx1% instead of %~d1%%~p1%%~n1%%~x1%",
    ),
    "W027": Rule(
        code="W027",
        name="Command behavior differs between interpreters",
        severity=RuleSeverity.WARNING,
        explanation="Command behaves differently in COMMAND.COM vs cmd.exe environments",
        recommendation="Test behavior in target environment or use interpreter-specific "
        "alternatives",
    ),
    "W028": Rule(
        code="W028",
        name="Errorlevel handling difference between .bat/.cmd",
        severity=RuleSeverity.WARNING,
        explanation="Commands like APPEND, DPATH, FTYPE, SET, PATH, ASSOC handle errorlevel "
        "differently in .bat vs .cmd files",
        recommendation="Use .cmd extension for consistent errorlevel behavior with these commands",
    ),
    "W029": Rule(
        code="W029",
        name="16-bit command in 64-bit context",
        severity=RuleSeverity.WARNING,
        explanation="16-bit .COM files may not work in 64-bit Windows environments",
        recommendation="Use 32-bit or 64-bit alternatives, or ensure 32-bit compatibility "
        "layer is available",
    ),
    "W030": Rule(
        code="W030",
        name="Non-ASCII characters may cause encoding issues",
        severity=RuleSeverity.WARNING,
        explanation="Characters outside Code Page 437 range may cause display or processing issues",
        recommendation="Use ASCII characters only, or use @CHCP command to set appropriate "
        "code page",
    ),
    "W031": Rule(
        code="W031",
        name="Unicode filename in batch operation",
        severity=RuleSeverity.WARNING,
        explanation="Files with Unicode names may not work correctly in batch operations",
        recommendation="Use cmd /U for Unicode support or rename files to use ASCII characters",
    ),
    "W032": Rule(
        code="W032",
        name="Missing character set declaration",
        severity=RuleSeverity.WARNING,
        explanation="Batch file uses non-ASCII characters without explicit character set "
        "declaration",
        recommendation="Add @CHCP 65001 for UTF-8 or appropriate code page at start of script",
    ),
    "W033": Rule(
        code="W033",
        name="Command execution may be ambiguous",
        severity=RuleSeverity.WARNING,
        explanation="Multiple files with same name but different extensions may cause "
        "ambiguous execution",
        recommendation="Use explicit file extensions in CALL statements and verify PATHEXT order",
    ),
    # Enhanced Performance Rule (P015)
    "P015": Rule(
        code="P015",
        name="Inefficient delay implementation",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Using ping localhost or choice for delays is inefficient on modern Windows",
        recommendation="Use TIMEOUT command for Vista+ or implement proper delay alternatives "
        "for older systems",
    ),
    # Advanced Escaping Rules (E030-E039)
    "E030": Rule(
        code="E030",
        name="Improper caret escape sequence",
        severity=RuleSeverity.ERROR,
        explanation="Caret character requires proper escaping when used as literal text",
        recommendation="Use ^^ to display a single caret, or ^^^ to escape special chars: ^^^&",
    ),
    "E031": Rule(
        code="E031",
        name="Invalid multilevel escaping",
        severity=RuleSeverity.ERROR,
        explanation="Complex multilevel escaping follows formula 2^n-1 carets for n levels",
        recommendation="Use correct caret count: ^ (1 level), ^^^ (2 levels), ^^^^^^^ (3 levels)",
    ),
    "E032": Rule(
        code="E032",
        name="Continuation character with trailing spaces",
        severity=RuleSeverity.ERROR,
        explanation="Spaces after caret continuation character prevent line wrapping",
        recommendation="Ensure caret is last character on line with no trailing spaces",
    ),
    "E033": Rule(
        code="E033",
        name="Double percent escaping error",
        severity=RuleSeverity.ERROR,
        explanation="Percent signs in output require double escaping: %% instead of %",
        recommendation="Use %% in ECHO statements to display single % character",
    ),
    # Advanced FOR Command Rules (W034-W043)
    "W034": Rule(
        code="W034",
        name="FOR /F missing usebackq option",
        severity=RuleSeverity.WARNING,
        explanation="usebackq option allows quoted filenames and command execution with backticks",
        recommendation='Use FOR /F "usebackq" when file names contain spaces or executing commands',
    ),
    "W035": Rule(
        code="W035",
        name="FOR /F tokenizing without proper delimiters",
        severity=RuleSeverity.WARNING,
        explanation="Default space/tab delimiters may not match your data format",
        recommendation='Specify explicit delims= option: FOR /F "delims=," for CSV data',
    ),
    "W036": Rule(
        code="W036",
        name="FOR /F missing skip option for headers",
        severity=RuleSeverity.WARNING,
        explanation="Files with header rows should use skip= option to avoid processing headers",
        recommendation="Add skip=1 or appropriate number to skip header rows",
    ),
    "W037": Rule(
        code="W037",
        name="FOR /F missing eol option for comments",
        severity=RuleSeverity.WARNING,
        explanation="Files with comment lines should specify end-of-line comment character",
        recommendation="Use eol=# or appropriate character to ignore comment lines",
    ),
    "W038": Rule(
        code="W038",
        name="FOR /R with explicit filename needs wildcard",
        severity=RuleSeverity.WARNING,
        explanation="FOR /R requires wildcard for explicit filenames to prevent directory listing",
        recommendation="Add trailing asterisk to explicit filename: filename.txt*",
    ),
    "W039": Rule(
        code="W039",
        name="Nested FOR loops without call optimization",
        severity=RuleSeverity.WARNING,
        explanation=("Complex nested FOR loops should use CALL :subroutine for maintainability"),
        recommendation="Move inner loop logic to separate subroutine using CALL :label",
    ),
    "W040": Rule(
        code="W040",
        name="FOR loop variable scope issue",
        severity=RuleSeverity.WARNING,
        explanation="FOR loop variables should use appropriate scope (% vs !) in contexts",
        recommendation="Use !var! inside FOR loops with delayed expansion, %var% outside",
    ),
    "W041": Rule(
        code="W041",
        name="Missing error handling for external commands",
        severity=RuleSeverity.WARNING,
        explanation=(
            "External commands should have errorlevel checking to handle failures properly"
        ),
        recommendation=(
            "Add error checking: IF ERRORLEVEL 1 (handle error) "
            "or IF %ERRORLEVEL% NEQ 0 (handle error). "
            "Don't just hide errors with 2>nul unless you have a specific reason"
        ),
    ),
    "W042": Rule(
        code="W042",
        name="Timeout command without /NOBREAK option",
        severity=RuleSeverity.WARNING,
        explanation="TIMEOUT allows user interruption unless /NOBREAK is specified",
        recommendation="Use TIMEOUT /T seconds /NOBREAK >NUL for uninterruptible delays",
    ),
    "W043": Rule(
        code="W043",
        name="Process management without proper verification",
        severity=RuleSeverity.WARNING,
        explanation="TASKKILL and TASKLIST commands should verify process existence first",
        recommendation="Use TASKLIST /FI to check process before TASKKILL operations",
    ),
    # Advanced Security Rules (SEC014-SEC019)
    "SEC014": Rule(
        code="SEC014",
        name="Unescaped user input in command execution",
        severity=RuleSeverity.SECURITY,
        explanation="User input containing special characters can break command execution",
        recommendation="Escape special characters in user input: ^&, ^|, ^>, ^<, ^^",
    ),
    "SEC015": Rule(
        code="SEC015",
        name="Process killing without authentication",
        severity=RuleSeverity.SECURITY,
        explanation="TASKKILL commands can terminate system processes without proper checks",
        recommendation="Add process ownership and permission checks before killing processes",
    ),
    "SEC016": Rule(
        code="SEC016",
        name="Automatic restart without failure limits",
        severity=RuleSeverity.SECURITY,
        explanation="Unlimited restart attempts can mask security issues or resource exhaustion",
        recommendation="Implement maximum restart attempts (3-5) with exponential backoff",
    ),
    "SEC017": Rule(
        code="SEC017",
        name="Temporary file creation in predictable location",
        severity=RuleSeverity.SECURITY,
        explanation="Predictable temp file names are vulnerable to race conditions and hijacking",
        recommendation="Use %RANDOM% or timestamp in temp file names: temp_%RANDOM%.tmp",
    ),
    "SEC018": Rule(
        code="SEC018",
        name="Command output redirection to insecure location",
        severity=RuleSeverity.SECURITY,
        explanation=(
            "Redirecting sensitive output to world-readable locations exposes information"
        ),
        recommendation=("Redirect to secure user directories or use appropriate file permissions"),
    ),
    "SEC019": Rule(
        code="SEC019",
        name="Batch self-modification vulnerability",
        severity=RuleSeverity.SECURITY,
        explanation="Scripts that modify themselves can be exploited to execute malicious code",
        recommendation="Avoid self-modifying scripts or validate all modifications carefully",
    ),
    # Advanced Style Rules (S021-S030)
    "S021": Rule(
        code="S021",
        name="Missing subroutine documentation",
        severity=RuleSeverity.STYLE,
        explanation=(
            "Subroutines (callable labels) should have descriptive comments "
            "explaining their purpose"
        ),
        recommendation=(
            "Add REM comments before subroutines describing what they do, "
            "parameters, and return behavior"
        ),
    ),
    "S022": Rule(
        code="S022",
        name="Inconsistent variable naming convention",
        severity=RuleSeverity.STYLE,
        explanation="Variables should follow consistent naming conventions",
        recommendation="Choose one naming convention and apply it consistently throughout script",
    ),
    "S023": Rule(
        code="S023",
        name="Magic timeout values without explanation",
        severity=RuleSeverity.STYLE,
        explanation="Hard-coded timeout values should be documented or made configurable",
        recommendation="Use variables for timeout values: SET waitTime=30",
    ),
    "S024": Rule(
        code="S024",
        name="Complex one-liner should be split",
        severity=RuleSeverity.STYLE,
        explanation="Complex commands spanning multiple operations should be split for readability",
        recommendation="Use continuation character ^ or separate commands for complex operations",
    ),
    "S025": Rule(
        code="S025",
        name="Missing subroutine documentation",
        severity=RuleSeverity.STYLE,
        explanation="Subroutines should have REM comments describing parameters and return values",
        recommendation="Document subroutines: REM Usage: CALL :SubName param1 param2",
    ),
    "S026": Rule(
        code="S026",
        name="Inconsistent continuation character usage",
        severity=RuleSeverity.STYLE,
        explanation="Continuation characters should be used consistently for line wrapping",
        recommendation="Use ^ consistently for line continuation and align parameters vertically",
    ),
    "S027": Rule(
        code="S027",
        name="Missing blank lines around code blocks",
        severity=RuleSeverity.STYLE,
        explanation="Code blocks should be separated by blank lines for better readability",
        recommendation="Add blank lines before and after major code sections and subroutines",
    ),
    "S028": Rule(
        code="S028",
        name="Redundant parentheses in simple commands",
        severity=RuleSeverity.STYLE,
        explanation="Simple single commands don't need parentheses for code blocks",
        recommendation="Remove parentheses for single commands: IF condition command",
    ),
    # Advanced Performance Rules (P016-P025)
    "P016": Rule(
        code="P016",
        name="Inefficient string concatenation in loops",
        severity=RuleSeverity.PERFORMANCE,
        explanation="String concatenation inside loops creates performance bottlenecks",
        recommendation="Use arrays or temporary files for large string operations in loops",
    ),
    "P017": Rule(
        code="P017",
        name="Repeated file existence checks",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Multiple IF EXIST checks on the same file waste I/O operations",
        recommendation="Store file existence result in variable for reuse",
    ),
    "P018": Rule(
        code="P018",
        name="Inefficient directory traversal",
        severity=RuleSeverity.PERFORMANCE,
        explanation="FOR /R without specific file masks processes unnecessary files",
        recommendation="Use specific file masks in FOR /R to reduce processing overhead",
    ),
    "P019": Rule(
        code="P019",
        name="Excessive variable expansion in loops",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Complex variable expansion inside tight loops impacts performance",
        recommendation="Pre-calculate complex variables before loop entry",
    ),
    "P020": Rule(
        code="P020",
        name="Redundant command echoing suppression",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Multiple @ECHO OFF commands or redundant @ prefixes waste processing",
        recommendation="Use single @ECHO OFF at script start, avoid @ on subsequent commands",
    ),
    "P021": Rule(
        code="P021",
        name="Inefficient process checking pattern",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Repeated TASKLIST calls without filters are resource-intensive",
        recommendation="Use TASKLIST /FI filters to reduce output and processing time",
    ),
    "P022": Rule(
        code="P022",
        name="Unnecessary output redirection in loops",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Redirecting output inside loops creates I/O overhead",
        recommendation="Collect output in variable and redirect once after loop completion",
    ),
    "P023": Rule(
        code="P023",
        name="Inefficient arithmetic operations",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Complex arithmetic in SET /A can be optimized with intermediate variables",
        recommendation="Break complex expressions into steps with intermediate variables",
    ),
    "P024": Rule(
        code="P024",
        name="Redundant SETLOCAL/ENDLOCAL pairs",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Multiple SETLOCAL/ENDLOCAL pairs create unnecessary scope overhead",
        recommendation="Use single SETLOCAL at script start with ENDLOCAL at end",
    ),
    "P025": Rule(
        code="P025",
        name="Inefficient wildcard usage in file operations",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Overly broad wildcards (*.*) process unnecessary files",
        recommendation="Use specific file extensions: *.txt instead of *.*",
    ),
}


def _detect_line_endings(file_path: str) -> Tuple[str, bool, int, int, int]:
    """
    Detect line ending types in a batch file.

    This function analyzes the raw file content to determine what type of line endings
    are used, which is critical for batch file compatibility since Unix line endings
    can cause GOTO/CALL label parsing failures in Windows batch files.

    Thread-safe: Yes - uses only local variables and read-only file operations
    Performance: Optimized to read file in chunks for memory efficiency

    Args:
        file_path: Path to the file to analyze for line endings

    Returns:
        Tuple containing:
            - dominant_type: 'CRLF', 'LF', 'CR', or 'MIXED'
            - has_mixed: True if multiple line ending types found
            - crlf_count: Number of CRLF (\\r\\n) sequences found
            - lf_only_count: Number of standalone LF (\\n) found
            - cr_only_count: Number of standalone CR (\\r) found

    Raises:
        FileNotFoundError: If the specified file doesn't exist
        PermissionError: If insufficient permissions to read the file
        OSError: If file operation fails due to system issues

    Example:
        >>> ending_type, mixed, crlf, lf, cr = _detect_line_endings("script.bat")
        >>> if ending_type == 'LF':
        ...     print("WARNING: Unix line endings detected!")
    """
    try:
        with open(file_path, "rb") as file_handle:
            content = file_handle.read()
    except (FileNotFoundError, PermissionError, OSError) as file_error:
        raise OSError(f"Cannot read file '{file_path}': {file_error}") from file_error

    # Count different line ending types
    crlf_count = content.count(b"\r\n")
    # Count LF that are NOT part of CRLF
    lf_total = content.count(b"\n")
    lf_only_count = lf_total - crlf_count
    # Count CR that are NOT part of CRLF
    cr_total = content.count(b"\r")
    cr_only_count = cr_total - crlf_count

    # Determine the dominant type and if mixed
    ending_types = []
    if crlf_count > 0:
        ending_types.append("CRLF")
    if lf_only_count > 0:
        ending_types.append("LF")
    if cr_only_count > 0:
        ending_types.append("CR")

    if len(ending_types) == 0:
        # No line endings found (empty file or single line)
        dominant_type = "NONE"
        has_mixed = False
    elif len(ending_types) == 1:
        dominant_type = ending_types[0]
        has_mixed = False
    else:
        # Multiple types found
        dominant_type = "MIXED"
        has_mixed = True

    logger.debug(
        "Line ending analysis for %s: %s (CRLF: %d, LF-only: %d, CR-only: %d)",
        file_path,
        dominant_type,
        crlf_count,
        lf_only_count,
        cr_only_count,
    )

    return dominant_type, has_mixed, crlf_count, lf_only_count, cr_only_count


def _has_multibyte_chars(lines: List[str]) -> Tuple[bool, List[int]]:
    """
    Check for multi-byte UTF-8 characters in batch file lines.

    Multi-byte characters combined with Unix line endings can cause buffer
    parsing errors in Windows batch files due to parser boundary misalignment.

    Thread-safe: Yes - uses only local variables and immutable operations
    Performance: Processes lines efficiently without regex overhead

    Args:
        lines: List of strings representing file lines

    Returns:
        Tuple containing:
            - has_multibyte: True if any multi-byte characters found
            - affected_lines: List of line numbers (1-based) containing multi-byte chars

    Example:
        >>> has_mb, line_nums = _has_multibyte_chars(["echo Hello", "echo ═══"])
        >>> if has_mb:
        ...     print(f"Multi-byte chars found on lines: {line_nums}")
    """
    has_multibyte = False
    affected_lines: List[int] = []

    for line_num, line in enumerate(lines, start=1):
        # Check if line contains any characters that require more than 1 byte in UTF-8
        try:
            line_bytes = line.encode("utf-8")
            # If UTF-8 byte count > character count, there are multi-byte chars
            if len(line_bytes) > len(line):
                has_multibyte = True
                affected_lines.append(line_num)
        except UnicodeEncodeError:
            # If encoding fails, there are definitely non-ASCII chars
            has_multibyte = True
            affected_lines.append(line_num)

    return has_multibyte, affected_lines


def read_file_with_encoding(file_path: str) -> Tuple[List[str], str]:
    """
    Reads a file with robust encoding detection and fallback mechanisms.

    This function implements a comprehensive encoding detection strategy:
    1. Attempts to use chardet for automatic detection (if available)
    2. Falls back to a prioritized list of common encodings
    3. Provides detailed error messages for troubleshooting

    Thread-safe: Yes - uses only local variables and immutable data
    Performance: Optimized for common cases (UTF-8 first)

    Args:
        file_path: Path to the file to read. Can be absolute or relative.

    Returns:
        Tuple containing:
            - lines: List of strings, each representing a line in the file
            - encoding_used: String indicating the encoding that was successful

    Raises:
        UnicodeDecodeError: If all encoding attempts fail (extremely rare)
        FileNotFoundError: If the specified file doesn't exist
        PermissionError: If insufficient permissions to read the file
        OSError: If file operation fails due to system issues

    Example:
        >>> lines, encoding = read_file_with_encoding("script.bat")
        >>> print(f"Read {len(lines)} lines using {encoding} encoding")
    """
    # List of encodings to try in order of preference
    encodings_to_try = [
        "utf-8",  # Standard UTF-8
        "utf-8-sig",  # UTF-8 with BOM
        "latin1",  # ISO 8859-1 (can decode any byte sequence)
        "cp1252",  # Windows-1252 (common Windows encoding)
        "iso-8859-1",  # ISO Latin-1
        "ascii",  # Basic ASCII
        "cp437",  # Original IBM PC encoding
        "utf-16",  # UTF-16 with BOM detection
        "utf-32",  # UTF-32 with BOM detection
    ]

    # Try to detect encoding using chardet if available
    try:
        import chardet  # pylint: disable=import-outside-toplevel  # isort: skip

        with open(file_path, "rb") as file_handle:
            raw_data = file_handle.read()

        detected = chardet.detect(raw_data)
        if detected and detected["encoding"] and detected["confidence"] > 0.7:
            detected_encoding = detected["encoding"].lower()
            logger.debug(
                "Chardet detected encoding: %s (confidence: %.2f)",
                detected_encoding,
                detected["confidence"],
            )
            # Add detected encoding to the front of our list if it's not already there
            if detected_encoding not in [enc.lower() for enc in encodings_to_try]:
                encodings_to_try.insert(0, detected_encoding)
            else:
                # Move detected encoding to front if it exists in our list
                for i, enc in enumerate(encodings_to_try):
                    if enc.lower() == detected_encoding:
                        encodings_to_try.insert(0, encodings_to_try.pop(i))
                        break
    except ImportError:
        # chardet not available, continue with fallback approach
        logger.debug("chardet not available, using fallback encoding detection")
    except (OSError, ValueError, TypeError) as detection_error:
        # Any other error in detection, continue with fallback
        logger.debug("Encoding detection failed: %s, using fallback", detection_error)

    # Try each encoding until one works
    last_exception: Optional[Exception] = None
    for encoding in encodings_to_try:
        try:
            logger.debug("Attempting to read file with encoding: %s", encoding)
            with open(file_path, "r", encoding=encoding, errors="strict") as file_handle:
                lines = file_handle.readlines()
            logger.debug("Successfully read %d lines using %s encoding", len(lines), encoding)
            return lines, encoding
        except UnicodeDecodeError as decode_error:
            logger.debug("UnicodeDecodeError with %s: %s", encoding, decode_error)
            last_exception = decode_error
            continue
        except (LookupError, ValueError) as encoding_error:
            # Encoding not supported or invalid
            logger.debug("Encoding error with %s: %s", encoding, encoding_error)
            last_exception = encoding_error
            continue

    # If we get here, all encodings failed - this should be extremely rare
    # since latin1 can decode any byte sequence
    if last_exception:
        raise OSError(
            f"All encoding attempts failed for file '{file_path}'. " f"Last error: {last_exception}"
        ) from last_exception

    raise OSError(f"Could not read file '{file_path}' with any supported encoding")


# Pattern definitions for rule matching
DANGEROUS_COMMAND_PATTERNS: List[Tuple[str, str]] = [
    (r"del\s+(?:[/-]\w+\s+)*[\"']?\*\.\*[\"']?(\s|$)", "SEC003"),  # del *.* with optional flags
    (
        r"del\s+(?:[/-]\w+\s+)*[\"']?\*/\*[\"']?(\s|$)",
        "SEC003",
    ),  # del */* pattern with optional flags
    (
        r"del\s+(?:[/-]\w+\s+)*[\"']?[a-z]:\\\*[\"']?(\s|$)",
        "SEC003",
    ),  # del c:\* type commands with optional flags
    (r"format\s+(?:[/-]\w+\s+)*[a-z]:", "SEC003"),  # format c: type commands with optional flags
    (r"shutdown", "SEC003"),  # shutdown commands
    (r"rmdir\s+/s\s+/q\s+", "SEC003"),  # rmdir /s /q commands
    (r"reg\s+delete\s+.*\s+/f", "SEC004"),  # forced registry deletions
]

COMMAND_CASING_KEYWORDS = {
    "echo",
    "set",
    "if",
    "for",
    "goto",
    "call",
    "exit",
    "rem",
    "pause",
    "copy",
    "move",
    "del",
    "dir",
    "type",
    "find",
    "findstr",
    "sort",
    "more",
    "cls",
    "cd",
    "pushd",
    "popd",
    "mkdir",
    "rmdir",
    "attrib",
    "xcopy",
    "robocopy",
    "ping",
    "ipconfig",
    "netstat",
    "tasklist",
    "taskkill",
    "sc",
    "net",
    "reg",
    "wmic",
    "powershell",
    "timeout",
    "choice",
    "setlocal",
    "endlocal",
    "enabledelayedexpansion",
}

OLDER_WINDOWS_COMMANDS = {"choice", "forfiles", "where", "icacls"}

ARCHITECTURE_SPECIFIC_PATTERNS = [
    r"Wow6432Node",  # 32-bit registry redirect
    r"Program Files \(x86\)",  # 32-bit program files
    r"SysWow64",  # 32-bit system directory
]

UNICODE_PROBLEMATIC_COMMANDS = {"type", "echo", "find", "findstr"}

# Additional patterns for new rules
# Note: xcopy is NOT deprecated despite robocopy being recommended for advanced scenarios
DEPRECATED_COMMANDS = {"assign", "backup", "comp", "edlin", "join", "subst"}

COMMON_COMMAND_TYPOS = {
    "iff": "if",
    "ecko": "echo",
    "ecoh": "echo",
    "forx": "for",
    "fro": "for",
    "goot": "goto",
    "sett": "set",
    "caal": "call",
    "exitt": "exit",
}

CREDENTIAL_PATTERNS = [
    r"password\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"pwd\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"passwd\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"apikey\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"api_key\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"secret\s*=\s*[\"']?[^\s\"']+[\"']?",
    r"token\s*=\s*[\"']?[^\s\"']+[\"']?",
]

SENSITIVE_ECHO_PATTERNS = [
    r"echo.*password",
    r"echo.*pwd",
    r"echo.*passwd",
    r"echo.*apikey",
    r"echo.*api_key",
    r"echo.*secret",
    r"echo.*token",
]


def _load_general_settings(config: BlinterConfig, parser: configparser.ConfigParser) -> None:
    """Load general settings from config parser."""
    if not parser.has_section("general"):
        return

    general = parser["general"]

    config.recursive = general.getboolean("recursive", fallback=True)
    config.show_summary = general.getboolean("show_summary", fallback=False)
    config.max_line_length = general.getint("max_line_length", fallback=150)

    severity_str = general.get("min_severity", "").strip()
    if severity_str:
        _set_min_severity(config, severity_str)


def _set_min_severity(config: BlinterConfig, severity_str: str) -> None:
    """Set minimum severity from string value."""
    severity_map = {
        "ERROR": RuleSeverity.ERROR,
        "SECURITY": RuleSeverity.SECURITY,
        "WARNING": RuleSeverity.WARNING,
        "PERFORMANCE": RuleSeverity.PERFORMANCE,
        "STYLE": RuleSeverity.STYLE,
    }
    severity_upper = severity_str.upper()
    if severity_upper in severity_map:
        config.min_severity = severity_map[severity_upper]
    else:
        logger.warning("Invalid min_severity value: %s", severity_str)


def _load_rule_settings(config: BlinterConfig, parser: configparser.ConfigParser) -> None:
    """Load rule settings from config parser."""
    if not parser.has_section("rules"):
        return

    rules = parser["rules"]

    # Handle enabled_rules
    enabled_str = rules.get("enabled_rules", "").strip()
    if enabled_str:
        config.enabled_rules = set(rule.strip() for rule in enabled_str.split(",") if rule.strip())

    # Handle disabled_rules
    disabled_str = rules.get("disabled_rules", "").strip()
    if disabled_str:
        config.disabled_rules = set(
            rule.strip() for rule in disabled_str.split(",") if rule.strip()
        )


def load_config(config_path: Optional[str] = None, use_config: bool = True) -> BlinterConfig:
    """
    Load configuration from blinter.ini file.

    Args:
        config_path: Optional path to config file. If None, looks for blinter.ini in
            current directory
        use_config: Whether to use config file at all

    Returns:
        BlinterConfig object with loaded settings
    """
    config = BlinterConfig()

    if not use_config:
        return config

    # Determine config file path
    config_path = config_path or "blinter.ini"
    config_file = Path(config_path)

    if not config_file.exists():
        logger.info("No configuration file found at %s, using defaults", config_file)
        return config

    try:
        parser = configparser.ConfigParser()
        parser.read(config_file, encoding="utf-8")

        _load_general_settings(config, parser)
        _load_rule_settings(config, parser)

        logger.info("Configuration loaded from %s", config_file)

    except (configparser.Error, OSError, ValueError) as error:
        logger.warning(
            "Error loading configuration from %s: %s. Using defaults.", config_file, error
        )

    return config


def create_default_config_file(config_path: str = "blinter.ini") -> None:
    """
    Create a default configuration file with all available options documented.

    Args:
        config_path: Path where to create the config file
    """
    config_content = """# Blinter Configuration File
# This file configures the behavior of the blinter batch file linter.
# All settings are optional - if not specified, defaults will be used.

[general]
# Whether to recursively search directories for batch files (default: true)
recursive = true

# Whether to show summary statistics at the end (default: false)  
show_summary = false

# Maximum line length before triggering S011 rule (default: 150)
max_line_length = 150

# Minimum severity level to report (default: none - show all)
# Valid values: ERROR, SECURITY, WARNING, PERFORMANCE, STYLE
# min_severity = WARNING

[rules]
# Comma-separated list of specific rules to enable (default: all rules enabled)
# If specified, ONLY these rules will be checked
# enabled_rules = E001,E002,W001,S001

# Comma-separated list of rules to disable (default: none disabled)
# These rules will be skipped even if they would normally be checked
# disabled_rules = S007,S011

# Examples:
# To only check for errors and security issues:
# enabled_rules = E001,E002,E003,E004,E005,E006,E007,E008,E009,E010,E011,E012,E013,E014,E015,E016,E017,E018,SEC001,SEC002,SEC003,SEC004,SEC005,SEC006,SEC007,SEC008,SEC009,SEC010,SEC011,SEC012,SEC013

# To disable style checks but keep everything else:
# disabled_rules = S001,S002,S003,S004,S005,S006,S007,S008,S009,S010,S011,S012,S013,S014,S015,S016,S017,S018,S019,S020

# To only show warnings and errors (skip style, performance):
# min_severity = WARNING
"""

    try:
        with open(config_path, "w", encoding="utf-8") as config_file:
            config_file.write(config_content)
        print(f"Default configuration file created: {config_path}")
    except OSError as error:
        print(f"Error creating configuration file: {error}")


def print_help() -> None:
    """Print help information for the blinter command."""
    help_text = """
Batch Linter - Help Menu

Usage:
  python blinter.py <path> [options]

Arguments:
  <path>              Path to a batch file (.bat or .cmd) OR directory containing batch files.
                     When a directory is specified, all .bat and .cmd files will be processed.

Options:
  --summary           Show a summary section with total errors and most common error.
  --severity          Show error severity levels and their meaning.
  --no-recursive      When processing directories, don't search subdirectories (default: recursive).
  --no-config         Don't use configuration file (blinter.ini) even if it exists.
  --create-config     Create a default blinter.ini configuration file and exit.
  --help              Display this help menu and exit.

Configuration:
  Blinter automatically looks for a 'blinter.ini' file in the current directory.
  If found, settings from this file will be used as defaults.
  Command line options override configuration file settings.

Rule Categories:
  E001-E999   Error Level    - Issues that will cause script failure
  W001-W999   Warning Level  - Bad practices that won't necessarily break script
  S001-S999   Style Level    - Code style and formatting issues
  SEC001+     Security Level - Security-related issues and vulnerabilities
  P001-P999   Performance    - Performance and efficiency improvements

Examples:
  python blinter.py myscript.bat
      Analyze a single batch file with detailed error list and recommendations.

  python blinter.py /path/to/batch/files
      Analyze all .bat and .cmd files in directory and subdirectories.

  python blinter.py /path/to/batch/files --no-recursive
      Analyze only .bat and .cmd files in the directory (no subdirectories).

  python blinter.py myscript.cmd --summary
      Shows summary and detailed errors for a single file.

  python blinter.py /project/scripts --summary --severity
      Shows summary, detailed errors and severity info for all batch files in directory.

If no <path> is specified or '--help' is passed, this help menu will be displayed.
"""
    print(help_text.strip())


def _is_comment_line(line: str) -> bool:
    """
    Check if a line is a comment (REM or ::).

    Args:
        line: The line to check

    Returns:
        True if the line is a comment
    """
    stripped = line.strip().lower()
    return stripped.startswith("rem ") or stripped.startswith("rem\t") or stripped.startswith("::")


def _is_command_in_safe_context(line: str) -> bool:
    """
    Check if a potentially dangerous command is in a safe context (REM comment or ECHO statement).

    Args:
        line: The line to check

    Returns:
        True if the command is in a safe context and shouldn't be flagged as dangerous
    """
    stripped = line.strip().lower()

    # Check if line is a comment (REM or ::)
    if _is_comment_line(line):
        return True

    # Check if line starts with ECHO (output statement)
    if stripped.startswith("echo ") or stripped.startswith("echo\t"):
        return True

    # Check for @ECHO off (common at start of scripts)
    if stripped.startswith("@echo ") or stripped.startswith("@echo\t"):
        return True

    return False


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
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["W013"],  # Duplicate label
                        context=f"Label '{label}' already defined on line {labels[label]}",
                    )
                )
            else:
                labels[label] = i

    return labels, issues


def _collect_set_variables(lines: List[str]) -> Set[str]:
    """Collect all variables that are set in the script."""
    set_vars: Set[str] = set()
    for line in lines:
        # Match different SET patterns, including quoted variable names
        # Use re.search instead of re.match to find SET commands anywhere in the line
        # This handles cases like: if not defined VAR set "VAR=value"
        patterns = [
            r"\bset\s+([A-Za-z0-9_]+)=",  # Regular set: set VAR=value
            r'\bset\s+"([A-Za-z0-9_]+)=',  # Quoted set: set "VAR=value"
            r"\bset\s+/p\s+([A-Za-z0-9_]+)=",  # Set with prompt: set /p VAR=
            r'\bset\s+/p\s+"([A-Za-z0-9_]+)=',  # Quoted set with prompt: set /p "VAR="
            r"\bset\s+/a\s+([A-Za-z0-9_]+)=",  # Arithmetic set: set /a VAR=
            r'\bset\s+/a\s+"([A-Za-z0-9_]+)=',  # Quoted arithmetic set: set /a "VAR="
        ]

        for pattern in patterns:
            set_match = re.search(pattern, line.strip(), re.IGNORECASE)
            if set_match:
                var_name_text: str = set_match.group(1)
                set_vars.add(var_name_text.upper())
                break

        # Handle dynamic variable assignments in FOR loops: set "%%~b=value"
        # This pattern is commonly used to dynamically create variables based on loop iteration
        # Example: for %%a in (list) do (set "%%~a=value")
        dynamic_set_match = re.search(r'\bset\s+"%%~[a-zA-Z]=', line.strip(), re.IGNORECASE)
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
    }
    set_vars.update(common_env_vars)

    return set_vars


def _check_goto_labels(stripped: str, line_num: int, labels: Dict[str, int]) -> List[LintIssue]:
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
    # Check if this looks like a label call (not an external program)
    # Skip if it contains path separators, extensions, or is a known command
    builtin_commands = {
        # Windows builtin commands
        "dir",
        "echo",
        "copy",
        "move",
        "del",
        "type",
        "find",
        "findstr",
        "sort",
        "more",
        "cls",
        "cd",
        "pushd",
        "popd",
        "mkdir",
        "rmdir",
        "attrib",
        "xcopy",
        "robocopy",
        "ping",
        "ipconfig",
        "netstat",
        "tasklist",
        "taskkill",
        "sc",
        "net",
        "reg",
        "wmic",
        "powershell",
        "timeout",
        "choice",
        "ver",
        "vol",
        "date",
        "time",
        "help",
        "set",
        "setlocal",
        "endlocal",
        # Common external commands and package managers
        "npm",
        "node",
        "npx",
        "yarn",
        "pnpm",
        "git",
        "gh",
        "svn",
        "hg",
        "python",
        "python3",
        "py",
        "pip",
        "pip3",
        "pipenv",
        "poetry",
        "ruby",
        "gem",
        "bundle",
        "php",
        "composer",
        "java",
        "javac",
        "maven",
        "mvn",
        "gradle",
        "dotnet",
        "nuget",
        "msbuild",
        "cargo",
        "rustc",
        "rustup",
        "go",
        "gofmt",
        "docker",
        "docker-compose",
        "kubectl",
        "helm",
        "aws",
        "az",
        "gcloud",
        "terraform",
        "make",
        "cmake",
        "ninja",
        "wget",
        "curl",
        "aria2c",
        "7z",
        "zip",
        "unzip",
        "tar",
        "gzip",
        "choco",
        "scoop",
        "winget",
        "code",
        "vim",
        "nano",
        "notepad",
        "ssh",
        "scp",
        "ftp",
        "telnet",
        "cscript",
        "wscript",
        "msiexec",
    }
    if (
        not re.search(r"[\\/.:]|\.(?:bat|cmd|exe|com)$", call_label_text.lower())
        and call_label_text.lower() not in builtin_commands
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
    if_match = re.match(r"if\s+(.+)", stripped, re.IGNORECASE)
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
    if not is_valid_if and not re.search(r"[&|()]", if_content):  # Not a complex conditional
        # Only flag if it looks like an incomplete comparison (has words but no operators)
        if re.match(r"[\"']?%?\w+%?[\"']?\s*$", if_content):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E003"],
                    context=(
                        "IF statement appears to be missing comparison operator " "or condition"
                    ),
                )
            )
    return issues


def _check_errorlevel_syntax(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for invalid errorlevel comparison syntax (E016)."""
    issues: List[LintIssue] = []
    errorlevel_if_match = re.match(r"if\s+(.+)", stripped, re.IGNORECASE)
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
                    "Invalid 'IF NOT %ERRORLEVEL% number' syntax - " "missing comparison operator"
                ),
            )
        )
    # Check for other invalid errorlevel patterns
    elif re.match(r"not\s+%errorlevel%\s+[^\s]+(?:\s|$)", errorlevel_content, re.IGNORECASE):
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
            if re.search(r"(::|scriptblock|split\s|regex)", escaped_content, re.IGNORECASE):
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

    # Skip REM comments - they can contain any characters
    stripped = line.strip()
    if stripped.lower().startswith("rem ") or stripped.lower().startswith("rem\t"):
        return issues

    # Skip echo statements - they often contain ASCII art with quotes
    # that aren't meant to be string delimiters
    if re.match(r"\s*echo\s+%", stripped, re.IGNORECASE):
        # This is likely ASCII art using variables, be lenient
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
        has_delayed_expansion = "!" in line and stripped.startswith("set ")
        has_call_substitution = re.search(r"call\s+:[^:]+", stripped, re.IGNORECASE)

        if not (has_delayed_expansion or has_call_substitution):
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
    if re.match(r"for\s+.*", stripped, re.IGNORECASE) and " do " not in stripped.lower():
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


def _check_variable_expansion(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for invalid variable expansion syntax (E011)."""
    issues: List[LintIssue] = []

    # Check for indirect variable expansion patterns like !%1!, !%var%!, or !%~n1!
    has_indirect_expansion = re.search(
        r"!([^!]*%[^%!]+%?[^!]*|%~?[a-z0-9]+)!", stripped, re.IGNORECASE
    )

    # Check for dynamic variable assignment like set "%1=value" or set "%%~a=value"
    has_dynamic_assignment = re.search(r'set\s+"[^"]*%%?~?[a-z0-9][^"]*=', stripped, re.IGNORECASE)

    # Only check for mismatched delimiters if not using indirect expansion or dynamic assignment
    if has_indirect_expansion or has_dynamic_assignment:
        return issues

    # Remove FOR loop variables with modifiers (%%~a, %%~nx1, etc.) first
    temp_stripped = re.sub(r"%%~[a-zA-Z]+", "", stripped)
    temp_stripped = re.sub(r"%%[a-zA-Z]", "", temp_stripped)

    # Remove command-line parameters with modifiers (%~nx1, %~dp0, etc.)
    temp_stripped = re.sub(
        r"%~?[fdpnxsatz]*[0-9*](?![0-9])", "", temp_stripped, flags=re.IGNORECASE
    )

    # Remove all valid variable expansion patterns
    temp_no_percent_vars = re.sub(r"%[A-Z0-9_~]+[^%]*%", "", temp_stripped, flags=re.IGNORECASE)
    temp_no_exclaim_vars = re.sub(r"![A-Z0-9_]+[^!]*!", "", temp_stripped, flags=re.IGNORECASE)

    # Now look for incomplete variable patterns that suggest mismatched delimiters
    has_incomplete_percent = re.search(
        r"%[A-Z0-9_]+(?:[^%]|$)", temp_no_percent_vars, re.IGNORECASE
    )
    has_incomplete_exclaim = re.search(
        r"![A-Z0-9_]+(?:[^!]|$)", temp_no_exclaim_vars, re.IGNORECASE
    )

    # Only flag if we found incomplete variable patterns
    if has_incomplete_percent:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E011"],
                context="Variable reference may have mismatched % delimiters",
            )
        )

    if has_incomplete_exclaim:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E011"],
                context="Delayed expansion variable may have mismatched ! delimiters",
            )
        )
    return issues


def _check_subroutine_call(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for missing CALL for subroutine invocation (E012)."""
    issues: List[LintIssue] = []
    if re.match(r":[A-Z0-9_]+\s+\S+", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E012"],
                context="Potential subroutine call without CALL keyword",
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

    # Now check for parameter modifiers used in wrong context (single % only)
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


def _check_quote_escaping(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for complex quote escaping errors (E028)."""
    issues: List[LintIssue] = []
    if '"""' not in stripped and not re.search(r'["\s]""[^"]', stripped):
        return issues

    # Exclude legitimate patterns:
    # 1. Comparisons with empty string: neq "", equ "", == "", != ""
    if re.search(r'\b(neq|equ|==|!=|lss|leq|gtr|geq)\s+""', stripped, re.IGNORECASE):
        return issues

    # 2. START command with triple-quote escaping: start ... /c ""!var!" ...
    if re.search(r'\bstart\b.*\s+/c\s+""[^"]+!"', stripped, re.IGNORECASE):
        return issues

    # 3. Properly formatted triple-quote patterns: """text"""
    if re.match(r'.*"""[^"]*""".*', stripped):
        return issues

    # Look for potentially problematic quote patterns
    quote_context = ""
    if '"""' in stripped:
        quote_context = "Triple quote pattern found"
    elif re.search(r'["\s]""[^"]', stripped):
        quote_context = "Complex quote escaping detected"

    issues.append(
        LintIssue(
            line_number=line_num,
            rule=RULES["E028"],
            context=quote_context,
        )
    )
    return issues


def _check_set_a_expression(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for complex SET /A expression errors (E029)."""
    issues: List[LintIssue] = []
    seta_match = re.match(r"set\s+/a\s+(.+)", stripped, re.IGNORECASE)
    if not seta_match:
        return issues

    expression: str = seta_match.group(1)

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


def _check_syntax_errors(line: str, line_num: int, labels: Dict[str, int]) -> List[LintIssue]:
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
    issues.extend(_check_subroutine_call(stripped, line_num))
    issues.extend(_check_command_typos(stripped, line_num))
    issues.extend(_check_parameter_modifiers(stripped, line_num))
    issues.extend(_check_unc_path(stripped, line_num))
    issues.extend(_check_quote_escaping(stripped, line_num))
    issues.extend(_check_set_a_expression(stripped, line_num))

    return issues


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
    variables: List[str] = re.findall(r"%[^%]+%", echo_content)
    for var in variables:
        # Check if variable contains non-standard characters (complex expansion)
        var_content = var[1:-1]  # Remove % signs
        if re.search(r"[^A-Z0-9_~]", var_content, re.IGNORECASE):
            # Allow common parameter expansions like %~n1, %~dp0
            if not re.match(r"~[a-z]*\d*$", var_content, re.IGNORECASE):
                complex_vars.append(var)

    # Check if this is safe file redirection (output to files, not complex shell operations)
    has_safe_redirection = bool(
        re.search(r">\s*(nul|\"[^\"]*\"|[^\s&|<>]+)(\s*2>&1)?\s*$", stripped, re.IGNORECASE)
    )

    # Only flag echo if it has real Unicode issues
    return (
        not all(
            ord(c) < 128 for c in echo_content if c.strip()
        )  # Contains non-ASCII in actual content
        or (
            bool(re.search(r"[<>]", stripped)) and not has_safe_redirection
        )  # Has unsafe redirection
        or len(complex_vars) > 0  # Has truly complex variable expansion
        or bool(re.search(r"[\x00-\x1f\x7f-\xff]", echo_content))  # Control chars in content
    )


def _check_search_unicode_risk(stripped: str) -> bool:
    """Check for Unicode risks in findstr/find commands."""
    return (
        not all(ord(c) < 128 for c in stripped)  # Contains non-ASCII
        or bool(re.search(r"/[a-z]", stripped, re.IGNORECASE))  # Uses flags affecting Unicode
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
    if re.search(r"^\s*(?:call\s+|start\s+)?[\w-]+\.com(?:\s|$)", stripped, re.IGNORECASE):
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
                line_number=line_num, rule=RULES["W008"], context="SETX modifies PATH permanently"
            )
        )

    # W015: Deprecated command usage
    first_word = stripped.split()[0].lower() if stripped.split() else ""
    if first_word in DEPRECATED_COMMANDS:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W015"],
                context=(
                    f"Command '{first_word}' is deprecated and may not work "
                    f"in newer Windows versions"
                ),
            )
        )

    return issues


def _check_unquoted_variables(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for unquoted variables with spaces (W005).

    Only flags genuinely problematic cases:
    - IF string comparisons (==) with unquoted variables
    """
    issues: List[LintIssue] = []

    # Only check IF string comparisons with == operator
    # These are the most common source of issues with unquoted variables
    if_string_comp = re.search(r"\bif\s+(?:not\s+)?%[A-Z0-9_]+%\s*==\s*", stripped, re.IGNORECASE)
    if if_string_comp:
        # Don't flag if already quoted properly elsewhere in the comparison
        if not re.search(r'\bif\s+(?:not\s+)?"[^"]*%[A-Z0-9_]+%[^"]*"', stripped, re.IGNORECASE):
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
    w017_if_match = re.match(r"if\s+(.+)", stripped, re.IGNORECASE)
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
                        "IF %ERRORLEVEL% NEQ 1 behaves differently than " "IF NOT ERRORLEVEL 1"
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
        if not re.search(r"\.[a-z]{1,4}$", call_target.lower()) and not call_target.startswith(":"):
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


def _check_style_issues(
    line: str,
    line_num: int,
    max_line_length: int = 150,
) -> List[LintIssue]:
    """Check for style level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # S003: Command capitalization consistency is now checked at file level

    # S004: Trailing whitespace
    if line.rstrip("\n") != line.rstrip():
        issues.append(
            LintIssue(
                line_number=line_num, rule=RULES["S004"], context="Line has trailing spaces or tabs"
            )
        )

    # S009: Magic numbers used (simple heuristic)
    number_patterns = [r"timeout\s+/t\s+(\d+)", r"ping\s+.*\s+-n\s+(\d+)"]
    for pattern in number_patterns:
        match = re.search(pattern, stripped, re.IGNORECASE)
        if match:
            number_result = match.group(1)
            if number_result is not None:
                if int(number_result) > 10:  # Only flag larger numbers
                    issues.append(
                        LintIssue(
                            line_number=line_num,
                            rule=RULES["S009"],
                            context=(
                                f"Magic number '{number_result}' should be defined "
                                f"as a variable"
                            ),
                        )
                    )

    # S011: Line exceeds maximum length
    line_length = len(line.rstrip("\n"))
    if line_length > max_line_length:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["S011"],
                context=f"Line is {line_length} characters (max {max_line_length})",
            )
        )

    # S014: Long parameter list affects readability
    call_match = re.match(r"call\s+:[A-Z0-9_]+\s+(.*)", stripped, re.IGNORECASE)
    if call_match:
        params: list[str] = call_match.group(1).split()
        if len(params) > 5:  # More than 5 parameters
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["S014"],
                    context=f"Function call has {len(params)} parameters, consider grouping them",
                )
            )

    return issues


def _check_input_validation_sec(line: str, line_num: int, stripped: str) -> List[LintIssue]:
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
            or re.match(r"^[\w.]+$", var_val)  # Skip simple constants like filename.ext, VARNAME
        )

        if not is_ansi_or_color and not (var_val.startswith('"') and var_val.endswith('"')):
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

    return issues


def _has_priv_check_before(lines: List[str], target_line_num: int) -> bool:
    """Check if there's a privilege check (net session) before the target line."""
    for _, line in enumerate(lines[: target_line_num - 1], start=1):
        stripped = line.strip().lower()
        if re.search(r"net\s+session\s*(>|$)", stripped):
            return True
    return False


def _check_privilege_security(
    stripped: str, line_num: int, lines: Optional[List[str]] = None
) -> List[LintIssue]:
    """Check for privilege escalation security issues (SEC005)."""
    issues: List[LintIssue] = []

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
            re.search(pattern, stripped.lower()) for pattern in net_privilege_check_patterns
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


def _check_path_security(stripped: str, line_num: int) -> List[LintIssue]:
    """Check for path-related security issues (SEC006-SEC007, SEC014)."""
    issues: List[LintIssue] = []

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

    # SEC007: Hardcoded temporary directory
    temp_paths = [r"C:\\temp", r"C:\\tmp", r"/tmp"]
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

    # SEC014: UNC path without UAC elevation check
    unc_operations = ["pushd", "copy", "xcopy", "robocopy", "move"]
    first_word = stripped.split()[0].lower() if stripped.split() else ""
    if first_word in unc_operations or re.search(r"\\\\[^\\]+\\", stripped):
        if "\\\\" in stripped:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC014"],
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
    """Check for malware-like behavior security issues (SEC015-SEC018)."""
    issues: List[LintIssue] = []

    # SEC015: Fork bomb pattern detected
    if (
        re.search(r'start\s+""\s*%0', stripped, re.IGNORECASE)
        or re.search(r"start\s+%0", stripped, re.IGNORECASE)
        or re.search(r"start\s+cmd\s*/c\s*%0", stripped, re.IGNORECASE)
    ):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC015"],
                context="Fork bomb pattern detected: recursive self-execution",
            )
        )

    # SEC016: Potential hosts file modification
    if re.search(r">>.*hosts", stripped, re.IGNORECASE) or re.search(
        r"echo.*>>.*drivers.*etc.*hosts", stripped, re.IGNORECASE
    ):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC016"],
                context="Hosts file modification detected - potential DNS poisoning",
            )
        )

    # SEC017: Autorun.inf creation detected
    if re.search(r"echo.*>.*autorun\.inf", stripped, re.IGNORECASE) or re.search(
        r"copy.*autorun\.inf", stripped, re.IGNORECASE
    ):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC017"],
                context="Autorun.inf creation detected - potential malware vector",
            )
        )

    # SEC018: Batch file copying itself to removable media
    if re.search(r"copy\s+%0\s+[a-z]:", stripped, re.IGNORECASE) or re.search(
        r"xcopy.*%0.*[a-z]:", stripped, re.IGNORECASE
    ):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC018"],
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
    issues.extend(_check_privilege_security(stripped, line_num))
    issues.extend(_check_path_security(stripped, line_num))
    issues.extend(_check_info_disclosure_sec(stripped, line_num))
    issues.extend(_check_malware_security(stripped, line_num))

    return issues


def _check_performance_issues(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    _lines: List[str],
    line_num: int,
    line: str,  # pylint: disable=unused-argument
    has_setlocal: bool,
    has_set_commands: bool,
    has_delayed_expansion: bool,
    uses_delayed_vars: bool,
) -> List[LintIssue]:
    """Check for performance level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # P003: Unnecessary SETLOCAL
    if "setlocal" in stripped.lower() and not has_set_commands:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["P003"],
                context="SETLOCAL used without any SET commands",
            )
        )

    # P004: Unnecessary ENABLEDELAYEDEXPANSION
    if "enabledelayedexpansion" in stripped.lower() and not uses_delayed_vars:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["P004"],
                context="ENABLEDELAYEDEXPANSION used without !variables!",
            )
        )

    # P005: ENDLOCAL without SETLOCAL
    if "endlocal" in stripped.lower() and not has_setlocal:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["P005"],
                context="ENDLOCAL used without corresponding SETLOCAL",
            )
        )

    # P007: Temporary file without random name
    temp_patterns = [r"temp\.txt", r"tmp\.txt", r"temp\.log"]
    for pattern in temp_patterns:
        if re.search(pattern, stripped, re.IGNORECASE) and "random" not in stripped.lower():
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["P007"],
                    context="Temporary file should use %RANDOM% to prevent collisions",
                )
            )
            break

    # P008: Delayed expansion without enablement (moved from old delayed expansion check)
    if not has_delayed_expansion and re.search(r"![A-Z0-9_]+!", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["P008"],
                context="Delayed expansion variables used without ENABLEDELAYEDEXPANSION",
            )
        )

    # P009: Inefficient FOR loop pattern
    for_match = re.match(r"for\s+/f\s+[\"']([^\"']*)[\"']\s+%%\w+\s+in", stripped, re.IGNORECASE)
    if for_match:
        for_options: str = for_match.group(1).lower()
        if "tokens=*" not in for_options:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["P009"],
                    context="FOR /F loop could be optimized with 'tokens=*' parameter",
                )
            )

    # P010: Missing optimization flags for directory operations
    if re.match(r"dir\s+(?!.*\/f)", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["P010"],
                context="DIR command could be optimized with /F flag for large directories",
            )
        )

    # P015: Inefficient delay implementation
    if (
        re.search(r"ping\s+.*localhost.*", stripped, re.IGNORECASE)
        or re.search(r"ping\s+127\.0\.0\.1", stripped, re.IGNORECASE)
        or re.search(r"choice\s+/t\s+\d+", stripped, re.IGNORECASE)
    ):
        # Check if this looks like a delay implementation
        if re.search(r"ping.*-n\s+\d+.*localhost", stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["P015"],
                    context="Using ping localhost for delays is inefficient - use TIMEOUT "
                    "command for Vista+",
                )
            )
        elif re.search(r"choice\s+/t\s+\d+.*>nul", stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["P015"],
                    context="Using CHOICE for delays is inefficient - use TIMEOUT command "
                    "for Vista+",
                )
            )

    return issues


def _check_undefined_variables(lines: List[str], set_vars: Set[str]) -> List[LintIssue]:
    """Check for usage of undefined variables."""
    issues: List[LintIssue] = []

    # If script uses dynamic variable assignment, be lenient about undefined vars
    uses_dynamic_vars = "__DYNAMIC_VARS__" in set_vars

    # Improved pattern to match only valid variable names, excluding string
    # operations and builtin variables
    var_usage_pattern = re.compile(r"%([A-Z][A-Z0-9_]*)%|!([A-Z][A-Z0-9_]*)!", re.IGNORECASE)

    # Built-in variables that don't need to be SET
    builtin_vars = {
        "DATE",
        "TIME",
        "CD",
        "ERRORLEVEL",
        "RANDOM",
        "CMDCMDLINE",
        "CMDEXTVERSION",
        "COMPUTERNAME",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOGONSERVER",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_ARCHITEW6432",  # WOW64 - native architecture on 64-bit when running 32-bit
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "PROMPT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERDNSDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",  # 64-bit program files folder
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "ALLUSERSPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PUBLIC",
        "SESSIONNAME",
        "CLIENTNAME",
        # Optional environment variables that may or may not be set
        "SUDO_USER",  # Set by newer Windows sudo command
        "ORIGINAL_USER",  # Sometimes set by scripts for elevation tracking
        "DRIVERDATA",  # Driver data directory (Windows 10+)
        "ONEDRIVE",  # OneDrive directory if configured
        "ONEDRIVECONSUMER",  # Consumer OneDrive
        "ONEDRIVECOMMERCIAL",  # Business OneDrive
    }

    for i, line in enumerate(lines, start=1):
        # Skip lines with string operations like %DATE:/=-%
        if re.search(r"%[A-Z]+:[^%]*%", line, re.IGNORECASE):
            continue

        for match in var_usage_pattern.finditer(line):
            var_match_1: Optional[str] = match.group(1)
            var_match_2: Optional[str] = match.group(2)
            var_name: str = (var_match_1 or var_match_2 or "").upper()

            # Skip built-in variables and single character variables (usually loop variables)
            if var_name in builtin_vars or len(var_name) <= 1:
                continue

            # If dynamic vars are used, skip undefined variable warnings
            # (too many false positives when variables are created dynamically)
            if uses_dynamic_vars:
                continue

            if var_name not in set_vars:
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["E006"],  # Undefined variable reference
                        context=f"Variable '{var_name}' is used but never defined",
                    )
                )

    return issues


def _detect_embedded_script_blocks(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
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

    # PowerShell indicators (strong signals)
    powershell_patterns = [
        r"\$\w+\s*=",  # PowerShell variable assignment: $var =
        r"\$\w+\.\w+",  # PowerShell member access: $var.property
        r"\[.*::\w+\]",  # PowerShell static method/type: [Type::Method]
        r"-match\s+",  # PowerShell -match operator
        r"-eq\s+",  # PowerShell -eq operator
        r"-ne\s+",  # PowerShell -ne operator
        r"-ge\s+",  # PowerShell -ge operator
        r"-le\s+",  # PowerShell -le operator
        r"-gt\s+",  # PowerShell -gt operator
        r"-lt\s+",  # PowerShell -lt operator
        r"Get-\w+",  # PowerShell cmdlets (Get-*)
        r"Set-\w+",  # PowerShell cmdlets (Set-*)
        r"Write-\w+",  # PowerShell cmdlets (Write-*)
        r"New-\w+",  # PowerShell cmdlets (New-*)
        r"foreach\s*\(",  # PowerShell foreach loop (lowercase)
        r"ForEach-Object",  # PowerShell ForEach-Object cmdlet
        r"\|\s*%\s*{",  # PowerShell pipe to % (ForEach-Object alias)
        r"\.Get\(\)",  # PowerShell method call pattern
        r"\.OpenSubKey\(",  # Registry access pattern
        r"\.GetSubKeyNames\(\)",  # Registry enumeration
        r"\[Microsoft\.Win32\.",  # .NET type usage
        r"\[System\.",  # .NET System namespace
        r"\[Convert\]::\w+",  # .NET Convert class
        r"\[Math\]::\w+",  # .NET Math class
    ]

    # VBScript indicators
    vbscript_patterns = [
        r"^\s*Dim\s+",  # VBScript Dim statement
        r"^\s*Set\s+\w+\s*=\s*CreateObject",  # VBScript CreateObject
        r"WScript\.",  # WScript object
        r"^\s*On\s+Error\s+Resume\s+Next",  # VBScript error handling
        r"^\s*Function\s+\w+\(",  # VBScript function definition
        r"^\s*Sub\s+\w+\(",  # VBScript subroutine definition
        r"^\s*End\s+Function",  # VBScript end function
        r"^\s*End\s+Sub",  # VBScript end sub
        r"^\s*'",  # VBScript comment (line starting with ')
    ]

    # C# indicators (often embedded in advanced scripts)
    csharp_patterns = [
        r"^\s*using\s+System",  # C# using statement
        # C# access modifiers
        r"^\s*(public|private|protected|internal)\s+(class|static|void|string|int|bool)",
        r"^\s*namespace\s+",  # C# namespace
        r"\bforeach\s*\(\s*\w+\s+\w+\s+in\s+",  # C# foreach (type var in collection)
        r"\bfor\s*\(\s*int\s+\w+\s*=",  # C# for loop with int declaration
        r"\bfor\s*\(\s*uint\s+\w+\s*=",  # C# for loop with uint declaration
        r"\bfor\s*\(\s*long\s+\w+\s*=",  # C# for loop with long declaration
        r"byte\s+\w+\s+in\s+",  # C# byte iteration
        r"^\s*{\s*$",  # C# opening brace on its own line (common in C#)
        r"0x[0-9A-Fa-f]+",  # Hexadecimal literals (common in C#/C++)
        r"\b(uint|byte|long|ushort|ulong)\s+",  # C# primitive types
    ]

    # Track if we're in an embedded script block
    in_powershell_block = False
    in_vbscript_block = False
    in_csharp_block = False
    block_start_line = 0

    # Track the last label line to detect blocks after labels
    last_label_line = 0

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Skip empty lines and batch comments
        if not stripped or stripped.startswith("::") or stripped.upper().startswith("REM "):
            continue

        # Track labels (potential start of embedded script block)
        if re.match(r"^:[a-zA-Z_][\w]*:", stripped):
            last_label_line = i
            in_powershell_block = False
            in_vbscript_block = False
            in_csharp_block = False
            continue

        # Check for PowerShell patterns
        is_powershell_line = False
        for pattern in powershell_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                is_powershell_line = True
                break

        # Check for VBScript patterns
        is_vbscript_line = False
        for pattern in vbscript_patterns:
            if re.search(pattern, line):
                is_vbscript_line = True
                break

        # Check for C# patterns
        is_csharp_line = False
        for pattern in csharp_patterns:
            if re.search(pattern, line):
                is_csharp_line = True
                break

        # If we detect embedded script syntax, start a block
        if is_powershell_line and not in_vbscript_block and not in_csharp_block:
            if not in_powershell_block:
                in_powershell_block = True
                block_start_line = i
                logger.debug(
                    "Detected PowerShell block starting at line %d (after label on line %d)",
                    i,
                    last_label_line,
                )
            skip_lines.add(i)
            continue

        if is_vbscript_line and not in_powershell_block and not in_csharp_block:
            if not in_vbscript_block:
                in_vbscript_block = True
                block_start_line = i
                logger.debug(
                    "Detected VBScript block starting at line %d (after label on line %d)",
                    i,
                    last_label_line,
                )
            skip_lines.add(i)
            continue

        if is_csharp_line and not in_powershell_block and not in_vbscript_block:
            if not in_csharp_block:
                in_csharp_block = True
                block_start_line = i
                logger.debug(
                    "Detected C# block starting at line %d (after label on line %d)",
                    i,
                    last_label_line,
                )
            skip_lines.add(i)
            continue

        # Continue skipping if we're in a block
        if in_powershell_block or in_vbscript_block or in_csharp_block:
            # Check if this looks like batch code (might be end of embedded block)
            # Batch indicators: @echo, set, if, for (uppercase), goto, call, exit
            batch_indicators = [
                r"^@?echo\s+",
                r"^setlocal\b",
                r"^endlocal\b",
                r"^set\s+[A-Z_]+=",  # Batch SET with uppercase var
                r"^if\s+",
                r"^FOR\s+",  # FOR in uppercase is batch
                r"^goto\s+",
                r"^call\s+",
                r"^exit\s+",
                r"^pause\s*$",
                r"^timeout\s+",
            ]

            is_batch_line = False
            for pattern in batch_indicators:
                if re.match(pattern, stripped, re.IGNORECASE):
                    # Additional check: make sure it's not PowerShell
                    if not any(re.search(p, line, re.IGNORECASE) for p in powershell_patterns):
                        is_batch_line = True
                        break

            if is_batch_line:
                # Looks like we're back to batch code
                if in_powershell_block:
                    logger.debug(
                        "PowerShell block ended at line %d (lasted %d lines)",
                        i - 1,
                        i - block_start_line,
                    )
                    in_powershell_block = False
                if in_vbscript_block:
                    logger.debug(
                        "VBScript block ended at line %d (lasted %d lines)",
                        i - 1,
                        i - block_start_line,
                    )
                    in_vbscript_block = False
                if in_csharp_block:
                    logger.debug(
                        "C# block ended at line %d (lasted %d lines)",
                        i - 1,
                        i - block_start_line,
                    )
                    in_csharp_block = False
            else:
                # Still in embedded script, skip this line
                skip_lines.add(i)

    if skip_lines:
        logger.info(
            "Detected and skipping %d lines of embedded PowerShell/VBScript/C# code",
            len(skip_lines),
        )

    return skip_lines


def _validate_and_read_file(file_path: str) -> Tuple[List[str], str]:
    """Validate file and read its contents.

    Returns:
        Tuple of (lines, encoding_used)
    """
    if not file_path or not isinstance(file_path, str):
        raise ValueError("file_path must be a non-empty string")

    # Validate file exists and is accessible
    file_obj = Path(file_path)
    if not file_obj.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not file_obj.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    # Check file size for performance warning
    file_size = file_obj.stat().st_size
    if file_size > 10 * 1024 * 1024:  # 10MB
        logger.warning(
            "Large file detected (%dMB). Processing may take longer.", file_size // 1024 // 1024
        )

    lines, encoding_used = read_file_with_encoding(file_path)

    # Issue a warning if we had to fall back from UTF-8, but not for pure ASCII files
    if encoding_used.lower() not in ["utf-8", "utf-8-sig", "ascii"]:
        warnings.warn(
            f"File '{file_path}' was read using '{encoding_used}' encoding instead of UTF-8. "
            f"Consider converting the file to UTF-8 for better compatibility.",
            UserWarning,
            stacklevel=3,
        )
    elif encoding_used.lower() == "ascii":
        # Check if file contains non-ASCII characters (shouldn't happen with ASCII encoding)
        # Only warn if the file actually needs UTF-8 features
        file_content = "".join(lines)
        if any(ord(char) > 127 for char in file_content):
            warnings.warn(
                f"File '{file_path}' contains non-ASCII characters but was read as ASCII. "
                f"Consider converting the file to UTF-8 for proper character support.",
                UserWarning,
                stacklevel=3,
            )

    return lines, encoding_used


def _analyze_script_structure(lines: List[str]) -> Tuple[bool, bool, bool, bool]:
    """Analyze script structure for context-aware checking.

    Returns:
        Tuple of (has_setlocal, has_set_commands, has_delayed_expansion, uses_delayed_vars)
    """
    has_setlocal = any("setlocal" in line.lower() for line in lines)
    has_set_commands = any(re.match(r"\s*set\s+[^=]+=.*", line, re.IGNORECASE) for line in lines)
    has_delayed_expansion = any(
        re.search(r"setlocal\s+enabledelayedexpansion", line, re.IGNORECASE) for line in lines
    )
    uses_delayed_vars = any(re.search(r"![A-Z0-9_]+!", line, re.IGNORECASE) for line in lines)
    return has_setlocal, has_set_commands, has_delayed_expansion, uses_delayed_vars


def _check_line_ending_rules(lines: List[str], file_path: str) -> List[LintIssue]:
    """
    Check for line ending related issues (E018, S005, W018, W019, S016).

    This function implements the critical line ending checks based on Windows batch
    parser limitations and the Stack Overflow findings about Unix line ending bugs.

    Args:
        lines: List of file lines (already processed by Python's universal newlines)
        file_path: Path to the file being analyzed

    Returns:
        List of LintIssue objects for line ending related problems
    """
    if not lines:
        return []

    try:
        return _analyze_line_endings(lines, file_path)
    except OSError as line_ending_error:
        logger.warning("Could not analyze line endings for %s: %s", file_path, line_ending_error)
        return []


def _analyze_line_endings(lines: List[str], file_path: str) -> List[LintIssue]:
    """Analyze line endings and return related issues."""
    issues: List[LintIssue] = []
    ending_info = _detect_line_endings(file_path)
    ending_type = ending_info[0]

    # Check basic line ending issues
    issues.extend(_check_basic_line_ending_issues(ending_info))

    # Check for risks with non-CRLF endings
    if ending_type in ["LF", "CR", "MIXED"]:
        issues.extend(_check_multibyte_risks(lines, ending_type))
        issues.extend(_check_goto_call_risks(lines, ending_type))
        issues.extend(_check_doublecolon_risks(lines, ending_type))

    return issues


def _check_basic_line_ending_issues(
    ending_info: Tuple[str, bool, int, int, int],
) -> List[LintIssue]:
    """Check for E018 and S005 line ending issues."""
    ending_type, has_mixed, crlf_count, lf_only_count, cr_only_count = ending_info
    issues: List[LintIssue] = []

    if ending_type == "LF":
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["E018"],
                context=(
                    f"File uses Unix line endings (LF-only) - "
                    f"{lf_only_count} LF sequences found"
                ),
            )
        )
    elif has_mixed and ending_type == "MIXED":
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["S005"],
                context=(
                    f"File has mixed line endings - CRLF: {crlf_count}, "
                    f"LF-only: {lf_only_count}, CR-only: {cr_only_count}"
                ),
            )
        )

    return issues


def _check_multibyte_risks(lines: List[str], ending_type: str) -> List[LintIssue]:
    """Check for W018 multi-byte character risks."""
    has_multibyte, affected_lines = _has_multibyte_chars(lines)
    if has_multibyte:
        return [
            LintIssue(
                line_number=affected_lines[0],
                rule=RULES["W018"],
                context=(
                    f"Multi-byte characters found on lines {affected_lines} "
                    f"with {ending_type} line endings"
                ),
            )
        ]
    return []


def _check_goto_call_risks(lines: List[str], ending_type: str) -> List[LintIssue]:
    """Check for W019 GOTO/CALL risks."""
    goto_call_lines = [
        line_num
        for line_num, line in enumerate(lines, start=1)
        if re.match(r"(goto|call)\s+:", line.strip().lower())
    ]

    if goto_call_lines:
        return [
            LintIssue(
                line_number=goto_call_lines[0],
                rule=RULES["W019"],
                context=(
                    f"GOTO/CALL statements found on lines {goto_call_lines[:5]} "
                    f"with {ending_type} line endings"
                ),
            )
        ]
    return []


def _check_doublecolon_risks(lines: List[str], ending_type: str) -> List[LintIssue]:
    """Check for S016 double-colon comment risks."""
    doublecolon_lines = [
        line_num for line_num, line in enumerate(lines, start=1) if line.strip().startswith("::")
    ]

    if doublecolon_lines:
        return [
            LintIssue(
                line_number=doublecolon_lines[0],
                rule=RULES["S016"],
                context=(
                    f"Double-colon comments found on lines {doublecolon_lines[:5]} "
                    f"with {ending_type} line endings"
                ),
            )
        ]
    return []


def _check_global_style_rules(lines: List[str], file_path: str) -> List[LintIssue]:
    """Check global style rules that apply to the entire file."""
    issues: List[LintIssue] = []

    if not lines:
        return issues
    # S001: Missing @ECHO OFF at file start
    if not lines[0].strip().lower().startswith("@echo off"):
        issues.append(
            LintIssue(
                line_number=1, rule=RULES["S001"], context="Script should start with @ECHO OFF"
            )
        )

    # S002: ECHO OFF without @ prefix
    first_line = lines[0].strip().lower()
    if first_line.startswith("echo off") and not first_line.startswith("@echo off"):
        issues.append(
            LintIssue(
                line_number=1, rule=RULES["S002"], context="Use @ECHO OFF instead of ECHO OFF"
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


def _process_file_checks(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    lines: List[str],
    labels: Dict[str, int],
    set_vars: Set[str],
    has_setlocal: bool,
    has_set_commands: bool,
    has_delayed_expansion: bool,
    uses_delayed_vars: bool,
    config: BlinterConfig,
    skip_lines: Optional[Set[int]] = None,
) -> List[LintIssue]:
    """Process all line-by-line and global checks.

    Args:
        skip_lines: Optional set of line numbers to skip (e.g., embedded script blocks)
    """
    issues: List[LintIssue] = []

    if skip_lines is None:
        skip_lines = set()

    # Check each line with all rule categories
    for i, line in enumerate(lines, start=1):
        # Skip lines that are part of embedded scripts
        if i in skip_lines:
            continue

        # Error level checks
        issues.extend(_check_syntax_errors(line, i, labels))

        # Advanced escaping rules (E030-E033)
        issues.extend(_check_advanced_escaping_rules(line, i))

        # Warning level checks
        issues.extend(_check_warning_issues(line, i, set_vars, has_delayed_expansion))

        # Advanced FOR command rules (W034-W043)
        issues.extend(_check_advanced_for_rules(line, i))
        issues.extend(_check_advanced_process_mgmt(line, i))

        # Style level checks
        style_issues = _check_style_issues(line, i, config.max_line_length)
        issues.extend(style_issues)

        # Advanced style patterns (S021-S028)
        issues.extend(_check_advanced_style_patterns(line, i, lines))

        # Security level checks (always enabled for safety)
        issues.extend(_check_security_issues(line, i))

        # Advanced security patterns (SEC014-SEC019)
        issues.extend(_check_advanced_security(line, i))

        # Performance level checks
        perf_issues = _check_performance_issues(
            lines,
            i,
            line,
            has_setlocal,
            has_set_commands,
            has_delayed_expansion,
            uses_delayed_vars,
        )
        issues.extend(perf_issues)

        # Advanced performance patterns (P016-P025)
        issues.extend(_check_advanced_performance(lines, i, line))

    # Global checks (across all lines)
    issues.extend(_check_undefined_variables(lines, set_vars))
    issues.extend(_check_unreachable_code(lines))
    issues.extend(_check_redundant_operations(lines))
    issues.extend(_check_code_duplication(lines))

    # Enhanced validation checks based on comprehensive batch scripting guide
    issues.extend(_check_advanced_vars(lines))  # Error level E017-E022
    issues.extend(_check_enhanced_commands(lines))  # Warning level W020-W025
    issues.extend(_check_enhanced_security_rules(lines))  # Security level SEC011-SEC013

    # Global checks that depend on configuration flags
    issues.extend(_check_missing_pause(lines))  # Warning level

    # Style-level global checks
    issues.extend(_check_inconsistent_indentation(lines))
    issues.extend(_check_missing_header_doc(lines))
    issues.extend(_check_cmd_case_consistency(lines))  # S003
    issues.extend(_check_advanced_style_rules(lines))  # Style level S017-S020

    # Performance-level global checks
    issues.extend(_check_enhanced_performance(lines))  # Performance level P012-P014

    return issues


# Advanced rule detection functions


def _check_advanced_escaping_rules(line: str, line_number: int) -> List[LintIssue]:
    """Check for advanced escaping technique issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # E030: Improper caret escape sequence
    # Look for single caret attempting to escape special chars
    # But exclude FOR loop command strings and ECHO statements (ASCII art)
    if re.search(r"\^[&|><](?!\^)", stripped):
        # Check if this is within a FOR loop command string (within single quotes)
        # In FOR loops, command strings like 'command 2^>nul ^| filter' use single caret correctly
        if re.match(r"for\s+.*", stripped, re.IGNORECASE):
            # This is a FOR loop, single caret escaping in command strings is correct
            pass
        # Check if this is an ECHO statement (likely ASCII art)
        elif re.match(r"echo\s+", stripped, re.IGNORECASE):
            # ECHO statements often contain ASCII art with carets - don't flag these
            pass
        else:
            issues.append(LintIssue(line_number, RULES["E030"], context=stripped))

    # E031: Invalid multilevel escaping
    # Check for incorrect caret counts in multilevel escaping
    caret_sequences: List[str] = re.findall(r"\^+[&|><]", stripped)
    for seq in caret_sequences:
        caret_count = len(seq) - 1  # -1 for the target character
        # Valid counts follow 2^n-1 pattern: 1, 3, 7, 15...
        valid_counts: List[int] = [1, 3, 7, 15, 31]  # 2^n-1 pattern for n=1 to 5
        if caret_count > 0 and caret_count not in valid_counts:
            issues.append(LintIssue(line_number, RULES["E031"], context=seq))

    # E032: Continuation character with trailing spaces
    # Check if line ends with ^ followed by spaces/tabs (before the line ending)
    if stripped.endswith("^"):
        # Get the line without line endings
        line_no_newline = line.rstrip("\r\n")
        # If the line doesn't end with ^ after removing spaces,
        # then there are trailing spaces after ^
        if not line_no_newline.endswith("^"):
            issues.append(
                LintIssue(line_number, RULES["E032"], context="Caret with trailing spaces")
            )

    # E033: Double percent escaping error
    # Look for single % in echo statements that should be %%
    if stripped.lower().startswith("echo") and "%" in stripped:
        # Only flag if there's a literal percentage (like "50%") not a variable reference
        # Variable references like %var% are fine
        # Check for percentage signs that might need escaping (number followed by %)
        # But exclude variable references %VAR%
        line_without_vars = re.sub(r"%[A-Za-z_][A-Za-z0-9_]*%", "", stripped)
        if re.search(r"\b\d+%(?!%)\b", line_without_vars):
            issues.append(
                LintIssue(line_number, RULES["E033"], context="Percentage needs double escaping")
            )

    return issues


def _check_advanced_for_rules(line: str, line_number: int) -> List[LintIssue]:
    """Check for advanced FOR command patterns."""
    issues: List[LintIssue] = []
    stripped = line.strip().lower()

    if not stripped.startswith("for"):
        return issues

    # W034: FOR /F missing usebackq option
    if "/f" in stripped and " " in stripped and '"' in stripped:
        if "usebackq" not in stripped and ("(" in stripped.split('"')[0] or "`" in stripped):
            issues.append(
                LintIssue(
                    line_number,
                    RULES["W034"],
                    context="FOR /F with spaces in filename needs usebackq",
                )
            )

    # W035: FOR /F tokenizing without proper delimiters
    if "/f" in stripped and "delims=" not in stripped and "tokens=" in stripped:
        issues.append(
            LintIssue(
                line_number, RULES["W035"], context="FOR /F tokenizing should specify delimiters"
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
    if stripped.startswith("timeout") and "/nobreak" not in stripped and "/t" in stripped:
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
                line_number, RULES["W043"], context="TASKKILL should verify process existence first"
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


def _check_advanced_security(line: str, line_number: int) -> List[LintIssue]:
    """Check for advanced security patterns."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # SEC014: Unescaped user input in command execution
    if "%1" in stripped or "%2" in stripped or "%*" in stripped:
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
    redirection_patterns = [r">\s*c:\\temp", r">\s*c:\\windows\\temp", r">\s*\\\\.*\\share"]
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


def _check_advanced_performance(lines: List[str], line_number: int, line: str) -> List[LintIssue]:
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
                line_number, RULES["P021"], context="TASKLIST should use /FI filters for efficiency"
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
        # Check for improper continuation usage
        if stripped.count("^") == 1 and not re.search(r"\^\s*$", line):
            issues.append(
                LintIssue(
                    line_number,
                    RULES["S026"],
                    context="Continuation character should be at line end",
                )
            )

    return issues


def lint_batch_file(  # pylint: disable=too-many-locals
    file_path: str,
    config: Optional[BlinterConfig] = None,
) -> List[LintIssue]:
    """
    Lint a batch file and return list of issues found.

    This is the main entry point for batch file analysis. It performs comprehensive
    static analysis including syntax validation, security checks, style analysis,
    and performance optimization suggestions.

    Thread-safe: Yes - uses only local variables and immutable global rules
    Performance: Optimized for files up to 10MB, handles larger files gracefully

    Args:
        file_path: Path to the batch file (.bat or .cmd) to lint.
                  Can be absolute or relative path.
        config: BlinterConfig object with configuration settings. If None, uses defaults.

    Returns:
        List of LintIssue objects containing detailed issue information.
        Each issue includes line number, rule details and contextual information.

    Raises:
        OSError: If file cannot be read or encoding issues occur
        FileNotFoundError: If the specified file doesn't exist
        PermissionError: If insufficient permissions to read the file
        ValueError: If file_path is empty or invalid

    Example:
        >>> issues = lint_batch_file("script.bat")
        >>> for issue in issues:
        ...     print(f"Line {issue.line_number}: {issue.rule.name}")

        >>> # With custom configuration
        >>> config = BlinterConfig(max_line_length=100)
        >>> issues = lint_batch_file("script.bat", config=config)
    """
    logger.info("Starting lint analysis of file: %s", file_path)

    # Use provided config or create default
    if config is None:
        config = BlinterConfig()

    # Read and validate file
    lines, _encoding_used = _validate_and_read_file(file_path)

    if not lines:
        return []  # Empty file, no issues

    # Detect embedded PowerShell/VBScript blocks to avoid false positives
    skip_lines = _detect_embedded_script_blocks(lines)

    # Store original max_line_length for S011 rule
    original_s011_rule = RULES["S011"]
    if config.max_line_length != 150:
        RULES["S011"] = Rule(
            code="S011",
            name=original_s011_rule.name,
            severity=original_s011_rule.severity,
            explanation=original_s011_rule.explanation.replace("150", str(config.max_line_length)),
            recommendation=original_s011_rule.recommendation,
        )

    issues: List[LintIssue] = []

    # Analyze script structure for context-aware checking
    structure_data = _analyze_script_structure(lines)
    has_setlocal, has_set_commands, has_delayed_expansion, uses_delayed_vars = structure_data

    # Critical line ending checks (includes ERROR level E018)
    issues.extend(_check_line_ending_rules(lines, file_path))

    # Style rules that apply globally
    issues.extend(_check_global_style_rules(lines, file_path))

    # Collect labels and check for duplicates
    labels, label_issues = _collect_labels(lines)
    issues.extend(label_issues)

    # Collect set variables for undefined variable checking
    set_vars = _collect_set_variables(lines)

    # Process all line-by-line and global checks
    issues.extend(
        _process_file_checks(
            lines,
            labels,
            set_vars,
            has_setlocal,
            has_set_commands,
            has_delayed_expansion,
            uses_delayed_vars,
            config,
            skip_lines,
        )
    )

    # Global checks for new rules
    issues.extend(_check_new_global_rules(lines, file_path))

    # Restore original S011 rule if modified
    if config.max_line_length != 150:
        RULES["S011"] = original_s011_rule

    # Filter issues based on configuration
    filtered_issues = []
    for issue in issues:
        # Check if rule is enabled
        if not config.is_rule_enabled(issue.rule.code):
            continue

        # Check if severity should be included
        if not config.should_include_severity(issue.rule.severity):
            continue

        filtered_issues.append(issue)

    logger.info(
        "Lint analysis completed. Found %d issues (filtered to %d) across %d error(s), "
        "%d warning(s), %d style issue(s), %d security issue(s), "
        "%d performance issue(s)",
        len(issues),
        len(filtered_issues),
        len([i for i in filtered_issues if i.rule.severity == RuleSeverity.ERROR]),
        len([i for i in filtered_issues if i.rule.severity == RuleSeverity.WARNING]),
        len([i for i in filtered_issues if i.rule.severity == RuleSeverity.STYLE]),
        len([i for i in filtered_issues if i.rule.severity == RuleSeverity.SECURITY]),
        len([i for i in filtered_issues if i.rule.severity == RuleSeverity.PERFORMANCE]),
    )

    return filtered_issues


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
                    re.search(pattern, stripped) for pattern in net_privilege_check_patterns
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


def _check_advanced_global_patterns(lines: List[str], file_path: str) -> List[LintIssue]:
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
            if any(keyword in stripped for keyword in ["%~f0", "%0", file_path.lower()]):
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

    # S021: Missing code block documentation
    issues.extend(_check_missing_documentation(lines))

    # S022: Inconsistent variable naming convention
    issues.extend(_check_var_naming(lines))

    return issues


# pylint: disable=too-many-branches
def _check_missing_documentation(
    lines: List[str],
) -> List[LintIssue]:
    """Check for missing code block documentation."""
    issues: List[LintIssue] = []
    in_complex_block = False
    complex_block_start = 0

    for i, line in enumerate(lines, start=1):
        stripped = line.strip().lower()

        # Identify complex code blocks
        is_complex_start = (
            stripped.startswith("for ")
            or (stripped.startswith("if ") and "(" in line)
            or (stripped.startswith(":") and len(stripped) > 5)
        )

        if is_complex_start and not in_complex_block:
            in_complex_block = True
            complex_block_start = i

            # Check for documentation in previous 3 lines
            has_doc = False
            for j in range(max(0, i - 3), i):
                if j < len(lines) and _is_comment_line(lines[j]):
                    has_doc = True
                    break

            if not has_doc and ":" in stripped:
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["S021"],
                        context="Complex code block or subroutine needs documentation",
                    )
                )

        # Comprehensive end of block detection
        # Detect actual block termination through various batch file constructs
        if in_complex_block:
            block_ended = False

            # Check for new label (starts a new section/subroutine)
            if stripped.startswith(":") and not stripped.startswith("::"):
                block_ended = True

            # Check for explicit control flow that exits the block
            elif re.match(r"^(goto|exit)\b", stripped, re.IGNORECASE):
                block_ended = True

            # Check for CALL to another label (may indicate block end)
            elif re.match(r"^call\s+:", stripped, re.IGNORECASE):
                block_ended = True

            # Check for closing parenthesis of multi-line IF or FOR blocks
            # Count parentheses to detect when we've closed the block
            open_parens = line.count("(")
            close_parens = line.count(")")
            if close_parens > open_parens:
                # More closing than opening suggests end of a block
                block_ended = True

            # Check for two consecutive empty lines (paragraph break)
            if line.strip() == "":
                # Look ahead to see if next line is also empty
                if i < len(lines) and lines[i].strip() == "":
                    block_ended = True

            # Check for significant distance from start (>15 lines) AND a clear boundary
            # (empty line, new command, etc.)
            if i - complex_block_start > 15:
                if line.strip() == "" or re.match(
                    r"^(echo|set|if|for|call|rem)\b", stripped, re.IGNORECASE
                ):
                    block_ended = True

            if block_ended:
                in_complex_block = False

    return issues


def _check_var_naming(lines: List[str]) -> List[LintIssue]:
    """Check for inconsistent variable naming conventions."""
    issues: List[LintIssue] = []
    variable_names = set()
    naming_styles = {
        "camelCase": 0,
        "PascalCase": 0,
        "snake_case": 0,
        "lowercase": 0,
        "UPPERCASE": 0,
    }

    for line in lines:
        # Skip lines that are clearly not batch SET commands
        stripped = line.strip()
        if (
            stripped.startswith("echo ")
            or stripped.startswith("rem ")
            or stripped.startswith("::")
            or ">" in stripped
            or ">>" in stripped
        ):
            continue

        # Extract variable names from SET commands - handle quoted and unquoted
        set_matches: List[str] = []
        set_patterns = [
            r"^\s*set\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=",  # Regular set: set VAR=value (line start)
            r'^\s*set\s+"([a-zA-Z_][a-zA-Z0-9_]*)\s*=',  # Quoted set: set "VAR=value" (line start)
        ]
        for pattern in set_patterns:
            matches: List[str] = re.findall(pattern, line, re.IGNORECASE)
            set_matches.extend(matches)
        for var_name in set_matches:
            variable_names.add(var_name)

            # Categorize naming style
            if "_" in var_name and var_name.islower():
                naming_styles["snake_case"] += 1
            elif var_name[0].isupper() and any(c.islower() for c in var_name[1:]):
                naming_styles["PascalCase"] += 1
            elif var_name[0].islower() and any(c.isupper() for c in var_name[1:]):
                naming_styles["camelCase"] += 1
            elif var_name.isupper():
                naming_styles["UPPERCASE"] += 1
            elif var_name.islower():
                naming_styles["lowercase"] += 1

    # Check for mixed styles (only if we have enough variables to analyze)
    if len(variable_names) >= 3:
        used_styles = sum(1 for count in naming_styles.values() if count > 0)
        if used_styles > 1:

            def get_count(style_name: str) -> int:
                return naming_styles[style_name]

            dominant_style: str = max(naming_styles, key=get_count)
            issues.append(
                LintIssue(
                    line_number=1,
                    rule=RULES["S022"],
                    context=f"Mixed variable naming styles detected. "
                    f"Consider using {dominant_style} consistently",
                )
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
                        context=(f"Code after {command} on line {i + 1} will never execute"),
                    )
                )

    return issues


def _find_truly_unreachable_code(lines: List[str], exit_line_index: int) -> Optional[int]:
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
    if re.search(r"\bif\b.*\(", line):
        return current_depth + 1
    if line == ")":
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
    if not line or line.startswith("rem") or line.startswith("::") or line.startswith(":"):
        return False

    # Skip pure structural elements
    if line in {")", "endlocal", "setlocal"}:
        return False

    # Skip ') else' patterns
    if re.match(r"^\)\s*(else\b.*)?$", line):
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

            if len(normalized) > 40:  # Only consider substantial commands (increased from 20)
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


def _find_single_line_mixed_indent(indented_lines: List[Tuple[int, str]]) -> List[LintIssue]:
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


def _find_file_mixed_indent(indented_lines: List[Tuple[int, str]]) -> Optional[LintIssue]:
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
        return LintIssue(
            line_number=later_line,
            rule=RULES["S012"],
            context=context,
        )
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


def _find_most_common_case(occurrences: List[Tuple[int, str]]) -> Tuple[str, Dict[str, List[int]]]:
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


def group_issues(issues: List[LintIssue]) -> DefaultDict[RuleSeverity, List[LintIssue]]:
    """Group issues by severity level.

    Args:
        issues: List of LintIssue objects

    Returns:
        Dictionary mapping severity levels to lists of issues
    """
    grouped: DefaultDict[RuleSeverity, List[LintIssue]] = defaultdict(list)
    for issue in issues:
        grouped[issue.rule.severity].append(issue)
    return grouped


def print_summary(issues: List[LintIssue]) -> None:
    """Print summary statistics of linting issues.

    Args:
        issues: List of LintIssue objects
    """
    total_issues = len(issues)

    # Group by rule for most common error
    rule_counts: DefaultDict[str, int] = defaultdict(int)
    for issue in issues:
        rule_counts[issue.rule.code] += 1

    most_common_rule: Tuple[str, int] = ("", 0)
    if rule_counts:
        max_count = 0
        max_rule = ""
        for rule_code, count in rule_counts.items():
            if count > max_count:
                max_count = count
                max_rule = rule_code
        most_common_rule = (max_rule, max_count)

    # Count by severity
    severity_counts: DefaultDict[RuleSeverity, int] = defaultdict(int)
    for issue in issues:
        severity_counts[issue.rule.severity] += 1

    print("\nSUMMARY:")
    print(f"Total issues: {total_issues}")
    if most_common_rule[0]:
        most_common_rule_obj = RULES[most_common_rule[0]]
        print(
            f"Most common issue: '{most_common_rule_obj.name}' "
            f"({most_common_rule[0]}) - {most_common_rule[1]} occurrences"
        )
    else:
        print("No issues found")

    print("\nIssues by severity:")
    severity_order = [
        RuleSeverity.ERROR,
        RuleSeverity.WARNING,
        RuleSeverity.STYLE,
        RuleSeverity.SECURITY,
        RuleSeverity.PERFORMANCE,
    ]
    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"  {severity.value}: {count}")


def print_detailed(issues: List[LintIssue]) -> None:
    """Print detailed issue information in the new format.

    Args:
        issues: List of LintIssue objects
    """
    if not issues:
        print("\nDETAILED ISSUES:")
        print("----------------")
        print("No issues found! ?\n")
        return

    # Group by severity
    grouped = group_issues(issues)

    print("\nDETAILED ISSUES:")
    print("----------------")

    severity_order = [
        RuleSeverity.ERROR,
        RuleSeverity.WARNING,
        RuleSeverity.STYLE,
        RuleSeverity.SECURITY,
        RuleSeverity.PERFORMANCE,
    ]

    for severity in severity_order:
        if severity not in grouped:
            continue

        severity_issues = grouped[severity]
        print(f"\n{severity.value.upper()} LEVEL ISSUES:")
        print("=" * (len(severity.value) + 14))

        # Group by rule within severity
        rule_groups: DefaultDict[str, List[LintIssue]] = defaultdict(list)
        for issue in severity_issues:
            rule_groups[issue.rule.code].append(issue)

        for rule_code in sorted(rule_groups.keys()):
            rule_issues = rule_groups[rule_code]
            rule = rule_issues[0].rule
            line_numbers = sorted([issue.line_number for issue in rule_issues])

            print(f"\nLine {', '.join(map(str, line_numbers))}: {rule.name} ({rule_code})")
            print(f"- Explanation: {rule.explanation}")
            print(f"- Recommendation: {rule.recommendation}")

            # Add context if available
            contexts = [issue.context for issue in rule_issues if issue.context]
            if contexts:
                # Remove duplicates while preserving order
                unique_contexts: List[str] = []
                seen: Set[str] = set()
                for context in contexts:
                    if context not in seen:
                        unique_contexts.append(context)
                        seen.add(context)
                for context in unique_contexts:
                    print(f"- Context: {context}")

        print()  # Extra spacing between severity levels


def print_severity_info(issues: List[LintIssue]) -> None:
    """Print severity level information.

    Args:
        issues: List of LintIssue objects
    """
    severity_counts: DefaultDict[RuleSeverity, int] = defaultdict(int)
    for issue in issues:
        severity_counts[issue.rule.severity] += 1

    descriptions: Dict[RuleSeverity, str] = {
        RuleSeverity.ERROR: "Critical issues that will cause script failure or incorrect behavior.",
        RuleSeverity.WARNING: "Issues that may cause problems or unexpected behavior.",
        RuleSeverity.STYLE: "Code style and formatting issues that affect readability.",
        RuleSeverity.SECURITY: "Security vulnerabilities and potential risks.",
        RuleSeverity.PERFORMANCE: "Performance issues and optimization opportunities.",
    }

    print("\nSEVERITY BREAKDOWN:")
    print("====================")

    severity_order = [
        RuleSeverity.ERROR,
        RuleSeverity.WARNING,
        RuleSeverity.STYLE,
        RuleSeverity.SECURITY,
        RuleSeverity.PERFORMANCE,
    ]

    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        if count == 0:
            continue
        issue_word = "issue" if count == 1 else "issues"
        print(f"\n{severity.value}: {count} {issue_word}")
        print(f"  {descriptions.get(severity, 'No description available.')}")


def find_batch_files(path: Union[str, Path], recursive: bool = True) -> List[Path]:
    """
    Find all batch files (.bat and .cmd) in a directory or return single file.

    Args:
        path: Path to file or directory to search
        recursive: Whether to search subdirectories recursively (default: True)

    Returns:
        List of Path objects representing batch files found

    Raises:
        FileNotFoundError: If the path doesn't exist
        ValueError: If path is not a file or directory
    """
    path_obj = Path(path)

    if not path_obj.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    if path_obj.is_file():
        # Return single file if it's a batch file
        if path_obj.suffix.lower() in [".bat", ".cmd"]:
            return [path_obj]
        raise ValueError(f"File '{path}' is not a batch file (.bat or .cmd)")

    if path_obj.is_dir():
        # Find all batch files in directory
        batch_files: List[Path] = []

        if recursive:
            # Recursive search
            for pattern in ["**/*.bat", "**/*.cmd"]:
                batch_files.extend(path_obj.glob(pattern))
        else:
            # Non-recursive search
            for pattern in ["*.bat", "*.cmd"]:
                batch_files.extend(path_obj.glob(pattern))

        # Sort for consistent output
        batch_files.sort()
        return batch_files

    raise ValueError(f"Path '{path}' is neither a file nor a directory")


@dataclass
class CliArguments:
    """Parsed CLI arguments."""

    target_path: str
    use_config: bool
    cli_show_summary: Optional[bool]
    cli_recursive: Optional[bool]


def _parse_cli_arguments() -> Optional[CliArguments]:
    """Parse command line arguments."""
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        return None

    # Handle special commands first
    if "--create-config" in sys.argv:
        create_default_config_file()
        return None

    target_path: Optional[str] = None
    use_config = True
    cli_show_summary = None  # None means use config default
    cli_recursive = None  # None means use config default

    for arg in sys.argv[1:]:
        if not arg.startswith("--"):
            # This should be the file or directory path
            if target_path is None:
                target_path = arg
        elif arg == "--summary":
            cli_show_summary = True
        elif arg == "--severity":
            pass  # Severity is always shown
        elif arg == "--no-recursive":
            cli_recursive = False
        elif arg == "--no-config":
            use_config = False

    if not target_path:
        print("Error: No batch file or directory provided.\n")
        print_help()
        return None

    return CliArguments(target_path, use_config, cli_show_summary, cli_recursive)


@dataclass
class ProcessingResults:
    """Results from processing batch files."""

    all_issues: List[LintIssue]
    file_results: Dict[str, List[LintIssue]]
    total_files_processed: int
    files_with_errors: int


def _process_batch_files(
    batch_files: List[Path], config: BlinterConfig
) -> Optional[ProcessingResults]:
    """Process all batch files and collect results."""
    all_issues: List[LintIssue] = []
    file_results: Dict[str, List[LintIssue]] = {}
    total_files_processed = 0
    files_with_errors = 0

    for batch_file in batch_files:
        try:
            issues = lint_batch_file(str(batch_file), config=config)
            file_results[str(batch_file)] = issues
            all_issues.extend(issues)
            total_files_processed += 1

            if any(issue.rule.severity == RuleSeverity.ERROR for issue in issues):
                files_with_errors += 1

        except UnicodeDecodeError as decode_error:
            print(f"Warning: Could not read '{batch_file}' due to encoding issues: {decode_error}")
            continue
        except (FileNotFoundError, PermissionError, OSError, ValueError, TypeError) as file_error:
            print(f"Warning: Could not process '{batch_file}': {file_error}")
            continue

    if total_files_processed == 0:
        print("Error: No batch files could be processed.")
        return None

    return ProcessingResults(all_issues, file_results, total_files_processed, files_with_errors)


def _display_results(
    results: ProcessingResults,
    target_path: str,
    config: BlinterConfig,
) -> None:
    """Display lint results to the user."""
    is_directory = Path(target_path).is_dir()

    if is_directory:
        print(f"\n Batch Files Analysis: {target_path}")
        print("=" * (26 + len(target_path)))
        file_count_text = "s" if results.total_files_processed != 1 else ""
        print(f"Processed {results.total_files_processed} batch file{file_count_text}")
        print()

        # Show results for each file if there are multiple files
        if len(results.file_results) > 1:
            for file_path, issues in results.file_results.items():
                relative_path = Path(file_path).relative_to(Path(target_path))
                print(f"\n File: {relative_path}")
                print("-" * (8 + len(str(relative_path))))

                if issues:
                    print_detailed(issues)
                else:
                    print("No issues found! OK")
                print()
        else:
            # Single file in directory
            print_detailed(results.all_issues)
    else:
        # Single file processing
        print(f"\n Batch File Analysis: {target_path}")
        print("=" * (25 + len(target_path)))
        print_detailed(results.all_issues)

    # Show combined summary if processing multiple files
    if is_directory and len(results.file_results) > 1:
        print("\n COMBINED RESULTS:")
        print("===================")

    if config.show_summary:
        print_summary(results.all_issues)

    print_severity_info(results.all_issues)


def _exit_with_results(results: ProcessingResults, target_path: str) -> None:
    """Exit with appropriate code based on results."""
    is_directory = Path(target_path).is_dir()
    error_count = sum(
        1 for issue in results.all_issues if issue.rule.severity == RuleSeverity.ERROR
    )

    if is_directory:
        if error_count > 0:
            error_text = "s" if error_count != 1 else ""
            file_text = "s" if results.files_with_errors != 1 else ""
            print(
                f"\nWARNING  Found {error_count} critical error{error_text} "
                f"across {results.files_with_errors} file{file_text} that must be fixed."
            )
            sys.exit(1)
        elif results.all_issues:
            issue_text = "s" if len(results.all_issues) != 1 else ""
            file_text = "s" if results.total_files_processed != 1 else ""
            print(
                f"\nOK No critical errors found, but {len(results.all_issues)} "
                f"total issue{issue_text} detected across "
                f"{results.total_files_processed} file{file_text}."
            )
            sys.exit(0)
        else:
            file_text = "s" if results.total_files_processed != 1 else ""
            look_text = "s" if results.total_files_processed == 1 else ""
            print(
                f"\n🎉 No issues found! All {results.total_files_processed} "
                f"batch file{file_text} look{look_text} great!"
            )
            sys.exit(0)
    else:
        if error_count > 0:
            print(
                f"\nWARNING  Found {error_count} critical "
                f"error{'s' if error_count != 1 else ''} that must be fixed."
            )
            sys.exit(1)
        elif results.all_issues:
            print(
                f"\nOK No critical errors found, but {len(results.all_issues)} "
                f"issue{'s' if len(results.all_issues) != 1 else ''} detected."
            )
            sys.exit(0)
        else:
            print("\nNo issues found! Your batch file looks great!")
            sys.exit(0)


def main() -> None:
    """Main entry point for the blinter application."""
    # Parse CLI arguments
    cli_args = _parse_cli_arguments()
    if cli_args is None:
        return

    # Load configuration
    config = load_config(use_config=cli_args.use_config)

    # Override config with CLI arguments
    if cli_args.cli_show_summary is not None:
        config.show_summary = cli_args.cli_show_summary
    if cli_args.cli_recursive is not None:
        config.recursive = cli_args.cli_recursive

    # Find all batch files to process
    try:
        batch_files = find_batch_files(cli_args.target_path, recursive=config.recursive)
    except FileNotFoundError:
        print(f"Error: Path '{cli_args.target_path}' not found.")
        return
    except ValueError as value_error:
        print(f"Error: {value_error}")
        return
    except (OSError, PermissionError) as path_error:
        print(f"Error: Cannot access '{cli_args.target_path}': {path_error}")
        return

    if not batch_files:
        print(f"No batch files (.bat or .cmd) found in: {cli_args.target_path}")
        return

    # Process batch files
    results = _process_batch_files(batch_files, config)
    if results is None:
        return

    # Display results
    _display_results(results, cli_args.target_path, config)

    # Exit with appropriate code
    _exit_with_results(results, cli_args.target_path)


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
    if re.match(r'\s*for\s+/f\s+(?!.*"[^"]*tokens[^"]*")[^(]*\(', stripped, re.IGNORECASE):
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
            line_number=line_number, rule=RULES["W021"], context="IF comparison should be quoted"
        )
    return None


def _check_deprecated_commands(stripped: str, line_number: int) -> List[LintIssue]:
    """Check for deprecated commands (W024)."""
    issues: List[LintIssue] = []
    # Note: xcopy is NOT deprecated, so it's not included here
    deprecated_commands = {
        "net send": "msg",
        "at ": "schtasks",
        "cacls": "icacls",
    }

    for deprecated, modern in deprecated_commands.items():
        if re.search(rf"\b{re.escape(deprecated)}\b", stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_number,
                    rule=RULES["W024"],
                    context=f"Use {modern} instead of {deprecated}",
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
                    "errorlevel" in lines[j - 1].lower() or "if " in lines[j - 1].lower()
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
            re.search(r"setlocal.*enabledelayedexpansion", line, re.IGNORECASE) for line in lines
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


def _check_function_docs(line: str, line_number: int, lines: List[str]) -> List[LintIssue]:
    """Check for function documentation (S018)."""
    issues: List[LintIssue] = []

    if re.match(r"\s*:[a-zA-Z_][a-zA-Z0-9_]*\s*$", line.strip()):
        # Found a label that might be a function
        # Check if previous lines have documentation
        doc_found = False
        for j in range(max(0, line_number - 5), line_number - 1):
            if j < len(lines) and re.match(r"\s*rem\s+", lines[j], re.IGNORECASE):
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


def _check_magic_numbers(line: str, line_number: int) -> List[LintIssue]:
    """Check for magic numbers (S019)."""
    issues: List[LintIssue] = []
    number_pattern = r"\b(?<!%)\d{2,}\b(?!%)"

    # Common exceptions: standard values, conversion factors, and system constants
    common_exceptions = {
        # Basic numbers
        "0",
        "1",
        "10",
        "100",
        "256",
        "60",
        "24",
        "365",
        # Conversion factors
        "1024",  # Bytes to KB
        "1000",  # Bytes to MB (decimal), Hz to kHz
        "1000000",  # Bytes to MB, Hz to MHz
        "1073741824",  # GB in bytes (1024^3)
        # Common system values
        "65536",  # 64KB, 16-bit limit
        "32768",  # 32KB, signed 16-bit limit
        "255",  # Byte limit, RGB values
        "127",  # Signed byte limit
        "255.255.255.255",  # IP address limit (partial match will work)
        # Time constants
        "3600",  # Seconds in hour
        "86400",  # Seconds in day
        "604800",  # Seconds in week
        # File size constants
        "512",  # Common block size
        "4096",  # Common page size
        # HTTP/networking
        "80",
        "443",
        "8080",
        "3389",  # Common ports
        # Windows-specific
        "260",  # MAX_PATH in Windows
        "32767",  # MAX_SHORT
        # ANSI color codes (foreground)
        *[str(i) for i in range(30, 38)],
        # ANSI color codes (background)
        *[str(i) for i in range(40, 48)],
        # ANSI bright color codes (foreground)
        *[str(i) for i in range(90, 98)],
        # ANSI bright color codes (background)
        *[str(i) for i in range(100, 108)],
        # Common exit codes and small numbers
        *[str(i) for i in range(11, 26)],
        # Single and double digit numbers commonly used in scripts
        "01",
        "02",
        "03",
        "04",
        "05",
        "06",
        "07",
        "08",
        "09",
        "11",
        "12",
        "13",
        "14",
        "15",
        "16",
        "17",
        "18",
        "19",
        "20",
        "21",
        "22",
        "23",
        "25",
        "26",
        "27",
        "28",
        "29",
        "38",
        "39",  # Additional ANSI codes
        "48",
        "49",  # Additional ANSI codes
        "50",
        "51",
        "52",
        "53",
        "54",
        "55",
        "56",
        "57",
        "58",
        "59",
        "61",
        "62",
        "63",
        "64",
        "65",
        "66",
        "67",
        "68",
        "69",
        "70",
        "71",
        "72",
        "73",
        "74",
        "75",
        "76",
        "77",
        "78",
        "79",
        "81",
        "82",
        "83",
        "84",
        "85",
        "86",
        "87",
        "88",
        "89",
        "99",
    }

    for match in re.finditer(number_pattern, line.strip()):
        number = match.group(0)

        # Don't flag numbers that are clearly part of identifiers, GUIDs, or registry paths
        context_before = line[: match.start()]
        context_after = line[match.end() :]

        # Skip if it looks like part of a GUID, file path, or identifier
        if (
            any(c in context_before[-10:] for c in ["-", "\\", "/", "{"])
            or any(c in context_after[:10] for c in ["-", "\\", "/", "}"])
            or
            # Skip if it's in a PowerShell math expression context
            ("round(" in context_before.lower() and ")" in context_after)
            or ("[math]::" in context_before.lower())
        ):
            continue

        if number not in common_exceptions:
            issues.append(
                LintIssue(
                    line_number=line_number,
                    rule=RULES["S019"],
                    context=f"Magic number {number} should be defined as constant",
                )
            )

    return issues


def _check_line_length(line: str, line_number: int) -> List[LintIssue]:
    """Check for long lines (S020)."""
    issues: List[LintIssue] = []

    if len(line) > 150 and "^" not in line:
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["S020"],
                context=f"Line length {len(line)} exceeds 150 characters",
            )
        )

    return issues


def _check_advanced_style_rules(lines: List[str]) -> List[LintIssue]:
    """Check for advanced style and best practice issues (S017-S020)."""
    issues: List[LintIssue] = []
    variables_seen: Dict[str, str] = {}  # var_name -> case_style

    for i, line in enumerate(lines, start=1):
        issues.extend(_check_variable_naming(line, i, variables_seen))
        issues.extend(_check_function_docs(line, i, lines))
        issues.extend(_check_magic_numbers(line, i))
        issues.extend(_check_line_length(line, i))

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
        var in system_variables or var.startswith("~") or var.isdigit() for var in variables_in_line
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
        re.search(r"\b(del|copy|move|type|xcopy|rd|md|mkdir|rmdir)\b", stripped, re.IGNORECASE)
    )
    has_only_redirection = bool(re.search(r">.*$", stripped))

    return is_file_operation and has_only_redirection and not has_command_chaining


def _check_enhanced_security_rules(lines: List[str]) -> List[LintIssue]:
    """Check for enhanced security issues (SEC011-SEC013)."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Check for path traversal (SEC011)
        if ".." in stripped and any(op in stripped for op in ["cd", "copy", "move", "del"]):
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


def _check_unnecessary_output_p014(lines: List[str], i: int, stripped: str) -> Optional[LintIssue]:
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
                            f"{cmd.upper()} output may be unnecessary in " "non-interactive context"
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


if __name__ == "__main__":
    main()
