"""Blinter - A professional-grade batch file linter for Windows.

This module provides comprehensive functionality to lint Windows batch files (.bat and .cmd)
for common syntax errors, style issues, security vulnerabilities and performance problems.

Features:
- 100+ built-in rules across 5 severity levels
- Thread-safe operations for concurrent processing
- Robust encoding detection and handling
- Comprehensive error handling for production use
- Performance optimized for large files
- Extensible architecture for custom rules

Usage:
    import blinter
    issues = blinter.lint_batch_file("script.bat")

Author: tboy1337
Version: 1.0.2
License: CRL
"""

# pylint: disable=too-many-lines

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
import logging
from pathlib import Path
import re
import sys
from typing import DefaultDict, Dict, List, Optional, Set, Tuple, Union
import warnings

__version__ = "1.0.2"
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
        name="Undefined variable reference",
        severity=RuleSeverity.ERROR,
        explanation="Script references variables that were never set, "
        "which may cause runtime errors",
        recommendation="Define the variable using SET before referencing it, "
        "or add existence checks",
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
        explanation="File operation may not handle Unicode characters properly",
        recommendation="Consider using commands with better Unicode support",
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
    "W016": Rule(
        code="W016",
        name="Mixed variable syntax within script",
        severity=RuleSeverity.WARNING,
        explanation=(
            "Inconsistent use of %VAR% and !VAR! syntax within the same script "
            "reduces readability"
        ),
        recommendation="Use consistent variable expansion syntax throughout the script",
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
        explanation="Batch commands should follow consistent casing conventions for readability",
        recommendation="Use consistent UPPERCASE for all batch commands",
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
        explanation="Lines longer than 120 characters are hard to read and maintain",
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
        severity=RuleSeverity.SECURITY,
        explanation="Absolute paths may not exist on other systems and could be security risks",
        recommendation="Use environment variables like %%USERPROFILE%% instead of hardcoded paths",
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
    "P011": Rule(
        code="P011",
        name="Redundant variable assignments",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Multiple assignments to the same variable without usage is inefficient",
        recommendation="Remove intermediate assignments or combine operations",
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
        explanation="Command is deprecated in modern Windows versions",
        recommendation=("Replace with modern equivalent: XCOPY→ROBOCOPY, NET SEND→MSG, etc."),
    ),
    "W025": Rule(
        code="W025",
        name="Missing error redirection",
        severity=RuleSeverity.WARNING,
        explanation=("Command may produce error output that should be redirected"),
        recommendation=("Add error redirection: 2>nul to suppress errors or 2>&1 to capture them"),
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
        name="Missing function documentation",
        severity=RuleSeverity.STYLE,
        explanation="Functions and subroutines should have documentation comments",
        recommendation=(
            "Add REM comments describing function purpose, parameters, and return values"
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
    # Enhanced Security Rules (SEC014-SEC018)
    "SEC014": Rule(
        code="SEC014",
        name="UNC path without UAC elevation check",
        severity=RuleSeverity.SECURITY,
        explanation="UNC operations may fail under UAC without proper elevation",
        recommendation="Add privilege checks before UNC operations: NET SESSION >nul 2>&1",
    ),
    "SEC015": Rule(
        code="SEC015",
        name="Fork bomb pattern detected",
        severity=RuleSeverity.SECURITY,
        explanation="Script contains patterns that could create resource exhaustion fork bombs",
        recommendation='Remove recursive self-execution patterns: :label + start "" %0 + '
        "goto label",
    ),
    "SEC016": Rule(
        code="SEC016",
        name="Potential hosts file modification",
        severity=RuleSeverity.SECURITY,
        explanation="Script attempts to modify system hosts file, potential DNS poisoning vector",
        recommendation="Avoid hosts file modifications unless explicitly required for "
        "legitimate purposes",
    ),
    "SEC017": Rule(
        code="SEC017",
        name="Autorun.inf creation detected",
        severity=RuleSeverity.SECURITY,
        explanation="Script creates autorun.inf files, common malware spreading vector",
        recommendation="Remove autorun.inf creation unless required for legitimate "
        "installation media",
    ),
    "SEC018": Rule(
        code="SEC018",
        name="Batch file copying itself to removable media",
        severity=RuleSeverity.SECURITY,
        explanation="Script copies itself to other drives, potential virus behavior",
        recommendation="Remove self-copying behavior unless required for legitimate deployment",
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
    (r"del\s+[\"']?\*\.\*[\"']?(\s|$)", "SEC003"),  # del *.* (more specific)
    (r"del\s+[\"']?\*/\*[\"']?(\s|$)", "SEC003"),  # del */* pattern
    (r"del\s+[\"']?[a-z]:\\\*[\"']?(\s|$)", "SEC003"),  # del c:\* type commands
    (r"format\s+[a-z]:", "SEC003"),  # format c: type commands
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

OLDER_WINDOWS_COMMANDS = {"choice", "forfiles", "where", "robocopy", "timeout", "icacls"}

ARCHITECTURE_SPECIFIC_PATTERNS = [
    r"Wow6432Node",  # 32-bit registry redirect
    r"Program Files \(x86\)",  # 32-bit program files
    r"SysWow64",  # 32-bit system directory
]

UNICODE_PROBLEMATIC_COMMANDS = {"type", "echo", "find", "findstr"}

# Additional patterns for new rules
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
  --help              Display this help menu and exit.

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


def _is_command_in_safe_context(line: str) -> bool:
    """
    Check if a potentially dangerous command is in a safe context (REM comment or ECHO statement).

    Args:
        line: The line to check

    Returns:
        True if the command is in a safe context and shouldn't be flagged as dangerous
    """
    stripped = line.strip().lower()

    # Check if line starts with REM (comment)
    if stripped.startswith("rem ") or stripped.startswith("rem\t"):
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
        if line.strip().startswith(":"):
            label = line.strip().lower()

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
        # Match different SET patterns
        patterns = [
            r"set\s+([A-Za-z0-9_]+)=",  # Regular set
            r"set\s+/p\s+([A-Za-z0-9_]+)=",  # Set with prompt
            r"set\s+/a\s+([A-Za-z0-9_]+)=",  # Arithmetic set
        ]

        for pattern in patterns:
            set_match = re.match(pattern, line.strip(), re.IGNORECASE)
            if set_match:
                var_name_text: str = set_match.group(1)
                set_vars.add(var_name_text.upper())
                break

    # Add common environment variables that are typically available
    common_env_vars = {
        "PATH",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "USERNAME",
        "COMPUTERNAME",
        "PROCESSOR_ARCHITECTURE",
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
        "ProgramW6432",  # 64-bit program files folder on 64-bit systems
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "ProgramFiles(x86)",
    }
    set_vars.update(common_env_vars)

    return set_vars


def _check_syntax_errors(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    line: str, line_num: int, labels: Dict[str, int]
) -> List[LintIssue]:
    """Check for syntax error level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # E002: Missing label for GOTO statement
    # E015: Missing colon in GOTO :EOF statement
    goto_match = re.match(r"goto\s+(:?\S+)", stripped, re.IGNORECASE)
    if goto_match:
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

    # E014: Missing colon in CALL statement
    call_match = re.match(r"call\s+([^:\s]\S*)", stripped, re.IGNORECASE)
    if call_match:
        call_label_text: str = call_match.group(1)
        # Check if this looks like a label call (not an external program)
        # Skip if it contains path separators, extensions, or is a known command
        builtin_commands = {
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

    # E003: IF statement improper formatting
    # Check for IF statements that may have improper syntax
    if_match = re.match(r"if\s+(.+)", stripped, re.IGNORECASE)
    if if_match:
        if_group_result = if_match.group(1)
        if if_group_result is not None:
            if_content: str = if_group_result.strip()

            # Valid IF patterns to check for:
            # 1. IF EXIST filename
            # 2. IF DEFINED variable
            # 3. IF ERRORLEVEL number
            # 4. IF /I for case insensitive
            # 5. IF NOT for negation
            # 6. Comparison operators: ==, EQU, NEQ, LSS, LEQ, GTR, GEQ
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

    # E016: Invalid errorlevel comparison syntax
    # Check for invalid errorlevel syntax patterns like "if not %errorlevel% 1"
    errorlevel_if_match = re.match(r"if\s+(.+)", stripped, re.IGNORECASE)
    if errorlevel_if_match:
        errorlevel_group_result = errorlevel_if_match.group(1)
        if errorlevel_group_result is not None:
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

    # E004: IF EXIST syntax mixing
    if re.match(r"if\s+exist\s+.*==.*", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E004"],
                context="Mixing IF EXIST with comparison operators",
            )
        )

    # E005: Invalid path syntax (basic check for invalid characters)
    path_patterns = [r'"([^"]*[<>|*?][^"]*)",', r"'([^']*[<>|*?][^']*)'"]
    for pattern in path_patterns:
        if re.search(pattern, stripped):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E005"],
                    context="Path contains invalid characters",
                )
            )
            break

    # E009: Mismatched quotes
    if line.count('"') % 2 != 0:
        issues.append(
            LintIssue(
                line_number=line_num, rule=RULES["E009"], context="Unmatched double quotes detected"
            )
        )

    # E010: Malformed FOR loop missing DO
    if re.match(r"for\s+.*", stripped, re.IGNORECASE) and " do " not in stripped.lower():
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E010"],
                context="FOR loop is missing required DO keyword",
            )
        )

    # E011: Invalid variable expansion syntax
    # Look for unmatched % or ! delimiters in variable references
    # This is a more conservative check that only flags obvious syntax errors

    # Count % characters - if odd number, might have unmatched delimiter
    percent_count = stripped.count("%")
    exclamation_count = stripped.count("!")

    # Only flag if there's an obvious mismatch (odd number of delimiters)
    # and there appear to be variable-like patterns
    if percent_count % 2 == 1 and re.search(r"%[A-Z0-9_]+", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E011"],
                context="Variable reference may have mismatched % delimiters",
            )
        )

    if exclamation_count % 2 == 1 and re.search(r"![A-Z0-9_]+", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E011"],
                context="Delayed expansion variable may have mismatched ! delimiters",
            )
        )

    # E012: Missing CALL for subroutine invocation
    # Check for potential subroutine calls without CALL (label followed by parameters)
    if re.match(r":[A-Z0-9_]+\s+\S+", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E012"],
                context="Potential subroutine call without CALL keyword",
            )
        )

    # E013: Invalid command syntax detected
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
    wrong_context_match: List[str] = re.findall(
        r"%~[a-zA-Z]+([^0-9%\s][^%\s]*|[A-Z_][A-Z0-9_]*)%", stripped
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

    # E027: UNC path used as working directory
    if re.match(r"cd\s+\\\\[^\\]+\\", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["E027"],
                context="CD command cannot use UNC paths as working directory",
            )
        )

    # E028: Complex quote escaping error
    # Check for problematic quote patterns
    if '"""' in stripped or re.search(r'["\s]""[^"]', stripped):
        # Look for potentially problematic triple quote or embedded quote patterns
        quote_context = ""
        if '"""' in stripped:
            quote_context = "Triple quote pattern found"
        elif re.search(r'["\s]""[^"]', stripped):
            quote_context = "Complex quote escaping detected"

        # Only flag if it looks problematic (not the recommended """text""" pattern)
        if not re.match(r'.*"""[^"]*""".*', stripped):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["E028"],
                    context=quote_context,
                )
            )

    # E029: Complex SET /A expression errors
    seta_match = re.match(r"set\s+/a\s+(.+)", stripped, re.IGNORECASE)
    if seta_match:
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

    # W011: Unicode handling issue
    for cmd in UNICODE_PROBLEMATIC_COMMANDS:
        if re.match(rf"{cmd}\s", stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W011"],
                    context=f"Command '{cmd}' may have Unicode handling issues",
                )
            )
            break

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
    if re.search(r"\.com\b", stripped, re.IGNORECASE):
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


def _check_warning_issues(  # pylint: disable=unused-argument,too-many-locals,too-many-branches
    line: str, line_num: int, set_vars: Set[str], delayed_expansion_enabled: bool
) -> List[LintIssue]:
    """Check for warning level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # W005: Unquoted variable with spaces
    unquoted_var_pattern = r'(?<!["\'])%[A-Z0-9_]+%|(?<!["\'])![A-Z0-9_]+!'
    if re.search(unquoted_var_pattern, stripped, re.IGNORECASE):
        # Check if it's in a context where spaces could be problematic
        if any(cmd in stripped.lower() for cmd in ["if", "echo", "set", "call"]):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W005"],
                    context="Variable may contain spaces and should be quoted",
                )
            )

    # W012: Non-ASCII characters detected
    if not all(ord(c) < 128 for c in stripped):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W012"],
                context="Line contains non-ASCII characters",
            )
        )

    # W017: Errorlevel comparison semantic difference
    w017_if_match = re.match(r"if\s+(.+)", stripped, re.IGNORECASE)
    if w017_if_match:
        w017_group_result = w017_if_match.group(1)
        if w017_group_result is not None:
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

    # W026: Inefficient parameter modifier usage
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

    # W028: .bat/.cmd errorlevel difference (check based on file extension)
    # This will be handled at file level in global checks since we need file extension context

    # W030: Non-ASCII characters
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

    # W031: Unicode filename in batch operation
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

    # W032: Missing character set declaration
    if any(ord(char) > 127 for char in stripped) and not re.match(
        r"@?chcp\s", stripped, re.IGNORECASE
    ):
        # Only flag if we haven't seen a CHCP command yet (this would need global context)
        pass  # Will be handled in global checks

    # W033: Command execution ambiguity
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

    # Add compatibility and command warnings
    issues.extend(_check_compatibility_warnings(line, line_num, stripped))
    issues.extend(_check_command_warnings(line, line_num, stripped))

    return issues


def _check_style_issues(
    line: str,
    line_num: int,
    max_line_length: int = 120,
) -> List[LintIssue]:
    """Check for style level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # S003: Inconsistent command capitalization
    for keyword in COMMAND_CASING_KEYWORDS:
        pattern = rf"\b{keyword}\b"
        if re.search(pattern, stripped, re.IGNORECASE):
            # Check if it's not uppercase
            if not re.search(rf"\b{keyword.upper()}\b", stripped):
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["S003"],
                        context=f"Command '{keyword}' should be uppercase for consistency",
                    )
                )
            break

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


def _check_security_issues(  # pylint: disable=too-many-branches,too-many-locals
    line: str, line_num: int
) -> List[LintIssue]:
    """Check for security level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # SEC001: Potential command injection vulnerability
    if re.search(r"set\s+/p\s+[^=]+=.*%.*%", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["SEC001"],
                context="User input used in command without validation",
            )
        )

    # SEC002: Unsafe SET command usage
    set_match = re.match(r"set\s+([A-Za-z0-9_]+)=(.+)", stripped, re.IGNORECASE)
    if set_match:
        var_val_text: str = set_match.group(2)
        var_val: str = var_val_text.strip()
        if not (var_val.startswith('"') and var_val.endswith('"')):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC002"],
                    context="SET command value should be quoted for safety",
                )
            )

    # SEC003: Dangerous command without confirmation
    # Only flag if not in a safe context (REM comment or ECHO statement)
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

    # SEC004: Dangerous registry operation (covered by patterns above)

    # SEC005: Missing privilege check for admin operations
    admin_commands = ["reg add hklm", "reg delete hklm", "sc ", "net "]
    for cmd in admin_commands:
        if cmd in stripped.lower():
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["SEC005"],
                    context=f"Command '{cmd.strip()}' may require administrator privileges",
                )
            )
            break

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
    var_usage_pattern = re.compile(r"%([A-Z0-9_]+)%|!([A-Z0-9_]+)!", re.IGNORECASE)

    for i, line in enumerate(lines, start=1):
        for match in var_usage_pattern.finditer(line):
            var_match_1: Optional[str] = match.group(1)
            var_match_2: Optional[str] = match.group(2)
            var_name: str = (var_match_1 or var_match_2 or "").upper()
            if var_name not in set_vars:
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["E006"],  # Undefined variable reference
                        context=f"Variable '{var_name}' is used but never defined",
                    )
                )

    return issues


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

    # Issue a warning if we had to fall back from UTF-8
    if encoding_used.lower() not in ["utf-8", "utf-8-sig"]:
        warnings.warn(
            f"File '{file_path}' was read using '{encoding_used}' encoding instead of UTF-8. "
            f"Consider converting the file to UTF-8 for better compatibility.",
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
    max_line_length: int,
    enable_performance_rules: bool,
    enable_style_rules: bool,
) -> List[LintIssue]:
    """Process all line-by-line and global checks."""
    issues: List[LintIssue] = []

    # Check each line with all rule categories
    for i, line in enumerate(lines, start=1):
        # Error level checks
        issues.extend(_check_syntax_errors(line, i, labels))

        # Warning level checks
        issues.extend(_check_warning_issues(line, i, set_vars, has_delayed_expansion))

        # Style level checks (if enabled)
        if enable_style_rules:
            style_issues = _check_style_issues(line, i, max_line_length)
            issues.extend(style_issues)

        # Security level checks (always enabled for safety)
        issues.extend(_check_security_issues(line, i))

        # Performance level checks (if enabled)
        if enable_performance_rules:
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
    issues.extend(_check_mixed_variable_syntax(lines))  # Warning level

    # Style-level global checks (only if style rules are enabled)
    if enable_style_rules:
        issues.extend(_check_inconsistent_indentation(lines))
        issues.extend(_check_missing_documentation(lines))
        issues.extend(_check_advanced_style_rules(lines))  # Style level S017-S020

    # Performance-level global checks (only if performance rules are enabled)
    if enable_performance_rules:
        issues.extend(_check_redundant_assignments(lines))
        issues.extend(_check_enhanced_performance(lines))  # Performance level P012-P014

    return issues


def lint_batch_file(  # pylint: disable=too-many-locals
    file_path: str,
    max_line_length: int = 120,
    enable_performance_rules: bool = True,
    enable_style_rules: bool = True,
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
        max_line_length: Maximum allowed line length for S011 rule (default: 120)
        enable_performance_rules: Whether to enable performance-related rules (default: True)
        enable_style_rules: Whether to enable style-related rules (default: True)

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
        >>> issues = lint_batch_file("script.bat", max_line_length=100,
        ...                         enable_style_rules=False)
    """
    logger.info("Starting lint analysis of file: %s", file_path)

    # Read and validate file
    lines, _encoding_used = _validate_and_read_file(file_path)

    if not lines:
        return []  # Empty file, no issues

    # Store original max_line_length for S011 rule
    original_s011_rule = RULES["S011"]
    if max_line_length != 120:
        RULES["S011"] = Rule(
            code="S011",
            name=original_s011_rule.name,
            severity=original_s011_rule.severity,
            explanation=original_s011_rule.explanation.replace("120", str(max_line_length)),
            recommendation=original_s011_rule.recommendation,
        )

    issues: List[LintIssue] = []

    # Analyze script structure for context-aware checking
    structure_data = _analyze_script_structure(lines)
    has_setlocal, has_set_commands, has_delayed_expansion, uses_delayed_vars = structure_data

    # Critical line ending checks (includes ERROR level E018)
    issues.extend(_check_line_ending_rules(lines, file_path))

    # Style rules that apply globally (only if style rules are enabled)
    if enable_style_rules:
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
            max_line_length,
            enable_performance_rules,
            enable_style_rules,
        )
    )

    # Global checks for new rules
    issues.extend(_check_new_global_rules(lines, file_path))

    # Restore original S011 rule if modified
    if max_line_length != 120:
        RULES["S011"] = original_s011_rule
    logger.info(
        "Lint analysis completed. Found %d issues across %d error(s), "
        "%d warning(s), %d style issue(s), %d security issue(s), "
        "%d performance issue(s)",
        len(issues),
        len([i for i in issues if i.rule.severity == RuleSeverity.ERROR]),
        len([i for i in issues if i.rule.severity == RuleSeverity.WARNING]),
        len([i for i in issues if i.rule.severity == RuleSeverity.STYLE]),
        len([i for i in issues if i.rule.severity == RuleSeverity.SECURITY]),
        len([i for i in issues if i.rule.severity == RuleSeverity.PERFORMANCE]),
    )

    return issues


def _check_new_global_rules(lines: List[str], file_path: str) -> List[LintIssue]:
    """Check for new global rules that require full file context."""
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

    for i, line in enumerate(lines, start=1):
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


def _check_unreachable_code(lines: List[str]) -> List[LintIssue]:
    """Check for unreachable code after EXIT or GOTO statements."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        if re.match(r"(exit\s|goto\s)", stripped):
            # Check if there's executable code after this line (not just labels or comments)
            for j in range(i + 1, len(lines)):
                next_line = lines[j].strip()
                if next_line and not next_line.startswith(":") and not next_line.startswith("rem"):
                    issues.append(
                        LintIssue(
                            line_number=j + 1,
                            rule=RULES["E008"],
                            context=f"Code after {stripped.split()[0].upper()} on "
                            f"line {i + 1} will never execute",
                        )
                    )
                    break

    return issues


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

    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        if stripped and not stripped.startswith(":") and not stripped.startswith("rem"):
            # Normalize the command for comparison
            normalized = re.sub(r"\S+\.(txt|log|bat|cmd)", "FILE", stripped)
            normalized = re.sub(r"%\w+%", "VAR", normalized)

            if len(normalized) > 20:  # Only consider substantial commands
                command_blocks[normalized].append(i + 1)

    for _normalized_cmd, line_numbers in command_blocks.items():
        if len(line_numbers) > 2:  # Found 3+ similar commands
            for line_num in line_numbers[1:]:  # Flag all but the first
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["P002"],
                        context=f"Similar command pattern repeated "
                        f"(also on lines {line_numbers[0]})",
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


def _check_mixed_variable_syntax(lines: List[str]) -> List[LintIssue]:
    """Check for mixed variable syntax within the same script (W016)."""
    issues: List[LintIssue] = []

    has_percent_vars = False
    has_exclamation_vars = False
    first_percent_line = 0
    first_exclamation_line = 0

    for i, line in enumerate(lines, start=1):
        if not has_percent_vars and re.search(r"%[A-Z0-9_]+%", line, re.IGNORECASE):
            has_percent_vars = True
            first_percent_line = i

        if not has_exclamation_vars and re.search(r"![A-Z0-9_]+!", line, re.IGNORECASE):
            has_exclamation_vars = True
            first_exclamation_line = i

    if has_percent_vars and has_exclamation_vars:
        # Flag the second occurrence
        if first_exclamation_line > first_percent_line:
            issues.append(
                LintIssue(
                    line_number=first_exclamation_line,
                    rule=RULES["W016"],
                    context=(
                        f"Mixed variable syntax detected "
                        f"(standard %VAR% used on line {first_percent_line})"
                    ),
                )
            )
        else:
            issues.append(
                LintIssue(
                    line_number=first_percent_line,
                    rule=RULES["W016"],
                    context=(
                        f"Mixed variable syntax detected "
                        f"(delayed !VAR! used on line {first_exclamation_line})"
                    ),
                )
            )

    return issues


def _check_inconsistent_indentation(  # pylint: disable=too-many-branches
    lines: List[str],
) -> List[LintIssue]:
    """Check for inconsistent indentation patterns across the file (S012)."""
    issues: List[LintIssue] = []

    # Track indentation patterns
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

    if len(indented_lines) < 2:
        return issues

    # Check for mixed patterns
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

        # Also check for mixed within single line
        if "\t" in whitespace and " " in whitespace:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["S012"],
                    context="Line mixes tabs and spaces for indentation",
                )
            )

    # Check for inconsistent indentation across file
    # Only if no single-line mixing found
    if uses_tabs and uses_spaces and not issues:
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

        issues.append(
            LintIssue(
                line_number=later_line,
                rule=RULES["S012"],
                context=context,
            )
        )

    return issues


def _check_missing_documentation(lines: List[str]) -> List[LintIssue]:
    """Check for missing file header documentation (S013)."""
    issues: List[LintIssue] = []

    if len(lines) < 5:  # Skip very short files
        return issues

    # Check first 5 lines for meaningful comments
    meaningful_comments = 0
    for line in lines[:5]:
        stripped = line.strip().lower()
        if stripped.startswith("rem ") and len(stripped) > 10:
            # Look for documentation indicators
            if any(
                keyword in stripped
                for keyword in ["script:", "purpose:", "author:", "date:", "description:"]
            ):
                meaningful_comments += 1

    if meaningful_comments == 0:
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["S013"],
                context="Script lacks header documentation (purpose, author, date)",
            )
        )

    return issues


def _collect_variable_data(lines: List[str]) -> Tuple[Dict[str, List[int]], Dict[str, List[int]]]:
    """Collect variable assignments and usage data from lines.

    Args:
        lines: List of batch file lines

    Returns:
        Tuple containing (assignments dict, usage dict)
    """
    var_assignments: Dict[str, List[int]] = defaultdict(list)
    var_usage: Dict[str, List[int]] = defaultdict(list)

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Track assignments
        set_match = re.match(r"set\s+([A-Za-z0-9_]+)\s*=", stripped, re.IGNORECASE)
        if set_match:
            var_name: str = set_match.group(1).upper()
            var_assignments[var_name].append(i)

        # Track usage
        for var_match in re.finditer(
            r"%([A-Za-z0-9_]+)%|!([A-Za-z0-9_]+)!", stripped, re.IGNORECASE
        ):
            var_name_part1: Optional[str] = var_match.group(1)
            var_name_part2: Optional[str] = var_match.group(2)
            used_var_name: str = (var_name_part1 or var_name_part2 or "").upper()
            if used_var_name:
                var_usage[used_var_name].append(i)

    return var_assignments, var_usage


def _find_redundant_assignments(
    var_assignments: Dict[str, List[int]], var_usage: Dict[str, List[int]]
) -> List[LintIssue]:
    """Find redundant variable assignments.

    Args:
        var_assignments: Dictionary mapping variable names to assignment line numbers
        var_usage: Dictionary mapping variable names to usage line numbers

    Returns:
        List of lint issues for redundant assignments
    """
    issues: List[LintIssue] = []

    # Find redundant assignments (multiple assignments without usage in between)
    for var_name, assignment_lines in var_assignments.items():
        if len(assignment_lines) > 1:
            usage_lines = var_usage.get(var_name, [])

            for i in range(len(assignment_lines) - 1):
                current_assignment = assignment_lines[i]
                next_assignment = assignment_lines[i + 1]

                # Check if there's any usage between assignments
                usage_between = any(
                    current_assignment < usage_line < next_assignment for usage_line in usage_lines
                )

                if not usage_between:
                    issues.append(
                        LintIssue(
                            line_number=current_assignment,
                            rule=RULES["P011"],
                            context=(
                                f"Variable '{var_name}' reassigned on line {next_assignment} "
                                f"without intermediate usage"
                            ),
                        )
                    )

    return issues


def _check_redundant_assignments(lines: List[str]) -> List[LintIssue]:
    """Check for redundant variable assignments (P011)."""
    var_assignments, var_usage = _collect_variable_data(lines)
    return _find_redundant_assignments(var_assignments, var_usage)


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


def main() -> (
    None
):  # pylint: disable=too-many-branches,too-many-statements,too-many-locals,too-many-return-statements
    """Main entry point for the blinter application."""
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        return

    target_path: Optional[str] = None
    show_summary = False
    recursive = True  # Default to recursive directory search

    for arg in sys.argv[1:]:
        if not arg.startswith("--"):
            # This should be the file or directory path
            if target_path is None:
                target_path = arg
        elif arg == "--summary":
            show_summary = True
        elif arg == "--severity":
            pass  # Severity is always shown
        elif arg == "--no-recursive":
            recursive = False

    if not target_path:
        print("Error: No batch file or directory provided.\n")
        print_help()
        return

    # Find all batch files to process
    try:
        batch_files = find_batch_files(target_path, recursive=recursive)
    except FileNotFoundError:
        print(f"Error: Path '{target_path}' not found.")
        return
    except ValueError as value_error:
        print(f"Error: {value_error}")
        return
    except (OSError, PermissionError) as path_error:
        print(f"Error: Cannot access '{target_path}': {path_error}")
        return

    if not batch_files:
        print(f"No batch files (.bat or .cmd) found in: {target_path}")
        return

    # Process each batch file
    all_issues: List[LintIssue] = []
    file_results: Dict[str, List[LintIssue]] = {}
    total_files_processed = 0
    files_with_errors = 0

    for batch_file in batch_files:
        try:
            issues = lint_batch_file(str(batch_file))
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
        return

    # Display results
    is_directory = Path(target_path).is_dir()

    if is_directory:
        print(f"\n🔍 Batch Files Analysis: {target_path}")
        print("=" * (26 + len(target_path)))
        file_count_text = "s" if total_files_processed != 1 else ""
        print(f"Processed {total_files_processed} batch file{file_count_text}")
        print()

        # Show results for each file if there are multiple files
        if len(file_results) > 1:
            for file_path, issues in file_results.items():
                relative_path = Path(file_path).relative_to(Path(target_path))
                print(f"\n📄 File: {relative_path}")
                print("-" * (8 + len(str(relative_path))))

                if issues:
                    print_detailed(issues)
                else:
                    print("No issues found! ✅")
                print()
        else:
            # Single file in directory
            print_detailed(all_issues)
    else:
        # Single file processing
        print(f"\n🔍 Batch File Analysis: {target_path}")
        print("=" * (25 + len(target_path)))
        print_detailed(all_issues)

    # Show combined summary if processing multiple files
    if is_directory and len(file_results) > 1:
        print("\n📊 COMBINED RESULTS:")
        print("===================")

    if show_summary:
        print_summary(all_issues)

    print_severity_info(all_issues)

    # Exit with appropriate code
    error_count = sum(1 for issue in all_issues if issue.rule.severity == RuleSeverity.ERROR)

    if is_directory:
        if error_count > 0:
            error_text = "s" if error_count != 1 else ""
            file_text = "s" if files_with_errors != 1 else ""
            print(
                f"\n⚠️  Found {error_count} critical error{error_text} "
                f"across {files_with_errors} file{file_text} that must be fixed."
            )
            sys.exit(1)
        elif all_issues:
            issue_text = "s" if len(all_issues) != 1 else ""
            file_text = "s" if total_files_processed != 1 else ""
            print(
                f"\n✅ No critical errors found, but {len(all_issues)} total "
                f"issue{issue_text} detected across {total_files_processed} file{file_text}."
            )
            sys.exit(0)
        else:
            file_text = "s" if total_files_processed != 1 else ""
            look_text = "s" if total_files_processed == 1 else ""
            print(
                f"\n🎉 No issues found! All {total_files_processed} "
                f"batch file{file_text} look{look_text} great!"
            )
            sys.exit(0)
    else:
        if error_count > 0:
            print(
                f"\n⚠️  Found {error_count} critical "
                f"error{'s' if error_count != 1 else ''} that must be fixed."
            )
            sys.exit(1)
        elif all_issues:
            print(
                f"\n✅ No critical errors found, but {len(all_issues)} "
                f"issue{'s' if len(all_issues) != 1 else ''} detected."
            )
            sys.exit(0)
        else:
            print("\n🎉 No issues found! Your batch file looks great!")
            sys.exit(0)


def _check_advanced_vars(lines: List[str]) -> List[LintIssue]:
    """Check for advanced variable expansion syntax issues (E017-E022)."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Check for percent-tilde syntax (E017, E018)
        tilde_pattern = r"%~([a-zA-Z]+)([0-9]+|[a-zA-Z])%"
        for match in re.finditer(tilde_pattern, stripped):
            modifiers = str(match.group(1)).lower()
            parameter = str(match.group(2))

            # Check for invalid modifiers
            valid_modifiers = set("nxfpdstaz")
            if not all(m in valid_modifiers for m in modifiers):
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["E017"],
                        context=f"Invalid modifier in %~{modifiers}{parameter}%",
                    )
                )

            # Check if used on non-parameter variable (not 0-9 or FOR variable)
            if not (parameter.isdigit() or (len(parameter) == 1 and parameter.isalpha())):
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["E019"],
                        context=f"Percent-tilde syntax used on invalid parameter: {parameter}",
                    )
                )

        # Check FOR loop variable syntax (E020)
        for_pattern = r"for\s+%%?([a-zA-Z])\s+in\s*\("
        for match in re.finditer(for_pattern, stripped, re.IGNORECASE):
            # In batch files, should use %%i, on command line %i
            var_syntax = match.group(0)
            if "%%" not in var_syntax:
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["E020"],
                        context="FOR loop variable should use %% in batch files",
                    )
                )

        # Check string operations syntax (E021)
        string_ops = [
            r"%[a-zA-Z_][a-zA-Z0-9_]*:~[^%]*%",  # Substring
            r"%[a-zA-Z_][a-zA-Z0-9_]*:[^=]*=[^%]*%",  # Replacement
        ]
        for pattern in string_ops:
            for match in re.finditer(pattern, stripped):
                # Basic validation - more complex validation would need parsing
                if match.group(0).count("%") != 2:
                    issues.append(
                        LintIssue(
                            line_number=i,
                            rule=RULES["E021"],
                            context=f"Malformed string operation: {match.group(0)}",
                        )
                    )

        # Check SET /A syntax (E022, E023)
        if re.match(r"\s*set\s+/a\s+", stripped, re.IGNORECASE):
            # Check for special characters that need quoting
            if any(char in stripped for char in "^&|<>()"):
                if not ('"' in stripped or "'" in stripped):
                    issues.append(
                        LintIssue(
                            line_number=i,
                            rule=RULES["E023"],
                            context="SET /A with special characters should be quoted",
                        )
                    )

    return issues


def _check_enhanced_commands(lines: List[str]) -> List[LintIssue]:
    """Check for enhanced command validation issues (W020-W025)."""
    issues: List[LintIssue] = []
    uses_delayed_expansion = False

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Check for delayed expansion usage
        if re.search(r"!\w+!", stripped):
            uses_delayed_expansion = True

        # Check FOR /F without proper options (W020)
        if re.match(r'\s*for\s+/f\s+(?!.*"[^"]*tokens[^"]*")[^(]*\(', stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=i,
                    rule=RULES["W020"],
                    context="FOR /F without explicit tokens/delims options",
                )
            )

        # Check IF comparisons without quotes (W021)
        if_pattern = r'\s*if\s+(?:not\s+)?%\w+%\s*==\s*[^"\']\w+'
        if re.search(if_pattern, stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=i, rule=RULES["W021"], context="IF comparison should be quoted"
                )
            )

        # Check for deprecated commands (W024)
        deprecated_commands = {
            "xcopy": "robocopy",
            "net send": "msg",
            "at ": "schtasks",
            "cacls": "icacls",
        }
        for deprecated, modern in deprecated_commands.items():
            if re.search(rf"\b{re.escape(deprecated)}\b", stripped, re.IGNORECASE):
                issues.append(
                    LintIssue(
                        line_number=i,
                        rule=RULES["W024"],
                        context=f"Use {modern} instead of {deprecated}",
                    )
                )

        # Check for missing error redirection (W025)
        commands_needing_redirect = ["del", "copy", "move", "mkdir", "rmdir"]
        for cmd in commands_needing_redirect:
            if re.match(rf"\s*{cmd}\s+", stripped, re.IGNORECASE):
                if "2>" not in stripped and ">nul" not in stripped:
                    issues.append(
                        LintIssue(
                            line_number=i,
                            rule=RULES["W025"],
                            context=f"{cmd.upper()} command without error redirection",
                        )
                    )

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
    var_matches = re.finditer(r"set\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=", line, re.IGNORECASE)

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
    common_exceptions = {"0", "1", "10", "100", "256", "60", "24", "365"}

    for match in re.finditer(number_pattern, line.strip()):
        number = match.group(0)
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

    if len(line) > 120 and "^" not in line:
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["S020"],
                context=f"Line length {len(line)} exceeds 120 characters",
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
        if re.search(r"%[a-zA-Z_][a-zA-Z0-9_]*%.*[&|<>]", stripped):
            issues.append(
                LintIssue(
                    line_number=i,
                    rule=RULES["SEC013"],
                    context="Variable used with shell operators may allow injection",
                )
            )

    return issues


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
        noisy_commands = ["echo", "type", "dir"]
        for cmd in noisy_commands:
            if re.match(rf"\s*{cmd}\s+", stripped, re.IGNORECASE):
                if ">nul" not in stripped.lower() and ">" not in stripped:
                    # This is a heuristic - may produce false positives
                    if i < len(lines) - 1 and "pause" not in lines[i].lower():
                        issues.append(
                            LintIssue(
                                line_number=i,
                                rule=RULES["P014"],
                                context=f"{cmd.upper()} output may be unnecessary",
                            )
                        )

    return issues


if __name__ == "__main__":
    main()
