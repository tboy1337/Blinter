"""Rule definitions and the RULES lookup table."""

# pylint: disable=too-many-lines
# Rule catalog is intentionally centralized in one module.

from typing import Dict

from blinter.models import Rule, RuleSeverity

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
        explanation="Mixing IF EXIST syntax with comparison operators "
        "creates invalid syntax",
        recommendation="Use either 'IF EXIST filename' or "
        '\'IF "variable"=="value"\' but not both together',
    ),
    "E005": Rule(
        code="E005",
        name="Invalid path syntax",
        severity=RuleSeverity.ERROR,
        explanation="Path contains invalid characters or exceeds "
        "system length limits",
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
        recommendation='Use proper syntax: IF "%%VAR%%"=="" for '
        "empty variable checks",
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
            "Command appears to have typos or invalid syntax that will cause "
            "execution errors"
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
            "Interactive scripts should include PAUSE to prevent window from "
            "closing immediately"
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
            "Ensure file uses CRLF line endings, or duplicate critical labels "
            "as a workaround"
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
            "Use consistent CRLF line endings throughout the file "
            "for Windows batch files"
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
        explanation="Lines longer than 100 characters are hard to read and maintain",
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
            "Use environment variables like %USERPROFILE%, %PROGRAMFILES%, etc. "
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
            "Use percent-tilde only with %1-%9 parameters or FOR loop "
            "variables like %%i"
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
            "Special characters in SET /A expressions need quoting to "
            "prevent parsing errors"
        ),
        recommendation=(
            'Quote expressions with special chars: SET /A "result=5^2" '
            "not SET /A result=5^2"
        ),
    ),
    # Enhanced Command Validation Rules (W020-W035)
    "W020": Rule(
        code="W020",
        name="FOR loop missing /F options for complex parsing",
        severity=RuleSeverity.WARNING,
        explanation=(
            "FOR /F should specify tokens and delims options for reliable parsing"
        ),
        recommendation=(
            'Use explicit options: FOR /F "tokens=1,2 delims=," '
            "instead of default behavior"
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
        explanation=(
            "Command is deprecated in modern Windows versions and may not be available "
            "in future releases or may have reduced functionality"
        ),
        recommendation=(
            "Replace with modern equivalent: "
            "WMIC->PowerShell WMI cmdlets (Get-WmiObject/Get-CimInstance), "
            "CACLS->ICACLS, "
            "WINRM->PowerShell Remoting (Enter-PSSession/Invoke-Command), "
            "BITSADMIN->PowerShell BitsTransfer module, "
            "NBTSTAT->Get-NetAdapter PowerShell cmdlets, "
            "DPATH->modify PATH environment variable, "
            "KEYS->use CHOICE or SET /P, "
            "NET SEND->MSG, "
            "AT->SCHTASKS. "
            "Note: XCOPY itself is NOT deprecated, but ROBOCOPY is recommended "
            "for advanced scenarios with better features"
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
        explanation="Subroutines (callable labels) should have documentation comments explaining their purpose, parameters, and return behavior",
        recommendation=(
            "Add REM comments before subroutines describing what they do, parameters, and return values"
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
        recommendation=(
            "Validate and sanitize variables before use in command execution"
        ),
    ),
    # Performance Enhancement Rules (P012-P020)
    "P012": Rule(
        code="P012",
        name="Inefficient string operations",
        severity=RuleSeverity.PERFORMANCE,
        explanation="Multiple string operations on same variable can be combined",
        recommendation=(
            "Combine operations: %var:~0,5:old=new% instead of multiple assignments"
        ),
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
    "E034": Rule(
        code="E034",
        name="Removed Windows command detected",
        severity=RuleSeverity.ERROR,
        explanation=(
            "Command has been completely removed from Windows and will not execute. "
            "These commands are no longer available in modern Windows versions and "
            "will cause script failures"
        ),
        recommendation=(
            "Replace removed commands with modern alternatives: "
            "CASPOL (removed - use Code Access Security Policy Tool from SDK), "
            "DISKCOMP (removed - use FC for file comparison), "
            "APPEND (removed - modify PATH or use full paths), "
            "BROWSTAT (removed - use NET VIEW or PowerShell), "
            "INUSE (removed - use HANDLE.EXE from Sysinternals), "
            "NET PRINT (removed - use PowerShell Print cmdlets), "
            "DISKCOPY (removed - use ROBOCOPY or XCOPY), "
            "STREAMS (removed - use Get-Item -Stream in PowerShell)"
        ),
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
        explanation=(
            "Complex nested FOR loops should use CALL :subroutine for maintainability"
        ),
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
        recommendation=(
            "Redirect to secure user directories or use appropriate file permissions"
        ),
    ),
    "SEC019": Rule(
        code="SEC019",
        name="Batch self-modification vulnerability",
        severity=RuleSeverity.SECURITY,
        explanation="Scripts that modify themselves can be exploited to execute malicious code",
        recommendation="Avoid self-modifying scripts or validate all modifications carefully",
    ),
    "SEC020": Rule(
        code="SEC020",
        name="UNC path without UAC elevation check",
        severity=RuleSeverity.SECURITY,
        explanation="UNC path operations may fail under UAC without proper elevation checks",
        recommendation="Check for administrator privileges before UNC operations using NET SESSION",
    ),
    "SEC021": Rule(
        code="SEC021",
        name="Fork bomb pattern detected",
        severity=RuleSeverity.SECURITY,
        explanation="Recursive self-execution patterns can crash the system",
        recommendation="Remove fork bomb patterns that recursively start copies of the script",
    ),
    "SEC022": Rule(
        code="SEC022",
        name="Potential hosts file modification",
        severity=RuleSeverity.SECURITY,
        explanation="Modifying the hosts file can redirect DNS for malicious purposes",
        recommendation="Avoid hosts file modification or require explicit administrator confirmation",
    ),
    "SEC023": Rule(
        code="SEC023",
        name="Autorun.inf creation detected",
        severity=RuleSeverity.SECURITY,
        explanation="Creating autorun.inf files is a common malware vector",
        recommendation="Remove autorun.inf creation - this is blocked on modern Windows",
    ),
    "SEC024": Rule(
        code="SEC024",
        name="Batch file copying itself to removable media",
        severity=RuleSeverity.SECURITY,
        explanation="Self-replicating batch files exhibit virus-like behavior",
        recommendation="Remove self-copying logic or limit to specific controlled directories",
    ),
    # Advanced Style Rules (S022-S030)
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
    "P026": Rule(
        code="P026",
        name="Redundant DISABLEDELAYEDEXPANSION",
        severity=RuleSeverity.PERFORMANCE,
        explanation=(
            "Delayed expansion is disabled by default in batch scripts, "
            "so explicit disablement is usually redundant unless ensuring a known "
            "state from parent scripts or protecting literal ! characters"
        ),
        recommendation=(
            "Remove unless: 1) After ENDLOCAL (toggling pattern), "
            "2) Protecting literal ! in strings, or 3) Defensive programming at script start"
        ),
    ),
}
