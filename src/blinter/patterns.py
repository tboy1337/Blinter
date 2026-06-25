"""Regex patterns for dangerous commands and deprecated syntax."""

import re
from typing import List, Set, Tuple

DANGEROUS_COMMAND_NAMES: List[str] = [
    "del",
    "format",
    "shutdown",
    "psshutdown",
    "rmdir",
    "reg",
]

_DANGEROUS_CMDS_REGEX: str = "|".join(DANGEROUS_COMMAND_NAMES)

_COMPILED_IF_PATTERN = re.compile(r"if\s+(.+)", re.IGNORECASE)

_COMPILED_SETLOCAL_DISABLE = re.compile(
    r"setlocal\s+disabledelayedexpansion", re.IGNORECASE
)

_COMPILED_SET_PATTERN = re.compile(r"\bset\s+", re.IGNORECASE)

_COMPILED_GOTO_PATTERN = re.compile(r"goto\s+(:?\S+)", re.IGNORECASE)

_COMPILED_VAR_EXPANSION = re.compile(r"%[^%]+%|!\w+!")

_COMPILED_ECHO_DOTS = re.compile(r"\s*echo\s+.*\.\.\.\.", re.IGNORECASE)

_COMPILED_NON_ASCII = re.compile(r"[\x00-\x1f\x7f-\xff]")

_COMPILED_NET_SESSION = re.compile(r"net\s+session\s*(>|$)", re.IGNORECASE)

_COMPILED_NET_COMMAND = re.compile(r"\bnet\s+", re.IGNORECASE)

_COMPILED_DELAYED_VAR = re.compile(r"![^!]+!")

DANGEROUS_COMMAND_PATTERNS: List[Tuple[str, str]] = [
    (
        r"del\s+(?:[/-]\w+\s+)*[\"']?\*\.\*[\"']?(\s|$)",
        "SEC003",
    ),  # del *.* with optional flags
    (
        r"del\s+(?:[/-]\w+\s+)*[\"']?\*/\*[\"']?(\s|$)",
        "SEC003",
    ),  # del */* pattern with optional flags
    (
        r"del\s+(?:[/-]\w+\s+)*[\"']?[a-z]:\\\*[\"']?(\s|$)",
        "SEC003",
    ),  # del c:\* type commands with optional flags
    (
        r"format\s+(?:[/-]\w+\s+)*[a-z]:",
        "SEC003",
    ),  # format c: type commands with optional flags
    (r"\b(ps)?shutdown\s+[/-]", "SEC003"),  # shutdown/psshutdown commands with flags
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

DEPRECATED_COMMANDS = {
    "wmic",  # Use PowerShell WMI cmdlets instead
    "cacls",  # Use icacls instead
    "winrm",  # Use PowerShell Remoting instead
    "bitsadmin",  # Use PowerShell BitsTransfer module instead
    "nbtstat",  # Use PowerShell Get-NetAdapter cmdlets instead
    "dpath",  # Modify PATH environment variable instead
    "keys",  # Use CHOICE or SET /P instead
    "assign",  # Legacy command
    "backup",  # Legacy command
    "comp",  # Use FC instead
    "edlin",  # Legacy line editor
    "join",  # Legacy command
    "subst",  # Use persistent drive mappings or UNC paths instead
}

REMOVED_COMMANDS = {
    "caspol",  # Removed - use Code Access Security Policy Tool from SDK
    "diskcomp",  # Removed - use FC for file comparison
    "append",  # Removed - modify PATH or use full paths
    "browstat",  # Removed - use NET VIEW or PowerShell
    "inuse",  # Removed - use HANDLE.EXE from Sysinternals
    "diskcopy",  # Removed - use ROBOCOPY or XCOPY
    "streams",  # Removed - use Get-Item -Stream in PowerShell
}

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

SENSITIVE_KEYWORDS: List[str] = [
    "password",
    "pwd",
    "passwd",
    "apikey",
    "api_key",
    "secret",
    "token",
]

CREDENTIAL_PATTERNS = [
    rf"{keyword}\s*=\s*[\"']?[^\s\"']+[\"']?" for keyword in SENSITIVE_KEYWORDS
]

SENSITIVE_ECHO_PATTERNS = [rf"echo.*{keyword}" for keyword in SENSITIVE_KEYWORDS]

BUILTIN_COMMANDS: Set[str] = {
    # Core batch commands
    "echo",
    "set",
    "if",
    "for",
    "goto",
    "call",
    "exit",
    "pause",
    "setlocal",
    "endlocal",
    "shift",
    "pushd",
    "popd",
    # File operations
    "dir",
    "copy",
    "move",
    "del",
    "erase",
    "ren",
    "rename",
    "type",
    "xcopy",
    "robocopy",
    "mkdir",
    "md",
    "rmdir",
    "rd",
    "cd",
    "chdir",
    "attrib",
    # System commands
    "cls",
    "ver",
    "vol",
    "date",
    "time",
    "title",
    "color",
    "prompt",
    "path",
    "help",
    "start",
    "cmd",
    "tasklist",
    "taskkill",
    # Network commands
    "ping",
    "ipconfig",
    "netstat",
    "net",
    "nslookup",
    "tracert",
    # Other common commands
    "find",
    "findstr",
    "sort",
    "more",
    "choice",
    "timeout",
    "sc",
    "reg",
    "wmic",
    "powershell",
    "cscript",
    "wscript",
    "msiexec",
    # Common external programs
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
}

POWERSHELL_PATTERNS: List[str] = [
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

VBSCRIPT_PATTERNS: List[str] = [
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

CSHARP_PATTERNS: List[str] = [
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

BATCH_INDICATORS: List[str] = [
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

SAFE_COMMAND_INJECTION_PATTERNS: List[str] = [
    r'cd\s+/d\s+"%[a-zA-Z_][a-zA-Z0-9_]*%"',
    r"echo\s+.*>\s*nul",
    r'echo\s+.*>>\s*"[^"]*"',
    r'echo\s+.*>\s*"[^"]*"',
    r'%[a-zA-Z_][a-zA-Z0-9_]*%"\s*>[^&|]*$',
    r"^[^&|]*\b(del|copy|move|type|xcopy)\s+[^&|]*%[a-zA-Z_][a-zA-Z0-9_]*%[^&|]*>[^&|]*$",
    r"^[^&|]*\b(rd|md|mkdir|rmdir)\s+[^&|]*%[a-zA-Z_][a-zA-Z0-9_]*%[^&|]*>[^&|]*$",
    r"^[^&|]*%[a-zA-Z_][a-zA-Z0-9_]*%[^&|]*%[a-zA-Z_][a-zA-Z0-9_]*%[^&|]*>[^&|]*$",
    r"%[a-zA-Z_][a-zA-Z0-9_]*%\s*(?:&&|\|\|)\s*\(\s*$",
    r"^if\s+%[^%]+%==\S+\s+setlocal\s*&\s*call\s+:\w+",
    r"^if\s+%[^%]+%==\S+\s+start\s+.*&\s*goto\s*:",
    r"^if\s+defined\s+\S+\s+\(set\s+",
    r"findstr\b.*%nul\d*%.*&&\s*set\b",
    r"^if\s+%[^%]+%==\S+\s+\(set\s+",
    r"^if\s+%[^%]+%==\S+\s+\(start\s+.*&\s*(?:goto|exit)\b",
    r"^if\s+!errorlevel!==\d+\s+\(start\s+.*&\s*exit\b",
    r"^if\s+defined\s+\S+\s+echo\s+\".*\"\s*\|\s*find\b",
    r"^%psc%\s+\"",
    r"^for\s+.*\bdo\s+\(%psc%\s+\"",
    r"reg\s+query\b.*%nul\d+%\s*\|\s*find\b.*%nul\d+%\s*&&\s*\(",
    r"^if\s+%[^%]+%\s+(?:EQU|NEQ|LSS|LEQ|GEQ|GTR)\s+\S+\s+\(set\s+",
    r"^if\s+%[^%]+%\s+(?:LSS|LEQ|GEQ|GTR)\s+\d+\s+if\s+exist\s+",
    r"^if\s+%[^%]+%\s+(?:LSS|LEQ)\s+\d+\s+\(set\s+.*&exit\b",
    r"^if\s+/i\s+\"%[^%]+%\"==\"\S+\"\s+\(set\s+",
    r"^if\s+defined\s+\S+\s+\(call\s+:",
    r"^if\s+defined\s+\S+\s+\(if\s+exist\s+",
    r"^%nul%\s+reg\s+query\b",
    r"^find\b.*/i\b.*%nul\d+%\s*&&\s*set\b",
    r"^if\s+%[^%]+%==\d+\s+timeout\b.*&\s*exit\b",
    r"^if\s+![^!]+!==\d+\s+start\b.*&\s*goto\b",
    r"^if\s+%[^%]+%\s+(?:EQU|NEQ)\s+\d+\s+set\s+\"\w+=for\s+/f",
    r"^(?:if\s+%[^%]+%\s+(?:EQU|NEQ)\s+\d+\s+)?wmic\b.*%nul\d+%\s*\|\s*find\b",
    r"^set\s+\"\w+=[^\"]*&(?:call|echo)\b",
    r"^set\s+@\w+=.*&\s*set\s+@",
]
