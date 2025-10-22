# Blinter 🚀

**Blinter** is a linter for Windows batch files (`.bat` and `.cmd`). It provides comprehensive static analysis to identify syntax errors, security vulnerabilities, performance issues and style problems. Blinter helps you write safer, more reliable and maintainable batch scripts. Even in 2025, batch files deserve professional tooling! 💻

- ✅ **Configurable Options** - Configurable rules, logging, robust error handling
- ✅ **Unicode Support** - Support for international characters and filenames
- ✅ **Performance Optimized** - Handles large files (10MB+) efficiently

## Features ✨

### 🔍 **Rule Categories**
- **159 Built-in Rules** across 5 severity levels
- **Error Level (E001-E999)**: Critical syntax errors that prevent execution
- **Warning Level (W001-W999)**: Potential runtime issues and bad practices
- **Style Level (S001-S999)**: Code formatting and readability improvements
- **Security Level (SEC001+)**: Security vulnerabilities and dangerous operations
- **Performance Level (P001-P999)**: Optimization opportunities and efficiency improvements

📖 **For complete rule descriptions with examples and implementation details, see [Batch-File-Linter-Requirements.md](https://github.com/tboy1337/Blinter/blob/main/docs/Batch-File-Linter-Requirements.md)**

### 📋 **Output Format**
- **Rule Codes**: Each issue has a unique identifier (e.g., E002, W005, SEC003)
- **Clear Explanations**: Detailed descriptions of why each issue matters
- **Actionable Recommendations**: Specific guidance on how to fix problems
- **Line-by-Line Analysis**: Precise location of every issue
- **Context Information**: Additional details about detected problems

### 🚀 **Advanced Analysis**
- **Static Code Analysis**: Detects unreachable code and logic errors
- **Advanced Variable Expansion**: Validates percent-tilde syntax (%~n1), string operations, and SET /A arithmetic
- **Command-Specific Validation**: FOR loop variations, IF statement best practices, deprecated command detection
- **Variable Tracking**: Identifies undefined variables and unsafe usage patterns
- **Security Scanning**: Path traversal attacks, command injection risks, unsafe temp file creation
- **Performance Optimization**: DIR flag optimization, unnecessary output detection, string operation efficiency
- **Cross-Platform Compatibility**: Warns about Windows version issues and deprecated commands
- **Large File Handling**: Efficiently processes files up to 10MB+ with performance warnings
- **Robust Encoding Detection**: Handles UTF-8, UTF-16, Latin-1 and 6 more encoding formats
- **Advanced Escaping Techniques**: Validates caret escape sequences, multilevel escaping, and continuation characters
- **Professional FOR Command Analysis**: Checks for usebackq, proper tokenizing, delimiters, and skip options
- **Process Management Best Practices**: Timeout command usage, process verification, and restart patterns
- **Enhanced Security Patterns**: User input validation, temporary file security, and self-modification detection

## Installation 🛠️

### 🚀 Quick Start (Recommended)

**Option 1: Install via pip (Recommended)**
```cmd
pip install Blinter
```

**Option 2: Download standalone executable**
- Download the latest `Blinter-v1.0.x-windows.zip` from [GitHub Releases](https://github.com/tboy1337/Blinter/releases)
- ⚠️ **Note**: Some antivirus software may flag the executable as a false positive due to PyInstaller's runtime unpacking behavior. The executable is completely safe (all source code is open for inspection). **We recommend using pip installation to avoid this issue.**

### 🔧 Manual Installation

1. Clone the repository:
```cmd
git clone https://github.com/tboy1337/Blinter.git
cd Blinter
```

2. (Optional) Create a virtual environment:
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

3. (Optional but recommended) Install dependencies:
```cmd
pip install -r requirements.txt
```

### Prerequisites
- **Python 3.10+** (required for pip installation and development)
- **Windows OS** (required for standalone executable)

## Usage 📟

### Basic Usage

**If installed via pip:**
```cmd
# Analyze a single batch file
python -m blinter script.bat

# Analyze all batch files in a directory (recursive)
python -m blinter /path/to/batch/files

# Analyze batch files in directory only (non-recursive)
python -m blinter /path/to/batch/files --no-recursive

# Analyze with summary
python -m blinter script.bat --summary

# Analyze script and scripts it calls with shared variable context
python -m blinter script.bat --follow-calls

# Analyze with custom maximum line length
python -m blinter script.bat --max-line-length 120

# Create configuration file
python -m blinter --create-config

# Ignore configuration file
python -m blinter script.bat --no-config

# Get help
python -m blinter --help

# Get version
python -m blinter --version
```

**If using standalone executable:**
```cmd
# Analyze a single batch file
Blinter-v1.0.x-windows.exe script.bat

# Analyze all batch files in a directory (recursive)
Blinter-v1.0.x-windows.exe /path/to/batch/files

# Analyze batch files in directory only (non-recursive)
Blinter-v1.0.x-windows.exe /path/to/batch/files --no-recursive

# Analyze with summary
Blinter-v1.0.x-windows.exe script.bat --summary

# Analyze script and scripts it calls with shared variable context
Blinter-v1.0.x-windows.exe script.bat --follow-calls

# Analyze with custom maximum line length
Blinter-v1.0.x-windows.exe script.bat --max-line-length 120

# Get help
Blinter-v1.0.x-windows.exe --help

# Get version
Blinter-v1.0.x-windows.exe --version
```

**If using manual installation:**
```cmd
# Analyze a single batch file
python blinter.py script.bat

# Analyze all batch files in a directory (recursive)
python blinter.py /path/to/batch/files

# Analyze batch files in directory only (non-recursive)
python blinter.py /path/to/batch/files --no-recursive

# Analyze with summary
python blinter.py script.bat --summary

# Analyze script and scripts it calls with shared variable context
python blinter.py script.bat --follow-calls

# Analyze with custom maximum line length
python blinter.py script.bat --max-line-length 120

# Create configuration file
python blinter.py --create-config

# Ignore configuration file
python blinter.py script.bat --no-config

# Get help
python blinter.py --help

# Get version
python blinter.py --version
```

### Command Line Options

- `<path>`: Path to a batch file (`.bat` or `.cmd`) OR directory containing batch files
- `--summary`: Display summary statistics of issues found
- `--severity`: Show detailed severity level breakdown (always included)
- `--max-line-length <n>`: Set maximum line length for S011 rule (default: 100)
- `--no-recursive`: When processing directories, only analyze files in the specified directory (not subdirectories)
- `--follow-calls`: Automatically analyze scripts called by CALL statements and merge their variable context. When enabled, variables defined in called scripts are recognized as "defined" in the calling script (position-aware: only after the CALL statement). This eliminates false positive undefined variable errors for configuration scripts
- `--no-config`: Don't use configuration file (blinter.ini) even if it exists
- `--create-config`: Create a default blinter.ini configuration file and exit
- `--help`: Show help menu and rule categories
- `--version`: Display version information

**Note:** Command line options override configuration file settings. Blinter automatically looks for `blinter.ini` in the current directory.

### Configuration File Options 📝

| Section | Setting | Description | Default |
|---------|---------|-------------|---------|
| `[general]` | `recursive` | Search subdirectories when analyzing folders | `true` |
| `[general]` | `show_summary` | Display summary statistics after analysis | `false` |
| `[general]` | `max_line_length` | Maximum line length for S011 rule | `100` |
| `[general]` | `follow_calls` | Analyze scripts called by CALL statements with shared variable context | `false` |
| `[general]` | `min_severity` | Minimum severity level to report | None (all) |
| `[rules]` | `enabled_rules` | Comma-separated list of rules to enable exclusively | None (all enabled) |
| `[rules]` | `disabled_rules` | Comma-separated list of rules to disable | None |

### Command Line Override

Command line options always override configuration file settings:

```cmd
# Use config file settings
python -m blinter myscript.bat

# Override config to show summary
python -m blinter myscript.bat --summary

# Analyze script and scripts it calls with shared variable context
python -m blinter myscript.bat --follow-calls

# Override config with custom line length
python -m blinter myscript.bat --max-line-length 100

# Ignore config file completely
python -m blinter myscript.bat --no-config
```

### 🔕 Inline Suppression Comments

You can suppress specific linter warnings directly in your batch files using special comments:

#### Suppress Next Line
```batch
REM LINT:IGNORE E009
ECHO '' .... Represents a " character
```

#### Suppress Current Line
```batch
REM LINT:IGNORE-LINE S013
```

#### Suppress Multiple Rules
```batch
REM LINT:IGNORE E009, W011, S004
ECHO Unmatched quotes "
```

#### Suppress All Rules on Line
```batch
REM LINT:IGNORE
REM This line and the next will be ignored for all rules
```

**Supported formats:**
- `REM LINT:IGNORE <code>` - Suppress specific rule(s) on the **next line**
- `REM LINT:IGNORE` - Suppress all rules on the **next line**
- `REM LINT:IGNORE-LINE <code>` - Suppress specific rule(s) on the **same line**
- `REM LINT:IGNORE-LINE` - Suppress all rules on the **same line**
- `:: LINT:IGNORE <code>` - Alternative comment syntax (also supported)

**Use cases:**
- Suppress false positives that can't be fixed
- Ignore intentional deviations from best practices
- Handle edge cases in documentation or help text
- Temporarily ignore issues during development

### 🐍 **Programmatic API Usage**

Blinter provides a powerful Python API for integration into your applications:

```python
import blinter

# Basic usage
issues = blinter.lint_batch_file("script.bat")
for issue in issues:
    print(f"Line {issue.line_number}: {issue.rule.name} ({issue.rule.code})")

# With custom configuration
from blinter import BlinterConfig, RuleSeverity
config = BlinterConfig(
    max_line_length=80,
    disabled_rules={"S007", "S011"},
    min_severity=RuleSeverity.WARNING
)
issues = blinter.lint_batch_file("script.bat", config=config)

# Process results
for issue in issues:
    print(f"Line {issue.line_number}: {issue.rule.name}")
    print(f"  {issue.rule.explanation}")
    print(f"  Fix: {issue.rule.recommendation}")


# Thread-safe design allows safe concurrent usage
# You can implement your own concurrent processing if needed
from concurrent.futures import ThreadPoolExecutor

files = ["script1.bat", "script2.cmd", "script3.bat"]
with ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(blinter.lint_batch_file, files))
```

### 🔧 **Configuration Options**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | `str` | Required | Path to batch file to analyze |
| `max_line_length` | `int` | `100` | Maximum line length for S011 rule |
| `enable_style_rules` | `bool` | `True` | Enable/disable style-related rules |
| `enable_performance_rules` | `bool` | `True` | Enable/disable performance rules |

*Note: Security rules are always enabled for safety.*

### Supported File Types
- `.bat` files (traditional batch files)
- `.cmd` files (recommended for modern Windows)
- **Unicode filenames** and international characters supported
- **Large files** (10MB+) handled efficiently with performance monitoring

### 📁 **Directory Processing**

Blinter can analyze entire directories of batch files with powerful options:

- **Recursive Analysis**: Automatically finds and processes all `.bat` and `.cmd` files in directories and subdirectories
- **Non-Recursive Mode**: Use `--no-recursive` to analyze only files in the specified directory
- **Batch Processing**: Handles multiple files efficiently with consolidated reporting
- **Error Resilience**: Continues processing other files even if some files have encoding or permission issues
- **Progress Tracking**: Shows detailed results for each file plus combined summary statistics

**Examples:**
```cmd
# Pip installation:
python -m blinter ./my-batch-scripts                 # Analyze all files recursively
python -m blinter . --no-recursive                   # Current directory only
python -m blinter ./scripts --summary               # With summary statistics

# Standalone executable:
Blinter-v1.0.x-windows.exe ./my-batch-scripts            # Analyze all files recursively
Blinter-v1.0.x-windows.exe . --no-recursive             # Current directory only
Blinter-v1.0.x-windows.exe ./scripts --summary          # With summary statistics

# Manual installation:
python blinter.py ./my-batch-scripts      # Analyze all files recursively
python blinter.py . --no-recursive       # Current directory only  
python blinter.py ./scripts --summary     # With summary statistics
```

## 🔥 **Integration Example**

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
- name: Lint Batch Files
  run: |
    python -c "
    import blinter
    import sys
    issues = blinter.lint_batch_file('deploy.bat')
    errors = [i for i in issues if i.rule.severity.value == 'Error']
    if errors:
        print(f'Found {len(errors)} critical errors!')
        sys.exit(1)
    print(f'✅ Batch file passed with {len(issues)} total issues')
    "
```

## Contributing 🤝

**Contributions are welcome!** 

### Ways to Contribute
- 🐛 Report bugs or issues
- 💡 Suggest new rules or features
- 📖 Improve documentation
- 🧪 Add test cases
- 🔧 Submit bug fixes or enhancements

## License 📄

This project is licensed under the CRL License - see [LICENSE.md](https://github.com/tboy1337/Blinter/blob/main/LICENSE.md) for details.
