#!/usr/bin/env python3
"""One-time mechanical split of blinter.py into src/blinter package modules."""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path
import shutil
import textwrap

ROOT = Path(__file__).resolve().parent.parent
SOURCE_PATH = ROOT / "blinter.py"
DEST_ROOT = ROOT / "src" / "blinter"

STDLIB_IMPORTS = textwrap.dedent(
    """
    from collections import defaultdict
    import configparser
    from dataclasses import dataclass
    from enum import Enum
    import logging
    from pathlib import Path
    import re
    import sys
    from typing import (
        Callable,
        DefaultDict,
        Dict,
        List,
        NoReturn,
        Optional,
        Set,
        Tuple,
        Union,
        cast,
    )
    import warnings
    """
).strip()

MODULE_IMPORTS: dict[str, str] = {
    "models": STDLIB_IMPORTS,
    "logging_config": "import logging",
    "_version": "",
    "constants": "from typing import Set",
    "patterns": "import re\nfrom typing import List, Set, Tuple",
    "rules.registry": (
        "from typing import Dict\n"
        "from blinter.models import Rule, RuleSeverity"
    ),
    "rules.helpers": (
        "from typing import List, Optional\n"
        "from blinter.models import LintIssue, Rule, RuleSeverity\n"
        "from blinter.rules.registry import RULES"
    ),
    "io.encoding": (
        STDLIB_IMPORTS
        + "\nfrom blinter.models import LintIssue\n"
        + "from blinter.rules.registry import RULES"
    ),
    "io.discovery": (
        "from pathlib import Path\n"
        "from typing import List, Union"
    ),
    "config.loader": (
        STDLIB_IMPORTS
        + "\nfrom blinter.models import BlinterConfig, RuleSeverity"
    ),
    "parsing.context": "import re",
    "parsing.structure": (
        STDLIB_IMPORTS
        + "\nfrom blinter.models import LintIssue\n"
        + "from blinter.parsing.context import _is_comment_line\n"
        + "from blinter.rules.helpers import _add_issue\n"
        + "from blinter.rules.registry import RULES"
    ),
    "parsing.embedded": (
        STDLIB_IMPORTS
        + "\nfrom blinter.logging_config import logger\n"
        + "from blinter.patterns import (\n"
        "    BATCH_INDICATORS,\n"
        "    CSHARP_PATTERNS,\n"
        "    POWERSHELL_PATTERNS,\n"
        "    VBSCRIPT_PATTERNS,\n"
        ")"
    ),
    "checkers.syntax": (
        STDLIB_IMPORTS
        + "\nfrom blinter.models import LintIssue\n"
        + "from blinter.parsing.context import _is_comment_line\n"
        + "from blinter.patterns import (\n"
        "    BUILTIN_COMMANDS,\n"
        "    COMMON_COMMAND_TYPOS,\n"
        "    _COMPILED_GOTO_PATTERN,\n"
        "    _COMPILED_IF_PATTERN,\n"
        ")\n"
        + "from blinter.rules.helpers import _add_issue\n"
        + "from blinter.rules.registry import RULES"
    ),
    "checkers.warnings": (
        STDLIB_IMPORTS
        + "\nfrom blinter.models import LintIssue\n"
        + "from blinter.patterns import (\n"
        "    ARCHITECTURE_SPECIFIC_PATTERNS,\n"
        "    DEPRECATED_COMMANDS,\n"
        "    OLDER_WINDOWS_COMMANDS,\n"
        "    REMOVED_COMMANDS,\n"
        "    UNICODE_PROBLEMATIC_COMMANDS,\n"
        "    _COMPILED_NON_ASCII,\n"
        ")\n"
        + "from blinter.rules.helpers import _add_issue\n"
        + "from blinter.rules.registry import RULES"
    ),
    "checkers.style": (
        STDLIB_IMPORTS
        + "\nfrom blinter.constants import MAGIC_NUMBER_EXCEPTIONS\n"
        + "from blinter.models import BlinterConfig, LintIssue\n"
        + "from blinter.rules.helpers import _add_issue, _s011_rule\n"
        + "from blinter.rules.registry import RULES"
    ),
    "checkers.security": (
        STDLIB_IMPORTS
        + "\nfrom blinter.models import LintIssue\n"
        + "from blinter.parsing.context import (\n"
        "    _is_command_in_safe_context,\n"
        "    _is_safe_ctx_for_privilege,\n"
        ")\n"
        + "from blinter.patterns import (\n"
        "    CREDENTIAL_PATTERNS,\n"
        "    DANGEROUS_COMMAND_PATTERNS,\n"
        "    SENSITIVE_ECHO_PATTERNS,\n"
        "    _COMPILED_NET_COMMAND,\n"
        "    _COMPILED_NET_SESSION,\n"
        "    _DANGEROUS_CMDS_REGEX,\n"
        ")\n"
        + "from blinter.rules.helpers import _add_issue\n"
        + "from blinter.rules.registry import RULES"
    ),
    "checkers.performance": (
        STDLIB_IMPORTS
        + "\nfrom blinter.models import LintIssue\n"
        + "from blinter.rules.helpers import _add_issue\n"
        + "from blinter.rules.registry import RULES"
    ),
    "checkers.vars": (
        STDLIB_IMPORTS
        + "\nfrom blinter.constants import BUILTIN_VARS\n"
        + "from blinter.models import LintIssue\n"
        + "from blinter.parsing.structure import _collect_set_variables\n"
        + "from blinter.rules.helpers import _add_issue\n"
        + "from blinter.rules.registry import RULES"
    ),
    "checkers.line_endings": (
        STDLIB_IMPORTS
        + "\nfrom blinter.io.encoding import _has_multibyte_chars\n"
        + "from blinter.models import LintIssue\n"
        + "from blinter.rules.helpers import _add_issue\n"
        + "from blinter.rules.registry import RULES"
    ),
    "checkers.globals": (
        STDLIB_IMPORTS
        + "\nfrom blinter.constants import BUILTIN_VARS\n"
        + "from blinter.models import LintIssue\n"
        + "from blinter.patterns import COMMAND_CASING_KEYWORDS\n"
        + "from blinter.parsing.context import _is_comment_line\n"
        + "from blinter.rules.helpers import _add_issue\n"
        + "from blinter.rules.registry import RULES"
    ),
    "checkers.advanced": (
        STDLIB_IMPORTS
        + "\nfrom blinter.constants import MAGIC_NUMBER_EXCEPTIONS\n"
        + "from blinter.models import LintIssue\n"
        + "from blinter.patterns import DEPRECATED_COMMANDS, REMOVED_COMMANDS\n"
        + "from blinter.rules.registry import RULES"
    ),
    "checkers.orchestration": (
        STDLIB_IMPORTS
        + "\nfrom blinter.checkers.advanced import (\n"
        "    _check_advanced_escaping_rules,\n"
        "    _check_advanced_for_rules,\n"
        "    _check_advanced_performance,\n"
        "    _check_advanced_process_mgmt,\n"
        "    _check_advanced_security,\n"
        "    _check_advanced_style_patterns,\n"
        "    _check_advanced_style_rules,\n"
        "    _check_advanced_vars,\n"
        "    _check_enhanced_commands,\n"
        "    _check_enhanced_performance,\n"
        "    _check_enhanced_security_rules,\n"
        ")\n"
        + "from blinter.checkers.globals import (\n"
        "    _check_cmd_case_consistency,\n"
        "    _check_code_duplication,\n"
        "    _check_inconsistent_indentation,\n"
        "    _check_missing_exit_statement,\n"
        "    _check_missing_header_doc,\n"
        "    _check_missing_pause,\n"
        "    _check_redundant_operations,\n"
        "    _check_unreachable_code,\n"
        ")\n"
        + "from blinter.checkers.line_endings import _check_line_ending_rules\n"
        + "from blinter.checkers.performance import _check_performance_issues\n"
        + "from blinter.checkers.security import _check_security_issues\n"
        + "from blinter.checkers.style import _check_style_issues\n"
        + "from blinter.checkers.syntax import _check_syntax_errors\n"
        + "from blinter.checkers.vars import _check_undefined_variables\n"
        + "from blinter.checkers.warnings import _check_warning_issues\n"
        + "from blinter.models import BlinterConfig, LintIssue\n"
        + "from blinter.parsing.embedded import _detect_embedded_script_blocks\n"
        + "from blinter.parsing.structure import _analyze_script_structure\n"
        + "from blinter.rules.helpers import _add_issue\n"
        + "from blinter.rules.registry import RULES"
    ),
    "engine.linter": (
        STDLIB_IMPORTS
        + "\nfrom blinter.checkers.globals import (\n"
        "    _check_global_style_rules,\n"
        "    _check_new_global_rules,\n"
        ")\n"
        + "from blinter.checkers.line_endings import _check_line_ending_rules\n"
        + "from blinter.checkers.orchestration import (\n"
        "    _filter_issues_by_config,\n"
        "    _process_file_checks,\n"
        ")\n"
        + "from blinter.engine.dependencies import _collect_called_vars\n"
        + "from blinter.io.encoding import _validate_and_read_file\n"
        + "from blinter.logging_config import logger\n"
        + "from blinter.models import BlinterConfig, LintIssue, RuleSeverity\n"
        + "from blinter.parsing.embedded import _detect_embedded_script_blocks\n"
        + "from blinter.parsing.structure import (\n"
        "    _analyze_script_structure,\n"
        "    _collect_labels,\n"
        "    _collect_set_variables,\n"
        "    _parse_suppression_comments,\n"
        ")\n"
        + "from blinter.rules.helpers import _add_issue\n"
        + "from blinter.rules.registry import RULES"
    ),
    "engine.dependencies": (
        STDLIB_IMPORTS
        + "\nfrom blinter.io.encoding import read_file_with_encoding\n"
        + "from blinter.logging_config import logger\n"
        + "from blinter.parsing.structure import _collect_set_variables\n"
        + "from blinter.patterns import BUILTIN_COMMANDS\n"
    ),
    "output.formatters": (
        STDLIB_IMPORTS
        + "\nfrom blinter._version import __version__\n"
        + "from blinter.models import LintIssue, RuleSeverity\n"
        + "from blinter.rules.registry import RULES"
    ),
    "cli.args": (
        STDLIB_IMPORTS
        + "\nfrom blinter._version import __version__\n"
        + "from blinter.config.loader import create_default_config_file, load_config\n"
        + "from blinter.models import CliArguments\n"
        + "from blinter.output.formatters import print_help, print_version"
    ),
    "cli.main": (
        STDLIB_IMPORTS
        + "\nfrom blinter._version import __version__\n"
        + "from blinter.cli.args import CliArguments, _parse_cli_arguments\n"
        + "from blinter.config.loader import load_config\n"
        + "from blinter.engine.dependencies import (\n"
        "    _build_call_dependency_graph,\n"
        "    _extract_called_scripts,\n"
        ")\n"
        + "from blinter.engine.linter import lint_batch_file\n"
        + "from blinter.io.discovery import find_batch_files\n"
        + "from blinter.models import BlinterConfig, LintIssue, ProcessingResults, ProcessingState\n"
        + "from blinter.output.formatters import (\n"
        "    group_issues,\n"
        "    print_detailed,\n"
        "    print_severity_info,\n"
        "    print_summary,\n"
        ")\n"
        + "from blinter.models import RuleSeverity\n"
        + "from blinter.rules.registry import RULES"
    ),
}

SYMBOL_TO_MODULE: dict[str, str] = {
    "__version__": "_version",
    "__author__": "_version",
    "__license__": "_version",
    "logger": "logging_config",
    "RuleSeverity": "models",
    "Rule": "models",
    "LintIssue": "models",
    "BlinterConfig": "models",
    "CliArguments": "models",
    "ProcessingResults": "models",
    "ProcessingState": "models",
    "ScriptBlockState": "parsing.embedded",
    "ScriptProcessingContext": "parsing.embedded",
    "_s011_rule": "rules.helpers",
    "_cli_error": "cli.main",
    "_add_issue": "rules.helpers",
    "_create_rule": "rules.helpers",
    "BUILTIN_VARS": "constants",
    "MAGIC_NUMBER_EXCEPTIONS": "constants",
    "RULES": "rules.registry",
    "_detect_line_endings": "io.encoding",
    "_has_multibyte_chars": "io.encoding",
    "_detect_encoding_charset_norm": "io.encoding",
    "_try_read_with_encoding": "io.encoding",
    "read_file_with_encoding": "io.encoding",
    "_validate_and_read_file": "io.encoding",
    "DANGEROUS_COMMAND_NAMES": "patterns",
    "_DANGEROUS_CMDS_REGEX": "patterns",
    "_COMPILED_IF_PATTERN": "patterns",
    "_COMPILED_SETLOCAL_DISABLE": "patterns",
    "_COMPILED_SET_PATTERN": "patterns",
    "_COMPILED_GOTO_PATTERN": "patterns",
    "_COMPILED_VAR_EXPANSION": "patterns",
    "_COMPILED_ECHO_DOTS": "patterns",
    "_COMPILED_NON_ASCII": "patterns",
    "_COMPILED_NET_SESSION": "patterns",
    "_COMPILED_NET_COMMAND": "patterns",
    "_COMPILED_DELAYED_VAR": "patterns",
    "DANGEROUS_COMMAND_PATTERNS": "patterns",
    "COMMAND_CASING_KEYWORDS": "patterns",
    "OLDER_WINDOWS_COMMANDS": "patterns",
    "ARCHITECTURE_SPECIFIC_PATTERNS": "patterns",
    "UNICODE_PROBLEMATIC_COMMANDS": "patterns",
    "DEPRECATED_COMMANDS": "patterns",
    "REMOVED_COMMANDS": "patterns",
    "COMMON_COMMAND_TYPOS": "patterns",
    "SENSITIVE_KEYWORDS": "patterns",
    "CREDENTIAL_PATTERNS": "patterns",
    "SENSITIVE_ECHO_PATTERNS": "patterns",
    "BUILTIN_COMMANDS": "patterns",
    "POWERSHELL_PATTERNS": "patterns",
    "VBSCRIPT_PATTERNS": "patterns",
    "CSHARP_PATTERNS": "patterns",
    "BATCH_INDICATORS": "patterns",
    "_load_general_settings": "config.loader",
    "_set_min_severity": "config.loader",
    "_load_rule_settings": "config.loader",
    "load_config": "config.loader",
    "create_default_config_file": "config.loader",
    "print_version": "output.formatters",
    "print_help": "output.formatters",
    "_is_comment_line": "parsing.context",
    "_is_command_in_safe_context": "parsing.context",
    "_is_safe_ctx_for_privilege": "parsing.context",
    "_collect_labels": "parsing.structure",
    "_is_in_subroutine_context": "parsing.structure",
    "_collect_set_variables": "parsing.structure",
    "_parse_suppression_comments": "parsing.structure",
    "_analyze_script_structure": "parsing.structure",
    "_is_script_language_line": "parsing.embedded",
    "_is_batch_code_line": "parsing.embedded",
    "_handle_script_block_start": "parsing.embedded",
    "_handle_script_block_end": "parsing.embedded",
    "_process_heredoc_block": "parsing.embedded",
    "_process_script_blocks": "parsing.embedded",
    "_detect_embedded_script_blocks": "parsing.embedded",
    "_check_goto_labels": "checkers.syntax",
    "_check_call_labels": "checkers.syntax",
    "_check_if_statement_formatting": "checkers.syntax",
    "_check_errorlevel_syntax": "checkers.syntax",
    "_check_if_exist_mixing": "checkers.syntax",
    "_check_path_syntax": "checkers.syntax",
    "_check_quotes": "checkers.syntax",
    "_check_for_loop_syntax": "checkers.syntax",
    "_has_special_variable_patterns": "checkers.syntax",
    "_check_variable_expansion": "checkers.syntax",
    "_check_subroutine_call": "checkers.syntax",
    "_check_command_typos": "checkers.syntax",
    "_check_parameter_modifiers": "checkers.syntax",
    "_check_unc_path": "checkers.syntax",
    "_is_legitimate_quote_pattern": "checkers.syntax",
    "_check_quote_escaping": "checkers.syntax",
    "_check_set_a_expression": "checkers.syntax",
    "_check_syntax_errors": "checkers.syntax",
    "_check_unicode_handling_issue": "checkers.warnings",
    "_check_echo_unicode_risk": "checkers.warnings",
    "_check_search_unicode_risk": "checkers.warnings",
    "_check_general_unicode_risk": "checkers.warnings",
    "_check_compatibility_warnings": "checkers.warnings",
    "_check_command_warnings": "checkers.warnings",
    "_check_unquoted_variables": "checkers.warnings",
    "_check_non_ascii_chars": "checkers.warnings",
    "_check_errorlevel_comparison": "checkers.warnings",
    "_check_inefficient_modifiers": "checkers.warnings",
    "_check_extended_non_ascii": "checkers.warnings",
    "_check_unicode_filenames": "checkers.warnings",
    "_check_call_ambiguity": "checkers.warnings",
    "_check_warning_issues": "checkers.warnings",
    "_find_unquoted_separator": "checkers.style",
    "_check_timeout_ping_numbers": "checkers.style",
    "_check_style_issues": "checkers.style",
    "_check_input_validation_sec": "checkers.security",
    "_has_priv_check_before": "checkers.security",
    "_check_privilege_security": "checkers.security",
    "_check_path_security": "checkers.security",
    "_check_info_disclosure_sec": "checkers.security",
    "_check_malware_security": "checkers.security",
    "_check_security_issues": "checkers.security",
    "_check_temp_file_usage": "checkers.performance",
    "_check_for_loop_optimization": "checkers.performance",
    "_check_delay_implementation": "checkers.performance",
    "_check_redundant_disable_delay": "checkers.performance",
    "_check_performance_issues": "checkers.performance",
    "_get_available_vars_at_line": "checkers.vars",
    "_should_check_variable": "checkers.vars",
    "_check_undefined_variables": "checkers.vars",
    "_check_line_ending_rules": "checkers.line_endings",
    "_analyze_line_endings": "checkers.line_endings",
    "_check_basic_line_ending_issues": "checkers.line_endings",
    "_check_multibyte_risks": "checkers.line_endings",
    "_check_goto_call_risks": "checkers.line_endings",
    "_check_doublecolon_risks": "checkers.line_endings",
    "_check_global_style_rules": "checkers.globals",
    "_check_goto_colon_consistency": "checkers.globals",
    "_check_global_priv_security": "checkers.globals",
    "_check_new_global_rules": "checkers.globals",
    "_check_bat_cmd_differences": "checkers.globals",
    "_check_advanced_global_patterns": "checkers.globals",
    "_check_nested_for_loops": "checkers.globals",
    "_find_nested_for_issue": "checkers.globals",
    "_check_external_error_handling": "checkers.globals",
    "_check_restart_limits": "checkers.globals",
    "_check_self_modification": "checkers.globals",
    "_check_code_documentation": "checkers.globals",
    "_categorize_variable_style": "checkers.globals",
    "_should_skip_line_for_var_check": "checkers.globals",
    "_check_var_naming": "checkers.globals",
    "_check_setlocal_redundancy": "checkers.globals",
    "_check_missing_exit_statement": "checkers.globals",
    "_can_main_execution_reach_eof": "checkers.globals",
    "_check_unreachable_code": "checkers.globals",
    "_find_truly_unreachable_code": "checkers.globals",
    "_calculate_exit_paren_depth": "checkers.globals",
    "_scan_for_unreachable_code": "checkers.globals",
    "_update_paren_depth": "checkers.globals",
    "_line_makes_code_reachable": "checkers.globals",
    "_is_truly_executable_command": "checkers.globals",
    "_check_redundant_operations": "checkers.globals",
    "_check_code_duplication": "checkers.globals",
    "_check_missing_pause": "checkers.globals",
    "_collect_indented_lines": "checkers.globals",
    "_find_single_line_mixed_indent": "checkers.globals",
    "_find_file_mixed_indent": "checkers.globals",
    "_check_inconsistent_indentation": "checkers.globals",
    "_check_missing_header_doc": "checkers.globals",
    "_collect_cmd_cases": "checkers.globals",
    "_find_most_common_case": "checkers.globals",
    "_check_cmd_case_consistency": "checkers.globals",
    "_process_file_checks": "checkers.orchestration",
    "_should_flag_caret_escape": "checkers.advanced",
    "_check_improper_caret_escape": "checkers.advanced",
    "_check_multilevel_escaping": "checkers.advanced",
    "_check_continuation_spaces": "checkers.advanced",
    "_check_double_percent_escaping": "checkers.advanced",
    "_check_advanced_escaping_rules": "checkers.advanced",
    "_check_advanced_for_rules": "checkers.advanced",
    "_check_advanced_process_mgmt": "checkers.advanced",
    "_check_advanced_security": "checkers.advanced",
    "_check_advanced_performance": "checkers.advanced",
    "_check_advanced_style_patterns": "checkers.advanced",
    "_filter_issues_by_config": "checkers.orchestration",
    "lint_batch_file": "engine.linter",
    "group_issues": "output.formatters",
    "print_summary": "output.formatters",
    "_format_line_numbers_with_files": "output.formatters",
    "_get_unique_contexts": "output.formatters",
    "_print_rule_group": "output.formatters",
    "print_detailed": "output.formatters",
    "print_severity_info": "output.formatters",
    "find_batch_files": "io.discovery",
    "_handle_special_cli_flags": "cli.args",
    "_parse_regular_arguments": "cli.args",
    "_parse_cli_arguments": "cli.args",
    "_extract_called_scripts": "engine.dependencies",
    "_resolve_call_script_path": "engine.dependencies",
    "_try_add_dependency": "engine.dependencies",
    "_extract_direct_dependencies": "engine.dependencies",
    "_build_call_dependency_graph": "engine.dependencies",
    "_collect_vars_from_dependencies": "engine.dependencies",
    "_resolve_script_path": "engine.dependencies",
    "_collect_vars_from_script": "engine.dependencies",
    "_collect_called_vars": "engine.dependencies",
    "_process_single_called_script": "cli.main",
    "_process_called_scripts": "cli.main",
    "_process_batch_files": "cli.main",
    "_display_analyzed_scripts": "cli.main",
    "_display_results": "cli.main",
    "_exit_with_results": "cli.main",
    "main": "cli.main",
    "_check_percent_tilde_syntax": "checkers.advanced",
    "_check_for_loop_var_syntax": "checkers.advanced",
    "_check_string_operation_syntax": "checkers.advanced",
    "_check_set_a_quoting": "checkers.advanced",
    "_check_advanced_vars": "checkers.advanced",
    "_check_for_f_options": "checkers.advanced",
    "_check_if_comparison_quotes": "checkers.advanced",
    "_check_deprecated_commands": "checkers.advanced",
    "_check_cmd_error_handling": "checkers.advanced",
    "_check_enhanced_commands": "checkers.advanced",
    "_check_variable_naming": "checkers.advanced",
    "_check_function_docs": "checkers.advanced",
    "_find_set_exclusion_ranges": "checkers.advanced",
    "_is_number_in_special_context": "checkers.advanced",
    "_check_magic_numbers": "checkers.advanced",
    "_check_line_length": "checkers.advanced",
    "_check_advanced_style_rules": "checkers.advanced",
    "_get_safe_system_variables": "checkers.advanced",
    "_get_safe_command_patterns": "checkers.advanced",
    "_is_safe_command_injection": "checkers.advanced",
    "_check_enhanced_security_rules": "checkers.advanced",
    "_check_unnecessary_output_p014": "checkers.advanced",
    "_has_nearby_interactive_cmds": "checkers.advanced",
    "_check_enhanced_performance": "checkers.advanced",
}


def _node_name(node: ast.AST) -> str | None:
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, ast.Assign):
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        return names[0] if len(names) == 1 else None
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
        return None
    return None


def _extract_nodes(source: str, lines: list[str]) -> list[tuple[str, str]]:
    tree = ast.parse(source)
    extracted: list[tuple[str, str]] = []
    for node in tree.body:
        name = _node_name(node)
        if name is None:
            continue
        if name not in SYMBOL_TO_MODULE:
            raise KeyError(f"No module mapping for symbol: {name}")
        start = node.lineno
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.decorator_list:
            start = node.decorator_list[0].lineno
        end = node.end_lineno or start
        chunk = "".join(lines[start - 1 : end])
        extracted.append((name, chunk))
    return extracted


def _module_path(module_key: str) -> Path:
    return DEST_ROOT.joinpath(*module_key.split(".")).with_suffix(".py")


def _write_module(module_key: str, chunks: list[str]) -> None:
    path = _module_path(module_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    header = MODULE_IMPORTS.get(module_key, "")
    body = "\n\n".join(chunk.rstrip() for chunk in chunks if chunk.strip())
    parts = ['"""Blinter package module."""\n']
    if header.strip():
        parts.append(header.strip())
        parts.append("")
    parts.append(body)
    parts.append("")
    path.write_text("\n".join(parts), encoding="utf-8")


def _write_version_module(pyproject_version: str) -> None:
    path = DEST_ROOT / "_version.py"
    path.write_text(
        f'"""Package version metadata."""\n\n'
        f'__version__ = "{pyproject_version}"\n'
        f'__author__ = "tboy1337"\n'
        f'__license__ = "AGPL-3.0"\n',
        encoding="utf-8",
    )


def _write_logging_module() -> None:
    path = DEST_ROOT / "logging_config.py"
    path.write_text(
        '"""Module-level logging configuration."""\n\n'
        "import logging\n\n"
        "logger = logging.getLogger(__name__)\n"
        "logger.setLevel(logging.INFO)\n",
        encoding="utf-8",
    )


def _write_package_inits() -> None:
    packages = [
        DEST_ROOT,
        DEST_ROOT / "rules",
        DEST_ROOT / "io",
        DEST_ROOT / "config",
        DEST_ROOT / "parsing",
        DEST_ROOT / "checkers",
        DEST_ROOT / "engine",
        DEST_ROOT / "output",
        DEST_ROOT / "cli",
    ]
    for package in packages:
        package.mkdir(parents=True, exist_ok=True)
        init_path = package / "__init__.py"
        if not init_path.exists():
            init_path.write_text('"""Blinter subpackage."""\n', encoding="utf-8")


def _read_pyproject_version() -> str:
    import re
    import tomllib

    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    if match:
        return match.group(1)
    data = tomllib.loads(text)
    project = data.get("project")
    if isinstance(project, dict) and isinstance(project.get("version"), str):
        return project["version"]
    raise ValueError("Could not read version from pyproject.toml")


def main() -> None:
    """Split monolith into package modules."""
    source = SOURCE_PATH.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    extracted = _extract_nodes(source, lines)

    if DEST_ROOT.exists():
        shutil.rmtree(DEST_ROOT)
    DEST_ROOT.mkdir(parents=True)

    grouped: dict[str, list[str]] = defaultdict(list)
    order: dict[str, list[str]] = defaultdict(list)
    for name, chunk in extracted:
        module_key = SYMBOL_TO_MODULE[name]
        grouped[module_key].append(chunk)
        order[module_key].append(name)

    _write_version_module(_read_pyproject_version())
    _write_logging_module()
    _write_package_inits()

    for module_key in sorted(grouped):
        _write_module(module_key, grouped[module_key])

    print(f"Split {len(extracted)} symbols into {len(grouped)} modules under {DEST_ROOT}")


if __name__ == "__main__":
    main()
