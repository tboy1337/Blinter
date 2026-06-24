"""Blinter - batch file linter package."""

from blinter._version import __author__
from blinter._version import __license__
from blinter._version import __version__
from blinter.checkers.advanced import _check_advanced_escaping_rules
from blinter.checkers.advanced import _check_advanced_for_rules
from blinter.checkers.advanced import _check_advanced_performance
from blinter.checkers.advanced import _check_advanced_process_mgmt
from blinter.checkers.advanced import _check_advanced_security
from blinter.checkers.advanced import _check_advanced_style_patterns
from blinter.checkers.advanced import _check_advanced_style_rules
from blinter.checkers.advanced import _check_advanced_vars
from blinter.checkers.advanced import _check_cmd_error_handling
from blinter.checkers.advanced import _check_continuation_spaces
from blinter.checkers.advanced import _check_deprecated_commands
from blinter.checkers.advanced import _check_double_percent_escaping
from blinter.checkers.advanced import _check_enhanced_commands
from blinter.checkers.advanced import _check_enhanced_performance
from blinter.checkers.advanced import _check_enhanced_security_rules
from blinter.checkers.advanced import _check_for_f_options
from blinter.checkers.advanced import _check_for_loop_var_syntax
from blinter.checkers.advanced import _check_function_docs
from blinter.checkers.advanced import _check_if_comparison_quotes
from blinter.checkers.advanced import _check_improper_caret_escape
from blinter.checkers.advanced import _check_line_length
from blinter.checkers.advanced import _check_magic_numbers
from blinter.checkers.advanced import _check_multilevel_escaping
from blinter.checkers.advanced import _check_percent_tilde_syntax
from blinter.checkers.advanced import _check_set_a_quoting
from blinter.checkers.advanced import _check_string_operation_syntax
from blinter.checkers.advanced import _check_unnecessary_output_p014
from blinter.checkers.advanced import _check_variable_naming
from blinter.checkers.advanced import _find_set_exclusion_ranges
from blinter.checkers.advanced import _get_safe_command_patterns
from blinter.checkers.advanced import _get_safe_system_variables
from blinter.checkers.advanced import _has_nearby_interactive_cmds
from blinter.checkers.advanced import _is_number_in_special_context
from blinter.checkers.advanced import _is_safe_command_injection
from blinter.checkers.advanced import _should_flag_caret_escape
from blinter.checkers.globals import _calculate_exit_paren_depth
from blinter.checkers.globals import _can_main_execution_reach_eof
from blinter.checkers.globals import _categorize_variable_style
from blinter.checkers.globals import _check_advanced_global_patterns
from blinter.checkers.globals import _check_bat_cmd_differences
from blinter.checkers.globals import _check_cmd_case_consistency
from blinter.checkers.globals import _check_code_documentation
from blinter.checkers.globals import _check_code_duplication
from blinter.checkers.globals import _check_external_error_handling
from blinter.checkers.globals import _check_global_priv_security
from blinter.checkers.globals import _check_global_style_rules
from blinter.checkers.globals import _check_goto_colon_consistency
from blinter.checkers.globals import _check_inconsistent_indentation
from blinter.checkers.globals import _check_missing_exit_statement
from blinter.checkers.globals import _check_missing_header_doc
from blinter.checkers.globals import _check_missing_pause
from blinter.checkers.globals import _check_nested_for_loops
from blinter.checkers.globals import _check_new_global_rules
from blinter.checkers.globals import _check_redundant_operations
from blinter.checkers.globals import _check_restart_limits
from blinter.checkers.globals import _check_self_modification
from blinter.checkers.globals import _check_setlocal_redundancy
from blinter.checkers.globals import _check_unreachable_code
from blinter.checkers.globals import _check_var_naming
from blinter.checkers.globals import _collect_cmd_cases
from blinter.checkers.globals import _collect_indented_lines
from blinter.checkers.globals import _find_file_mixed_indent
from blinter.checkers.globals import _find_most_common_case
from blinter.checkers.globals import _find_nested_for_issue
from blinter.checkers.globals import _find_single_line_mixed_indent
from blinter.checkers.globals import _find_truly_unreachable_code
from blinter.checkers.globals import _is_truly_executable_command
from blinter.checkers.globals import _line_makes_code_reachable
from blinter.checkers.globals import _scan_for_unreachable_code
from blinter.checkers.globals import _should_skip_line_for_var_check
from blinter.checkers.globals import _update_paren_depth
from blinter.checkers.line_endings import _analyze_line_endings
from blinter.checkers.line_endings import _check_basic_line_ending_issues
from blinter.checkers.line_endings import _check_doublecolon_risks
from blinter.checkers.line_endings import _check_goto_call_risks
from blinter.checkers.line_endings import _check_line_ending_rules
from blinter.checkers.line_endings import _check_multibyte_risks
from blinter.checkers.orchestration import _filter_issues_by_config
from blinter.checkers.orchestration import _process_file_checks
from blinter.checkers.performance import _check_delay_implementation
from blinter.checkers.performance import _check_for_loop_optimization
from blinter.checkers.performance import _check_performance_issues
from blinter.checkers.performance import _check_redundant_disable_delay
from blinter.checkers.performance import _check_temp_file_usage
from blinter.checkers.security import _check_info_disclosure_sec
from blinter.checkers.security import _check_input_validation_sec
from blinter.checkers.security import _check_malware_security
from blinter.checkers.security import _check_path_security
from blinter.checkers.security import _check_privilege_security
from blinter.checkers.security import _check_security_issues
from blinter.checkers.security import _has_priv_check_before
from blinter.checkers.style import _check_style_issues
from blinter.checkers.style import _check_timeout_ping_numbers
from blinter.checkers.style import _find_unquoted_separator
from blinter.checkers.syntax import _check_call_labels
from blinter.checkers.syntax import _check_command_typos
from blinter.checkers.syntax import _check_errorlevel_syntax
from blinter.checkers.syntax import _check_for_loop_syntax
from blinter.checkers.syntax import _check_goto_labels
from blinter.checkers.syntax import _check_if_exist_mixing
from blinter.checkers.syntax import _check_if_statement_formatting
from blinter.checkers.syntax import _check_parameter_modifiers
from blinter.checkers.syntax import _check_path_syntax
from blinter.checkers.syntax import _check_quote_escaping
from blinter.checkers.syntax import _check_quotes
from blinter.checkers.syntax import _check_set_a_expression
from blinter.checkers.syntax import _check_subroutine_call
from blinter.checkers.syntax import _check_syntax_errors
from blinter.checkers.syntax import _check_unc_path
from blinter.checkers.syntax import _check_variable_expansion
from blinter.checkers.syntax import _has_special_variable_patterns
from blinter.checkers.syntax import _is_legitimate_quote_pattern
from blinter.checkers.vars import _check_undefined_variables
from blinter.checkers.vars import _get_available_vars_at_line
from blinter.checkers.vars import _should_check_variable
from blinter.checkers.warnings import _check_call_ambiguity
from blinter.checkers.warnings import _check_command_warnings
from blinter.checkers.warnings import _check_compatibility_warnings
from blinter.checkers.warnings import _check_echo_unicode_risk
from blinter.checkers.warnings import _check_errorlevel_comparison
from blinter.checkers.warnings import _check_extended_non_ascii
from blinter.checkers.warnings import _check_general_unicode_risk
from blinter.checkers.warnings import _check_inefficient_modifiers
from blinter.checkers.warnings import _check_non_ascii_chars
from blinter.checkers.warnings import _check_search_unicode_risk
from blinter.checkers.warnings import _check_unicode_filenames
from blinter.checkers.warnings import _check_unicode_handling_issue
from blinter.checkers.warnings import _check_unquoted_variables
from blinter.checkers.warnings import _check_warning_issues
from blinter.cli.args import _handle_special_cli_flags
from blinter.cli.args import _parse_cli_arguments
from blinter.cli.args import _parse_regular_arguments
from blinter.cli.main import _cli_error
from blinter.cli.main import _display_analyzed_scripts
from blinter.cli.main import _display_results
from blinter.cli.main import _exit_with_results
from blinter.cli.main import _process_batch_files
from blinter.cli.main import _process_called_scripts
from blinter.cli.main import _process_single_called_script
from blinter.cli.main import main
from blinter.config.loader import _load_general_settings
from blinter.config.loader import _load_rule_settings
from blinter.config.loader import _set_min_severity
from blinter.config.loader import create_default_config_file
from blinter.config.loader import load_config
from blinter.constants import BUILTIN_VARS
from blinter.constants import MAGIC_NUMBER_EXCEPTIONS
from blinter.engine.dependencies import _build_call_dependency_graph
from blinter.engine.dependencies import _collect_called_vars
from blinter.engine.dependencies import _collect_vars_from_dependencies
from blinter.engine.dependencies import _collect_vars_from_script
from blinter.engine.dependencies import _extract_called_scripts
from blinter.engine.dependencies import _extract_direct_dependencies
from blinter.engine.dependencies import _resolve_call_script_path
from blinter.engine.dependencies import _resolve_script_path
from blinter.engine.dependencies import _try_add_dependency
from blinter.engine.linter import lint_batch_file
from blinter.io.discovery import find_batch_files
from blinter.io.encoding import _detect_encoding_charset_norm
from blinter.io.encoding import _detect_line_endings
from blinter.io.encoding import _has_multibyte_chars
from blinter.io.encoding import _try_read_with_encoding
from blinter.io.encoding import _validate_and_read_file
from blinter.io.encoding import read_file_with_encoding
from blinter.logging_config import logger
from blinter.models import BlinterConfig
from blinter.models import CliArguments
from blinter.models import LintIssue
from blinter.models import ProcessingResults
from blinter.models import ProcessingState
from blinter.models import Rule
from blinter.models import RuleSeverity
from blinter.output.formatters import _format_line_numbers_with_files
from blinter.output.formatters import _get_unique_contexts
from blinter.output.formatters import _print_rule_group
from blinter.output.formatters import group_issues
from blinter.output.formatters import print_detailed
from blinter.output.formatters import print_help
from blinter.output.formatters import print_severity_info
from blinter.output.formatters import print_summary
from blinter.output.formatters import print_version
from blinter.parsing.context import _is_command_in_safe_context
from blinter.parsing.context import _is_comment_line
from blinter.parsing.context import _is_safe_ctx_for_privilege
from blinter.parsing.embedded import ScriptBlockState
from blinter.parsing.embedded import ScriptProcessingContext
from blinter.parsing.embedded import _detect_embedded_script_blocks
from blinter.parsing.embedded import _handle_script_block_end
from blinter.parsing.embedded import _handle_script_block_start
from blinter.parsing.embedded import _is_batch_code_line
from blinter.parsing.embedded import _is_script_language_line
from blinter.parsing.embedded import _process_heredoc_block
from blinter.parsing.embedded import _process_script_blocks
from blinter.parsing.structure import _analyze_script_structure
from blinter.parsing.structure import _collect_labels
from blinter.parsing.structure import _collect_set_variables
from blinter.parsing.structure import _is_in_subroutine_context
from blinter.parsing.structure import _parse_suppression_comments
from blinter.patterns import ARCHITECTURE_SPECIFIC_PATTERNS
from blinter.patterns import BATCH_INDICATORS
from blinter.patterns import BUILTIN_COMMANDS
from blinter.patterns import COMMAND_CASING_KEYWORDS
from blinter.patterns import COMMON_COMMAND_TYPOS
from blinter.patterns import CREDENTIAL_PATTERNS
from blinter.patterns import CSHARP_PATTERNS
from blinter.patterns import DANGEROUS_COMMAND_NAMES
from blinter.patterns import DANGEROUS_COMMAND_PATTERNS
from blinter.patterns import DEPRECATED_COMMANDS
from blinter.patterns import OLDER_WINDOWS_COMMANDS
from blinter.patterns import POWERSHELL_PATTERNS
from blinter.patterns import REMOVED_COMMANDS
from blinter.patterns import SENSITIVE_ECHO_PATTERNS
from blinter.patterns import SENSITIVE_KEYWORDS
from blinter.patterns import UNICODE_PROBLEMATIC_COMMANDS
from blinter.patterns import VBSCRIPT_PATTERNS
from blinter.patterns import _COMPILED_DELAYED_VAR
from blinter.patterns import _COMPILED_ECHO_DOTS
from blinter.patterns import _COMPILED_GOTO_PATTERN
from blinter.patterns import _COMPILED_IF_PATTERN
from blinter.patterns import _COMPILED_NET_COMMAND
from blinter.patterns import _COMPILED_NET_SESSION
from blinter.patterns import _COMPILED_NON_ASCII
from blinter.patterns import _COMPILED_SETLOCAL_DISABLE
from blinter.patterns import _COMPILED_SET_PATTERN
from blinter.patterns import _COMPILED_VAR_EXPANSION
from blinter.patterns import _DANGEROUS_CMDS_REGEX
from blinter.rules.helpers import _add_issue
from blinter.rules.helpers import _create_rule
from blinter.rules.helpers import _s011_rule
from blinter.rules.registry import RULES

__all__ = [
    "__author__",
    "__license__",
    "__version__",
    "_check_advanced_escaping_rules",
    "_check_advanced_for_rules",
    "_check_advanced_performance",
    "_check_advanced_process_mgmt",
    "_check_advanced_security",
    "_check_advanced_style_patterns",
    "_check_advanced_style_rules",
    "_check_advanced_vars",
    "_check_cmd_error_handling",
    "_check_continuation_spaces",
    "_check_deprecated_commands",
    "_check_double_percent_escaping",
    "_check_enhanced_commands",
    "_check_enhanced_performance",
    "_check_enhanced_security_rules",
    "_check_for_f_options",
    "_check_for_loop_var_syntax",
    "_check_function_docs",
    "_check_if_comparison_quotes",
    "_check_improper_caret_escape",
    "_check_line_length",
    "_check_magic_numbers",
    "_check_multilevel_escaping",
    "_check_percent_tilde_syntax",
    "_check_set_a_quoting",
    "_check_string_operation_syntax",
    "_check_unnecessary_output_p014",
    "_check_variable_naming",
    "_find_set_exclusion_ranges",
    "_get_safe_command_patterns",
    "_get_safe_system_variables",
    "_has_nearby_interactive_cmds",
    "_is_number_in_special_context",
    "_is_safe_command_injection",
    "_should_flag_caret_escape",
    "_calculate_exit_paren_depth",
    "_can_main_execution_reach_eof",
    "_categorize_variable_style",
    "_check_advanced_global_patterns",
    "_check_bat_cmd_differences",
    "_check_cmd_case_consistency",
    "_check_code_documentation",
    "_check_code_duplication",
    "_check_external_error_handling",
    "_check_global_priv_security",
    "_check_global_style_rules",
    "_check_goto_colon_consistency",
    "_check_inconsistent_indentation",
    "_check_missing_exit_statement",
    "_check_missing_header_doc",
    "_check_missing_pause",
    "_check_nested_for_loops",
    "_check_new_global_rules",
    "_check_redundant_operations",
    "_check_restart_limits",
    "_check_self_modification",
    "_check_setlocal_redundancy",
    "_check_unreachable_code",
    "_check_var_naming",
    "_collect_cmd_cases",
    "_collect_indented_lines",
    "_find_file_mixed_indent",
    "_find_most_common_case",
    "_find_nested_for_issue",
    "_find_single_line_mixed_indent",
    "_find_truly_unreachable_code",
    "_is_truly_executable_command",
    "_line_makes_code_reachable",
    "_scan_for_unreachable_code",
    "_should_skip_line_for_var_check",
    "_update_paren_depth",
    "_analyze_line_endings",
    "_check_basic_line_ending_issues",
    "_check_doublecolon_risks",
    "_check_goto_call_risks",
    "_check_line_ending_rules",
    "_check_multibyte_risks",
    "_filter_issues_by_config",
    "_process_file_checks",
    "_check_delay_implementation",
    "_check_for_loop_optimization",
    "_check_performance_issues",
    "_check_redundant_disable_delay",
    "_check_temp_file_usage",
    "_check_info_disclosure_sec",
    "_check_input_validation_sec",
    "_check_malware_security",
    "_check_path_security",
    "_check_privilege_security",
    "_check_security_issues",
    "_has_priv_check_before",
    "_check_style_issues",
    "_check_timeout_ping_numbers",
    "_find_unquoted_separator",
    "_check_call_labels",
    "_check_command_typos",
    "_check_errorlevel_syntax",
    "_check_for_loop_syntax",
    "_check_goto_labels",
    "_check_if_exist_mixing",
    "_check_if_statement_formatting",
    "_check_parameter_modifiers",
    "_check_path_syntax",
    "_check_quote_escaping",
    "_check_quotes",
    "_check_set_a_expression",
    "_check_subroutine_call",
    "_check_syntax_errors",
    "_check_unc_path",
    "_check_variable_expansion",
    "_has_special_variable_patterns",
    "_is_legitimate_quote_pattern",
    "_check_undefined_variables",
    "_get_available_vars_at_line",
    "_should_check_variable",
    "_check_call_ambiguity",
    "_check_command_warnings",
    "_check_compatibility_warnings",
    "_check_echo_unicode_risk",
    "_check_errorlevel_comparison",
    "_check_extended_non_ascii",
    "_check_general_unicode_risk",
    "_check_inefficient_modifiers",
    "_check_non_ascii_chars",
    "_check_search_unicode_risk",
    "_check_unicode_filenames",
    "_check_unicode_handling_issue",
    "_check_unquoted_variables",
    "_check_warning_issues",
    "_handle_special_cli_flags",
    "_parse_cli_arguments",
    "_parse_regular_arguments",
    "_cli_error",
    "_display_analyzed_scripts",
    "_display_results",
    "_exit_with_results",
    "_process_batch_files",
    "_process_called_scripts",
    "_process_single_called_script",
    "main",
    "_load_general_settings",
    "_load_rule_settings",
    "_set_min_severity",
    "create_default_config_file",
    "load_config",
    "BUILTIN_VARS",
    "MAGIC_NUMBER_EXCEPTIONS",
    "_build_call_dependency_graph",
    "_collect_called_vars",
    "_collect_vars_from_dependencies",
    "_collect_vars_from_script",
    "_extract_called_scripts",
    "_extract_direct_dependencies",
    "_resolve_call_script_path",
    "_resolve_script_path",
    "_try_add_dependency",
    "lint_batch_file",
    "find_batch_files",
    "_detect_encoding_charset_norm",
    "_detect_line_endings",
    "_has_multibyte_chars",
    "_try_read_with_encoding",
    "_validate_and_read_file",
    "read_file_with_encoding",
    "logger",
    "BlinterConfig",
    "CliArguments",
    "LintIssue",
    "ProcessingResults",
    "ProcessingState",
    "Rule",
    "RuleSeverity",
    "_format_line_numbers_with_files",
    "_get_unique_contexts",
    "_print_rule_group",
    "group_issues",
    "print_detailed",
    "print_help",
    "print_severity_info",
    "print_summary",
    "print_version",
    "_is_command_in_safe_context",
    "_is_comment_line",
    "_is_safe_ctx_for_privilege",
    "ScriptBlockState",
    "ScriptProcessingContext",
    "_detect_embedded_script_blocks",
    "_handle_script_block_end",
    "_handle_script_block_start",
    "_is_batch_code_line",
    "_is_script_language_line",
    "_process_heredoc_block",
    "_process_script_blocks",
    "_analyze_script_structure",
    "_collect_labels",
    "_collect_set_variables",
    "_is_in_subroutine_context",
    "_parse_suppression_comments",
    "ARCHITECTURE_SPECIFIC_PATTERNS",
    "BATCH_INDICATORS",
    "BUILTIN_COMMANDS",
    "COMMAND_CASING_KEYWORDS",
    "COMMON_COMMAND_TYPOS",
    "CREDENTIAL_PATTERNS",
    "CSHARP_PATTERNS",
    "DANGEROUS_COMMAND_NAMES",
    "DANGEROUS_COMMAND_PATTERNS",
    "DEPRECATED_COMMANDS",
    "OLDER_WINDOWS_COMMANDS",
    "POWERSHELL_PATTERNS",
    "REMOVED_COMMANDS",
    "SENSITIVE_ECHO_PATTERNS",
    "SENSITIVE_KEYWORDS",
    "UNICODE_PROBLEMATIC_COMMANDS",
    "VBSCRIPT_PATTERNS",
    "_COMPILED_DELAYED_VAR",
    "_COMPILED_ECHO_DOTS",
    "_COMPILED_GOTO_PATTERN",
    "_COMPILED_IF_PATTERN",
    "_COMPILED_NET_COMMAND",
    "_COMPILED_NET_SESSION",
    "_COMPILED_NON_ASCII",
    "_COMPILED_SETLOCAL_DISABLE",
    "_COMPILED_SET_PATTERN",
    "_COMPILED_VAR_EXPANSION",
    "_DANGEROUS_CMDS_REGEX",
    "_add_issue",
    "_create_rule",
    "_s011_rule",
    "RULES",
]
