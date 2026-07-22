"""AST visitor implementing syntax rules backed by the ANTLR grammar."""

from __future__ import annotations

import logging
import re
from typing import List, Set

from antlr4.tree.Tree import ParseTree, TerminalNode

from blinter.generated.BatchLexer import BatchLexer
from blinter.generated.BatchParser import BatchParser
from blinter.generated.BatchParserVisitor import BatchParserVisitor
from blinter.models import LintIssue
from blinter.parsing.antlr_bridge import ParseResult, parse_batch_lines
from blinter.parsing.fast_syntax import check_grammar_backed_syntax_fast
from blinter.parsing.grammar_rules import GRAMMAR_BACKED_RULE_CODES
from blinter.parsing.preprocessor import map_line_number
from blinter.parsing.structure import _build_delayed_expansion_state
from blinter.parsing.visitors.rule_impl.advanced.escaping import (
    _check_continuation_spaces,
    _check_double_percent_escaping,
    _check_improper_caret_escape,
    _check_multilevel_escaping,
)
from blinter.parsing.visitors.rule_impl.advanced.vars_syntax import (
    _invalid_percent_tilde_modifier_chars,
    _is_valid_percent_tilde_parameter,
    _split_percent_tilde_interior,
)
from blinter.parsing.visitors.rule_impl.syntax import (
    _check_quotes,
    _check_variable_expansion,
)
from blinter.rules.expansion_data import VALID_MODIFIERS
from blinter.rules.registry import RULES

logger = logging.getLogger(__name__)

_AST_RULE_CODES: Set[str] = set(GRAMMAR_BACKED_RULE_CODES)

_PERCENT_TILDE_RE = re.compile(r"%~([^%]+)%", re.IGNORECASE)


def ast_handled_rule_codes() -> Set[str]:
    """Rule codes handled exclusively by the AST syntax visitor."""
    return set(_AST_RULE_CODES)


class SyntaxLintVisitor(BatchParserVisitor):
    """Walk ANTLR parse tree and emit grammar-backed syntax diagnostics."""

    def __init__(
        self,
        *,
        parse_result: ParseResult,
        original_lines: List[str],
        has_delayed_expansion: bool,
    ) -> None:
        super().__init__()
        self._parse_result: ParseResult = parse_result
        self.original_lines = original_lines
        self.has_delayed_expansion = has_delayed_expansion
        self._delayed_expansion_state = _build_delayed_expansion_state(original_lines)
        self.issues: List[LintIssue] = []
        self._seen: Set[tuple[int, str]] = set()

    def _original_line(self, preprocessed_line: int) -> int:
        return map_line_number(self._parse_result.preprocessed, preprocessed_line)

    def _add(self, line_number: int, code: str, context: str = "") -> None:
        key = (line_number, code)
        if key in self._seen or code not in _AST_RULE_CODES:
            return
        rule = RULES.get(code)
        if rule is None:
            return
        self._seen.add(key)
        self.issues.append(LintIssue(line_number, rule, context=context))

    def add_issue(self, line_number: int, code: str, context: str = "") -> None:
        """Record a grammar-backed issue (used by preprocessor continuation hooks)."""
        self._add(line_number, code, context=context)

    def _walk_tokens(self, node: ParseTree, preprocessed_line: int) -> None:
        if isinstance(node, TerminalNode):
            token = node.getSymbol()
            line_no = self._original_line(token.line)
            token_type = token.type
            text = token.text or ""
            if token_type == BatchLexer.UNMATCHED_DQ:
                return
            if token_type == BatchLexer.PERCENT_TILDE:
                self._check_percent_tilde_token(text, line_no)
            return
        for index in range(node.getChildCount()):
            self._walk_tokens(node.getChild(index), preprocessed_line)

    def _check_percent_tilde_token(self, text: str, line_number: int) -> None:
        match = _PERCENT_TILDE_RE.match(text)
        if not match:
            self._add(line_number, "E017", context=text)
            return
        interior = match.group(1)
        modifiers, parameter = _split_percent_tilde_interior(interior)
        has_path_search = "$" in modifiers
        invalid_chars = _invalid_percent_tilde_modifier_chars(interior)
        if invalid_chars:
            self._add(
                line_number,
                "E017",
                context=(
                    f"Invalid modifier in {text}: {', '.join(sorted(invalid_chars))}"
                ),
            )
        numeric_parameter = re.sub(r"^[a-z]+", "", parameter, flags=re.IGNORECASE)
        if numeric_parameter and numeric_parameter[0].isdigit():
            parameter = numeric_parameter
        if not parameter or not _is_valid_percent_tilde_parameter(
            parameter,
            has_path_search=has_path_search,
        ):
            self._add(
                line_number,
                "E019",
                context=f"Percent-tilde on invalid parameter: {parameter or '(missing)'}",
            )

    def visitCommandLine(self, ctx: BatchParser.CommandLineContext) -> None:
        preprocessed_line = ctx.start.line
        line_no = self._original_line(preprocessed_line)
        self._walk_tokens(ctx, preprocessed_line)
        if 1 <= line_no <= len(self.original_lines):
            line = self.original_lines[line_no - 1]
            stripped = line.strip()
            self._check_line_text(line, stripped, line_no)
        return None

    def _check_line_text(self, line: str, stripped: str, line_number: int) -> None:
        for issue in _check_variable_expansion(
            stripped,
            line_number,
            delayed_expansion_state=self._delayed_expansion_state,
        ):
            if issue.rule.code in _AST_RULE_CODES:
                self._add(line_number, issue.rule.code, context=issue.context or "")
        for issue in _check_improper_caret_escape(stripped, line_number, line):
            self._add(line_number, issue.rule.code, context=issue.context or "")
        for issue in _check_multilevel_escaping(stripped, line_number):
            self._add(line_number, issue.rule.code, context=issue.context or "")
        for issue in _check_continuation_spaces(line, stripped, line_number):
            self._add(line_number, issue.rule.code, context=issue.context or "")
        for issue in _check_double_percent_escaping(stripped, line_number):
            self._add(line_number, issue.rule.code, context=issue.context or "")


def check_ast_syntax_rules(
    lines: List[str],
    *,
    has_delayed_expansion: bool = False,
) -> List[LintIssue]:
    """
    Run grammar-backed syntax checks using the fast line scanner.

    ANTLR remains available via ``check_ast_syntax_rules_antlr`` for corpus
    conformance tests and grammar validation.
    """
    return check_grammar_backed_syntax_fast(
        lines,
        has_delayed_expansion=has_delayed_expansion,
    )


def check_ast_syntax_rules_antlr(
    lines: List[str],
    *,
    has_delayed_expansion: bool = False,
) -> List[LintIssue]:
    """Run grammar-backed syntax checks by walking the ANTLR parse tree."""
    parse_result = parse_batch_lines(lines, delayed_expansion=has_delayed_expansion)
    if parse_result.errors:
        logger.debug("ANTLR parse messages: %s", parse_result.errors)

    visitor = SyntaxLintVisitor(
        parse_result=parse_result,
        original_lines=lines,
        has_delayed_expansion=has_delayed_expansion,
    )
    visitor.visit(parse_result.tree)

    for line_number, line in enumerate(lines, start=1):
        for issue in _check_quotes(line, line_number):
            visitor.add_issue(
                issue.line_number,
                issue.rule.code,
                context=issue.context or "",
            )

    for line_number, rule_code in parse_result.preprocessed.continuation_issues:
        visitor.add_issue(line_number, rule_code)

    return visitor.issues
