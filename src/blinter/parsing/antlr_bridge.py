"""Bridge between preprocessed batch source and ANTLR parse tree."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import List, Optional

from antlr4 import CommonTokenStream, InputStream, PredictionMode
from antlr4.error.ErrorListener import ErrorListener
from antlr4.error.ErrorStrategy import BailErrorStrategy, DefaultErrorStrategy
from antlr4.error.Errors import ParseCancellationException

from blinter.generated.BatchLexer import BatchLexer
from blinter.generated.BatchParser import BatchParser
from blinter.parsing.preprocessor import PreprocessedScript, preprocess_lines

logger = logging.getLogger(__name__)


class _CollectingErrorListener(ErrorListener):
    """Collect ANTLR syntax errors while delegating other listener hooks."""

    def __init__(self) -> None:
        super().__init__()
        self.messages: List[str] = []

    def syntaxError(
        self,
        recognizer: object,
        offending_symbol: object,
        line: int,
        column: int,
        msg: str,
        e: object,
    ) -> None:
        del recognizer, offending_symbol, e
        self.messages.append(f"line {line}:{column} {msg}")


@dataclass
class ParseResult:
    """ANTLR parse output for a batch script."""

    preprocessed: PreprocessedScript
    tree: object
    errors: List[str] = field(default_factory=list)
    delayed_expansion_enabled: bool = False


def _detect_delayed_expansion(lines: List[str]) -> bool:
    lowered = "\n".join(line.lower() for line in lines)
    return "enabledelayedexpansion" in lowered


def _parse_with_antlr(
    token_stream: CommonTokenStream,
) -> tuple[object, list[str]]:
    """Parse using SLL+bail first, then fall back to LL+recovery when needed."""
    parser = BatchParser(token_stream)
    error_listener = _CollectingErrorListener()
    parser.removeErrorListeners()
    parser.addErrorListener(error_listener)

    parser._interp.predictionMode = PredictionMode.SLL  # type: ignore[attr-defined]
    parser._errHandler = BailErrorStrategy()
    try:
        tree = parser.script()
        return tree, list(error_listener.messages)
    except ParseCancellationException:
        token_stream.seek(0)
        parser.reset()
        error_listener.messages.clear()
        parser._interp.predictionMode = PredictionMode.LL  # type: ignore[attr-defined]
        parser._errHandler = DefaultErrorStrategy()
        tree = parser.script()
        return tree, list(error_listener.messages)


def parse_batch_lines(
    lines: List[str],
    *,
    delayed_expansion: Optional[bool] = None,
) -> ParseResult:
    """Parse batch lines into an ANTLR parse tree."""
    preprocessed = preprocess_lines(lines)
    source_text = "\n".join(preprocessed.lines)
    if delayed_expansion is None:
        delayed_expansion = _detect_delayed_expansion(lines)

    input_stream = InputStream(source_text)
    lexer = BatchLexer(input_stream)
    lexer_error_listener = _CollectingErrorListener()
    lexer.removeErrorListeners()
    lexer.addErrorListener(lexer_error_listener)
    token_stream = CommonTokenStream(lexer)

    tree, parser_errors = _parse_with_antlr(token_stream)
    errors = list(lexer_error_listener.messages) + parser_errors
    if errors:
        logger.debug("ANTLR parse messages: %s", errors)

    return ParseResult(
        preprocessed=preprocessed,
        tree=tree,
        errors=errors,
        delayed_expansion_enabled=bool(delayed_expansion),
    )
