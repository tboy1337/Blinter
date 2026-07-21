"""Bridge between preprocessed batch source and ANTLR parse tree."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import List, Optional

from antlr4 import CommonTokenStream, InputStream
from antlr4.error.ErrorListener import ErrorListener

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
    token_stream = CommonTokenStream(lexer)
    parser = BatchParser(token_stream)
    error_listener = _CollectingErrorListener()
    parser.removeErrorListeners()
    parser.addErrorListener(error_listener)

    tree = parser.script()
    if error_listener.messages:
        logger.debug("ANTLR parse messages: %s", error_listener.messages)

    return ParseResult(
        preprocessed=preprocessed,
        tree=tree,
        errors=list(error_listener.messages),
        delayed_expansion_enabled=bool(delayed_expansion),
    )
