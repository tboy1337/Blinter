"""Backward-compatible module alias."""

import sys

import blinter.parsing.visitors.rule_impl.warnings as _impl

sys.modules[__name__] = _impl
