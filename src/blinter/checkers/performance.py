"""Backward-compatible module alias."""

import sys

import blinter.parsing.visitors.rule_impl.performance as _impl

sys.modules[__name__] = _impl
