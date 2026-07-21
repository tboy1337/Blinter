"""Backward-compatible module alias."""

import sys

import blinter.parsing.visitors.rule_impl.vars as _impl

sys.modules[__name__] = _impl
