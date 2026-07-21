"""Backward-compatible module alias."""

import sys

import blinter.parsing.visitors.rule_impl.advanced.vars_syntax as _impl

sys.modules[__name__] = _impl
