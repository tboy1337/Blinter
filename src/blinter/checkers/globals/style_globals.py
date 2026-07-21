"""Backward-compatible module alias."""

import sys

import blinter.parsing.visitors.rule_impl.globals.style_globals as _impl

sys.modules[__name__] = _impl
