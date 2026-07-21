"""Backward-compatible module alias."""

import sys

import blinter.parsing.visitors.rule_impl.globals.exit_flow as _impl

sys.modules[__name__] = _impl
