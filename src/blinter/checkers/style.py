"""Backward-compatible module alias."""

import sys

import blinter.parsing.visitors.rule_impl.style as _impl

sys.modules[__name__] = _impl
