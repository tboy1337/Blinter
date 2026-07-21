"""Backward-compatible module alias."""

import sys

import blinter.parsing.visitors.rule_impl.advanced.enhanced as _impl

sys.modules[__name__] = _impl
