"""Backward-compatible module alias."""

import sys

import blinter.parsing.visitors.rule_impl.advanced.escaping as _impl

sys.modules[__name__] = _impl
