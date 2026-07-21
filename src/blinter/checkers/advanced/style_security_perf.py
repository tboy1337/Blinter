"""Backward-compatible module alias."""

import sys

import blinter.parsing.visitors.rule_impl.advanced.style_security_perf as _impl

sys.modules[__name__] = _impl
