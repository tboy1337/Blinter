"""Shared logger configuration for Blinter modules."""

import logging

logger = logging.getLogger("blinter")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())
