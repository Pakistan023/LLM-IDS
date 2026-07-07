"""
Centralized logging setup for LLM-IDS.

Usage:
    from src.utils.logger import get_logger
    log = get_logger(__name__)
    log.info("message")
"""

import logging
import os
import sys

_CONFIGURED = False


def _configure_root():
    global _CONFIGURED
    if _CONFIGURED:
        return

    level = os.getenv("LOG_LEVEL", "INFO").upper()

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    _configure_root()
    return logging.getLogger(name)
