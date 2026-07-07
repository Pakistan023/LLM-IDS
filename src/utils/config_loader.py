"""
Small helper for loading config/config.yaml and .env once, from anywhere
in the project, regardless of current working directory.
"""

import os
from functools import lru_cache

import yaml
from dotenv import load_dotenv

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@lru_cache(maxsize=1)
def load_config() -> dict:
    env_path = os.path.join(_PROJECT_ROOT, ".env")
    if os.path.exists(env_path):
        load_dotenv(env_path)

    cfg_path = os.path.join(_PROJECT_ROOT, "config", "config.yaml")
    with open(cfg_path, "r") as f:
        cfg = yaml.safe_load(f)

    # resolve relative paths against project root so it works from any CWD
    def _abs(path: str) -> str:
        return path if os.path.isabs(path) else os.path.join(_PROJECT_ROOT, path)

    cfg["_project_root"] = _PROJECT_ROOT
    cfg["_abs"] = _abs
    return cfg


def project_root() -> str:
    return _PROJECT_ROOT
