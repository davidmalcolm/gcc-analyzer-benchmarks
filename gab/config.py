# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Configuration: where the compilers and suite checkouts live.

Resolution order, first hit wins:

  1. --config PATH
  2. $GAB_CONFIG
  3. ./config.json next to the repo root
  4. ~/.config/gcc-analyzer-benchmarks/config.json

Values may contain $VAR / ${VAR} and ~, so a single config can be shared
between a laptop and a compile-farm box.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
USER_CONFIG = Path.home() / ".config" / "gcc-analyzer-benchmarks" / "config.json"


def expand(value: str) -> str:
    return os.path.expanduser(os.path.expandvars(value))


def find_config(explicit: Optional[str] = None) -> Path:
    if explicit:
        p = Path(expand(explicit))
        if not p.is_file():
            raise FileNotFoundError(f"no such config file: {p}")
        return p
    env = os.environ.get("GAB_CONFIG")
    if env:
        p = Path(expand(env))
        if not p.is_file():
            raise FileNotFoundError(f"$GAB_CONFIG points at a missing file: {p}")
        return p
    for p in (REPO_ROOT / "config.json", USER_CONFIG):
        if p.is_file():
            return p
    raise FileNotFoundError(
        "no config found; expected one of "
        f"{REPO_ROOT / 'config.json'} or {USER_CONFIG}, "
        "or set $GAB_CONFIG"
    )


def load_config(explicit: Optional[str] = None) -> dict:
    path = find_config(explicit)
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["__path__"] = str(path)
    return cfg


def suite_options(cfg: dict, name: str, version: Optional[str] = None) -> dict:
    """Per-suite options from config, with an optional CLI version override."""
    entry = (cfg.get("suites") or {}).get(name)
    opts = dict(entry) if isinstance(entry, dict) else {}
    opts.pop("path", None)
    opts.pop("adapter", None)
    if version:
        opts["version"] = version
    return opts


def suite_adapter(cfg: dict, name: str) -> str:
    """Which adapter implements a configured suite.

    Defaults to the config key, so the common case needs no "adapter"
    field.  Setting it lets the same adapter be configured more than
    once -- for instance two BenchProctor releases, which rotate their
    contents and so cannot share one entry.
    """
    entry = (cfg.get("suites") or {}).get(name)
    if isinstance(entry, dict):
        return entry.get("adapter") or name
    return name


def suite_root(cfg: dict, name: str) -> Path:
    suites = cfg.get("suites") or {}
    if name not in suites:
        raise KeyError(
            f"suite {name!r} not in {cfg.get('__path__')}; "
            f"configured: {', '.join(sorted(suites)) or '(none)'}"
        )
    entry = suites[name]
    path = entry if isinstance(entry, str) else entry.get("path")
    if not path:
        raise KeyError(f"suite {name!r} has no 'path' in {cfg.get('__path__')}")
    return Path(expand(path))
