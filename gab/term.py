# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Terminal colour, with the usual escape hatches.

Colour is on only when writing to a terminal, and never when NO_COLOR is
set in the environment (https://no-color.org) or the output is piped --
so `gab diff | less` and `gab score > file` stay clean without anyone
having to remember a flag.

The palette is deliberately tiny and semantic rather than decorative:
green means the analyzer got better, red means it got worse or crashed.
Nothing else is coloured, so a red line in a diff always means the same
thing at a glance.
"""

from __future__ import annotations

import os
import sys
from typing import IO, Optional

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "bold_red": "\033[1;31m",
    "bold_green": "\033[1;32m",
}


class Palette:
    """Colour-wrapping functions, or plain passthrough when disabled."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, name: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"{_CODES[name]}{text}{_CODES['reset']}"

    def good(self, text: str) -> str:
        """An improvement: a new true positive, a fixed crash."""
        return self._wrap("green", text)

    def bad(self, text: str) -> str:
        """A regression: a lost true positive, a new false positive."""
        return self._wrap("red", text)

    def alarm(self, text: str) -> str:
        """A compiler crash -- the loudest thing we can say."""
        return self._wrap("bold_red", text)

    def warn(self, text: str) -> str:
        return self._wrap("yellow", text)

    def head(self, text: str) -> str:
        return self._wrap("bold", text)

    def dim(self, text: str) -> str:
        return self._wrap("dim", text)

    def outcome(self, before: str, after: str) -> str:
        """Colour an OUTCOME -> OUTCOME transition by its direction."""
        from gab.diff import IMPROVEMENTS, REGRESSIONS

        text = f"{before} -> {after}"
        if (before, after) in IMPROVEMENTS:
            return self.good(text)
        if (before, after) in REGRESSIONS:
            return self.bad(text)
        return text


def make_palette(mode: str = "auto", stream: Optional[IO] = None) -> Palette:
    """mode is one of auto | always | never."""
    if mode == "always":
        return Palette(True)
    if mode == "never":
        return Palette(False)
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return Palette(False)
    if os.environ.get("TERM") == "dumb":
        return Palette(False)
    try:
        return Palette(bool(stream.isatty()))
    except (AttributeError, ValueError):
        return Palette(False)
