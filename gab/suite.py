# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Suite abstraction.

A *suite* is a named collection of single-file test cases, each carrying
"ground truth": whether the file contains a flaw, which CWE, and (if the
suite records it) which lines.

Suites differ in the shape of their ground truth.  BenchProctor knows only
"this file is/isn't vulnerable, in this category"; CASTLE additionally
pins down the offending lines.  `TestCase` is the union: `lines` is empty
when a suite has no line-level truth, and scorers must cope with that.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Type


@dataclass(frozen=True)
class TestCase:
    """One single-file test case plus its ground truth."""

    suite: str
    name: str
    """Stable identifier, unique within the suite.  Used as a filename, so
    it must not contain '/' or whitespace."""

    source: Path
    """Absolute path to the source file."""

    compile_args: tuple = ()
    """Suite-specific flags needed to compile this file at all (-std=...,
    -I..., -Wno-error=...).  Analyzer flags are added by the runner."""

    vulnerable: bool = False
    """Ground truth: does this file contain the flaw?"""

    cwe: Optional[int] = None
    """Ground-truth CWE.  Set for both vulnerable cases and their "fixed"
    counterparts -- for a non-vulnerable case it names the CWE the file is
    *about*, i.e. the one a tool would be wrong to report."""

    category: Optional[str] = None
    """Suite-local category name, where the suite has one."""

    lines: tuple = ()
    """Ground-truth line numbers of the flaw.  Empty if unknown."""

    def ground_truth(self) -> dict:
        return {
            "vulnerable": self.vulnerable,
            "cwe": self.cwe,
            "category": self.category,
            "lines": list(self.lines),
        }


class Suite:
    """Base class for suite adapters."""

    name: str = "<unnamed>"

    def __init__(self, root: Path, options: Optional[dict] = None):
        self.root = Path(root).expanduser().resolve()
        self.options = dict(options or {})
        if not self.root.is_dir():
            raise FileNotFoundError(
                f"suite {self.name!r}: checkout not found at {self.root}"
            )

    def version(self) -> str:
        """Human-readable version of the *data*, so a run can be tied to the
        exact ground truth it was scored against."""
        raise NotImplementedError

    def tests(self) -> List[TestCase]:
        raise NotImplementedError

    def cwe_parents(self) -> Dict[int, List[int]]:
        """Optional CWE hierarchy shipped with the suite: child -> parents."""
        return {}

    def out_of_scope_categories(self) -> List[str]:
        """Categories -fanalyzer does not attempt, and never will.

        Listing a whole category as a false negative is noise, not a
        finding: GCC's analyzer has nothing to say about SQL injection
        or weak ciphers, so those tests are not "areas for improvement"
        in any useful sense.  Reports that are about improving the
        analyzer skip these by default.

        Scoring does *not* skip them automatically -- a score silently
        computed over a subset would be misleading, and comparability
        with published numbers depends on saying which categories were
        counted.  Pass --skip-category there, as the suite's own
        scorers expect.
        """
        return []

    def content_hash(self, tests: Optional[List[TestCase]] = None) -> str:
        """Hash of the exact test data a run was executed against.

        A version string is not enough.  BenchProctor rotates its
        contents -- it is a changing subset drawn from a larger private
        pool, and filenames deliberately change between releases so that
        tools cannot cheat by recognising them.  Two runs are only
        comparable if this hash matches; `gab diff` can then refuse, or
        warn, rather than silently diffing against different tests.

        Covers every test's identity, ground truth and source contents.
        """
        if tests is None:
            tests = self.tests()
        h = hashlib.sha256()
        for t in sorted(tests, key=lambda t: t.name):
            h.update(t.name.encode())
            h.update(repr(sorted(t.ground_truth().items())).encode())
            h.update(b"\0".join(a.encode() for a in t.compile_args))
            try:
                with open(t.source, "rb") as f:
                    h.update(hashlib.sha256(f.read()).digest())
            except OSError:
                h.update(b"<unreadable>")
        return h.hexdigest()

    # -- helpers for subclasses ------------------------------------------

    def _git_describe(self) -> Optional[str]:
        """Best-effort revision of the suite checkout, for provenance."""
        try:
            out = subprocess.run(
                ["git", "-C", str(self.root), "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, timeout=10,
            )
            if out.returncode == 0:
                return out.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return None


_REGISTRY: Dict[str, Type[Suite]] = {}


def register(cls: Type[Suite]) -> Type[Suite]:
    _REGISTRY[cls.name] = cls
    return cls


def suite_names() -> List[str]:
    _load_builtin()
    return sorted(_REGISTRY)


def get_suite(name: str, root: Path, options: Optional[dict] = None,
              label: Optional[str] = None) -> Suite:
    """Instantiate a suite adapter.

    `name` selects the adapter; `label` is what this particular instance
    is called in run directories and reports.  They differ when the same
    adapter is configured twice -- two BenchProctor releases side by
    side, say -- which a config entry requests with "adapter": "<name>".
    """
    _load_builtin()
    try:
        cls = _REGISTRY[name]
    except KeyError:
        raise KeyError(
            f"unknown suite adapter {name!r}; "
            f"known: {', '.join(sorted(_REGISTRY))}"
        ) from None
    suite = cls(root, options)
    if label and label != cls.name:
        # Shadow the class attribute on this instance only; the registry
        # still keys off the adapter's own name.
        suite.name = label
    return suite


_loaded = False


def _load_builtin() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    from gab.suites import benchproctor, castle, itc  # noqa: F401
