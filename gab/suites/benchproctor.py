# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""BenchProctor -- C standalone suite.

https://github.com/TheAuditorTool/BenchProctor

Apache-2.0 licensed.  There is no paper; cite the repository and the
release -- see CITATIONS.md.

Ground truth is a CSV of `test name,category,real vulnerability,CWE`, one
row per file, with no line information.  Test names are CamelCase
(`BenchmarkTest00001`) while the files are snake_case
(`benchmark_test_00001.c`).

The compile flags come from the suite's own compile_commands.json, which
deliberately makes implicit-function-declaration and int-conversion hard
errors.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from gab.suite import Suite, TestCase, register

# From the suite's compile_commands.json.
COMPILE_ARGS = (
    "-std=c11",
    "-Werror=implicit-function-declaration",
    "-Werror=int-conversion",
)


#: Categories with no -fanalyzer coverage: injection, crypto and
#: randomness weaknesses, which are outside a C memory-safety
#: analyzer's remit.  This is the same list the maintainer has been
#: passing to BenchProctor's own scorer as --skip-categories.
OUT_OF_SCOPE = (
    "cmdi", "ldapi", "pathtraver", "sqli", "ssrf",
    "weakcipher", "weakhash", "weakrand", "xpathi", "xxe",
)


@register
class BenchProctorC(Suite):
    name = "benchproctor-c"

    SUBDIR = Path("Benchmarks/standalone/c/standalone")

    def __init__(self, root: Path, options=None):
        super().__init__(root, options)
        self.base = self.root / self.SUBDIR
        if not self.base.is_dir():
            raise FileNotFoundError(
                f"{self.name}: expected {self.SUBDIR} under {self.root}"
            )
        self.csv_path = self._find_csv()

    def out_of_scope_categories(self) -> List[str]:
        return list(OUT_OF_SCOPE)

    def available_versions(self) -> List[str]:
        return [
            re.sub(r"^expectedresults-|\.csv$", "", p.name)
            for p in sorted(self.base.glob("expectedresults-*.csv"))
        ]

    def _find_csv(self) -> Path:
        candidates = sorted(self.base.glob("expectedresults-*.csv"))
        if not candidates:
            raise FileNotFoundError(
                f"{self.name}: no expectedresults-*.csv in {self.base}"
            )
        want = self.options.get("version")
        if want:
            # Pin to a named release.  BenchProctor rotates its contents
            # between releases, so "whatever is newest" silently changes
            # what a run means; an explicit pin does not.
            for p in candidates:
                if p.name == f"expectedresults-{want}.csv":
                    return p
            raise FileNotFoundError(
                f"{self.name}: no release {want!r} in {self.base}; "
                f"available: {', '.join(self.available_versions())}"
            )
        # Names are date-stamped, so lexicographic max is the newest.
        return candidates[-1]

    def version(self) -> str:
        m = re.search(r"expectedresults-(.+)\.csv$", self.csv_path.name)
        ver = m.group(1) if m else self.csv_path.name
        rev = self._git_describe()
        return f"{ver}+g{rev}" if rev else ver

    def tests(self) -> List[TestCase]:
        out: List[TestCase] = []
        missing: List[str] = []
        with open(self.csv_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 4:
                    continue
                name, category, vuln, cwe = parts[0], parts[1], parts[2], parts[3]
                src = self._source_for(name)
                if src is None:
                    missing.append(name)
                    continue
                out.append(
                    TestCase(
                        suite=self.name,
                        name=name,
                        source=src,
                        compile_args=COMPILE_ARGS,
                        vulnerable=vuln.lower() == "true",
                        cwe=int(cwe) if cwe.isdigit() else None,
                        category=category,
                        lines=(),
                    )
                )
        if missing:
            raise FileNotFoundError(
                f"{self.name}: {len(missing)} CSV rows have no source file "
                f"(first few: {', '.join(missing[:5])})"
            )
        return out

    def _source_for(self, name: str) -> Optional[Path]:
        """BenchmarkTest00001 -> testcode/benchmark_test_00001.c"""
        m = re.fullmatch(r"BenchmarkTest(\d+)", name)
        if not m:
            return None
        p = self.base / "testcode" / f"benchmark_test_{m.group(1)}.c"
        return p if p.is_file() else None
