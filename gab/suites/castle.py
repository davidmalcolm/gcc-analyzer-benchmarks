# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""CASTLE-C250.

https://github.com/CASTLE-Benchmark/CASTLE-Benchmark

MIT licensed.  Cite Dubniczky et al., TASE 2025,
doi:10.1007/978-3-031-98208-8_15 -- see CITATIONS.md.

250 hand-written C files over 25 CWEs, 150 of them vulnerable.  Ground
truth is a single JSON file carrying, per test, `vulnerable`, `cwe` and
`lines` (the offending line numbers) -- so this suite supports line-level
scoring, unlike BenchProctor.  The JSON also ships a CWE hierarchy, which
we expose for scorers that want to accept a parent or child of the
expected CWE.

The suite's own compile command is a bare `gcc foo.c -o foo`, which no
longer works: these files were written against a pre-C23 compiler, and a
handful of them encode flaws that modern GCC rejects in the front end
(CASTLE-822-1 trips -Wint-conversion, CASTLE-843-2 trips
-Wincompatible-pointer-types -- both are the vulnerability itself).  We
compile as gnu17 and downgrade exactly those errors back to warnings, so
that -fanalyzer actually gets a chance to run on them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from gab.suite import Suite, TestCase, register

COMPILE_ARGS = (
    # These files predate C23: some use `nullptr` as an ordinary identifier.
    "-std=gnu17",
    # GCC 14 promoted these to errors.  Several CASTLE tests *are* the
    # error, so the analyzer would never see them otherwise.
    "-Wno-error=implicit-function-declaration",
    "-Wno-error=int-conversion",
    "-Wno-error=incompatible-pointer-types",
    "-Wno-error=implicit-int",
    "-Wno-error=return-mismatch",
)


#: CASTLE CWEs that -fanalyzer does not attempt.  Injection, crypto,
#: credential-handling and concurrency weaknesses are outside a C
#: memory-safety analyzer's remit, so a miss there says nothing about
#: analyzer quality.
#:
#: MAINTAINER: this is a judgement call about what -fanalyzer is *for*,
#: and it is the one list in this file worth arguing about.  Borderline
#: cases deliberately left IN scope, because the analyzer has or could
#: have something to say: CWE-134 (format string, reachable via taint
#: mode), 253, 628, 674, 761, 770, 822.
OUT_OF_SCOPE_CWES = (22, 78, 89, 327, 362, 522, 798, 843)


@register
class CastleC250(Suite):
    name = "castle-c250"

    JSON = Path("datasets/CASTLE-C250.json")
    SRCDIR = Path("datasets/CASTLE-C250")

    def __init__(self, root: Path, options=None):
        super().__init__(root, options)
        self.json_path = self.root / self.JSON
        self.srcdir = self.root / self.SRCDIR
        if not self.json_path.is_file():
            raise FileNotFoundError(f"{self.name}: missing {self.json_path}")
        if not self.srcdir.is_dir():
            raise FileNotFoundError(f"{self.name}: missing {self.srcdir}")
        with open(self.json_path, encoding="utf-8") as f:
            self._data = json.load(f)

    def version(self) -> str:
        ver = self._data.get("version", "?")
        rev = self._git_describe()
        return f"{ver}+g{rev}" if rev else str(ver)

    def tests(self) -> List[TestCase]:
        out: List[TestCase] = []
        missing: List[str] = []
        for t in self._data.get("tests", []):
            fname = t["name"]                 # e.g. "CASTLE-22-1.c"
            src = self.srcdir / fname
            if not src.is_file():
                missing.append(fname)
                continue
            cwe = t.get("cwe")
            out.append(
                TestCase(
                    suite=self.name,
                    name=fname[:-2] if fname.endswith(".c") else fname,
                    source=src,
                    compile_args=COMPILE_ARGS,
                    vulnerable=bool(t.get("vulnerable")),
                    cwe=int(cwe) if cwe is not None else None,
                    # CASTLE has no category axis; use the CWE so that
                    # per-category reporting still says something useful.
                    category=f"CWE-{cwe}" if cwe is not None else None,
                    lines=tuple(int(n) for n in (t.get("lines") or [])),
                )
            )
        if missing:
            raise FileNotFoundError(
                f"{self.name}: {len(missing)} tests have no source file "
                f"(first few: {', '.join(missing[:5])})"
            )
        return out

    def out_of_scope_categories(self) -> List[str]:
        return [f"CWE-{c}" for c in OUT_OF_SCOPE_CWES]

    def cwe_names(self) -> Dict[int, str]:
        """CWE -> short name, from the dataset's own taxonomy."""
        out = {}
        for cwe_str, info in (self._data.get("cwes") or {}).items():
            try:
                out[int(cwe_str)] = info.get("name") or ""
            except (TypeError, ValueError):
                pass
        return {k: v for k, v in out.items() if v}

    def cwe_parents(self) -> Dict[int, List[int]]:
        """child CWE -> parent CWEs, from the dataset's own taxonomy."""
        out: Dict[int, List[int]] = {}
        for cwe_str, info in (self._data.get("cwes") or {}).items():
            try:
                cwe = int(cwe_str)
            except (TypeError, ValueError):
                continue
            parents: List[int] = []
            for p in info.get("parents") or []:
                for k in p:
                    try:
                        parents.append(int(k))
                    except (TypeError, ValueError):
                        pass
            if parents:
                out[cwe] = parents
        return out
