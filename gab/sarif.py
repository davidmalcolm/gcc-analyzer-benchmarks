# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Reading GCC's SARIF output.

GCC is unusually cooperative here: each result carries `taxa[].id` holding
the bare CWE number, so a finding's CWE never has to be scraped out of a
rule name.  It also tags analyzer results with
`properties["gcc/analyzer/pending_diagnostic/kind"]`, which is a more
stable handle on "what kind of bug" than the user-facing warning name.

We distil each SARIF into a small flat list of findings and store that in
the run record, so scoring never has to re-parse SARIF.  The raw SARIF is
kept alongside for when you need the full event path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ANALYZER_PREFIX = "-Wanalyzer-"

#: Analyzer diagnostics that report a property of the *analysis* rather
#: than a bug in the code.  They must never count as a detection.
META_RULES = frozenset(
    {
        "-Wanalyzer-too-complex",
        "-Wanalyzer-symbol-too-complex",
    }
)


def _cwes_from_result(result: dict) -> List[int]:
    out = []
    for tx in result.get("taxa") or []:
        tid = tx.get("id")
        if isinstance(tid, str) and tid.isdigit():
            out.append(int(tid))
        elif isinstance(tid, int):
            out.append(tid)
    return sorted(set(out))


def _primary_location(result: dict) -> Dict[str, Any]:
    for loc in result.get("locations") or []:
        phys = loc.get("physicalLocation") or {}
        art = phys.get("artifactLocation") or {}
        region = phys.get("region") or {}
        return {
            "uri": art.get("uri"),
            "line": region.get("startLine"),
            "column": region.get("startColumn"),
        }
    return {"uri": None, "line": None, "column": None}


def _path_lines(result: dict) -> List[int]:
    """Every source line touched by the diagnostic's event path.

    This is what the analyzer was "thinking about" on the way to the
    report, and it matters for scoring: GCC reports a leak at the point
    the last reference dies (a `return`, or the closing brace), while
    benchmarks typically mark the allocation site.  Those are different
    line numbers for the same bug, but the allocation site is always in
    the event path, so path-aware matching needs no fudge factor.
    """
    lines = set()
    for cf in result.get("codeFlows") or []:
        for tf in cf.get("threadFlows") or []:
            for loc in tf.get("locations") or []:
                phys = ((loc.get("location") or {}).get("physicalLocation") or {})
                ln = (phys.get("region") or {}).get("startLine")
                if isinstance(ln, int):
                    lines.add(ln)
    return sorted(lines)


def parse_findings(path: Path) -> List[dict]:
    """Flatten a SARIF file into a list of finding dicts.

    Raises ValueError if the file is not parseable -- a truncated SARIF
    usually means the compiler died partway, which the caller wants to
    know about rather than silently score as "no findings".
    """
    doc = _load(path)
    findings: List[dict] = []
    for run in doc.get("runs") or []:
        for result in run.get("results") or []:
            rule = result.get("ruleId") or ""
            loc = _primary_location(result)
            findings.append(
                {
                    "rule": rule,
                    "analyzer": rule.startswith(ANALYZER_PREFIX),
                    "meta": rule in META_RULES,
                    "level": result.get("level"),
                    "cwes": _cwes_from_result(result),
                    "kind": (result.get("properties") or {}).get(
                        "gcc/analyzer/pending_diagnostic/kind"
                    ),
                    "line": loc["line"],
                    "column": loc["column"],
                    "uri": loc["uri"],
                    "path_lines": _path_lines(result),
                    "message": ((result.get("message") or {}).get("text") or "")[:400],
                }
            )
    return findings


def _load(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"{path}: malformed SARIF: {e}") from None


#: Timevars worth keeping out of a -ftime-report.  Everything matching
#: "analyzer*" is kept too; this is just the non-analyzer context.
_KEEP_TIMEVARS = ("TOTAL",)


def parse_invocation(path: Path) -> dict:
    """Pull per-compilation facts out of SARIF's `invocations`.

    GCC records the cc1 command line, start/end time and
    `executionSuccessful` here, and -- with -ftime-report -- a
    `gcc/timeReport` property bag of timevars.  The analyzer's own
    timevars ("analyzer: processing worklist" and friends) are the only
    way to separate analysis cost from the rest of the compile.

    The ggc_mem figures in that bag are deliberately dropped: they cover
    only GCC's garbage-collected heap, which is close to irrelevant for
    -fanalyzer.  Peak RSS from wait4 is the number that matters.
    """
    out: dict = {}
    try:
        doc = _load(path)
    except (ValueError, OSError):
        return out
    for run in doc.get("runs") or []:
        for inv in run.get("invocations") or []:
            out["execution_successful"] = inv.get("executionSuccessful")
            out["start_time"] = inv.get("startTimeUtc")
            out["end_time"] = inv.get("endTimeUtc")
            notifications = inv.get("toolExecutionNotifications") or []
            if notifications:
                # Where GCC's crash handler would leave a backtrace.
                out["notifications"] = [
                    ((n.get("message") or {}).get("text") or "")[:2000]
                    for n in notifications
                ]
            tr = (inv.get("properties") or {}).get("gcc/timeReport")
            if tr:
                timevars = {}
                for tv in tr.get("timevars") or []:
                    name = tv.get("name") or ""
                    if name.startswith("analyzer") or name in _KEEP_TIMEVARS:
                        wall = (tv.get("elapsed") or {}).get("wall")
                        if wall is not None:
                            timevars[name] = wall
                if timevars:
                    out["timevars"] = timevars
                    out["analyzer_wall"] = round(
                        sum(v for k, v in timevars.items()
                            if k.startswith("analyzer")), 6
                    )
            return out
    return out


def real_analyzer_findings(findings: List[dict]) -> List[dict]:
    """Analyzer findings that are claims about the code, not about the
    analysis itself."""
    return [f for f in findings if f.get("analyzer") and not f.get("meta")]
