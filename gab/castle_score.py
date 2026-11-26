# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""The CASTLE Score.

Implements section 3.3 of:

    Dubniczky, Horvat, Bisztray, Ferrag, Cordeiro and Tihanyi,
    "CASTLE: Benchmarking Dataset for Static Code Analyzers and LLMs
    Towards CWE Detection", TASE 2025, doi:10.1007/978-3-031-98208-8_15

The CASTLE repository ships the dataset but no scorer, so this is a
reimplementation from the paper rather than a port of reference code.
That makes it worth stating exactly what the paper says, because the
metric is unlike the rest of `gab`:

    CASTLE(t) = sum over tests of
        5 - (|t(d)| - 1) + B(cwe)   if the test is vulnerable and the
                                    tool reported the correct CWE
        2                           if the test is clean and the tool
                                    reported nothing
        -|t(d)|                     otherwise

where |t(d)| is how many findings the tool reported for that test, and
B is a bonus for CWEs in MITRE's 2024 Top 25:

    B(cwe) = 5 - floor((rank - 1) / 5)   for rank <= 25, else 0

Three consequences worth knowing before reading a number:

* It is **CWE-identity based**.  A tool that finds the right bug at the
  right line but labels it with a different CWE scores as a miss.  This
  is the opposite of `gab`'s default matching rule, which deliberately
  ignores CWE identity -- so the CASTLE Score and `gab score` can and
  will disagree, and both are right about different questions.

* **Extra findings are penalised individually.**  Even on a test the
  tool got right, each additional finding costs a point; on a test it
  got wrong, every finding costs a point.  Noise is expensive.

* **Missing a vulnerability silently costs nothing** -- the penalty is
  -|t(d)|, which is zero when the tool reported nothing at all.  A tool
  that says nothing anywhere scores 2 points per clean test and zero
  elsewhere.  On CASTLE-C250 that floor is 200 points.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from gab.scoring import analyzer_findings

BMAX = 5

#: MITRE's 2024 CWE Top 25, in rank order, exactly as the CASTLE
#: authors' own code lists it (charts.ipynb, `top_25_cwes`).  Rank is
#: the 1-based position.
#:
#: This is reference [30] of the paper, which is what equation (1)
#: says to use.  It is deliberately preferred over the paper's Table 2,
#: which disagrees for nine of the dataset's CWEs: Table 2 assigns a
#: standing to CWE-134, 369, 415, 522, 674, 761, 770, 822 and 835 even
#: though none of them appear in the real list, and puts CWE-798 at 14
#: where MITRE has it at 22.  Table 2 also repeats several ranks.  The
#: authors' code uses the list below, so the list below is what
#: reproduces published scores.
TOP25_2024 = (
    79, 787, 89, 352, 22, 125, 78, 416, 862, 434, 94, 20, 77, 287, 269,
    502, 200, 863, 918, 119, 476, 798, 190, 400, 306,
)

TOP25_RANK: Dict[int, int] = {c: i + 1 for i, c in enumerate(TOP25_2024)}


def bonus(cwe: Optional[int]) -> int:
    """B(cwe) from equation (1)."""
    if cwe is None:
        return 0
    rank = TOP25_RANK.get(cwe)
    if rank is None or rank > 25:
        return 0
    return BMAX - (rank - 1) // BMAX


@dataclass
class TestScore:
    name: str
    cwe: Optional[int]
    vulnerable: bool
    n_findings: int
    correct_cwe_reported: bool
    points: int
    bonus: int = 0
    case: str = ""
    """detected | clean-and-quiet | missed-or-wrong | excluded"""


@dataclass
class CastleResult:
    total: int
    per_test: List[TestScore] = field(default_factory=list)
    excluded: List[str] = field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for t in self.per_test:
            out[t.case] = out.get(t.case, 0) + 1
        return dict(sorted(out.items()))

    @property
    def by_case_points(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for t in self.per_test:
            out[t.case] = out.get(t.case, 0) + t.points
        return dict(sorted(out.items()))

    def as_dict(self) -> dict:
        return {
            "score": self.total,
            "counts": self.counts,
            "points_by_case": self.by_case_points,
            "excluded": self.excluded,
            "reference": "Dubniczky et al., TASE 2025, "
                         "doi:10.1007/978-3-031-98208-8_15, section 3.3",
        }


def reported_cwes(record: dict) -> set:
    out = set()
    for f in analyzer_findings(record):
        for c in f.get("cwes") or []:
            out.add(c)
    return out


def castle_score(records: Sequence[dict], detect: str = "cwe") -> CastleResult:
    """Equation (2) over a run's records.

    `detect` decides the "v_i in t(d_i)" test, which the paper states
    but does not operationalise -- the authors evaluated each tool's
    findings as a separate step, so the published numbers depend on a
    judgement this code cannot see:

      "cwe"   the literal reading: the tool must report a finding
              carrying the ground-truth CWE.  Use this for anything
              you intend to compare against published scores.

      any gab matcher name ("path+1", "line", ...): the tool must
              report a finding at the right place, whatever CWE it
              attaches.  Not the published metric, but it answers
              "did the analyzer find this bug" rather than "did it
              agree about the taxonomy".

    Tests the compiler failed to process at all are excluded rather
    than scored: the paper assumes every benchmark compiles, so an ICE
    or a missing header is outside the metric's domain.  They are
    listed separately so the number is never quietly computed over a
    smaller set than it claims.
    """
    from gab.scoring import BAD_STATUSES, MATCHERS

    matcher = None
    if detect != "cwe":
        try:
            matcher = MATCHERS[detect]
        except KeyError:
            raise KeyError(f"unknown detection rule {detect!r}; use 'cwe' "
                           f"or one of {', '.join(MATCHERS)}") from None

    per_test: List[TestScore] = []
    excluded: List[str] = []
    total = 0

    for rec in records:
        name = rec.get("name", "?")
        if rec.get("status") in BAD_STATUSES:
            excluded.append(name)
            continue

        gt = rec.get("ground_truth") or {}
        vulnerable = bool(gt.get("vulnerable"))
        cwe = gt.get("cwe")
        findings = analyzer_findings(rec)
        n = len(findings)
        if matcher is None:
            correct = (vulnerable and cwe is not None
                       and cwe in reported_cwes(rec))
        else:
            lines = gt.get("lines") or []
            correct = vulnerable and any(
                matcher(f, lines) if lines else True for f in findings)

        if correct:
            b = bonus(cwe)
            points = 5 - (n - 1) + b
            case = "detected"
        elif not vulnerable and n == 0:
            b, points, case = 0, 2, "clean-and-quiet"
        else:
            b, points, case = 0, -n, "missed-or-wrong"

        total += points
        per_test.append(TestScore(
            name=name, cwe=cwe, vulnerable=vulnerable, n_findings=n,
            correct_cwe_reported=correct, points=points, bonus=b,
            case=case))

    return CastleResult(total=total, per_test=per_test, excluded=excluded)


# -- grid view -----------------------------------------------------------

def max_points(cwe: Optional[int], vulnerable: bool) -> int:
    """The best a tool can score on one test.

    A vulnerable test peaks at 5 + B(cwe): the tool reports the right
    CWE and nothing else, so the `-(|t(d)|-1)` term is zero.  A clean
    test peaks at 2, for staying silent.
    """
    return (5 + bonus(cwe)) if vulnerable else 2


@dataclass
class GridCell:
    name: str
    index: Optional[int]
    vulnerable: bool
    points: int
    max_points: int
    case: str

    @property
    def ratio(self) -> float:
        """Score as a fraction of the best possible, clamped to [-1, 1].

        Negative means the tool lost points here -- it reported
        something that was not the flaw under test.
        """
        if self.max_points <= 0:
            return 0.0
        return max(-1.0, min(1.0, self.points / self.max_points))


@dataclass
class GridRow:
    cwe: Optional[int]
    bonus: int
    cells: List[GridCell]

    @property
    def points(self) -> int:
        return sum(c.points for c in self.cells)

    @property
    def max_points(self) -> int:
        return sum(c.max_points for c in self.cells)

    @property
    def ratio(self) -> float:
        return (self.points / self.max_points) if self.max_points else 0.0


_NAME_INDEX = re.compile(r"-(\d+)$")


def grid(result: "CastleResult") -> List[GridRow]:
    """Per-CWE rows of per-test cells.

    CASTLE-C250 is exactly 25 CWEs x 10 tests, the first six of each
    vulnerable, so this lays out as a dense grid with no gaps.  Nothing
    here assumes that: rows are whatever CWEs are present, and cells
    are ordered by the trailing number in the test name where there is
    one, falling back to the order scored.
    """
    rows: Dict[Optional[int], List[GridCell]] = {}
    for t in result.per_test:
        m = _NAME_INDEX.search(t.name)
        rows.setdefault(t.cwe, []).append(GridCell(
            name=t.name,
            index=int(m.group(1)) if m else None,
            vulnerable=t.vulnerable,
            points=t.points,
            max_points=max_points(t.cwe, t.vulnerable),
            case=t.case,
        ))
    out = []
    for cwe in sorted(rows, key=lambda c: (c is None, c or 0)):
        cells = sorted(rows[cwe],
                       key=lambda c: (c.index is None, c.index or 0, c.name))
        out.append(GridRow(cwe=cwe, bonus=bonus(cwe), cells=cells))
    return out
