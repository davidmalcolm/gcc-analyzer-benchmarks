# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Turning a run directory into true/false positives and negatives.

Scoring never runs a compiler.  It reads the records written by `gab
run`, which embed both the findings and the ground truth, so a run can
be re-scored under a different matching rule as often as you like.

Matching rules
--------------

What counts as "the analyzer detected this flaw" is the one genuinely
contentious choice in the whole harness, so it is selectable rather than
baked in, and every report says which rule produced it.

The interesting case is a leak.  Ground truth typically marks the
allocation site, while GCC reports the point where the last reference
dies -- a `return`, or the closing brace of the function.  Those are
different line numbers for the same bug.  Rather than paper over it with
a tolerance window, the `path` rules look at the diagnostic's codeFlow:
the allocation site is in the event path even when it is not the primary
location, so the match is exact rather than approximate.

Asymmetry between the vulnerable and non-vulnerable halves is
deliberate.  A file labelled vulnerable is detected only if a finding
lands on the flaw.  A file labelled non-vulnerable should produce *no*
analyzer report at all, so any finding in one is a false positive --
line matching cannot apply, as there is no ground-truth line to match
against.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

Matcher = Callable[[dict, Sequence[int]], bool]


def _primary_within(finding: dict, lines: Sequence[int], tol: int) -> bool:
    ln = finding.get("line")
    return ln is not None and any(abs(ln - L) <= tol for L in lines)


def _path_hits(finding: dict, lines: Sequence[int]) -> bool:
    return bool(set(finding.get("path_lines") or []) & set(lines))


MATCHERS: Dict[str, Matcher] = {
    # Any analyzer report anywhere in the file.  Generous: it credits
    # the analyzer for finding a different bug than the one under test.
    "file": lambda f, lines: True,
    # The primary location is exactly on a ground-truth line.
    "line": lambda f, lines: _primary_within(f, lines, 0),
    # ... or within two lines of one.
    "line2": lambda f, lines: _primary_within(f, lines, 2),
    # The diagnostic's event path touches a ground-truth line.
    "path": _path_hits,
    # Either of the above: handles the leak convention via the path, and
    # loop-header-vs-body style off-by-ones via the primary location.
    "path+1": lambda f, lines: _path_hits(f, lines) or _primary_within(f, lines, 1),
}

DEFAULT_MATCHER = "path+1"

#: Statuses that mean the compiler did not deliver a usable verdict.
#: These are excluded from the confusion matrix -- counting a crash as a
#: missed detection would quietly hide it.
BAD_STATUSES = frozenset({"ice", "timeout", "compile-error", "spawn-error",
                          "bad-sarif"})


def analyzer_findings(record: dict) -> List[dict]:
    return [f for f in record.get("findings") or []
            if f.get("analyzer") and not f.get("meta")]


@dataclass
class Verdict:
    name: str
    category: Optional[str]
    vulnerable: bool
    status: str
    outcome: str
    """TP | FP | FN | TN | excluded"""
    n_findings: int = 0
    matched: List[dict] = field(default_factory=list)
    unmatched: List[dict] = field(default_factory=list)

    @property
    def scored(self) -> bool:
        return self.outcome != "excluded"


def classify(record: dict, matcher: Matcher) -> Verdict:
    gt = record.get("ground_truth") or {}
    status = record.get("status", "ok")
    vulnerable = bool(gt.get("vulnerable"))
    category = gt.get("category")
    findings = analyzer_findings(record)

    if status in BAD_STATUSES:
        return Verdict(record["name"], category, vulnerable, status,
                       "excluded", len(findings))

    lines = gt.get("lines") or []
    if vulnerable:
        if lines:
            matched = [f for f in findings if matcher(f, lines)]
        else:
            # No line-level truth (BenchProctor): fall back to file level.
            matched = list(findings)
        unmatched = [f for f in findings if f not in matched]
        outcome = "TP" if matched else "FN"
    else:
        # Any report on a clean file is a false positive.
        matched = []
        unmatched = list(findings)
        outcome = "FP" if findings else "TN"

    return Verdict(record["name"], category, vulnerable, status, outcome,
                   len(findings), matched, unmatched)


@dataclass
class Counts:
    TP: int = 0
    FP: int = 0
    FN: int = 0
    TN: int = 0
    excluded: int = 0

    def add(self, outcome: str) -> None:
        setattr(self, outcome, getattr(self, outcome) + 1)

    @property
    def scored(self) -> int:
        return self.TP + self.FP + self.FN + self.TN

    @property
    def precision(self) -> Optional[float]:
        d = self.TP + self.FP
        return self.TP / d if d else None

    @property
    def recall(self) -> Optional[float]:
        """True positive rate."""
        d = self.TP + self.FN
        return self.TP / d if d else None

    @property
    def fpr(self) -> Optional[float]:
        d = self.FP + self.TN
        return self.FP / d if d else None

    @property
    def accuracy(self) -> Optional[float]:
        return (self.TP + self.TN) / self.scored if self.scored else None

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if not p or not r:
            return None
        return 2 * p * r / (p + r)

    def as_dict(self) -> dict:
        return {
            "TP": self.TP, "FP": self.FP, "FN": self.FN, "TN": self.TN,
            "excluded": self.excluded,
            "precision": self.precision, "recall": self.recall,
            "fpr": self.fpr, "accuracy": self.accuracy, "f1": self.f1,
        }


@dataclass
class Report:
    matcher: str
    overall: Counts
    by_category: Dict[str, Counts]
    verdicts: List[Verdict]
    scope: dict
    excluded: List[Verdict]

    @property
    def macro(self) -> dict:
        """Category-averaged TPR and FPR, and TPR-FPR.

        This is BenchProctor's own headline metric.  Averaging per
        category rather than over all tests stops a large category from
        drowning out a small one.
        """
        tprs = [c.recall for c in self.by_category.values() if c.recall is not None]
        fprs = [c.fpr for c in self.by_category.values() if c.fpr is not None]
        tpr = sum(tprs) / len(tprs) if tprs else None
        fpr = sum(fprs) / len(fprs) if fprs else None
        return {
            "tpr": tpr,
            "fpr": fpr,
            "score": (tpr - fpr) if (tpr is not None and fpr is not None) else None,
            "n_categories": len(self.by_category),
        }

    def as_dict(self) -> dict:
        return {
            "matcher": self.matcher,
            "scope": self.scope,
            "overall": self.overall.as_dict(),
            "category_averaged": self.macro,
            "by_category": {k: v.as_dict()
                            for k, v in sorted(self.by_category.items())},
            "excluded": [
                {"name": v.name, "status": v.status} for v in self.excluded
            ],
        }


def score(
    records: Sequence[dict],
    matcher_name: str = DEFAULT_MATCHER,
    categories: Optional[Sequence[str]] = None,
    skip_categories: Optional[Sequence[str]] = None,
) -> Report:
    try:
        matcher = MATCHERS[matcher_name]
    except KeyError:
        raise KeyError(
            f"unknown matcher {matcher_name!r}; "
            f"known: {', '.join(MATCHERS)}"
        ) from None

    keep = set(categories) if categories else None
    drop = set(skip_categories) if skip_categories else set()

    overall = Counts()
    by_category: Dict[str, Counts] = {}
    verdicts: List[Verdict] = []
    excluded: List[Verdict] = []
    n_in_scope = 0

    for rec in records:
        cat = (rec.get("ground_truth") or {}).get("category")
        if keep is not None and cat not in keep:
            continue
        if cat in drop:
            continue
        n_in_scope += 1
        v = classify(rec, matcher)
        verdicts.append(v)
        overall.add(v.outcome)
        bucket = by_category.setdefault(cat or "(uncategorised)", Counts())
        bucket.add(v.outcome)
        if not v.scored:
            excluded.append(v)

    return Report(
        matcher=matcher_name,
        overall=overall,
        by_category=by_category,
        verdicts=verdicts,
        excluded=excluded,
        scope={
            "categories": sorted(keep) if keep else None,
            "skip_categories": sorted(drop) if drop else None,
            "n_tests_scored": n_in_scope,
            "n_tests_available": len(records),
        },
    )


def compare_matchers(records: Sequence[dict], **kwargs) -> Dict[str, Counts]:
    """Every matching rule's confusion matrix, for seeing how much the
    choice of rule is driving the headline number."""
    return {name: score(records, name, **kwargs).overall for name in MATCHERS}
