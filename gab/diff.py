# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Comparing two runs.

This is the artifact that actually validates a patch: not "what does the
analyzer score", but "what did my change do to the analyzer".

Three independent axes are reported, because they fail in different ways
and matter to different degrees:

  * **status** -- a test that used to compile and now ICEs is a serious
    bug, regardless of what it scores.  Reported first and loudest.
  * **outcome** -- FN->TP is an improvement, TP->FN a regression, and
    likewise TN->FP.  This is the scoring axis.
  * **findings** -- the individual diagnostics that appeared or vanished.
    A test can keep the same outcome while the analyzer's reasoning
    changes underneath it, which is exactly what you want to see when
    reviewing your own patch.

Comparability is checked rather than assumed.  Two runs are only
comparable if they used the same suite content: BenchProctor rotates its
contents between releases and deliberately changes filenames, so equal
version strings do not imply equal tests.  The run manifest records a
content hash for this purpose.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Sequence, Tuple

from gab.scoring import (DEFAULT_MATCHER, MATCHERS, Counts, Report, Verdict,
                         classify, score)

#: Metrics shown in the scoring-delta table, with the direction that
#: counts as an improvement.
SCORE_METRICS = (
    ("TP", "higher"), ("FP", "lower"), ("FN", "lower"), ("TN", "higher"),
    ("precision", "higher"), ("recall", "higher"), ("fpr", "lower"),
    ("accuracy", "higher"), ("f1", "higher"),
)

#: Outcome transitions, classified.  Anything not listed is no change.
IMPROVEMENTS = {("FN", "TP"), ("FP", "TN")}
REGRESSIONS = {("TP", "FN"), ("TN", "FP")}


def finding_key(f: dict) -> Tuple:
    """Identity of a finding for churn detection.

    Deliberately excludes the message text: rewording a diagnostic should
    not read as the analyzer finding something different.
    """
    return (f.get("rule"), f.get("line"), f.get("column"))


@dataclass
class TestDelta:
    name: str
    category: Optional[str]
    before: Verdict
    after: Verdict
    new_findings: List[dict] = field(default_factory=list)
    gone_findings: List[dict] = field(default_factory=list)
    repro: List[str] = field(default_factory=list)
    """The exact command line the 'after' run used, so a regression can
    go straight into a debugger."""
    sarif: Optional[str] = None

    @property
    def status_changed(self) -> bool:
        return self.before.status != self.after.status

    @property
    def outcome_changed(self) -> bool:
        return self.before.outcome != self.after.outcome

    @property
    def transition(self) -> Tuple[str, str]:
        return (self.before.outcome, self.after.outcome)

    @property
    def improved(self) -> bool:
        return self.transition in IMPROVEMENTS

    @property
    def regressed(self) -> bool:
        return self.transition in REGRESSIONS

    @property
    def findings_changed(self) -> bool:
        return bool(self.new_findings or self.gone_findings)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "before": {"status": self.before.status,
                       "outcome": self.before.outcome},
            "after": {"status": self.after.status,
                      "outcome": self.after.outcome},
            "new_findings": [
                {"rule": f.get("rule"), "line": f.get("line"),
                 "message": f.get("message")} for f in self.new_findings
            ],
            "gone_findings": [
                {"rule": f.get("rule"), "line": f.get("line"),
                 "message": f.get("message")} for f in self.gone_findings
            ],
            "repro": self.repro,
            "sarif": self.sarif,
        }


@dataclass
class ResourceDelta:
    name: str
    wall_before: float
    wall_after: float
    rss_before: int
    rss_after: int

    @property
    def rss_ratio(self) -> float:
        return (self.rss_after / self.rss_before) if self.rss_before else 1.0

    @property
    def wall_ratio(self) -> float:
        return (self.wall_after / self.wall_before) if self.wall_before else 1.0


@dataclass
class DiffReport:
    matcher: str
    compatible: bool
    incompatibilities: List[str]
    warnings: List[str]
    deltas: List[TestDelta]
    only_in_before: List[str]
    only_in_after: List[str]
    totals_before: dict
    totals_after: dict
    resources: List[ResourceDelta]
    score_before: Optional["Report"] = None
    score_after: Optional["Report"] = None
    suite_before: dict = field(default_factory=dict)
    suite_after: dict = field(default_factory=dict)
    castle_before: Optional[dict] = None
    castle_after: Optional[dict] = None
    castle_rows_before: Optional[list] = None
    castle_rows_after: Optional[list] = None
    castle_meta: dict = field(default_factory=dict)
    """cwe_names and out_of_scope, for rendering the grid."""
    rss_baseline_ratio: float = 1.0
    """Median peak-RSS ratio across all shared tests: the systematic
    difference in footprint between the two compilers.  `resources`
    holds only the tests that moved relative to this."""

    @property
    def improved(self) -> List[TestDelta]:
        return [d for d in self.deltas if d.improved]

    @property
    def regressed(self) -> List[TestDelta]:
        return [d for d in self.deltas if d.regressed]

    @property
    def new_crashes(self) -> List[TestDelta]:
        return [d for d in self.deltas
                if d.after.status in ("ice", "timeout")
                and d.before.status not in ("ice", "timeout")]

    @property
    def fixed_crashes(self) -> List[TestDelta]:
        return [d for d in self.deltas
                if d.before.status in ("ice", "timeout")
                and d.after.status not in ("ice", "timeout")]

    @property
    def other_status_changes(self) -> List[TestDelta]:
        crashes = {id(d) for d in self.new_crashes + self.fixed_crashes}
        return [d for d in self.deltas
                if d.status_changed and id(d) not in crashes]

    @property
    def churn_only(self) -> List[TestDelta]:
        """Same outcome, different diagnostics."""
        return [d for d in self.deltas
                if d.findings_changed and not d.outcome_changed
                and not d.status_changed]

    @property
    def clean(self) -> bool:
        return not (self.regressed or self.new_crashes)

    def score_deltas(self) -> List[dict]:
        """Metric-by-metric movement between the two runs."""
        if not (self.score_before and self.score_after):
            return []
        b, a = self.score_before.overall, self.score_after.overall
        out = []
        for metric, better in SCORE_METRICS:
            vb, va = getattr(b, metric), getattr(a, metric)
            if vb is None and va is None:
                continue
            delta = None if (vb is None or va is None) else va - vb
            direction = "same"
            if delta:
                up = delta > 0
                direction = "better" if (up == (better == "higher")) else "worse"
            out.append({"metric": metric, "before": vb, "after": va,
                        "delta": delta, "direction": direction,
                        "is_rate": metric not in ("TP", "FP", "FN", "TN")})
        return out

    def category_score_deltas(self) -> List[dict]:
        """Per-category recall movement, so a change concentrated in one
        category is visible rather than diluted by the aggregate."""
        if not (self.score_before and self.score_after):
            return []
        cb = self.score_before.by_category
        ca = self.score_after.by_category
        out = []
        for name in sorted(set(cb) | set(ca)):
            b = cb.get(name, Counts())
            a = ca.get(name, Counts())
            if (b.TP, b.FP, b.FN, b.TN) == (a.TP, a.FP, a.FN, a.TN):
                continue
            out.append({
                "category": name,
                "before": b.as_dict(), "after": a.as_dict(),
                "tp_delta": a.TP - b.TP, "fp_delta": a.FP - b.FP,
            })
        return out

    def castle_delta(self) -> Optional[dict]:
        """Movement in the CASTLE Score, when the suite is CASTLE.

        Reported separately from the main scoring table because it is a
        different question: the CASTLE Score is CWE-identity based and
        charges per extra finding, so it can move in the opposite
        direction to recall.
        """
        if not (self.castle_before and self.castle_after):
            return None
        b = self.castle_before["score"]
        a = self.castle_after["score"]
        return {
            "before": b, "after": a, "delta": a - b,
            "detect": self.castle_before.get("detect", "cwe"),
            "direction": ("better" if a > b
                          else "worse" if a < b else "same"),
            "counts_before": self.castle_before.get("counts", {}),
            "counts_after": self.castle_after.get("counts", {}),
        }

    def macro_delta(self) -> Optional[dict]:
        if not (self.score_before and self.score_after):
            return None
        mb, ma = self.score_before.macro, self.score_after.macro
        if mb["score"] is None or ma["score"] is None:
            return None
        return {"before": mb["score"], "after": ma["score"],
                "delta": ma["score"] - mb["score"]}

    def suite_summary(self) -> dict:
        """What was tested, and whether both sides agree it was the same.

        Worth stating explicitly in every report: a diff is only as
        meaningful as the identity of the tests behind it, and the suite
        version alone cannot establish that -- hence the content hash.
        """
        b, a = self.suite_before, self.suite_after
        return {
            "name": b.get("name") or a.get("name"),
            "same_name": b.get("name") == a.get("name"),
            "version_before": b.get("version"),
            "version_after": a.get("version"),
            "same_version": b.get("version") == a.get("version"),
            "content_hash_before": b.get("content_hash"),
            "content_hash_after": a.get("content_hash"),
            "same_content": b.get("content_hash") == a.get("content_hash"),
            "n_tests_compared": len(self.score_before.verdicts)
                                if self.score_before else None,
            "subset": bool(b.get("subset") or a.get("subset")),
        }

    def as_dict(self) -> dict:
        return {
            "matcher": self.matcher,
            "suite": self.suite_summary(),
            "compatible": self.compatible,
            "incompatibilities": self.incompatibilities,
            "warnings": self.warnings,
            "summary": {
                "improved": len(self.improved),
                "regressed": len(self.regressed),
                "new_crashes": len(self.new_crashes),
                "fixed_crashes": len(self.fixed_crashes),
                "other_status_changes": len(self.other_status_changes),
                "churn_only": len(self.churn_only),
                "only_in_before": len(self.only_in_before),
                "only_in_after": len(self.only_in_after),
            },
            "improved": [d.as_dict() for d in self.improved],
            "regressed": [d.as_dict() for d in self.regressed],
            "new_crashes": [d.as_dict() for d in self.new_crashes],
            "fixed_crashes": [d.as_dict() for d in self.fixed_crashes],
            "other_status_changes": [d.as_dict()
                                     for d in self.other_status_changes],
            "churn_only": [d.as_dict() for d in self.churn_only],
            "only_in_before": self.only_in_before,
            "only_in_after": self.only_in_after,
            "scoring": {
                "matcher": self.matcher,
                "before": self.score_before.overall.as_dict()
                          if self.score_before else None,
                "after": self.score_after.overall.as_dict()
                         if self.score_after else None,
                "deltas": self.score_deltas(),
                "by_category": self.category_score_deltas(),
                "category_averaged": self.macro_delta(),
            "castle": self.castle_delta(),
            },
            "resources": {
                "before": self.totals_before,
                "after": self.totals_after,
                "rss_baseline_ratio": self.rss_baseline_ratio,
                "moved": [
                    {"name": r.name, "rss_before": r.rss_before,
                     "rss_after": r.rss_after, "rss_ratio": r.rss_ratio}
                    for r in self.resources
                ],
                "caveats": warnings_for(self.warnings, "perf"),
            },
        }


def check_compatible(mb: dict, ma: dict) -> Tuple[List[str], List[str]]:
    """Reasons two runs should not be compared.

    Returns (errors, warnings).  An error means the comparison is
    meaningless -- different tests, or different compiler flags -- and
    `gab diff` refuses unless forced.  A warning means the numbers are
    real but easy to misread, so the diff proceeds with the caveat
    attached to it.
    """
    errors: List[str] = []
    warnings: List[dict] = []

    def warn(scope: str, message: str) -> None:
        """scope is 'results' or 'perf' -- it decides where the caveat is
        printed, so that a reader meets it next to the numbers it
        undermines rather than in a block at the top they have already
        scrolled past."""
        warnings.append({"scope": scope, "message": message})

    sb, sa = mb.get("suite") or {}, ma.get("suite") or {}

    if sb.get("name") != sa.get("name"):
        errors.append(
            f"different suites: {sb.get('name')} vs {sa.get('name')}"
        )
    elif sb.get("content_hash") != sa.get("content_hash"):
        errors.append(
            "suite content differs between runs "
            f"({(sb.get('content_hash') or '?')[:12]} vs "
            f"{(sa.get('content_hash') or '?')[:12]}); "
            f"versions {sb.get('version')} vs {sa.get('version')}"
        )

    ab = mb.get("analyzer_args", []) + mb.get("extra_args", [])
    aa = ma.get("analyzer_args", []) + ma.get("extra_args", [])
    if ab != aa:
        errors.append(f"different compiler arguments: {ab} vs {aa}")

    tb, ta = mb.get("toolchain") or {}, ma.get("toolchain") or {}
    # Compare the architecture, not the spelling of the triplet: a
    # distro build calls itself x86_64-redhat-linux where a local build
    # says x86_64-pc-linux-gnu, and those are the same target.  Only a
    # genuine architecture difference makes the results incomparable.
    arch_b, arch_a = _target_arch(tb), _target_arch(ta)
    if arch_b and arch_a and arch_b != arch_a:
        errors.append(
            f"different target architectures: {tb.get('target')} vs "
            f"{ta.get('target')}"
        )
    elif tb.get("target") != ta.get("target"):
        warn("results",
             f"target triplets differ in spelling only: {tb.get('target')} "
             f"vs {ta.get('target')}")
    if (tb.get("cc1") or {}).get("sha256") == (ta.get("cc1") or {}).get("sha256") \
            and tb.get("cc1") is not None:
        errors.append("both runs used the identical cc1 binary "
                      "(nothing to compare)")

    # Below here the results are valid; only their interpretation is at
    # risk, so warn rather than refuse.
    if tb.get("build_type") != ta.get("build_type"):
        warn("perf",
             f"different checking levels ({tb.get('build_type')} vs "
             f"{ta.get('build_type')}): timings are not comparable")
    bootstrap_b = (tb.get("bootstrap"), (tb.get("configure_args") or ""))
    bootstrap_a = (ta.get("bootstrap"), (ta.get("configure_args") or ""))
    if bootstrap_b[0] != bootstrap_a[0]:
        warn("perf",
             "one compiler is a bootstrap build and the other is not: "
             "they are built with different optimisation, so timings "
             "reflect the build as much as the analyzer")
    vb, va = tb.get("dumpversion"), ta.get("dumpversion")
    if vb and va and vb.split(".")[0] != va.split(".")[0]:
        warn("results",
             f"different GCC major versions: {vb} vs {va} -- this is a "
             f"release-to-release comparison, not a patch validation")
    skew = _revision_skew(tb, ta)
    if skew:
        warn("results", skew)
    return errors, warnings


def warnings_for(warnings: Sequence[dict], scope: str) -> List[str]:
    return [w["message"] for w in warnings if w.get("scope") == scope]


def _target_arch(t: dict) -> Optional[str]:
    """First component of a target triplet, e.g. 'x86_64' or 'aarch64'."""
    target = t.get("target")
    return target.split("-")[0] if target else None


def _revision_skew(tb: dict, ta: dict) -> Optional[str]:
    """Warn when the two compilers sit at different points on trunk.

    A patched tree is usually branched from an older base than the
    baseline tree it is compared against.  Any difference then conflates
    the patch with every upstream commit in between, which is exactly
    the kind of false attribution that makes a benchmark result
    worthless.  GCC's r<major>-<count> revision naming gives us the
    distance cheaply.
    """
    def rev(t):
        descr = ((t.get("git") or {}).get("gcc_descr") or "")
        m = re.match(r"^r(\d+)-(\d+)", descr)
        return (int(m.group(1)), int(m.group(2))) if m else None

    rb, ra = rev(tb), rev(ta)
    if not rb or not ra or rb == ra:
        return None
    if rb[0] != ra[0]:
        return (f"different GCC major versions: r{rb[0]} vs r{ra[0]}")
    delta = abs(ra[1] - rb[1])
    return (
        f"compilers are {delta} trunk revisions apart "
        f"(r{rb[0]}-{rb[1]} vs r{ra[0]}-{ra[1]}); differences conflate "
        f"the change under test with upstream commits in between"
    )


def diff_runs(
    manifest_before: dict, records_before: Sequence[dict],
    manifest_after: dict, records_after: Sequence[dict],
    matcher_name: str = DEFAULT_MATCHER,
    resource_threshold: float = 1.5,
    categories: Optional[Sequence[str]] = None,
    skip_categories: Optional[Sequence[str]] = None,
    castle_detect: Optional[str] = None,
) -> DiffReport:
    matcher = MATCHERS[matcher_name]

    before = {r["name"]: r for r in records_before}
    after = {r["name"]: r for r in records_after}
    shared = sorted(set(before) & set(after))

    deltas: List[TestDelta] = []
    all_resources: List[ResourceDelta] = []

    for name in shared:
        rb, ra = before[name], after[name]
        vb, va = classify(rb, matcher), classify(ra, matcher)

        fb = {finding_key(f): f for f in (rb.get("findings") or [])
              if f.get("analyzer")}
        fa = {finding_key(f): f for f in (ra.get("findings") or [])
              if f.get("analyzer")}
        new = [fa[k] for k in fa.keys() - fb.keys()]
        gone = [fb[k] for k in fb.keys() - fa.keys()]

        if vb.outcome != va.outcome or vb.status != va.status or new or gone:
            deltas.append(TestDelta(
                name=name,
                category=(rb.get("ground_truth") or {}).get("category"),
                before=vb, after=va,
                new_findings=sorted(new, key=lambda f: (f.get("line") or 0)),
                gone_findings=sorted(gone, key=lambda f: (f.get("line") or 0)),
                repro=list(ra.get("argv") or []),
                sarif=ra.get("sarif"),
            ))

        all_resources.append(ResourceDelta(
            name, rb.get("wall_time", 0.0), ra.get("wall_time", 0.0),
            rb.get("maxrss_kb", 0), ra.get("maxrss_kb", 0)))

    def totals(recs):
        return {
            "cpu_time": round(sum(r.get("user_time", 0.0) + r.get("sys_time", 0.0)
                                  for r in recs), 3),
            "wall_time": round(sum(r.get("wall_time", 0.0) for r in recs), 3),
            "max_maxrss_kb": max((r.get("maxrss_kb", 0) for r in recs),
                                 default=0),
        }

    # Two compilers almost always differ in baseline footprint -- a
    # PGO/LTO distro build against a local -O0 build shifts every test
    # by the same factor.  Flagging all of them says nothing.  Measure
    # each test against the *median* shift instead, so what surfaces is
    # the test that moved differently from its peers.
    ratios = sorted(r.rss_ratio for r in all_resources if r.rss_before)
    baseline = ratios[len(ratios) // 2] if ratios else 1.0
    resources = [
        r for r in all_resources
        if r.rss_before and (
            r.rss_ratio / baseline >= resource_threshold
            or r.rss_ratio / baseline <= 1 / resource_threshold
        )
    ]

    # Score both sides over the *shared* tests only, so the aggregate
    # delta reflects the compiler change and not a difference in which
    # tests were run.
    shared_set = set(shared)
    kw = {"categories": categories, "skip_categories": skip_categories}
    score_before = score([r for r in records_before if r["name"] in shared_set],
                         matcher_name, **kw)
    score_after = score([r for r in records_after if r["name"] in shared_set],
                        matcher_name, **kw)

    castle_b = castle_a = None
    castle_rows_b = castle_rows_a = None
    castle_meta = {}
    suite_meta = manifest_before.get("suite") or {}
    adapter = suite_meta.get("adapter") or suite_meta.get("name")
    if adapter == "castle-c250":
        from gab.castle_score import castle_score as _cs, grid as _grid
        detect = castle_detect or "cwe"
        res_b = _cs([r for r in records_before
                     if r["name"] in shared_set], detect)
        res_a = _cs([r for r in records_after
                     if r["name"] in shared_set], detect)
        castle_b = dict(res_b.as_dict(), detect=detect)
        castle_a = dict(res_a.as_dict(), detect=detect)
        castle_rows_b, castle_rows_a = _grid(res_b), _grid(res_a)
        names = {}
        for k, v in (suite_meta.get("cwe_names") or {}).items():
            try:
                names[int(k)] = v
            except (TypeError, ValueError):
                pass
        castle_meta = {
            "cwe_names": names,
            "out_of_scope": suite_meta.get("out_of_scope_categories") or [],
        }

    errors, warnings = check_compatible(manifest_before, manifest_after)
    return DiffReport(
        castle_before=castle_b,
        castle_after=castle_a,
        castle_rows_before=castle_rows_b,
        castle_rows_after=castle_rows_a,
        castle_meta=castle_meta,
        score_before=score_before,
        score_after=score_after,
        suite_before=manifest_before.get("suite") or {},
        suite_after=manifest_after.get("suite") or {},
        matcher=matcher_name,
        incompatibilities=errors,
        warnings=warnings,
        compatible=not errors,
        deltas=deltas,
        only_in_before=sorted(set(before) - set(after)),
        only_in_after=sorted(set(after) - set(before)),
        totals_before=totals(list(before.values())),
        totals_after=totals(list(after.values())),
        resources=sorted(resources, key=lambda r: -r.rss_ratio),
        rss_baseline_ratio=baseline,
    )
