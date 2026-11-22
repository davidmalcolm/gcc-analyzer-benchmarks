# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""HTML rendering.

Self-contained single-file output: styles are inlined and there are no
scripts, fonts or images, so a report can be mailed, attached to a bug,
or opened straight off disk years later and still render.

The colour language matches the terminal output deliberately -- green
for an improvement, red for a regression or a crash -- so the same
result reads the same way whichever format you looked at.
"""

from __future__ import annotations

import html
import re
from datetime import datetime
from typing import Iterable, List, Optional, Sequence

STYLE = """
:root { color-scheme: light dark; }
body { font: 14px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 70rem;
       padding: 0 1rem; }
h1 { font-size: 1.4rem; margin-bottom: 0.2rem; }
h2 { font-size: 1.1rem; margin-top: 2rem; border-bottom: 1px solid #8884;
     padding-bottom: 0.2rem; }
table { border-collapse: collapse; margin: 0.6rem 0; }
th, td { padding: 0.2rem 0.7rem 0.2rem 0; text-align: left;
         border-bottom: 1px solid #8882; }
th { font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
code, .mono { font-family: ui-monospace, monospace; font-size: 0.92em; }
.good { color: #0a7a28; }
.bad { color: #c02020; }
.alarm { color: #fff; background: #c02020; padding: 0.1rem 0.4rem;
         border-radius: 3px; font-weight: 600; }
.muted { color: #8889; }
a.good, a.good:visited { color: #0a7a28; }
a.bad, a.bad:visited { color: #c02020; }
a.muted, a.muted:visited { color: #8889; }
a.alarm, a.alarm:visited { color: #fff; }
.caveat { background: #fff6d5; border-left: 3px solid #e0b000;
          padding: 0.5rem 0.8rem; margin: 0.6rem 0; }
.repro { font-family: ui-monospace, monospace; font-size: 0.82em;
         color: #8889; word-break: break-all; }
.meta td:first-child { color: #8889; padding-right: 1.2rem; }

/* Disclosure sections. */
details.sect { margin: 1.2rem 0; }
details.sect > summary { font-size: 1.1rem; font-weight: 600;
    cursor: pointer; padding: 0.25rem 0; border-bottom: 1px solid #8884;
    list-style-position: outside; }
details.sect > summary:hover { background: #8881; }
details.sect > .inner { padding-left: 0.2rem; }
details.suite > summary { font-size: 1.25rem; margin-top: 1rem;
    border-bottom: 2px solid #8886; }
summary .count { font-weight: 400; color: #8889; }
a.anchor { text-decoration: none; color: #8886; margin-left: 0.5rem;
    font-weight: 400; opacity: 0; }
summary:hover a.anchor, h2:hover a.anchor { opacity: 1; }
:target > summary { background: #e0b00033; }
nav.toc { margin: 0.8rem 0 1.5rem; padding: 0.6rem 0.9rem;
    border: 1px solid #8884; border-radius: 4px; }
nav.toc ul { margin: 0.3rem 0; padding-left: 1.2rem; }
nav.toc a { text-decoration: none; }
nav.toc a:hover { text-decoration: underline; }
.controls { margin: 0.5rem 0; }
.controls a { font-size: 0.85em; color: #8889; margin-right: 0.8rem; }

@media (prefers-color-scheme: dark) {
  .good, a.good, a.good:visited { color: #4ad06a; }
  .bad, a.bad, a.bad:visited { color: #ff6b6b; }
  .caveat { background: #3a3000; border-left-color: #e0b000; }
}
@media print { details.sect { display: block; } details.sect > .inner
    { display: block !important; } }
"""


def slug(*parts) -> str:
    """A stable, URL-safe id built from the given parts.

    Ids are namespaced by suite in a grouped report so that two suites'
    "regressed" sections do not collide.
    """
    text = "-".join(str(p) for p in parts if p)
    out = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return out or "section"


def section(title: str, inner: str, anchor: str, *, open_: bool = True,
            count: Optional[int] = None, cls: str = "",
            kind: str = "sect") -> str:
    """A collapsible, linkable section.

    Uses <details>/<summary> so expand/collapse needs no JavaScript, and
    carries the id on the <details> element so that the URL fragment
    addresses the whole section rather than just its heading.
    """
    if not inner:
        return ""
    label = esc(title)
    if count is not None:
        label += f" <span class=\"count\">({count})</span>"
    classes = f"{kind} {cls}".strip()
    return (
        f"<details class=\"{classes}\" id=\"{esc(anchor)}\""
        f"{' open=\"open\"' if open_ else ''}>"
        f"<summary>{label}"
        f"<a class=\"anchor\" href=\"#{esc(anchor)}\" "
        f"title=\"link to this section\">#</a></summary>"
        f"<div class=\"inner\">{inner}</div></details>"
    )


def toc(entries: Sequence[tuple]) -> str:
    """Table of contents from (anchor, label) pairs."""
    entries = [e for e in entries if e]
    if not entries:
        return ""
    items = "".join(
        f"<li><a href=\"#{esc(a)}\">{esc(label)}</a></li>"
        for a, label in entries
    )
    return f"<nav class=\"toc\"><strong>Contents</strong><ul>{items}</ul></nav>"


def esc(x) -> str:
    return html.escape("" if x is None else str(x))


def document(title: str, body: str) -> str:
    """Wrap a body in a complete, self-contained page.

    The generator and timestamp go in both a <meta> tag and a visible
    footer: a report attached to a bug outlives the tool that made it,
    and the first question about an old one is always which version
    produced it.

    Deliberately *not* included: the hostname.  These reports are meant
    to be attachable to a public bug report, and the run directory
    already records the host for anyone who needs it locally.
    """
    from gab import __version__

    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    generator = f"gab {__version__}"
    footer = (f"<hr /><p class=\"muted\">Generated by "
              f"<strong>{esc(generator)}</strong> on {esc(stamp)}.</p>")
    return (
        "<!DOCTYPE html>\n"
        "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\">\n<head>\n"
        "<meta charset=\"utf-8\" />\n"
        "<meta name=\"viewport\" content=\"width=device-width, "
        "initial-scale=1\" />\n"
        f"<meta name=\"generator\" content=\"{esc(generator)}\" />\n"
        f"<meta name=\"date\" content=\"{esc(stamp)}\" />\n"
        f"<title>{esc(title)}</title>\n<style>{STYLE}</style>\n"
        f"</head>\n<body>\n<h1>{esc(title)}</h1>\n{body}\n{footer}\n"
        "</body>\n</html>\n"
    )


def meta_table(rows: Sequence[tuple]) -> str:
    cells = "".join(
        f"<tr><td>{esc(k)}</td><td class=\"mono\">{esc(v)}</td></tr>"
        for k, v in rows if v is not None
    )
    return f"<table class=\"meta\">{cells}</table>"


def table(headers: Sequence[str], rows: Iterable[Sequence],
          numeric: Sequence[int] = ()) -> str:
    def cls(i):
        return " class=\"num\"" if i in numeric else ""
    head = "".join(f"<th{cls(i)}>{esc(h)}</th>" for i, h in enumerate(headers))
    body = []
    for row in rows:
        tds = "".join(f"<td{cls(i)}>{c}</td>" for i, c in enumerate(row))
        body.append(f"<tr>{tds}</tr>")
    if not body:
        return ""
    return (f"<table><thead><tr>{head}</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table>")


def caveats(messages: Sequence[str], heading: str = "Caveats") -> str:
    if not messages:
        return ""
    items = "".join(f"<li>{esc(m)}</li>" for m in messages)
    return (f"<div class=\"caveat\"><strong>{esc(heading)}</strong>"
            f"<ul>{items}</ul></div>")


def pct(x) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def signed(x, is_rate: bool) -> str:
    if x is None:
        return ""
    if is_rate:
        return f"{x * 100:+.1f}pp"
    return f"{x:+d}" if isinstance(x, int) else f"{x:+.3f}"


def tint(text: str, direction: str) -> str:
    """Wrap text in the class matching a 'better'/'worse'/'same' verdict."""
    if direction == "better":
        return f"<span class=\"good\">{text}</span>"
    if direction == "worse":
        return f"<span class=\"bad\">{text}</span>"
    return text


# -- whole-report renderers ---------------------------------------------

def render_score(report, manifest: dict, run_dir: str) -> str:
    tc = manifest.get("toolchain") or {}
    suite = manifest.get("suite") or {}
    body, entries = _score_body(report, manifest, run_dir, prefix="")
    title = f"gab score -- {suite.get('name')} / {tc.get('name')}"
    return document(title, toc(entries) + body)


def _score_body(report, manifest: dict, run_dir: str, prefix: str):
    """Body fragment plus (anchor, label) pairs for a table of contents."""
    tc = manifest.get("toolchain") or {}
    suite = manifest.get("suite") or {}
    c = report.overall
    m = report.macro
    parts, entries = [], []

    def add(title, inner, key, **kw):
        anchor = slug(prefix, key)
        html_ = section(title, inner, anchor, **kw)
        if html_:
            parts.append(html_)
            entries.append((anchor, title))

    parts.append(meta_table([
        ("run", run_dir),
        ("toolchain", f"{tc.get('name')} -- {tc.get('version')}"),
        ("build", f"{tc.get('build_type')} (-fchecking={tc.get('fchecking')})"),
        ("target", tc.get("target")),
        ("suite", f"{suite.get('name')} v{suite.get('version')}"
                  + ("  [subset]" if suite.get("subset") else "")),
        ("suite content", (suite.get("content_hash") or "")[:16]),
        ("matcher", report.matcher),
        ("scope", f"{report.scope['n_tests_scored']} of "
                  f"{report.scope['n_tests_available']} tests"),
    ]))

    score_txt = "n/a" if m["score"] is None else f"{m['score']:+.3f}"
    add("Overall", table(
        ["TP", "FP", "FN", "TN", "precision", "recall", "FPR", "accuracy",
         "F1"],
        [[c.TP, c.FP, c.FN, c.TN, pct(c.precision), pct(c.recall),
          pct(c.fpr), pct(c.accuracy), pct(c.f1)]],
        numeric=range(9))
        + f"<p>Category-averaged over {m['n_categories']} categories: "
          f"TPR {pct(m['tpr'])}, FPR {pct(m['fpr'])}, "
          f"score <strong>{esc(score_txt)}</strong></p>", "overall")

    if report.excluded:
        by_status = {}
        for v in report.excluded:
            by_status.setdefault(v.status, []).append(v.name)
        add("Excluded from scoring",
            "<p><span class=\"alarm\">the compiler did not deliver a "
            "verdict for these</span></p>"
            + table(["status", "count", "tests"],
                    [[esc(st), len(n),
                      f"<span class=\"mono\">{esc(', '.join(n[:20]))}</span>"]
                     for st, n in sorted(by_status.items())], numeric=[1]),
            "excluded", cls="bad")

    add("By category", table(
        ["category", "TP", "FP", "FN", "TN", "recall", "precision"],
        [[esc(name), cc.TP, cc.FP, cc.FN, cc.TN, pct(cc.recall),
          pct(cc.precision)]
         for name, cc in sorted(report.by_category.items())],
        numeric=[1, 2, 3, 4, 5, 6]), "by-category")

    return "\n".join(parts), entries


def render_score_group(reports, group_manifest: dict, root: str) -> str:
    """Score report for a multi-suite run: a summary then one section
    per suite, each independently linkable and collapsible."""
    tc = group_manifest.get("toolchain") or {}
    parts, entries = [], []

    parts.append(meta_table([
        ("run", root),
        ("toolchain", f"{tc.get('name')} -- {tc.get('version')}"),
        ("build", tc.get("build_type")),
        ("matcher", reports[0][3].matcher if reports else None),
        ("suites", ", ".join(name for name, _, _, _ in reports)),
    ]))

    rows, totals = [], {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for name, _child, manifest, rep in reports:
        c, m = rep.overall, rep.macro
        for k in totals:
            totals[k] += getattr(c, k)
        su = manifest.get("suite") or {}
        rows.append([
            f"<a href=\"#{esc(slug(name))}\">{esc(name)}</a>",
            esc(su.get("version")), rep.scope["n_tests_scored"],
            c.TP, c.FP, c.FN, c.TN, pct(c.recall), pct(c.precision),
            "n/a" if m["score"] is None else f"{m['score']:+.3f}"])

    summary_anchor = slug("summary")
    parts.append(section(
        "Per suite",
        table(["suite", "version", "tests", "TP", "FP", "FN", "TN",
               "recall", "precision", "macro"], rows,
              numeric=[2, 3, 4, 5, 6, 7, 8, 9])
        + f"<p class=\"muted\">Combined: TP {totals['TP']}, "
          f"FP {totals['FP']}, FN {totals['FN']}, TN {totals['TN']} -- a "
          f"flat sum, so the largest suite dominates it; prefer the "
          f"per-suite rows.</p>",
        summary_anchor))
    entries.append((summary_anchor, "Per suite"))

    for name, child, manifest, rep in reports:
        inner, _ = _score_body(rep, manifest, str(child), prefix=name)
        anchor = slug(name)
        parts.append(section(name, inner, anchor, kind="sect suite"))
        entries.append((anchor, name))

    return document(f"gab score -- {tc.get('name')} (all suites)",
                    toc(entries) + "\n".join(parts))


def _delta_rows(report):
    for d in report.score_deltas():
        is_rate = d["is_rate"]
        before = pct(d["before"]) if is_rate else d["before"]
        after = pct(d["after"]) if is_rate else d["after"]
        yield [esc(d["metric"]), before, after,
               tint(esc(signed(d["delta"], is_rate)), d["direction"])]


def diff_title(mb: dict, ma: dict) -> str:
    tb = (mb.get("toolchain") or {}).get("name")
    ta = (ma.get("toolchain") or {}).get("name")
    return f"gab diff -- {tb} vs {ta}"


def render_diff(report, mb: dict, ma: dict, perf_caveats, result_caveats,
                show_all: bool = False) -> str:
    body, entries = _diff_body(report, mb, ma, perf_caveats,
                               result_caveats, show_all, prefix="")
    return document(diff_title(mb, ma), toc(entries) + body)


def render_diff_group(items, group_before: dict, group_after: dict) -> str:
    """One document for a multi-suite diff.

    Each suite becomes a top-level section named after the benchmark,
    with its own anchor, so a reviewer can link straight to
    `#castle-c250` or to `#castle-c250-regressed`.
    """
    parts, entries = [], []
    tb = (group_before.get("toolchain") or {})
    ta = (group_after.get("toolchain") or {})

    parts.append(meta_table([
        ("before", f"{tb.get('name')} -- {tb.get('version')} "
                   f"[{tb.get('build_type')}]"),
        ("after", f"{ta.get('name')} -- {ta.get('version')} "
                  f"[{ta.get('build_type')}]"),
        ("suites", ", ".join(name for name, *_ in items)),
    ]))

    def count_cell(n: int, suite: str, anchor_key: str, cls: str) -> str:
        """A count, tinted by what it means, linking to its section.

        Zero is left unlinked and unhighlighted: there is no section to
        jump to, and colouring a zero would draw the eye to nothing.
        """
        if not n:
            return "<span class=\"muted\">0</span>"
        return (f"<a class=\"{cls}\" href=\"#{esc(slug(suite, anchor_key))}\">"
                f"{n}</a>")

    rows = []
    for name, report, *_ in items:
        verdict = ("<span class=\"good\">no regressions</span>"
                   if report.clean else
                   f"<span class=\"bad\">{len(report.regressed)} regressed, "
                   f"{len(report.new_crashes)} new crash(es)</span>")
        rows.append([
            f"<a href=\"#{esc(slug(name))}\">{esc(name)}</a>",
            count_cell(len(report.improved), name, "improved", "good"),
            count_cell(len(report.regressed), name, "regressed", "bad"),
            count_cell(len(report.new_crashes), name, "new-crashes",
                       "alarm"),
            count_cell(len(report.churn_only), name, "churn", "muted"),
            verdict])
    anchor = slug("summary")
    parts.append(section("Summary", table(
        ["suite", "improved", "regressed", "new crashes", "churn",
         "verdict"], rows, numeric=[1, 2, 3, 4]), anchor))
    entries.append((anchor, "Summary"))

    for name, report, mb, ma, perf, results in items:
        inner, _ = _diff_body(report, mb, ma, perf, results,
                              show_all=False, prefix=name,
                              include_meta=False)
        a = slug(name)
        label = name
        if not report.clean:
            label += f"  ({len(report.regressed)} regressed)"
        parts.append(section(label, inner, a, kind="sect suite",
                             cls="" if report.clean else "bad"))
        entries.append((a, name))

    return document(f"gab diff -- {tb.get('name')} vs {ta.get('name')} "
                    f"(all suites)", toc(entries) + "\n".join(parts))


def _diff_body(report, mb: dict, ma: dict, perf_caveats, result_caveats,
               show_all: bool = False, prefix: str = "",
               include_meta: bool = True):
    tb, ta = mb.get("toolchain") or {}, ma.get("toolchain") or {}
    parts, entries = [], []

    def add(title, inner, key, **kw):
        a = slug(prefix, key)
        html_ = section(title, inner, a, **kw)
        if html_:
            parts.append(html_)
            entries.append((a, title))

    def descr(t):
        g = t.get("git") or {}
        return (f"{t.get('name')} -- {t.get('version')} "
                f"[{t.get('build_type')}]"
                + (f" {g.get('gcc_descr')}" if g.get("gcc_descr") else ""))

    su = report.suite_summary()
    suite_version = (f"v{su['version_before']}" if su["same_version"]
                     else f"v{su['version_before']} -> v{su['version_after']}")
    content = ((su["content_hash_before"] or "?")[:16] if su["same_content"]
               else f"{(su['content_hash_before'] or '?')[:16]} -> "
                    f"{(su['content_hash_after'] or '?')[:16]} "
                    f"(DIFFERENT TESTS)")
    meta_rows = [
        ("suite", f"{su['name']} {suite_version}"
                  + (f" -- {su['n_tests_compared']} tests compared"
                     if su["n_tests_compared"] is not None else "")
                  + ("  [subset]" if su["subset"] else "")),
        ("suite content", content),
        ("matcher", report.matcher),
    ]
    if include_meta:
        meta_rows[2:2] = [("before", descr(tb)), ("after", descr(ta))]
    parts.append(meta_table(meta_rows))

    if report.incompatibilities:
        parts.append(caveats(report.incompatibilities,
                             "Comparing anyway, despite"))
    parts.append(caveats(result_caveats, "Caveats on these results"))

    if report.new_crashes:
        add("New compiler failures", table(
            ["test", "change", "reproduce with"],
            [[esc(d.name),
              f"<span class=\"bad\">{esc(d.before.status)} &#8594; "
              f"{esc(d.after.status)}</span>",
              f"<span class=\"repro\">{esc(' '.join(d.repro))}</span>"]
             for d in report.new_crashes]),
            "new-crashes", count=len(report.new_crashes), cls="bad")

    scoring_inner = table(["metric", "before", "after", "change"],
                          list(_delta_rows(report)), numeric=[1, 2, 3])
    md = report.macro_delta()
    if md:
        direction = ("better" if md["delta"] > 0
                     else "worse" if md["delta"] < 0 else "same")
        scoring_inner += (f"<p>Category-averaged score: "
                          f"{md['before']:+.3f} &#8594; {md['after']:+.3f} "
                          f"({tint(signed(md['delta'], False), direction)})"
                          f"</p>")
    cat_rows = []
    for d in report.category_score_deltas():
        tp, fp = d["tp_delta"], d["fp_delta"]
        cat_rows.append([
            esc(d["category"]),
            f"{d['before']['TP']} &#8594; {d['after']['TP']}",
            tint(signed(tp, False),
                 "better" if tp > 0 else "worse" if tp < 0 else "same"),
            f"{d['before']['FP']} &#8594; {d['after']['FP']}",
            tint(signed(fp, False),
                 "worse" if fp > 0 else "better" if fp < 0 else "same"),
        ])
    if cat_rows:
        scoring_inner += ("<h3>Categories that moved</h3>"
                          + table(["category", "TP", "", "FP", ""],
                                  cat_rows, numeric=[1, 2, 3, 4]))
    add("Scoring", scoring_inner, "scoring")

    def test_table(items):
        rows = []
        for d in (items if show_all else items[:50]):
            findings = "".join(
                f"<div class=\"bad\">- {esc(f.get('rule'))} "
                f"@{esc(f.get('line'))}</div>" for f in d.gone_findings
            ) + "".join(
                f"<div class=\"good\">+ {esc(f.get('rule'))} "
                f"@{esc(f.get('line'))}</div>" for f in d.new_findings
            )
            rows.append([esc(d.name),
                         f"{esc(d.before.outcome)} &#8594; "
                         f"{esc(d.after.outcome)}",
                         esc(d.category or ""), findings])
        out = table(["test", "change", "category", "diagnostics"], rows)
        if not show_all and len(items) > 50:
            out += (f"<p class=\"muted\">... and {len(items) - 50} more; "
                    f"re-run with --all</p>")
        return out

    add("Regressed", test_table(report.regressed), "regressed",
        count=len(report.regressed), cls="bad")
    add("Improved", test_table(report.improved), "improved",
        count=len(report.improved), cls="good")
    add("Fixed crashes", test_table(report.fixed_crashes), "fixed-crashes",
        count=len(report.fixed_crashes), cls="good")
    add("Other status changes", test_table(report.other_status_changes),
        "status-changes", count=len(report.other_status_changes))
    add("Same outcome, different diagnostics",
        test_table(report.churn_only), "churn",
        count=len(report.churn_only), open_=False)

    tb_, ta_ = report.totals_before, report.totals_after
    ratio = (ta_["cpu_time"] / tb_["cpu_time"]) if tb_["cpu_time"] else 0
    res_inner = table(
        ["", "CPU time", "peak RSS"],
        [["before", f"{tb_['cpu_time']:.1f}s",
          f"{tb_['max_maxrss_kb'] / 1024:.0f} MiB"],
         ["after", f"{ta_['cpu_time']:.1f}s",
          f"{ta_['max_maxrss_kb'] / 1024:.0f} MiB"],
         ["change", f"{ratio:.2f}x",
          f"{report.rss_baseline_ratio:.2f}x median"]],
        numeric=[1, 2])
    # The caveat belongs here, beside the numbers it undermines.
    res_inner += caveats(perf_caveats,
                         "Caveats on these performance numbers")
    if report.resources:
        res_inner += ("<h3>Tests that moved out of line with that "
                      "baseline</h3>" + table(
                          ["test", "before", "after", "ratio",
                           "vs baseline"],
                          [[esc(r.name), f"{r.rss_before / 1024:.0f} MiB",
                            f"{r.rss_after / 1024:.0f} MiB",
                            f"{r.rss_ratio:.2f}x",
                            f"{r.rss_ratio / report.rss_baseline_ratio:.2f}x"]
                           for r in report.resources[:25]],
                          numeric=[1, 2, 3, 4]))
    else:
        res_inner += ("<p class=\"muted\">No test moved peak RSS out of "
                      "line with that baseline.</p>")
    add("Resources", res_inner, "resources")

    parts.append("<p class=\"good\"><strong>No regressions</strong></p>"
                 if report.clean else
                 f"<p><span class=\"alarm\">{len(report.regressed)} "
                 f"regression(s), {len(report.new_crashes)} new crash(es)"
                 f"</span></p>")
    return "\n".join(parts), entries
