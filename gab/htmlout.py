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
/* Out-of-scope and unchanged must not use the same visual channel:
   in a diff nearly every row is unchanged, so opacity is spoken for.
   Scope gets a tint and a rule; opacity means "nothing moved here". */
tr.oos { background: #8882; }
tr.oos > td:first-child { border-left: 3px solid #8887;
                          padding-left: 0.45rem; }
tr.quiet td { opacity: 0.55; }
.cell.unchanged { background: none; color: inherit; min-width: 0; }
.oos-tag { font-size: 0.72em; text-transform: uppercase;
           letter-spacing: 0.04em; color: #8889; border: 1px solid #8886;
           border-radius: 3px; padding: 0 0.35em; margin-left: 0.4em;
           white-space: nowrap; }
.cell { display: inline-block; min-width: 3.1em; padding: 0.1rem 0.3rem;
        border-radius: 3px; color: #111; text-align: center;
        font-variant-numeric: tabular-nums; }

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
    open_text = ' open="open"' if open_ else ''
    return (
        f"<details class=\"{classes}\" id=\"{esc(anchor)}\""
        f"{open_text}>"
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

def render_score(report, manifest: dict, run_dir: str, castle=None) -> str:
    tc = manifest.get("toolchain") or {}
    suite = manifest.get("suite") or {}
    body, entries = _score_body(report, manifest, run_dir, prefix="",
                                castle=castle)
    title = f"gab score -- {suite.get('name')} / {tc.get('name')}"
    return document(title, toc(entries) + body)


def _score_body(report, manifest: dict, run_dir: str, prefix: str,
                castle=None):
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

    if castle:
        add("CASTLE score grid",
            render_castle_grid(castle["rows"], castle.get("cwe_names"),
                               castle.get("out_of_scope")),
            "castle-grid")

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
        ("suites", ", ".join(name for name, *_ in reports)),
    ]))

    rows, totals = [], {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for name, _child, manifest, rep, *_ in reports:
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

    for entry in reports:
        name, child, manifest, rep = entry[:4]
        castle = entry[4] if len(entry) > 4 else None
        inner, _ = _score_body(rep, manifest, str(child), prefix=name,
                               castle=castle)
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
    cd = report.castle_delta()
    if cd:
        scoring_inner += (
            f"<p>CASTLE Score: {cd['before']} &#8594; {cd['after']} "
            f"({tint(signed(cd['delta'], False), cd['direction'])})"
            f" <span class=\"muted\">detection rule: "
            f"{esc(cd['detect'])}</span></p>")
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

    if report.castle_rows_before or report.castle_rows_after:
        meta = report.castle_meta or {}
        add("CASTLE score grid",
            render_castle_diff_grid(report.castle_rows_before,
                                    report.castle_rows_after,
                                    meta.get("cwe_names"),
                                    meta.get("out_of_scope")),
            "castle-grid")

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


def render_failures(groups, report, manifest: dict, run_dir: str) -> str:
    """Where the analyzer could do better, grouped by category."""
    tc = manifest.get("toolchain") or {}
    suite = manifest.get("suite") or {}
    parts, entries = [], []

    parts.append(meta_table([
        ("run", run_dir),
        ("toolchain", f"{tc.get('name')} -- {tc.get('version')}"),
        ("suite", f"{suite.get('name')} v{suite.get('version')}"),
        ("matcher", report.matcher),
        ("totals", f"{report.overall.FP} false positives, "
                   f"{report.overall.FN} false negatives"),
    ]))

    if not groups:
        parts.append("<p class=\"good\"><strong>No false results.</strong>"
                     "</p>")
        return document("gab failures", "\n".join(parts))

    overview = [[f"<a href=\"#{esc(slug(cat))}\">{esc(cat)}</a>",
                 sum(1 for e in v if e["outcome"] == "FP"),
                 sum(1 for e in v if e["outcome"] == "FN")]
                for cat, v in groups.items()]
    a = slug("overview")
    parts.append(section("By category",
                         table(["category", "FP", "FN"], overview,
                               numeric=[1, 2]), a))
    entries.append((a, "By category"))

    for category, items in groups.items():
        rows = []
        for e in items:
            cls = "bad" if e["outcome"] == "FP" else "muted"
            truth = f"CWE-{e['cwe']}" if e["cwe"] else ""
            if e["outcome"] == "FN" and e["lines"]:
                truth += (" at line(s) "
                          + ", ".join(str(n) for n in e["lines"]))
            reported = "".join(
                f"<div>{esc(f['rule'])} @{esc(f['line'])} "
                f"<span class=\"muted\">{esc(f['message'][:90])}</span></div>"
                for f in e["findings"]
            ) or "<span class=\"muted\">nothing reported</span>"
            rows.append([
                f"<span class=\"{cls}\">{esc(e['outcome'])}</span>",
                esc(e["name"]), esc(truth), reported])
        anchor = slug(category)
        n_fp = sum(1 for e in items if e["outcome"] == "FP")
        n_fn = sum(1 for e in items if e["outcome"] == "FN")
        parts.append(section(
            f"{category} ({n_fp} FP, {n_fn} FN)",
            table(["", "test", "ground truth", "analyzer said"], rows),
            anchor))
        entries.append((anchor, category))

    return document(f"gab failures -- {suite.get('name')} / "
                    f"{tc.get('name')}", toc(entries) + "\n".join(parts))


def heat(ratio: float) -> str:
    """Background colour for a score cell, good (green) to bad (red).

    Zero is grey rather than red: scoring nothing on a test means the
    analyzer stayed silent, which is a miss but not a harm.  Red is
    reserved for negative cells, where it reported something that was
    not the flaw and actively lost points.

    Lightness carries the magnitude and the hue carries the sign, so
    the grid still reads correctly in greyscale and when printed.  The
    backgrounds are always light, so cell text is pinned dark and the
    table survives dark mode.
    """
    if ratio > 0:
        return f"hsl(125 55% {92 - 32 * min(ratio, 1.0):.0f}%)"
    if ratio < 0:
        return f"hsl(5 70% {92 + 25 * max(ratio, -1.0):.0f}%)"
    return "hsl(0 0% 90%)"


def _cwe_label(cwe, bonus, cwe_names, out_of_scope) -> str:
    label = f"CWE-{cwe}" if cwe is not None else "(none)"
    title = (cwe_names or {}).get(cwe)
    cell = (f"<span title=\"{esc(title)}\">{esc(label)}</span>"
            if title else esc(label))
    if bonus:
        cell += f" <span class=\"muted\">+{bonus}</span>"
    if out_of_scope:
        cell += (" <span class=\"oos-tag\" title=\"-fanalyzer does not"
                 " attempt this weakness; a miss here is not an analyzer"
                 " shortcoming\">out of scope</span>")
    return cell


def render_castle_grid(rows, cwe_names=None, out_of_scope=()) -> str:
    """The CASTLE score as a CWE x test grid.

    One row per CWE, one cell per test, each showing points out of the
    best achievable for that test.  The per-test maximum is not
    uniform: a vulnerable test is worth 5 plus the CWE's Top-25 bonus,
    a clean one is worth 2, so a row's total depends on which CWE it
    is.  Showing score/max per cell keeps that visible instead of
    hiding it in a single number.

    Rows for weaknesses -fanalyzer does not attempt are greyed and
    tagged.  They still count towards the headline CASTLE Score --
    that is the published metric and we do not get to narrow it -- but
    a reader should be able to see at a glance which rows represent
    real shortcomings and which are simply out of remit.
    """
    cwe_names = cwe_names or {}
    oos = {_oos_key(c) for c in (out_of_scope or ())}
    if not rows:
        return ""
    width = max(len(r.cells) for r in rows)

    head = ["CWE", "score"] + [str(i + 1) for i in range(width)]
    body, in_pts, in_max = [], 0, 0
    for r in rows:
        is_oos = r.cwe in oos
        if not is_oos:
            in_pts += r.points
            in_max += r.max_points
        cells = [_cwe_label(r.cwe, r.bonus, cwe_names, is_oos),
                 f"<strong>{r.points}</strong>/{r.max_points}"]
        for c in r.cells:
            kind = "vulnerable" if c.vulnerable else "clean"
            style = f"background:{heat(c.ratio)}"
            if is_oos:
                style += ";opacity:0.45"
            cells.append(
                f"<span class=\"cell\" style=\"{style}\""
                f" title=\"{esc(c.name)} ({kind}, {esc(c.case)})\">"
                f"{c.points}/{c.max_points}</span>")
        body.append((cells, is_oos))

    rendered = []
    for cells, is_oos in body:
        tds = "".join(
            f"<td{' class=\"num\"' if i else ''}>{c}</td>"
            for i, c in enumerate(cells))
        rendered.append(f"<tr{' class=\"oos\"' if is_oos else ''}>"
                        f"{tds}</tr>")
    header = "".join(
        f"<th{' class=\"num\"' if i else ''}>{esc(h)}</th>"
        for i, h in enumerate(head))
    grid_html = (f"<table><thead><tr>{header}</tr></thead>"
                 f"<tbody>{''.join(rendered)}</tbody></table>")

    total = sum(r.points for r in rows)
    best = sum(r.max_points for r in rows)
    note = (f"<p>Total <strong>{total}</strong> of a possible {best}.")
    if oos and in_max != best:
        note += (f" Excluding the {len(oos)} out-of-scope rows:"
                 f" <strong>{in_pts}</strong> of {in_max}.")
    note += ("</p>")
    return (
        grid_html + note
        + "<p class=\"muted\">Columns are the suite's tests in order;"
          " in CASTLE-C250 tests 1-6 are vulnerable and 7-10 are clean."
          " A CWE's +n is its Top-25 bonus, which raises the maximum for"
          " its vulnerable tests."
          " Green: points scored. Grey: nothing reported, a miss that"
          " cost nothing. Red: points lost to findings that were not the"
          " flaw under test."
          " Greyed rows are weaknesses -fanalyzer does not attempt.</p>"
    )


def _oos_key(category):
    """Out-of-scope categories are named 'CWE-nnn'; rows key on the int."""
    try:
        return int(str(category).removeprefix("CWE-"))
    except (TypeError, ValueError):
        return category


def render_castle_diff_grid(rows_before, rows_after, cwe_names=None,
                            out_of_scope=()) -> str:
    """The CASTLE grid as a before/after comparison.

    Cells that did not move are shown once, greyed: on a typical
    patch almost every cell is unchanged, so the eye should be drawn
    only to the ones that moved.  Changed cells show `before -> after`
    and are tinted by the *direction of the change*, not by the
    absolute score -- a cell going 0 -> 5 is good news even though 0
    was bad, and one going 5 -> 0 is bad news even though 5 was good.
    """
    cwe_names = cwe_names or {}
    oos = {_oos_key(c) for c in (out_of_scope or ())}
    before = {r.cwe: r for r in rows_before or ()}
    after = {r.cwe: r for r in rows_after or ()}
    cwes = sorted(set(before) | set(after),
                  key=lambda c: (c is None, c or 0))
    if not cwes:
        return ""
    width = max((len(r.cells) for r in list(before.values())
                 + list(after.values())), default=0)

    n_changed = 0
    rendered = []
    for cwe in cwes:
        rb, ra = before.get(cwe), after.get(cwe)
        cells_b = {c.name: c for c in (rb.cells if rb else ())}
        cells_a = {c.name: c for c in (ra.cells if ra else ())}
        order = [c.name for c in (ra.cells if ra else rb.cells)]
        is_oos = cwe in oos

        row_changed = False
        tds = []
        for name in order:
            cb, ca = cells_b.get(name), cells_a.get(name)
            if cb is None or ca is None:
                tds.append("<td class=\"num\"><span class=\"muted\">"
                           "-</span></td>")
                continue
            kind = "vulnerable" if ca.vulnerable else "clean"
            title = f"{ca.name} ({kind}, {esc(ca.case)})"
            if cb.points == ca.points:
                tds.append(
                    f"<td class=\"num\"><span class=\"cell unchanged\""
                    f" title=\"{esc(title)}\">{ca.points}/"
                    f"{ca.max_points}</span></td>")
                continue
            row_changed = True
            n_changed += 1
            delta = ca.points - cb.points
            direction = "better" if delta > 0 else "worse"
            colour = heat(1.0 if delta > 0 else -1.0)
            tds.append(
                f"<td class=\"num\"><span class=\"cell\""
                f" style=\"background:{colour}\""
                f" title=\"{esc(title)}: {signed(delta, False)}\">"
                f"{cb.points}&#8594;{ca.points}/{ca.max_points}</span>"
                f"</td>")

        pb = rb.points if rb else 0
        pa = ra.points if ra else 0
        mx = (ra or rb).max_points
        score_cell = (f"<strong>{pa}</strong>/{mx}" if pb == pa else
                      tint(f"<strong>{pb}&#8594;{pa}</strong>/{mx}",
                           "better" if pa > pb else "worse"))
        label = _cwe_label(cwe, (ra or rb).bonus, cwe_names, is_oos)
        classes = " ".join(x for x in ("oos" if is_oos else "",
                                       "" if row_changed else "quiet") if x)
        rendered.append(
            f"<tr{f' class=\"{classes}\"' if classes else ''}>"
            f"<td>{label}</td><td class=\"num\">{score_cell}</td>"
            + "".join(tds) + "</tr>")

    header = "".join(
        f"<th{' class=\"num\"' if i else ''}>{esc(h)}</th>"
        for i, h in enumerate(["CWE", "score"]
                              + [str(i + 1) for i in range(width)]))
    tb = sum(r.points for r in rows_before or ())
    ta = sum(r.points for r in rows_after or ())
    best = sum(r.max_points for r in rows_after or rows_before or ())
    summary = (f"<p>{n_changed} cell(s) moved. Total "
               f"{tb} &#8594; {ta} of a possible {best}.</p>"
               if n_changed else
               f"<p class=\"muted\">No cell moved; total {ta} of a "
               f"possible {best}.</p>")
    return (f"<table><thead><tr>{header}</tr></thead><tbody>"
            f"{''.join(rendered)}</tbody></table>" + summary
            + "<p class=\"muted\">Changed cells show before&#8594;after"
              " and are tinted by the direction of the change. Unchanged"
              " cells are greyed. Greyed rows are weaknesses -fanalyzer"
              " does not attempt.</p>")
