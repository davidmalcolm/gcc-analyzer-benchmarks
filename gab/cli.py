# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Command-line interface."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

from gab import __version__, diff, htmlout, scoring
from gab.castle_score import castle_score
from gab.config import (expand, load_config, suite_adapter,
                        suite_options, suite_root)
from gab.term import make_palette
from gab.runner import (DEFAULT_TIMEOUT, Runner, is_group,
                        load_group, load_run,
                        write_group_manifest)
from gab.suite import TestCase, get_suite, suite_names
from gab.toolchain import Toolchain


def _die(msg: str) -> "NoReturn":  # noqa: F821
    print(f"gab: error: {msg}", file=sys.stderr)
    raise SystemExit(2)


def _select(tests: List[TestCase], patterns: Optional[List[str]],
            limit: Optional[int]) -> List[TestCase]:
    if patterns:
        tests = [
            t for t in tests
            if any(fnmatch.fnmatch(t.name, p) for p in patterns)
        ]
    if limit:
        tests = tests[:limit]
    return tests


# -- commands ------------------------------------------------------------

def cmd_suites(args) -> int:
    cfg = load_config(args.config)
    configured = cfg.get("suites") or {}

    if args.json:
        out = {"config": cfg["__path__"], "suites": {}}
        for name in suite_names():
            if name not in configured:
                out["suites"][name] = {"configured": False}
                continue
            try:
                suite = get_suite(suite_adapter(cfg, name),
                                  suite_root(cfg, name),
                                  suite_options(cfg, name, None),
                                  label=name)
                tests = suite.tests()
            except (OSError, KeyError, ValueError) as e:
                out["suites"][name] = {"configured": True, "error": str(e)}
                continue
            out["suites"][name] = {
                "configured": True,
                "root": str(suite.root),
                "version": suite.version(),
                "content_hash": suite.content_hash(tests),
                "n_tests": len(tests),
                "n_vulnerable": sum(1 for t in tests if t.vulnerable),
                "n_with_line_truth": sum(1 for t in tests if t.lines),
                "categories": sorted({t.category for t in tests if t.category}),
            }
        json.dump(out, sys.stdout, indent=2, sort_keys=True)
        print()
        return 0

    print(f"config: {cfg['__path__']}\n")
    for name in suite_names():
        if name not in configured:
            print(f"  {name:<18} (not configured)")
            continue
        try:
            suite = get_suite(suite_adapter(cfg, name),
                              suite_root(cfg, name),
                              suite_options(cfg, name, None), label=name)
            tests = suite.tests()
        except (OSError, KeyError, ValueError) as e:
            print(f"  {name:<18} ERROR: {e}")
            continue
        vuln = sum(1 for t in tests if t.vulnerable)
        cats = len({t.category for t in tests if t.category})
        lines = sum(1 for t in tests if t.lines)
        print(f"  {name:<18} {len(tests):>5} tests  "
              f"{vuln:>4} vulnerable  {cats:>3} categories  "
              f"{lines:>4} with line truth   v{suite.version()}")
        print(f"  {'':<18} {suite.root}")
    return 0


def cmd_toolchains(args) -> int:
    cfg = load_config(args.config)

    if args.json:
        out = {"config": cfg["__path__"], "toolchains": {}}
        for name, tc_cfg in (cfg.get("toolchains") or {}).items():
            try:
                out["toolchains"][name] = Toolchain.from_config(
                    name, tc_cfg).identity()
            except (OSError, ValueError) as e:
                out["toolchains"][name] = {"available": False,
                                           "error": str(e)}
        json.dump(out, sys.stdout, indent=2, sort_keys=True)
        print()
        return 0

    print(f"config: {cfg['__path__']}\n")
    for name, tc_cfg in (cfg.get("toolchains") or {}).items():
        desc = tc_cfg.get("description", "")
        try:
            tc = Toolchain.from_config(name, tc_cfg)
        except (OSError, ValueError) as e:
            print(f"  {name:<12} UNAVAILABLE: {e}")
            continue
        ident = tc.identity()
        print(f"  {name:<12} {ident.get('version')}")
        if desc:
            print(f"  {'':<12} {desc}")
        print(f"  {'':<12} {ident.get('build_type')} "
              f"(-fchecking={ident.get('fchecking')})  "
              f"host {ident.get('host')} -> target {ident.get('target')}")
        git = ident.get("git")
        if git:
            dirty = " (dirty)" if git.get("dirty") else ""
            print(f"  {'':<12} {git.get('gcc_descr') or git.get('describe')} "
                  f"on {git.get('branch')}{dirty}")
        cc1 = ident.get("cc1")
        if cc1:
            dbg = "with debuginfo" if cc1.get("has_debug_info") else "stripped"
            print(f"  {'':<12} cc1 {(cc1.get('sha256') or '?')[:12]} "
                  f"({dbg}) {cc1.get('path')}")
        print()
    return 0


def resolve_suites(cfg: dict, requested: List[str]) -> List[str]:
    """Expand the -s arguments into an ordered list of suite names.

    'all' means every configured suite; names may also be repeated or
    comma-separated.  Order follows the config so that a group directory
    lists its suites predictably.
    """
    configured = list((cfg.get("suites") or {}).keys())
    names: List[str] = []
    for item in requested:
        for part in str(item).split(","):
            part = part.strip()
            if not part:
                continue
            if part == "all":
                names.extend(configured)
            else:
                names.append(part)
    if not names:
        _die("no suites selected")
    unknown = [n for n in names if n not in configured]
    if unknown:
        _die(f"unknown suite(s) {', '.join(unknown)}; configured: "
             f"{', '.join(configured) or '(none)'}")
    # De-duplicate, keeping first-seen order.
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def cmd_run(args) -> int:
    cfg = load_config(args.config)

    tc_cfg = (cfg.get("toolchains") or {}).get(args.toolchain)
    if tc_cfg is None:
        _die(f"unknown toolchain {args.toolchain!r}; configured: "
             f"{', '.join(sorted(cfg.get('toolchains') or {}))}")
    try:
        toolchain = Toolchain.from_config(args.toolchain, tc_cfg)
    except (OSError, ValueError) as e:
        _die(str(e))

    suite_names_ = resolve_suites(cfg, args.suite)

    # Where everything goes.  A single suite keeps the flat layout it
    # has always had; several suites get a parent directory with one
    # child per suite, so that each child is still an ordinary run
    # directory that score and diff can consume directly.
    if args.out:
        root = Path(expand(args.out))
    else:
        runs_dir = Path(expand(cfg.get("runs_dir", "runs")))
        if not runs_dir.is_absolute():
            runs_dir = Path(cfg["__path__"]).parent / runs_dir
        stamp = time.strftime("%Y%m%d-%H%M%S")
        label = suite_names_[0] if len(suite_names_) == 1 else "all"
        root = runs_dir / f"{stamp}-{args.toolchain}-{label}"
    if root.exists() and any(root.iterdir()) and not args.force:
        _die(f"{root} already exists and is not empty (use --force)")
    root.mkdir(parents=True, exist_ok=True)

    if len(suite_names_) > 1:
        return _run_group(args, cfg, toolchain, suite_names_, root)
    return _run_single(args, cfg, toolchain, suite_names_[0], root)


def _run_group(args, cfg, toolchain, names: List[str], root: Path) -> int:
    """Run several suites into child directories under one parent."""
    started = time.time()
    t0 = time.monotonic()
    members, outcomes = [], []
    worst = 0

    for name in names:
        child = root / name
        child.mkdir(parents=True, exist_ok=True)
        if not args.json:
            print(make_palette(args.color).head(f"=== {name}"))
        code, summary = _run_single(args, cfg, toolchain, name, child,
                                    as_member=True)
        worst = max(worst, code)
        members.append({"suite": name, "dir": name,
                        "n_tests": summary["n_tests"],
                        "status": summary["status"]})
        outcomes.append(summary)
        if not args.json:
            print()

    elapsed = time.monotonic() - t0
    write_group_manifest(root, members, toolchain.identity(), started,
                         elapsed, ["-fanalyzer"], args.extra_arg or [],
                         args.jobs or (os.cpu_count() or 1))

    if args.json:
        json.dump({
            "kind": "group",
            "out_dir": str(root),
            "elapsed_wall": elapsed,
            "suites": outcomes,
            "toolchain": toolchain.identity(),
        }, sys.stdout, indent=2, sort_keys=True)
        print()
        return worst

    c = make_palette(args.color)
    print(c.head("SUMMARY"))
    total_tests = sum(o["n_tests"] for o in outcomes)
    total_cpu = sum(o["cpu_time"] for o in outcomes)
    for o in outcomes:
        bad = sum(n for s, n in o["status"].items() if s != "ok")
        line = (f"  {o['suite']:<18} {o['n_tests']:>5} tests  "
                f"{o['cpu_time']:>7.1f}s cpu")
        print(line + (c.alarm(f"  {bad} not ok") if bad else ""))
    print(f"  {'total':<18} {total_tests:>5} tests  {total_cpu:>7.1f}s cpu  "
          f"in {elapsed:.1f}s wall")
    print(f"\nwrote {root}")
    return worst


def _run_single(args, cfg, toolchain, suite_name: str, out_dir: Path,
                as_member: bool = False):
    """Run one suite into one run directory.

    Returns an exit code, or (exit code, summary dict) when invoked as
    part of a group.
    """
    def finish(code, summary):
        return (code, summary) if as_member else code

    try:
        suite = get_suite(suite_adapter(cfg, suite_name),
                          suite_root(cfg, suite_name),
                          suite_options(cfg, suite_name,
                                        args.suite_version),
                          label=suite_name)
        tests = suite.tests()
    except (OSError, KeyError, ValueError) as e:
        _die(str(e))

    tests = _select(tests, args.filter, args.limit)
    if not tests:
        _die(f"no tests selected for suite {suite_name!r}")

    runner = Runner(
        toolchain=toolchain,
        suite=suite,
        out_dir=out_dir,
        extra_args=args.extra_arg or (),
        timeout=args.timeout,
        jobs=args.jobs,
        keep_sarif=not args.no_sarif,
        time_report=args.time_report,
    )

    if not args.json:
        if not as_member:
            print(f"toolchain : {args.toolchain}  "
                  f"{toolchain.identity().get('version')}")
        print(f"suite     : {suite.name} v{suite.version()}  "
              f"({len(tests)} tests)")
        print(f"out       : {out_dir}")
        if not as_member:
            print(f"jobs      : {runner.jobs}")
        print()

    # Keep stdout pure JSON: progress and per-test problems go to stderr.
    quiet = args.quiet or args.json or not sys.stderr.isatty()
    t0 = time.monotonic()
    problems: List = []

    def progress(n, total, res):
        if res.status != "ok":
            problems.append(res)
            print(f"  [{res.status}] {res.name}", file=sys.stderr)
        if not quiet:
            print(f"\r  {n}/{total}", end="", file=sys.stderr, flush=True)

    results = runner.run(tests, progress=progress)
    if not quiet:
        print("\r" + " " * 30 + "\r", end="", file=sys.stderr)

    elapsed = time.monotonic() - t0
    cpu = sum(r.user_time + r.sys_time for r in results)
    peak = max((r.maxrss_kb for r in results), default=0)
    slowest = max(results, key=lambda r: r.wall_time, default=None)

    tally_all = {}
    for r in results:
        tally_all[r.status] = tally_all.get(r.status, 0) + 1
    crashed = [r for r in results if r.status in ("ice", "timeout")]

    summary = {
        "suite": suite.name,
        "out_dir": str(out_dir),
        "n_tests": len(results),
        "elapsed_wall": elapsed,
        "cpu_time": cpu,
        "max_maxrss_kb": peak,
        "status": dict(sorted(tally_all.items())),
        "too_complex": sum(1 for r in results if r.too_complex),
        "crashes": [
            {"name": r.name, "status": r.status, "signal": r.signal,
             "exit_code": r.exit_code, "repro": r.argv,
             "log": str(out_dir / r.log) if r.log else None}
            for r in crashed
        ],
    }

    if args.json and as_member:
        return finish(1 if crashed else 0, summary)

    if args.json:
        json.dump({
            "out_dir": str(out_dir),
            "n_tests": len(results),
            "elapsed_wall": elapsed,
            "cpu_time": cpu,
            "max_maxrss_kb": peak,
            "jobs": runner.jobs,
            "status": dict(sorted(tally_all.items())),
            "too_complex": sum(1 for r in results if r.too_complex),
            "crashes": [
                {"name": r.name, "status": r.status, "signal": r.signal,
                 "exit_code": r.exit_code, "repro": r.argv,
                 "log": str(out_dir / r.log) if r.log else None}
                for r in crashed
            ],
            "toolchain": toolchain.identity(),
            "suite": {"name": suite.name, "version": suite.version()},
        }, sys.stdout, indent=2, sort_keys=True)
        print()
        return finish(1 if crashed else 0, summary)

    print(f"ran {len(results)} tests in {elapsed:.1f}s wall, "
          f"{cpu:.1f}s cpu  (peak RSS {peak / 1024:.0f} MiB)")
    if slowest:
        print(f"slowest   : {slowest.name} {slowest.wall_time:.2f}s")

    tally = {}
    for r in results:
        tally[r.status] = tally.get(r.status, 0) + 1
    for status, n in sorted(tally.items()):
        mark = "  " if status == "ok" else "!!"
        print(f"{mark} {status:<14} {n}")

    n_too_complex = sum(1 for r in results if r.too_complex)
    if n_too_complex:
        print(f"   too-complex    {n_too_complex}")

    if not as_member:
        print(f"\nwrote {out_dir}")

    # A compiler crash is a serious bug, not a scoring event.  Say so
    # unmissably, name every affected test, and fail the command.
    crashes = crashed
    if crashes:
        pal = make_palette(args.color, sys.stderr)
        bar = "=" * 68
        print(pal.alarm(f"\n{bar}"), file=sys.stderr)
        print(pal.alarm(f"  COMPILER FAILURE on {len(crashes)} test case(s) "
                        f"-- this is a GCC bug"), file=sys.stderr)
        print(pal.alarm(bar), file=sys.stderr)
        for r in crashes[:40]:
            detail = (f"signal {r.signal}" if r.signal
                      else f"exit {r.exit_code}")
            print(f"  {r.status:<8} {r.name:<22} {detail}", file=sys.stderr)
            if r.log:
                print(f"           log: {out_dir / r.log}", file=sys.stderr)
        if len(crashes) > 40:
            print(f"  ... and {len(crashes) - 40} more", file=sys.stderr)
        print(f"\n  reproduce with:", file=sys.stderr)
        print(f"    {' '.join(crashes[0].argv)}", file=sys.stderr)
        print(pal.alarm(bar), file=sys.stderr)

    # Nonzero exit when the *tool* failed, not when the analyzer merely
    # scored badly.
    return finish(1 if crashes else 0, summary)


def _signed(x, is_rate: bool) -> str:
    if x is None:
        return ""
    if is_rate:
        return f"{x * 100:+.1f}pp"
    return f"{x:+d}" if isinstance(x, int) else f"{x:+.3f}"


def _pct(x) -> str:
    return "   n/a" if x is None else f"{x * 100:5.1f}%"


def _print_castle_grid(rows, c, out_of_scope=()) -> None:
    """The score grid in a terminal.

    Same shape as the HTML version, with colour standing in for the
    heat map: green where points were scored, red where they were
    lost, dim where the analyzer simply said nothing.
    """
    if not rows:
        return
    oos = {htmlout._oos_key(x) for x in (out_of_scope or ())}
    width = max(len(r.cells) for r in rows)
    print(c.head("\n  CASTLE score grid"))
    print(f"  {'CWE':<11} {'score':>8}  "
          + " ".join(f"{i + 1:>5}" for i in range(width)))
    for r in rows:
        cells = []
        for cell in r.cells:
            text = f"{cell.points}/{cell.max_points}"
            if cell.points < 0:
                cells.append(c.bad(f"{text:>5}"))
            elif cell.ratio >= 1.0:
                cells.append(c.good(f"{text:>5}"))
            elif cell.points > 0:
                cells.append(c.warn(f"{text:>5}"))
            else:
                cells.append(c.dim(f"{text:>5}"))
        label = f"CWE-{r.cwe}" if r.cwe is not None else "(none)"
        bonus = f"+{r.bonus}" if r.bonus else "  "
        line = (f"  {label:<8}{bonus:>3} {r.points:>4}/{r.max_points:<3} "
                + " ".join(cells))
        print(c.dim(line + "   (out of scope)") if r.cwe in oos else line)
    total = sum(r.points for r in rows)
    best = sum(r.max_points for r in rows)
    print(f"  {'total':<11} {total:>4}/{best:<3}")
    in_rows = [r for r in rows if r.cwe not in oos]
    if oos and len(in_rows) != len(rows):
        print(f"  {'in scope':<11} {sum(r.points for r in in_rows):>4}"
              f"/{sum(r.max_points for r in in_rows):<3}")
    print(c.dim("  tests 1-6 vulnerable, 7-10 clean; +n is the Top-25 "
                "bonus, which raises\n  the maximum for that CWE's "
                "vulnerable tests"))


def _castle_grid_for(manifest: dict, records, args) -> Optional[dict]:
    """Grid data for the CASTLE score, when the suite is CASTLE."""
    suite = manifest.get("suite") or {}
    adapter = suite.get("adapter") or suite.get("name")
    if adapter != "castle-c250" and not getattr(args, "castle_score", False):
        return None
    from gab.castle_score import castle_score as _cs, grid as _grid
    detect = getattr(args, "castle_detect", None) or "cwe"
    names = {}
    for k, v in (suite.get("cwe_names") or {}).items():
        try:
            names[int(k)] = v
        except (TypeError, ValueError):
            pass
    return {"rows": _grid(_cs(records, detect)),
            "cwe_names": names,
            "out_of_scope": suite.get("out_of_scope_categories") or []}


def _castle_score_for(manifest: dict, records, args) -> Optional[dict]:
    """The CASTLE Score, when it applies.

    Only computed for the CASTLE adapter: it is that benchmark's own
    metric, with CWE ranks specific to that dataset, so reporting it
    for any other suite would be meaningless.
    """
    suite = manifest.get("suite") or {}
    adapter = suite.get("adapter") or suite.get("name")
    if adapter != "castle-c250" and not getattr(args, "castle_score", False):
        return None
    detect = getattr(args, "castle_detect", None) or "cwe"
    try:
        result = castle_score(records, detect)
    except KeyError as e:
        _die(str(e))
    out = result.as_dict()
    out["detect"] = detect
    return out


def cmd_score(args) -> int:
    run_dir = Path(expand(args.run_dir))
    if is_group(run_dir):
        return _score_group(args, run_dir)
    return _score_one(args, run_dir)


def _score_group(args, root: Path) -> int:
    """Score every suite in a multi-suite run.

    Each suite is reported on its own terms.  There is a combined line,
    but it is explicitly labelled as dominated by the largest suite --
    summing across suites with different ground-truth shapes and
    unrelated category namespaces is a convenience, not a metric.
    """
    group_manifest, members = load_group(root)
    reports = []
    for suite_name, child in members:
        manifest, records = load_run(child)
        try:
            report = scoring.score(records, args.match, args.category,
                                   args.skip_category)
        except KeyError as e:
            _die(str(e))
        reports.append((suite_name, child, manifest, report,
                        _castle_grid_for(manifest, records, args)))

    combined = scoring.Counts()
    for _, _, _, r, *_ in reports:
        for field in ("TP", "FP", "FN", "TN", "excluded"):
            setattr(combined, field,
                    getattr(combined, field) + getattr(r.overall, field))

    if args.json:
        json.dump({
            "kind": "group",
            "run": str(root),
            "matcher": args.match,
            "toolchain": group_manifest.get("toolchain", {}),
            "suites": {name: rep.as_dict()
                       for name, _, _, rep, *_ in reports},
            "combined": combined.as_dict(),
        }, sys.stdout, indent=2, sort_keys=True)
        print()
        return 1 if combined.excluded else 0

    if args.format == "html":
        print(htmlout.render_score_group(reports, group_manifest, str(root)),
              end="")
        return 1 if combined.excluded else 0

    pal = make_palette(args.color)
    tc = group_manifest.get("toolchain", {})
    print(f"run       : {root}")
    print(f"toolchain : {tc.get('name')}  {tc.get('version')}  "
          f"[{tc.get('build_type')}]")
    print(f"matcher   : {args.match}")
    print("suites    :")
    for name, _child, manifest, rep, *_ in reports:
        su = manifest.get("suite") or {}
        subset = "  [subset]" if su.get("subset") else ""
        print(f"            {name} v{su.get('version')}  "
              f"{rep.scope['n_tests_scored']} tests  "
              f"content {(su.get('content_hash') or '?')[:12]}{subset}")
    print()
    print(f"  {'suite':<18} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5}"
          f" {'recall':>8} {'prec':>8} {'macro':>8}")
    for name, _, _, rep, *_ in reports:
        c, m = rep.overall, rep.macro
        macro = "n/a" if m["score"] is None else f"{m['score']:+.3f}"
        print(f"  {name:<18} {c.TP:>5} {c.FP:>5} {c.FN:>5} {c.TN:>5}"
              f" {_pct(c.recall):>8} {_pct(c.precision):>8} {macro:>8}")
    print(f"  {'combined':<18} {combined.TP:>5} {combined.FP:>5} "
          f"{combined.FN:>5} {combined.TN:>5}"
          f" {_pct(combined.recall):>8} {_pct(combined.precision):>8}")
    print(pal.dim("  (combined is a flat sum, so the largest suite "
                  "dominates it; prefer the per-suite rows)"))

    if getattr(args, "castle_grid", False):
        shown = False
        for name, _child, _manifest, _rep, *rest in reports:
            cg = rest[0] if rest else None
            if not cg:
                continue
            shown = True
            print(pal.head(f"\n=== {name}"))
            _print_castle_grid(cg["rows"], pal, cg.get("out_of_scope"))
        if not shown:
            print(pal.warn("\n  --castle-grid: no CASTLE suite in this "
                           "run"))
    if combined.excluded:
        print(pal.alarm(f"\n!! {combined.excluded} test(s) excluded "
                        f"across all suites"))
    return 1 if combined.excluded else 0


def _score_one(args, run_dir: Path) -> int:
    manifest, records = load_run(run_dir)
    try:
        report = scoring.score(records, args.match,
                               args.category, args.skip_category)
    except KeyError as e:
        _die(str(e))

    if args.json:
        out = report.as_dict()
        cs = _castle_score_for(manifest, records, args)
        if cs:
            out["castle_score"] = cs
        out["run"] = {
            "dir": str(run_dir),
            "toolchain": manifest.get("toolchain", {}).get("name"),
            "version": manifest.get("toolchain", {}).get("version"),
            "build_type": manifest.get("toolchain", {}).get("build_type"),
            "suite": manifest.get("suite", {}),
        }
        json.dump(out, sys.stdout, indent=2, sort_keys=True)
        print()
        return 0

    if args.format == "html":
        print(htmlout.render_score(report, manifest, str(run_dir),
                                   castle=_castle_grid_for(manifest,
                                                           records, args)),
              end="")
        return 1 if report.overall.excluded else 0

    tc = manifest.get("toolchain", {})
    suite = manifest.get("suite", {})
    print(f"run       : {run_dir}")
    print(f"toolchain : {tc.get('name')}  {tc.get('version')}  "
          f"[{tc.get('build_type')}]")
    subset = "  [subset]" if suite.get("subset") else ""
    print(f"suite     : {suite.get('name')} v{suite.get('version')}  "
          f"{report.scope['n_tests_scored']} tests  "
          f"content {(suite.get('content_hash') or '?')[:12]}{subset}")
    print(f"matcher   : {args.match}")
    scope = report.scope
    if scope["categories"] or scope["skip_categories"]:
        print(f"scope     : {scope['n_tests_scored']}"
              f"/{scope['n_tests_available']} tests"
              + (f", only {', '.join(scope['categories'])}"
                 if scope["categories"] else "")
              + (f", skipping {', '.join(scope['skip_categories'])}"
                 if scope["skip_categories"] else ""))
    print()

    c = report.overall
    print(f"  TP {c.TP:<5} FP {c.FP:<5} FN {c.FN:<5} TN {c.TN:<5}")
    print(f"  precision {_pct(c.precision)}   recall {_pct(c.recall)}   "
          f"FPR {_pct(c.fpr)}")
    print(f"  accuracy  {_pct(c.accuracy)}   F1     {_pct(c.f1)}")
    m = report.macro
    macro_score = "n/a" if m["score"] is None else f"{m['score']:+.3f}"
    print(f"  category-averaged over {m['n_categories']} categories: "
          f"TPR {_pct(m['tpr'])}  FPR {_pct(m['fpr'])}  score {macro_score}")

    cs = _castle_score_for(manifest, records, args)
    if cs:
        print(f"\n  CASTLE Score: {cs['score']}  "
              f"(detection rule: {cs['detect']})")
        counts = cs["counts"]
        print(f"    {counts.get('detected', 0)} detected, "
              f"{counts.get('clean-and-quiet', 0)} clean and quiet, "
              f"{counts.get('missed-or-wrong', 0)} missed or wrong")
        if cs["detect"] == "cwe":
            print(make_palette(args.color).dim(
                "    per Dubniczky et al. TASE 2025 s3.3; requires the "
                "reported CWE to equal ground truth"))

    pal = make_palette(args.color)
    if c.excluded:
        print(pal.alarm(f"\n!! {c.excluded} test(s) excluded from scoring "
                        f"(compiler did not deliver a verdict):"))
        by_status = {}
        for v in report.excluded:
            by_status.setdefault(v.status, []).append(v.name)
        for status, names in sorted(by_status.items()):
            shown = ", ".join(names[:6])
            more = f" ... +{len(names) - 6}" if len(names) > 6 else ""
            print(f"     {status:<14} {len(names):>4}   {shown}{more}")

    if getattr(args, "castle_grid", False):
        cg = _castle_grid_for(manifest, records, args)
        if cg:
            _print_castle_grid(cg["rows"], make_palette(args.color),
                               cg.get("out_of_scope"))
        else:
            print(make_palette(args.color).warn(
                "  --castle-grid: this run is not a CASTLE run"))

    if not args.no_categories:
        print(f"\n  {'category':<22} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}"
              f" {'recall':>8} {'prec':>8}")
        for name, cc in sorted(report.by_category.items(),
                               key=lambda kv: scoring.category_key(kv[0])):
            print(f"  {name:<22} {cc.TP:>4} {cc.FP:>4} {cc.FN:>4} {cc.TN:>4}"
                  f" {_pct(cc.recall):>8} {_pct(cc.precision):>8}")

    if args.compare_matchers:
        print(f"\n  how much does the matching rule matter?")
        print(f"  {'rule':<10} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}"
              f" {'recall':>8} {'prec':>8}")
        for rule, cc in scoring.compare_matchers(
                records, categories=args.category,
                skip_categories=args.skip_category).items():
            mark = "*" if rule == args.match else " "
            print(f" {mark}{rule:<10} {cc.TP:>4} {cc.FP:>4} {cc.FN:>4}"
                  f" {cc.TN:>4} {_pct(cc.recall):>8} {_pct(cc.precision):>8}")

    # Nonzero when the compiler failed to deliver a verdict somewhere.
    return 1 if c.excluded else 0


def cmd_diff(args) -> int:
    before_dir, after_dir = Path(expand(args.before)), Path(expand(args.after))
    b_group, a_group = is_group(before_dir), is_group(after_dir)
    if b_group and a_group:
        return _diff_group(args, before_dir, after_dir)
    if b_group or a_group:
        # One side is a whole multi-suite run and the other a single
        # suite.  Rather than refuse, narrow the group to the suite the
        # other side actually holds -- comparing one suite against the
        # same suite inside a larger run is a perfectly sensible thing
        # to ask for, and often how you have the runs lying around.
        before_dir, after_dir = _narrow_to_common_suite(
            before_dir, after_dir, b_group, args)
    return _diff_one(args, before_dir, after_dir)


def _narrow_to_common_suite(before_dir: Path, after_dir: Path,
                            before_is_group: bool, args):
    """Replace the group side with the child matching the other side."""
    group_dir = before_dir if before_is_group else after_dir
    single_dir = after_dir if before_is_group else before_dir

    single_manifest, _ = load_run(single_dir)
    wanted = (single_manifest.get("suite") or {}).get("name")
    _, members = load_group(group_dir)
    match = dict(members).get(wanted)
    if match is None:
        _die(f"{group_dir} has no suite {wanted!r}; it contains "
             f"{', '.join(n for n, _ in members) or '(nothing)'}")

    if not args.json and args.format != "html":
        print(f"note    : narrowed {group_dir.name} to its {wanted!r} "
              f"suite\n")
    return (match, single_dir) if before_is_group else (single_dir, match)


def _diff_group(args, before_root: Path, after_root: Path) -> int:
    """Diff two multi-suite runs, pairing children by suite name."""
    gb, mb_members = load_group(before_root)
    ga, ma_members = load_group(after_root)
    before = dict(mb_members)
    after = dict(ma_members)

    shared = [n for n, _ in mb_members if n in after]
    missing = sorted(set(before) ^ set(after))
    if not shared:
        _die("the two runs have no suites in common")

    # Compute every suite's diff once, then render.
    items = []
    for name in shared:
        mb, rb = load_run(before[name])
        ma, ra = load_run(after[name])
        report = diff.diff_runs(
            mb, rb, ma, ra, args.match,
            resource_threshold=args.resource_threshold,
            categories=args.category,
            skip_categories=args.skip_category)
        if report.incompatibilities and not args.force:
            print(f"gab: refusing to diff {name}:", file=sys.stderr)
            for p in report.incompatibilities:
                print(f"  - {p}", file=sys.stderr)
            print("  (use --force to diff anyway)", file=sys.stderr)
            return 2
        items.append((name, report, mb, ma,
                      diff.warnings_for(report.warnings, "perf"),
                      diff.warnings_for(report.warnings, "results")))
    worst = max((0 if r.clean else 1 for _, r, *_ in items), default=0)

    if args.format == "html":
        print(htmlout.render_diff_group(items, gb, ga), end="")
        return worst

    if args.json:
        json.dump({
            "kind": "group",
            "matcher": args.match,
            "suites": {name: rep.as_dict() for name, rep, *_ in items},
            "only_in_one_run": missing,
            "clean": worst == 0,
        }, sys.stdout, indent=2, sort_keys=True)
        print()
        return worst

    c = make_palette(args.color)
    # The toolchains are the same for every suite in a group, so say so
    # once rather than repeating it under each heading.
    first = items[0]
    print(_tc_line("before :", first[2]))
    print(_tc_line("after  :", first[3]))
    print(f"matcher : {args.match}")
    shared_caveats = set(items[0][5])
    for _, _, _, _, _, res in items[1:]:
        shared_caveats &= set(res)
    if shared_caveats:
        print(c.warn("\n!! caveats on these results:"))
        for p in sorted(shared_caveats):
            print(c.warn(f"   - {p}"))
    print()

    for name, report, mb, ma, perf, results in items:
        print(c.head(f"=== {name}"))
        _render_diff_text(args, report, mb, ma, perf, results,
                          show_header=False, skip_caveats=shared_caveats)
        print()

    print(c.head("SUMMARY"))
    for name, report, *_ in items:
        verdict = (c.good("no regressions") if report.clean
                   else c.alarm(f"{len(report.regressed)} regressed, "
                                f"{len(report.new_crashes)} new crash(es)"))
        extra = (f"  (+{len(report.improved)} improved)"
                 if report.improved else "")
        print(f"  {name:<18} {verdict}{c.good(extra)}")
    if missing:
        print(c.warn(f"  suites in only one run: {', '.join(missing)}"))
    return worst


def _diff_one(args, before_dir: Path, after_dir: Path,
              label: Optional[str] = None) -> int:
    mb, rb = load_run(before_dir)
    ma, ra = load_run(after_dir)

    report = diff.diff_runs(mb, rb, ma, ra, args.match,
                            resource_threshold=args.resource_threshold,
                            categories=args.category,
                            skip_categories=args.skip_category,
                            castle_detect=getattr(args, "castle_detect",
                                                  None))
    perf_caveats = diff.warnings_for(report.warnings, "perf")
    result_caveats = diff.warnings_for(report.warnings, "results")

    if report.incompatibilities and not args.force:
        print("gab: refusing to diff incomparable runs:", file=sys.stderr)
        for p in report.incompatibilities:
            print(f"  - {p}", file=sys.stderr)
        print("  (use --force to diff anyway)", file=sys.stderr)
        return 2

    if args.json:
        json.dump(report.as_dict(), sys.stdout, indent=2, sort_keys=True)
        print()
        return 0 if report.clean else 1

    if args.format == "html":
        print(htmlout.render_diff(report, mb, ma, perf_caveats,
                                  result_caveats, show_all=args.all), end="")
        return 0 if report.clean else 1

    return _render_diff_text(args, report, mb, ma, perf_caveats,
                             result_caveats)


def _tc_line(label, m):
    t = m.get("toolchain", {})
    g = t.get("git") or {}
    rev = g.get("gcc_descr") or (g.get("head") or "")[:12]
    return (f"{label:<9} {t.get('name')}  {t.get('version')}  "
            f"[{t.get('build_type')}]" + (f"  {rev}" if rev else ""))


def _render_diff_text(args, report, mb, ma, perf_caveats, result_caveats,
                      show_header: bool = True,
                      skip_caveats=frozenset()) -> int:
    """Text rendering of one diff.

    `show_header` and `skip_caveats` exist for grouped runs: the
    toolchains and most caveats are identical for every suite in a
    group, so they are printed once at the top rather than repeated for
    each suite.
    """
    tc_line = _tc_line
    c = make_palette(args.color)
    s = report.suite_summary()
    if s["same_name"] and s["same_version"]:
        suite_line = f"{s['name']} v{s['version_before']}"
    else:
        suite_line = (f"{s['name']} v{s['version_before']} "
                      f"-> v{s['version_after']}")
    if s["n_tests_compared"] is not None:
        suite_line += f"  ({s['n_tests_compared']} tests compared)"
    if s["subset"]:
        suite_line += "  [subset]"
    print(f"suite   : {suite_line}")
    if s["same_content"]:
        print(f"content : {(s['content_hash_before'] or '?')[:16]}")
    else:
        print(c.warn(f"content : {(s['content_hash_before'] or '?')[:16]} "
                     f"-> {(s['content_hash_after'] or '?')[:16]}  "
                     f"(DIFFERENT TESTS)"))
    if show_header:
        print(tc_line("before :", mb))
        print(tc_line("after  :", ma))
        print(f"matcher : {report.matcher}")
    if report.incompatibilities:
        print(c.bad("\n!! comparing anyway, despite:"))
        for p in report.incompatibilities:
            print(c.bad(f"   - {p}"))
    unique_caveats = [p for p in result_caveats if p not in skip_caveats]
    if unique_caveats:
        print(c.warn("\n!! caveats on these results:"))
        for p in unique_caveats:
            print(c.warn(f"   - {p}"))
    print()

    if report.new_crashes:
        bar = "=" * 68
        print(c.alarm(bar))
        print(c.alarm(f"  {len(report.new_crashes)} NEW COMPILER FAILURE(S)"))
        print(c.alarm(bar))
        for d in report.new_crashes:
            print(c.alarm(f"  {d.name:<24} "
                          f"{d.before.status} -> {d.after.status}"))
            print(f"           repro: {' '.join(d.repro or []) or 'n/a'}")
        print()

    def section(title, items, tint=None, show_findings=True):
        if not items:
            return
        heading = f"{title} ({len(items)})"
        print(tint(heading) if tint else c.head(heading))
        limit = len(items) if args.all else 25
        for d in items[:limit]:
            print(f"  {d.name:<24} "
                  f"{c.outcome(d.before.outcome, d.after.outcome)}"
                  f"   {d.category or ''}")
            if show_findings and args.verbose:
                for f in d.gone_findings:
                    print(c.bad(f"      - {f.get('rule')} @{f.get('line')}"))
                for f in d.new_findings:
                    print(c.good(f"      + {f.get('rule')} @{f.get('line')}"))
            if d.regressed and d.repro:
                print(c.dim(f"      repro: {' '.join(d.repro)}"))
        if len(items) > limit:
            print(f"  ... and {len(items) - limit} more (use --all)")
        print()

    section("REGRESSED", report.regressed, c.bad)
    section("IMPROVED", report.improved, c.good)
    section("fixed crashes", report.fixed_crashes, c.good)
    section("other status changes", report.other_status_changes)
    if args.churn:
        section("same outcome, different diagnostics", report.churn_only)
    elif report.churn_only:
        print(f"same outcome, different diagnostics: {len(report.churn_only)}"
              f"  (use --churn to list)\n")

    if report.only_in_before or report.only_in_after:
        print(f"tests only in before: {len(report.only_in_before)}, "
              f"only in after: {len(report.only_in_after)}\n")

    # -- scoring ---------------------------------------------------------
    deltas = report.score_deltas()
    if deltas:
        print(c.head("SCORING"))
        print(f"  {'metric':<10} {'before':>9} {'after':>9} {'change':>10}")
        for d in deltas:
            is_rate = d["is_rate"]
            fmt = (lambda v: "n/a" if v is None
                   else (f"{v * 100:.1f}%" if is_rate else str(v)))
            change = _signed(d["delta"], is_rate)
            tinted = (c.good(change) if d["direction"] == "better"
                      else c.bad(change) if d["direction"] == "worse"
                      else change)
            pad = " " * max(0, 10 - len(change))
            print(f"  {d['metric']:<10} {fmt(d['before']):>9} "
                  f"{fmt(d['after']):>9} {pad}{tinted}")
        cd = report.castle_delta()
        if cd:
            change = _signed(cd["delta"], False)
            tinted = (c.good(change) if cd["direction"] == "better"
                      else c.bad(change) if cd["direction"] == "worse"
                      else change)
            pad = " " * max(0, 10 - len(change))
            print(f"  {'CASTLE':<10} {cd['before']:>9} {cd['after']:>9} "
                  f"{pad}{tinted}")
            cb, ca = cd["counts_before"], cd["counts_after"]
            moved = [k for k in set(cb) | set(ca)
                     if cb.get(k, 0) != ca.get(k, 0)]
            if moved:
                bits = ", ".join(f"{k} {cb.get(k, 0)}->{ca.get(k, 0)}"
                                 for k in sorted(moved))
                print(c.dim(f"             ({bits}; rule: {cd['detect']})"))
        md = report.macro_delta()
        if md:
            change = _signed(md["delta"], False)
            tinted = (c.good(change) if md["delta"] > 0
                      else c.bad(change) if md["delta"] < 0 else change)
            print(f"  {'macro':<10} {md['before']:>+9.3f} "
                  f"{md['after']:>+9.3f}     {tinted}")
        cat_moves = report.category_score_deltas()
        if cat_moves:
            print(f"\n  categories that moved:")
            for d in cat_moves:
                tp, fp = d["tp_delta"], d["fp_delta"]
                bits = []
                if tp:
                    bits.append((c.good if tp > 0 else c.bad)(
                        f"TP {d['before']['TP']}->{d['after']['TP']}"))
                if fp:
                    bits.append((c.bad if fp > 0 else c.good)(
                        f"FP {d['before']['FP']}->{d['after']['FP']}"))
                print(f"    {d['category']:<22} {'  '.join(bits)}")
        print()

    # -- resources -------------------------------------------------------
    print(c.head("RESOURCES"))
    tb, ta = report.totals_before, report.totals_after
    def ratio(a, b):
        return f"{(b / a):.2f}x" if a else "n/a"
    print(f"  cpu {tb['cpu_time']:.1f}s -> {ta['cpu_time']:.1f}s "
          f"({ratio(tb['cpu_time'], ta['cpu_time'])})   "
          f"peak RSS {tb['max_maxrss_kb'] / 1024:.0f} -> "
          f"{ta['max_maxrss_kb'] / 1024:.0f} MiB")
    # The caveat sits here, beside the numbers it undermines, rather
    # than in a block at the top that a reader has already scrolled past.
    for p in perf_caveats:
        print(c.warn(f"  !! {p}"))
    base = report.rss_baseline_ratio
    if abs(base - 1.0) > 0.02:
        print(f"  peak RSS moved {base:.2f}x across the board "
              f"(baseline footprint differs between these builds)")
    if report.resources:
        print(f"  {len(report.resources)} test(s) moved "
              f">={args.resource_threshold}x relative to that baseline:")
        for r in report.resources[:10]:
            print(f"    {r.name:<24} {r.rss_before / 1024:.0f} -> "
                  f"{r.rss_after / 1024:.0f} MiB  ({r.rss_ratio:.2f}x, "
                  f"{r.rss_ratio / base:.2f}x vs baseline)")
    else:
        print("  no test moved peak RSS out of line with that baseline")

    print()
    if report.clean:
        msg = "no regressions"
        if report.improved:
            msg += f", {len(report.improved)} improvement(s)"
        print(c.good(msg))
    else:
        print(c.alarm(f"!! {len(report.regressed)} regression(s), "
                      f"{len(report.new_crashes)} new crash(es)"))
    return 0 if report.clean else 1


def _collect_failures(records, matcher_name, categories, skip_categories):
    """Group a run's false results by category.

    False positives and false negatives are the two shapes of "the
    analyzer could do better here", and they want different detail:
    for an FP you need to see what it wrongly said, for an FN what it
    should have found and where.
    """
    report = scoring.score(records, matcher_name, categories,
                           skip_categories)
    by_name = {r["name"]: r for r in records}
    groups = {}
    for v in report.verdicts:
        if v.outcome not in ("FP", "FN"):
            continue
        rec = by_name.get(v.name, {})
        gt = rec.get("ground_truth") or {}
        entry = {
            "name": v.name,
            "outcome": v.outcome,
            "category": v.category,
            "cwe": gt.get("cwe"),
            "lines": gt.get("lines") or [],
            "source": rec.get("source"),
            "sarif": rec.get("sarif"),
            "repro": rec.get("argv") or [],
            "findings": [
                {"rule": f.get("rule"), "line": f.get("line"),
                 "cwes": f.get("cwes"), "message": f.get("message")}
                for f in scoring.analyzer_findings(rec)
            ],
        }
        groups.setdefault(v.category or "(uncategorised)", []).append(entry)
    for entries in groups.values():
        entries.sort(key=lambda e: (e["outcome"], e["name"]))
    return report, dict(sorted(groups.items(),
                               key=lambda kv: scoring.category_key(kv[0])))


def cmd_failures(args) -> int:
    run_dir = Path(expand(args.run_dir))
    if is_group(run_dir):
        _, members = load_group(run_dir)
        worst = 0
        for suite_name, child in members:
            if not args.json:
                print(make_palette(args.color).head(f"=== {suite_name}"))
            worst = max(worst, _failures_one(args, child))
            if not args.json:
                print()
        return worst
    return _failures_one(args, run_dir)


def _failures_one(args, run_dir: Path) -> int:
    manifest, records = load_run(run_dir)

    # Categories the analyzer does not attempt are not improvement
    # areas, so they are out of the way by default here (unlike in
    # `score`, where hiding tests would distort the number).
    skip = list(args.skip_category or [])
    out_of_scope = (manifest.get("suite") or {}).get(
        "out_of_scope_categories") or []
    hidden = []
    if out_of_scope and not args.all_categories and not args.category:
        hidden = [c for c in out_of_scope if c not in skip]
        skip += hidden

    try:
        report, groups = _collect_failures(records, args.match,
                                           args.category, skip)
    except KeyError as e:
        _die(str(e))

    wanted = {k.upper() for k in (args.kind or ["fp", "fn"])}
    groups = {
        cat: [e for e in entries if e["outcome"] in wanted]
        for cat, entries in groups.items()
    }
    groups = {k: v for k, v in groups.items() if v}

    if args.json:
        json.dump({
            "run": str(run_dir),
            "matcher": args.match,
            "suite": manifest.get("suite", {}),
            "toolchain": manifest.get("toolchain", {}),
            "counts": {"FP": report.overall.FP, "FN": report.overall.FN},
            "hidden_categories": hidden,
            "by_category": groups,
        }, sys.stdout, indent=2, sort_keys=True)
        print()
        return 0

    if args.format == "html":
        print(htmlout.render_failures(groups, report, manifest,
                                      str(run_dir)), end="")
        return 0

    c = make_palette(args.color)
    tc = manifest.get("toolchain", {})
    suite = manifest.get("suite", {})
    print(f"run       : {run_dir}")
    print(f"toolchain : {tc.get('name')}  {tc.get('version')}")
    print(f"suite     : {suite.get('name')} v{suite.get('version')}")
    print(f"matcher   : {args.match}")
    print(f"totals    : {c.bad(str(report.overall.FP))} false positives, "
          f"{c.bad(str(report.overall.FN))} false negatives")
    if hidden:
        print(c.dim(f"hidden    : {len(hidden)} categories -fanalyzer does "
                    f"not attempt ({', '.join(hidden)});"))
        print(c.dim(f"            pass --all-categories to include them"))
    print()

    if not groups:
        print(c.good("no false results"))
        return 0

    for category, entries in groups.items():
        fps = [e for e in entries if e["outcome"] == "FP"]
        fns = [e for e in entries if e["outcome"] == "FN"]
        head = f"{category}  ({len(fps)} FP, {len(fns)} FN)"
        print(c.head(head))
        for e in entries:
            tag = c.bad("FP") if e["outcome"] == "FP" else c.warn("FN")
            detail = (f"CWE-{e['cwe']}" if e["cwe"] else "")
            if e["outcome"] == "FN" and e["lines"]:
                detail += f" at line(s) {', '.join(map(str, e['lines']))}"
            print(f"  {tag} {e['name']:<22} {detail}")
            if args.verbose:
                for f in e["findings"]:
                    print(c.dim(f"       reported {f['rule']} "
                                f"@{f['line']}: {f['message'][:70]}"))
                if e["outcome"] == "FN" and not e["findings"]:
                    print(c.dim("       reported nothing"))
                if e["source"]:
                    print(c.dim(f"       source {e['source']}"))
        print()

    if not args.verbose:
        print(c.dim("(-v shows what was reported, and the source path)"))
    return 0


def cmd_show(args) -> int:
    manifest, records = load_run(Path(expand(args.run_dir)))
    if args.manifest:
        json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
        print()
        return 0
    for rec in records:
        if args.filter and not any(
            fnmatch.fnmatch(rec["name"], p) for p in args.filter
        ):
            continue
        json.dump(rec, sys.stdout, sort_keys=True)
        print()
    return 0


# -- entry point ---------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gab",
        description="Benchmark GCC's static analyzer (-fanalyzer).",
    )
    p.add_argument("--version", action="version", version=f"gab {__version__}")
    # These are accepted both before and after the subcommand, so that
    # `gab --config X score R` and `gab score R --config X` both work.
    # The subcommand copies use SUPPRESS so that, when absent, they do
    # not overwrite a value given before the subcommand.
    def add_common(parser, suppress: bool):
        d = (lambda v: argparse.SUPPRESS if suppress else v)
        parser.add_argument("-c", "--config", metavar="PATH",
                            default=d(None),
                            help="config file "
                                 "(default: ./config.json or $GAB_CONFIG)")
        parser.add_argument("--color", choices=("auto", "always", "never"),
                            default=d("auto"),
                            help="colourise output (default: auto -- on "
                                 "only when writing to a terminal, never "
                                 "under NO_COLOR)")
        parser.add_argument("-f", "--format",
                            choices=("text", "json", "html"),
                            default=d("text"),
                            help="output format (default: text)")
        parser.add_argument("--json", dest="json", action="store_true",
                            default=d(False),
                            help="shorthand for --format json")
        parser.add_argument("--html", dest="html", action="store_true",
                            default=d(False),
                            help="shorthand for --format html")

    add_common(p, suppress=False)
    common = argparse.ArgumentParser(add_help=False)
    add_common(common, suppress=True)

    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("suites", parents=[common], help="list configured suites")
    s.set_defaults(func=cmd_suites)

    s = sub.add_parser("toolchains", parents=[common], help="list configured compilers")
    s.set_defaults(func=cmd_toolchains)

    s = sub.add_parser("run", parents=[common], help="run a suite under a compiler")
    s.add_argument("-t", "--toolchain", required=True)
    s.add_argument("-s", "--suite", required=True, action="append",
                   metavar="NAME",
                   help="suite to run; 'all' for every configured suite, "
                        "repeatable, or comma-separated. More than one "
                        "suite writes a parent directory with one child "
                        "run per suite.")
    s.add_argument("--suite-version", metavar="VER",
                   help="pin the suite to a named release "
                        "(BenchProctor rotates its contents between releases)")
    s.add_argument("--time-report", action="store_true",
                   help="add -ftime-report to separate analyzer time from "
                        "total compile time (perturbs timing slightly)")
    s.add_argument("-j", "--jobs", type=int, default=0,
                   help="parallel compilations (default: CPU count)")
    s.add_argument("-o", "--out", metavar="DIR",
                   help="run directory (default: runs/<stamp>-<tc>-<suite>)")
    s.add_argument("--filter", action="append", metavar="GLOB",
                   help="only run tests matching GLOB (repeatable)")
    s.add_argument("--limit", type=int, metavar="N",
                   help="only run the first N selected tests")
    s.add_argument("--extra-arg", action="append", metavar="ARG",
                   help="extra compiler argument (repeatable)")
    s.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   metavar="SECONDS")
    s.add_argument("--no-sarif", action="store_true",
                   help="discard raw SARIF after extracting findings")
    s.add_argument("--force", action="store_true",
                   help="overwrite a non-empty run directory")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("score", parents=[common], help="score a run directory")
    s.add_argument("run_dir")
    s.add_argument("-m", "--match", default=scoring.DEFAULT_MATCHER,
                   choices=sorted(scoring.MATCHERS),
                   help=f"what counts as a detection "
                        f"(default: {scoring.DEFAULT_MATCHER})")
    s.add_argument("--category", action="append", metavar="CAT",
                   help="score only this category (repeatable)")
    s.add_argument("--skip-category", action="append", metavar="CAT",
                   help="exclude this category, e.g. one -fanalyzer does "
                        "not cover (repeatable)")
    s.add_argument("--castle-score", action="store_true",
                   help="compute the CASTLE Score even for a non-CASTLE "
                        "suite (it is shown automatically for CASTLE)")
    s.add_argument("--castle-detect", metavar="RULE", default="cwe",
                   help="how the CASTLE Score decides a detection: 'cwe' "
                        "(the paper's rule, needed for comparability) or "
                        "a gab matcher name (default: cwe)")
    s.add_argument("--castle-grid", action="store_true",
                   help="show the CASTLE score as a CWE x test grid "
                        "(always included in --format html)")
    s.add_argument("--compare-matchers", action="store_true",
                   help="also show every matching rule, to see how much "
                        "the choice drives the result")
    s.add_argument("--no-categories", action="store_true",
                   help="omit the per-category table")
    s.set_defaults(func=cmd_score)

    s = sub.add_parser("diff", parents=[common], help="compare two run directories")
    s.add_argument("before")
    s.add_argument("after")
    s.add_argument("-m", "--match", default=scoring.DEFAULT_MATCHER,
                   choices=sorted(scoring.MATCHERS))
    s.add_argument("--category", action="append", metavar="CAT",
                   help="restrict scoring deltas to this category "
                        "(repeatable)")
    s.add_argument("--skip-category", action="append", metavar="CAT",
                   help="exclude this category from scoring deltas "
                        "(repeatable)")
    s.add_argument("--force", action="store_true",
                   help="diff even if the runs are not comparable")
    s.add_argument("--all", action="store_true",
                   help="list every changed test, not just the first 25")
    s.add_argument("--churn", action="store_true",
                   help="also list tests whose outcome held but whose "
                        "diagnostics changed")
    s.add_argument("-v", "--verbose", action="store_true",
                   help="show the individual findings that changed")
    s.add_argument("--castle-detect", metavar="RULE", default="cwe",
                   help="detection rule for the CASTLE Score, shown when "
                        "diffing CASTLE runs (default: cwe)")
    s.add_argument("--resource-threshold", type=float, default=1.5,
                   metavar="RATIO",
                   help="flag tests whose peak RSS moved by this factor "
                        "(default: 1.5)")
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("failures", parents=[common],
                       help="list the false positives and false negatives "
                            "in a run")
    s.add_argument("run_dir")
    s.add_argument("-m", "--match", default=scoring.DEFAULT_MATCHER,
                   choices=sorted(scoring.MATCHERS))
    s.add_argument("-k", "--kind", action="append", choices=("fp", "fn"),
                   help="restrict to false positives or false negatives "
                        "(default: both)")
    s.add_argument("--category", action="append", metavar="CAT")
    s.add_argument("--skip-category", action="append", metavar="CAT")
    s.add_argument("--all-categories", action="store_true",
                   help="include categories -fanalyzer does not attempt, "
                        "which are hidden by default")
    s.add_argument("-v", "--verbose", action="store_true",
                   help="show what the analyzer reported, and source paths")
    s.set_defaults(func=cmd_failures)

    s = sub.add_parser("show", parents=[common], help="dump a run directory as JSON")
    s.add_argument("run_dir")
    s.add_argument("--manifest", action="store_true",
                   help="print run.json instead of the per-test records")
    s.add_argument("--filter", action="append", metavar="GLOB")
    s.set_defaults(func=cmd_show)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    # --json and --html are shorthands; normalise onto args.format so the
    # rest of the code only ever asks about that.
    if getattr(args, "json", False):
        args.format = "json"
    elif getattr(args, "html", False):
        args.format = "html"
    args.json = args.format == "json"
    args.html = args.format == "html"
    try:
        return args.func(args)
    except (FileNotFoundError, IsADirectoryError) as e:
        _die(str(e))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
