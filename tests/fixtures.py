# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Shared test fixtures.

Two things make the whole suite runnable with no GCC and no benchmark
checkout:

  * a synthetic suite whose sources and ground truth are generated into
    a temp directory, and
  * a stub compiler -- a small Python script that speaks enough of GCC's
    command line to be driven by the real `Runner`, and which decides
    what to emit from markers in the source file.

The stub matters more than it looks.  It means the runner's process
handling, SARIF parsing, status classification and crash detection are
exercised end to end on every run of the tests, including the paths for
an ICE, a hang and a malformed SARIF, which are impossible to provoke
on demand with a real compiler.
"""

from __future__ import annotations

import json
import os
import stat
import textwrap
from pathlib import Path
from typing import List, Optional

from gab.suite import Suite, TestCase, register

# Markers a synthetic source file can carry to steer the stub compiler.
MARK_FINDING = "GAB_EMIT_FINDING"     # emit an analyzer finding at a line
MARK_ICE = "GAB_ICE"                  # pretend to be an internal error
MARK_HANG = "GAB_HANG"                # sleep forever, to test timeouts
MARK_FAIL = "GAB_COMPILE_ERROR"       # exit nonzero without an ICE
MARK_BAD_SARIF = "GAB_BAD_SARIF"      # write truncated JSON
MARK_NO_SARIF = "GAB_NO_SARIF"        # write nothing at all


STUB_COMPILER = r'''#!/usr/bin/env python3
"""A fake GCC, just real enough to drive gab's runner."""
import json, os, re, sys, time

argv = sys.argv[1:]
sarif_path = None
source = None
for a in argv:
    m = re.match(r"-fdiagnostics-add-output=sarif:file=(.*)", a)
    if m:
        sarif_path = m.group(1)
    elif a.endswith(".c"):
        source = a

if "--version" in argv:
    print("stubgcc (GCC) 99.1.0 20260101 (experimental)")
    sys.exit(0)
if "-dumpversion" in argv:
    print("99.1.0"); sys.exit(0)
if "-dumpmachine" in argv:
    print("x86_64-pc-linux-gnu"); sys.exit(0)
if "-print-prog-name=cc1" in argv:
    print(os.environ.get("GAB_STUB_CC1", "cc1")); sys.exit(0)
if "-v" in argv:
    sys.stderr.write("Target: x86_64-pc-linux-gnu\n")
    sys.stderr.write("Configured with: ../configure "
                     "--enable-checking=release --enable-bootstrap\n")
    sys.exit(0)
if "--help=common" in argv or "-Q" in argv:
    print("  -fchecking=        \t0")
    sys.exit(0)

text = open(source).read() if source else ""

if "GAB_HANG" in text:
    time.sleep(3600)
if "GAB_ICE" in text:
    sys.stderr.write("%s: internal compiler error: Segmentation fault\n"
                     % source)
    sys.stderr.write("Please submit a full bug report.\n")
    sys.exit(1)
if "GAB_COMPILE_ERROR" in text:
    sys.stderr.write("%s:1:1: error: synthetic failure\n" % source)
    sys.exit(1)
if "GAB_NO_SARIF" in text:
    sys.exit(0)
if sarif_path and "GAB_BAD_SARIF" in text:
    open(sarif_path, "w").write('{"runs": [{"resu')
    sys.exit(0)

results = []
# GAB_EMIT_FINDING:<rule>:<cwe>:<line>:<path lines, dash separated>
for m in re.finditer(r"GAB_EMIT_FINDING:([\w-]+):(\d+):(\d+):([\d-]*)", text):
    rule, cwe, line, path = m.groups()
    results.append({
        "ruleId": rule,
        "level": "warning",
        "message": {"text": "synthetic %s" % rule},
        "taxa": [{"id": cwe, "toolComponent": {"name": "cwe"}}],
        "properties": {"gcc/analyzer/pending_diagnostic/kind": rule},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": os.path.basename(source)},
            "region": {"startLine": int(line), "startColumn": 3}}}],
        "codeFlows": [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": {
                "artifactLocation": {"uri": os.path.basename(source)},
                "region": {"startLine": int(p)}}}}
            for p in path.split("-") if p]}]}] if path else [],
    })

if sarif_path:
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "GNU C23", "version": "99.1.0"}},
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": "2026-01-01T00:00:00Z",
                "endTimeUtc": "2026-01-01T00:00:01Z",
                "properties": {"gcc/timeReport": {"timevars": [
                    {"name": "analyzer: processing worklist",
                     "elapsed": {"wall": 0.01, "ggc_mem": 1234}},
                    {"name": "TOTAL", "elapsed": {"wall": 0.02}},
                ]}} if "-ftime-report" in argv else {},
            }],
            "results": results,
        }],
    }
    with open(sarif_path, "w") as f:
        json.dump(doc, f)
sys.exit(0)
'''


def write_stub_compiler(directory: Path) -> Path:
    path = Path(directory) / "stubgcc"
    path.write_text(STUB_COMPILER, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP)
    return path


# -- synthetic suite -----------------------------------------------------

#: name, vulnerable, category, cwe, truth lines, body markers
SYNTHETIC_SPEC = [
    # A clean detection: finding sits exactly on a ground-truth line.
    ("hit-exact", True, "leak", 401, [5],
     "GAB_EMIT_FINDING:-Wanalyzer-malloc-leak:401:5:4-5"),
    # Leak convention: reported at the closing brace, allocation in path.
    ("hit-via-path", True, "leak", 401, [4],
     "GAB_EMIT_FINDING:-Wanalyzer-malloc-leak:401:9:4-9"),
    # Off by one from truth: only the +-1 and +-2 rules catch it.
    ("hit-off-by-one", True, "loop", 835, [6],
     "GAB_EMIT_FINDING:-Wanalyzer-infinite-loop:835:7:7"),
    # A real finding, but nowhere near the flaw under test.
    ("miss-wrong-place", True, "leak", 401, [5],
     "GAB_EMIT_FINDING:-Wanalyzer-out-of-bounds:787:40:40"),
    # Vulnerable, nothing reported at all.
    ("miss-silent", True, "null", 476, [5], ""),
    # Clean file, correctly silent.
    ("clean-quiet", False, "leak", 401, [], ""),
    # Clean file with a report: a false positive.
    ("clean-noisy", False, "null", 476, [],
     "GAB_EMIT_FINDING:-Wanalyzer-null-dereference:476:5:5"),
    # An analyzer note about the analysis, which must never count.
    ("clean-too-complex", False, "leak", 401, [],
     "GAB_EMIT_FINDING:-Wanalyzer-too-complex:0:5:5"),
]


def make_synthetic_suite(root: Path) -> Path:
    """Write sources + a ground-truth JSON, and return the root."""
    root = Path(root)
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    truth = []
    for name, vuln, cat, cwe, lines, marker in SYNTHETIC_SPEC:
        body = textwrap.dedent(f"""\
            /* synthetic test {name} */
            #include <stdlib.h>
            void {name.replace('-', '_')}(void)
            {{
                char *p = malloc(16);
                if (!p)
                    return;
                /* {marker} */
            }}
            """)
        (src / f"{name}.c").write_text(body, encoding="utf-8")
        truth.append({"name": name, "vulnerable": vuln, "category": cat,
                      "cwe": cwe, "lines": lines})
    (root / "truth.json").write_text(
        json.dumps({"version": "test-1.0", "tests": truth}), encoding="utf-8")
    return root


@register
class SyntheticSuite(Suite):
    """Suite adapter over `make_synthetic_suite`'s output."""

    name = "synthetic"

    def __init__(self, root: Path, options=None):
        super().__init__(root, options)
        self._data = json.loads(
            (self.root / "truth.json").read_text(encoding="utf-8"))

    def version(self) -> str:
        return self._data["version"]

    def tests(self) -> List[TestCase]:
        return [
            TestCase(
                suite=self.name,
                name=t["name"],
                source=self.root / "src" / f"{t['name']}.c",
                compile_args=("-std=c11",),
                vulnerable=t["vulnerable"],
                cwe=t["cwe"],
                category=t["category"],
                lines=tuple(t["lines"]),
            )
            for t in self._data["tests"]
        ]


def make_config(tmp: Path, suite_root: Path, compiler: Path,
                extra_toolchains: Optional[dict] = None) -> Path:
    """Write a gab config pointing at the stub compiler and suite."""
    cfg = {
        "toolchains": {
            "stub": {"cc": str(compiler), "description": "stub compiler"},
        },
        "suites": {"synthetic": {"path": str(suite_root)}},
        "runs_dir": str(Path(tmp) / "runs"),
    }
    if extra_toolchains:
        cfg["toolchains"].update(extra_toolchains)
    path = Path(tmp) / "config.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


# -- synthetic run directories ------------------------------------------

def make_record(name: str, *, vulnerable=True, category="leak", cwe=401,
                lines=(5,), findings=(), status="ok", wall=0.1,
                maxrss=30000, argv=("cc", "x.c")) -> dict:
    """One results.jsonl record, built directly rather than by running."""
    return {
        "name": name,
        "suite": "synthetic",
        "source": f"/tmp/{name}.c",
        "ground_truth": {"vulnerable": vulnerable, "category": category,
                         "cwe": cwe, "lines": list(lines)},
        "status": status,
        "exit_code": 0 if status == "ok" else 1,
        "signal": 11 if status == "ice" else None,
        "wall_time": wall,
        "user_time": wall * 0.8,
        "sys_time": wall * 0.2,
        "maxrss_kb": maxrss,
        "findings": list(findings),
        "n_analyzer_findings": sum(
            1 for f in findings if f.get("analyzer") and not f.get("meta")),
        "too_complex": any(f.get("meta") for f in findings),
        "invocation": {},
        "sarif": f"sarif/{name}.sarif",
        "log": None,
        "error": None,
        "argv": list(argv),
    }


def make_finding(rule="-Wanalyzer-malloc-leak", cwe=401, line=5,
                 path_lines=(), meta=False) -> dict:
    return {
        "rule": rule,
        "analyzer": rule.startswith("-Wanalyzer-"),
        "meta": meta,
        "level": "warning",
        "cwes": [cwe] if cwe else [],
        "kind": rule.replace("-Wanalyzer-", ""),
        "line": line,
        "column": 3,
        "uri": "x.c",
        "path_lines": list(path_lines),
        "message": f"synthetic {rule}",
    }


def write_run(path: Path, records, *, toolchain_name="before",
              cc1_sha="a" * 64, gcc_descr=None, build_type="release",
              content_hash="hash-1", suite_name="synthetic",
              analyzer_args=("-fanalyzer",), target="x86_64-pc-linux-gnu",
              dumpversion="99.1.0", bootstrap=False) -> Path:
    """Write a complete run directory from pre-built records."""
    path = Path(path)
    (path / "sarif").mkdir(parents=True, exist_ok=True)
    with open(path / "results.jsonl", "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    manifest = {
        "gab_version": "test",
        "schema": 1,
        "started": 0,
        "n_tests": len(records),
        "jobs": 1,
        "analyzer_args": list(analyzer_args),
        "extra_args": [],
        "toolchain": {
            "name": toolchain_name,
            "version": f"gcc (GCC) {dumpversion} (experimental)",
            "dumpversion": dumpversion,
            "target": target,
            "host": target,
            "build_type": build_type,
            "fchecking": 0 if build_type == "release" else 2,
            "bootstrap": bootstrap,
            "cc1": {"path": "/x/cc1", "sha256": cc1_sha,
                    "has_debug_info": False},
            "git": ({"gcc_descr": gcc_descr, "head": "deadbeef",
                     "branch": "b", "dirty": False} if gcc_descr else None),
        },
        "suite": {"name": suite_name, "version": "test-1.0",
                  "content_hash": content_hash, "cwe_parents": {}},
        "host": {"hostname": "testhost", "cpus": 1},
        "totals": {},
    }
    with open(path / "run.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    return path
