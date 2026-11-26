# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""End-to-end CLI tests: every command, every output format.

These drive the real `main()` against the stub compiler, so the runner's
process handling, SARIF parsing and status classification are exercised
for real -- including the ICE, timeout and malformed-SARIF paths, which
cannot be provoked on demand with an actual GCC.
"""

import contextlib
import html.parser
import io
import json
import re
import xml.etree.ElementTree as ET
import shutil
import tempfile
import unittest
from pathlib import Path

from gab.cli import main
from tests.fixtures import (make_config, make_finding, make_record,
                            make_synthetic_suite, write_run,
                            write_stub_compiler)


class HTMLWellFormed(html.parser.HTMLParser):
    VOID = {"meta", "br", "hr", "link", "img", "input"}

    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []

    def handle_startendtag(self, tag, attrs):
        pass   # <foo /> opens and closes in one go

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.errors.append(f"</{tag}> closes {self.stack[-1:]}")


def run_cli(*argv):
    """Invoke main(), capturing stdout/stderr and the exit code."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
    return code, out.getvalue(), err.getvalue()


class CLITestCase(unittest.TestCase):
    """Base: a temp dir with a synthetic suite and a stub compiler."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="gab-test-"))
        cls.suite_root = make_synthetic_suite(cls.tmp / "suite")
        cls.compiler = write_stub_compiler(cls.tmp)
        cls.config = make_config(cls.tmp, cls.suite_root, cls.compiler)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def gab(self, *argv):
        return run_cli("--config", str(self.config), *argv)

    def assert_valid_html(self, text):
        """Check the output is well-formed XHTML, not merely plausible.

        Parsing with a real XML parser is a much stronger check than
        tag-balance counting: it catches unescaped '&', unclosed void
        elements, bare boolean attributes and HTML-only named entities
        such as &rarr;, every one of which a browser would quietly
        forgive but which make the output unusable as XML.

        Note this is well-formedness, not validation against the XHTML
        schema -- that would need a DTD and a network fetch.
        """
        self.assertTrue(text.startswith("<!DOCTYPE html>"), "missing doctype")
        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            self.fail(f"output is not well-formed XML: {e}")
        self.assertEqual(root.tag,
                         "{http://www.w3.org/1999/xhtml}html")

        # Belt and braces: the HTML parser should agree about nesting.
        p = HTMLWellFormed()
        p.feed(text)
        self.assertEqual(p.errors, [], "mismatched tags")
        self.assertEqual(p.stack, [], "unclosed tags")

        # Self-contained: no external resources to go stale.
        for bad in ("<script", "src=\"http", "href=\"http"):
            self.assertNotIn(bad, text)


class TestSuitesCommand(CLITestCase):
    def test_text(self):
        code, out, _ = self.gab("suites")
        self.assertEqual(code, 0)
        self.assertIn("synthetic", out)

    def test_json(self):
        code, out, _ = self.gab("suites", "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        s = data["suites"]["synthetic"]
        self.assertEqual(s["n_tests"], 8)
        self.assertEqual(s["n_vulnerable"], 5)
        self.assertTrue(s["content_hash"])

    def test_content_hash_is_stable_and_content_sensitive(self):
        _, a, _ = self.gab("suites", "--json")
        _, b, _ = self.gab("suites", "--json")
        self.assertEqual(json.loads(a)["suites"]["synthetic"]["content_hash"],
                         json.loads(b)["suites"]["synthetic"]["content_hash"])

        src = self.suite_root / "src" / "clean-quiet.c"
        original = src.read_text()
        try:
            src.write_text(original + "\n/* changed */\n")
            _, c, _ = self.gab("suites", "--json")
            self.assertNotEqual(
                json.loads(a)["suites"]["synthetic"]["content_hash"],
                json.loads(c)["suites"]["synthetic"]["content_hash"])
        finally:
            src.write_text(original)


class TestToolchainsCommand(CLITestCase):
    def test_text(self):
        code, out, _ = self.gab("toolchains")
        self.assertEqual(code, 0)
        self.assertIn("stub", out)

    def test_json_reports_identity(self):
        code, out, _ = self.gab("toolchains", "--json")
        self.assertEqual(code, 0)
        tc = json.loads(out)["toolchains"]["stub"]
        self.assertEqual(tc["target"], "x86_64-pc-linux-gnu")
        self.assertEqual(tc["build_type"], "release")

    def test_missing_compiler_is_reported_not_crashed(self):
        cfg = json.loads(self.config.read_text())
        cfg["toolchains"]["ghost"] = {"cc": "/nonexistent/gcc"}
        p = self.tmp / "cfg-ghost.json"
        p.write_text(json.dumps(cfg))
        code, out, _ = run_cli("--config", str(p), "toolchains")
        self.assertEqual(code, 0)
        self.assertIn("UNAVAILABLE", out)


class TestRunCommand(CLITestCase):
    def test_run_text_and_records(self):
        out_dir = self.tmp / "run-basic"
        code, out, _ = self.gab("run", "-t", "stub", "-s", "synthetic",
                                "-o", str(out_dir), "--force", "-q")
        self.assertEqual(code, 0)
        self.assertIn("ran 8 tests", out)

        records = [json.loads(l) for l in
                   (out_dir / "results.jsonl").read_text().splitlines() if l]
        self.assertEqual(len(records), 8)
        by = {r["name"]: r for r in records}
        self.assertEqual(by["hit-exact"]["n_analyzer_findings"], 1)
        self.assertEqual(by["miss-silent"]["n_analyzer_findings"], 0)
        # A meta diagnostic is recorded but does not count as a finding.
        self.assertTrue(by["clean-too-complex"]["too_complex"])
        self.assertEqual(by["clean-too-complex"]["n_analyzer_findings"], 0)

    def test_codeflow_path_lines_are_captured(self):
        out_dir = self.tmp / "run-path"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(out_dir),
                 "--force", "-q")
        records = {json.loads(l)["name"]: json.loads(l) for l in
                   (out_dir / "results.jsonl").read_text().splitlines() if l}
        f = records["hit-via-path"]["findings"][0]
        self.assertEqual(f["line"], 9)
        self.assertIn(4, f["path_lines"])

    def test_manifest_records_provenance(self):
        out_dir = self.tmp / "run-manifest"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(out_dir),
                 "--force", "-q")
        m = json.loads((out_dir / "run.json").read_text())
        self.assertEqual(m["suite"]["name"], "synthetic")
        self.assertFalse(m["suite"]["subset"])
        self.assertTrue(m["suite"]["content_hash"])
        self.assertEqual(m["toolchain"]["name"], "stub")

    def test_limit_marks_the_run_as_a_subset(self):
        out_dir = self.tmp / "run-subset"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(out_dir),
                 "--force", "-q", "--limit", "3")
        m = json.loads((out_dir / "run.json").read_text())
        self.assertTrue(m["suite"]["subset"])
        self.assertEqual(m["n_tests"], 3)

    def test_filter_selects_by_glob(self):
        out_dir = self.tmp / "run-filter"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(out_dir),
                 "--force", "-q", "--filter", "hit-*")
        m = json.loads((out_dir / "run.json").read_text())
        self.assertEqual(m["n_tests"], 3)

    def test_json_format(self):
        out_dir = self.tmp / "run-json"
        code, out, _ = self.gab("run", "-t", "stub", "-s", "synthetic",
                                "-o", str(out_dir), "--force", "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)          # stdout must be pure JSON
        self.assertEqual(data["n_tests"], 8)
        self.assertEqual(data["status"]["ok"], 8)
        self.assertEqual(data["crashes"], [])

    def test_time_report_captures_analyzer_timevars(self):
        out_dir = self.tmp / "run-time"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(out_dir),
                 "--force", "-q", "--time-report")
        rec = json.loads(
            (out_dir / "results.jsonl").read_text().splitlines()[0])
        inv = rec["invocation"]
        self.assertIn("analyzer: processing worklist", inv["timevars"])
        self.assertAlmostEqual(inv["analyzer_wall"], 0.01)

    def test_refuses_to_clobber_without_force(self):
        out_dir = self.tmp / "run-clobber"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(out_dir),
                 "--force", "-q", "--limit", "1")
        code, _, err = self.gab("run", "-t", "stub", "-s", "synthetic",
                                "-o", str(out_dir), "-q", "--limit", "1")
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)

    def test_unknown_toolchain_and_suite_are_errors(self):
        code, _, err = self.gab("run", "-t", "nope", "-s", "synthetic",
                                "-o", str(self.tmp / "x"))
        self.assertEqual(code, 2)
        self.assertIn("unknown toolchain", err)


class TestRunFailureModes(CLITestCase):
    """The compiler misbehaving, which is the thing we must never miss."""

    def _run_one(self, marker, name, extra=()):
        src = self.suite_root / "src" / f"{name}.c"
        src.write_text(f"/* {marker} */\nint main(void) {{ return 0; }}\n")
        truth = json.loads((self.suite_root / "truth.json").read_text())
        truth["tests"].append({"name": name, "vulnerable": True,
                               "category": "leak", "cwe": 401, "lines": [1]})
        (self.suite_root / "truth.json").write_text(json.dumps(truth))
        out_dir = self.tmp / f"fail-{name}"
        try:
            code, out, err = self.gab(
                "run", "-t", "stub", "-s", "synthetic", "-o", str(out_dir),
                "--force", "-q", "--filter", name, *extra)
            rec = json.loads(
                (out_dir / "results.jsonl").read_text().splitlines()[0])
            return code, out, err, rec
        finally:
            src.unlink(missing_ok=True)
            truth["tests"] = [t for t in truth["tests"]
                              if t["name"] != name]
            (self.suite_root / "truth.json").write_text(json.dumps(truth))

    def test_ice_is_detected_and_loud(self):
        code, out, err, rec = self._run_one("GAB_ICE", "crasher")
        self.assertEqual(rec["status"], "ice")
        self.assertEqual(code, 1, "an ICE must fail the command")
        self.assertIn("COMPILER FAILURE", err)
        self.assertIn("reproduce with", err)

    def test_timeout_is_detected(self):
        code, _, err, rec = self._run_one("GAB_HANG", "hanger",
                                          extra=("--timeout", "1"))
        self.assertEqual(rec["status"], "timeout")
        self.assertEqual(code, 1)

    def test_compile_error_is_not_an_ice(self):
        code, _, _, rec = self._run_one("GAB_COMPILE_ERROR", "broken")
        self.assertEqual(rec["status"], "compile-error")
        self.assertEqual(code, 0, "a compile error is not a GCC crash")

    def test_truncated_sarif_is_not_silently_zero_findings(self):
        _, _, _, rec = self._run_one("GAB_BAD_SARIF", "truncated")
        self.assertEqual(rec["status"], "bad-sarif")

    def test_missing_sarif_is_reported(self):
        _, _, _, rec = self._run_one("GAB_NO_SARIF", "nosarif")
        self.assertEqual(rec["status"], "bad-sarif")

    def test_crashes_appear_in_json(self):
        src = self.suite_root / "src" / "crasher2.c"
        src.write_text("/* GAB_ICE */\n")
        truth = json.loads((self.suite_root / "truth.json").read_text())
        truth["tests"].append({"name": "crasher2", "vulnerable": True,
                               "category": "leak", "cwe": 401, "lines": [1]})
        (self.suite_root / "truth.json").write_text(json.dumps(truth))
        try:
            code, out, _ = self.gab(
                "run", "-t", "stub", "-s", "synthetic",
                "-o", str(self.tmp / "fail-json"), "--force", "--json",
                "--filter", "crasher2")
            data = json.loads(out)
            self.assertEqual(code, 1)
            self.assertEqual(len(data["crashes"]), 1)
            self.assertTrue(data["crashes"][0]["repro"])
        finally:
            src.unlink(missing_ok=True)
            truth["tests"] = [t for t in truth["tests"]
                              if t["name"] != "crasher2"]
            (self.suite_root / "truth.json").write_text(json.dumps(truth))


class TestScoreCommand(CLITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.run_dir = cls.tmp / "score-run"
        run_cli("--config", str(cls.config), "run", "-t", "stub",
                "-s", "synthetic", "-o", str(cls.run_dir), "--force", "-q")

    def test_text(self):
        code, out, _ = self.gab("score", str(self.run_dir))
        self.assertEqual(code, 0)
        self.assertIn("precision", out)
        self.assertIn("category", out)

    def test_json_counts_match_the_fixture(self):
        code, out, _ = self.gab("score", str(self.run_dir), "--json")
        self.assertEqual(code, 0)
        o = json.loads(out)["overall"]
        # 5 vulnerable: hit-exact, hit-via-path, hit-off-by-one are TP
        # under path+1; miss-wrong-place and miss-silent are FN.
        # 3 clean: clean-noisy is FP, the other two TN.
        self.assertEqual((o["TP"], o["FP"], o["FN"], o["TN"]), (3, 1, 2, 2))

    def test_matcher_changes_the_result(self):
        def tp(rule):
            _, out, _ = self.gab("score", str(self.run_dir), "--json",
                                 "-m", rule)
            return json.loads(out)["overall"]["TP"]
        self.assertEqual(tp("line"), 1)     # only hit-exact
        self.assertEqual(tp("line2"), 2)    # + hit-off-by-one
        self.assertEqual(tp("path"), 2)     # hit-exact + hit-via-path
        self.assertEqual(tp("path+1"), 3)   # all three
        self.assertEqual(tp("file"), 4)     # + miss-wrong-place

    def test_skip_category_narrows_scope(self):
        _, out, _ = self.gab("score", str(self.run_dir), "--json",
                             "--skip-category", "leak")
        data = json.loads(out)
        self.assertNotIn("leak", data["by_category"])

    def test_compare_matchers_lists_every_rule(self):
        _, out, _ = self.gab("score", str(self.run_dir),
                             "--compare-matchers")
        for rule in ("file", "line", "line2", "path", "path+1"):
            self.assertIn(rule, out)

    def test_html(self):
        code, out, _ = self.gab("score", str(self.run_dir), "--format",
                                "html")
        self.assertEqual(code, 0)
        self.assert_valid_html(out)
        self.assertIn("By category", out)

    def test_excluded_tests_make_score_exit_nonzero(self):
        run_dir = self.tmp / "score-excluded"
        write_run(run_dir, [make_record("t", status="ice")])
        code, out, _ = self.gab("score", str(run_dir))
        self.assertEqual(code, 1)
        self.assertIn("excluded", out)


class TestDiffCommand(CLITestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(dir=self.tmp))
        self.before = write_run(
            self.base / "before",
            [make_record("improves", lines=(5,)),
             make_record("regresses", lines=(5,),
                         findings=[make_finding(line=5)]),
             make_record("crashes", lines=(5,)),
             make_record("steady", lines=(5,),
                         findings=[make_finding(line=5)])],
            toolchain_name="before", cc1_sha="a" * 64)
        self.after = write_run(
            self.base / "after",
            [make_record("improves", lines=(5,),
                         findings=[make_finding(line=5)]),
             make_record("regresses", lines=(5,)),
             make_record("crashes", lines=(5,), status="ice"),
             make_record("steady", lines=(5,),
                         findings=[make_finding(line=5)])],
            toolchain_name="after", cc1_sha="b" * 64)

    def test_text_shows_all_three_axes(self):
        code, out, _ = self.gab("diff", str(self.before), str(self.after))
        self.assertEqual(code, 1)
        self.assertIn("NEW COMPILER FAILURE", out)
        self.assertIn("REGRESSED", out)
        self.assertIn("IMPROVED", out)
        self.assertIn("SCORING", out)
        self.assertIn("RESOURCES", out)

    def test_perf_caveat_sits_with_the_numbers_not_at_the_top(self):
        after = write_run(self.base / "after2",
                          [make_record("steady", lines=(5,))],
                          toolchain_name="after", cc1_sha="c" * 64,
                          build_type="checking+extra")
        before = write_run(self.base / "before2",
                           [make_record("steady", lines=(5,))],
                           toolchain_name="before", cc1_sha="d" * 64)
        _, out, _ = self.gab("diff", str(before), str(after))
        caveat = "timings are not comparable"
        self.assertIn(caveat, out)
        self.assertGreater(out.index(caveat), out.index("RESOURCES"),
                           "perf caveat must follow the resource numbers")

    def test_json(self):
        code, out, _ = self.gab("diff", str(self.before), str(self.after),
                                "--json")
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["summary"]["improved"], 1)
        self.assertEqual(data["summary"]["regressed"], 1)
        self.assertEqual(data["summary"]["new_crashes"], 1)
        self.assertEqual(data["scoring"]["deltas"][0]["metric"], "TP")
        self.assertIn("caveats", data["resources"])

    def test_html(self):
        code, out, _ = self.gab("diff", str(self.before), str(self.after),
                                "--format", "html")
        self.assertEqual(code, 1)
        self.assert_valid_html(out)
        self.assertIn("Regressed", out)
        self.assertIn("Scoring", out)

    def test_html_escapes_content(self):
        run_a = write_run(self.base / "esc-a", [make_record("t", lines=(5,))])
        run_b = write_run(
            self.base / "esc-b",
            [make_record("t", lines=(5,), findings=[
                make_finding(rule="-Wanalyzer-<script>alert(1)</script>",
                             line=5)])],
            cc1_sha="z" * 64)
        _, out, _ = self.gab("diff", str(run_a), str(run_b), "--format",
                             "html", "--force")
        self.assertIn("-Wanalyzer-", out, "the finding should be rendered")
        self.assertNotIn("<script>alert", out)
        self.assertIn("&lt;script&gt;", out)

    def test_clean_diff_exits_zero(self):
        code, out, _ = self.gab("diff", str(self.before), str(self.before),
                                "--force")
        self.assertEqual(code, 0)
        self.assertIn("no regressions", out)

    def test_incomparable_runs_are_refused(self):
        other = write_run(self.base / "other", [make_record("t")],
                          cc1_sha="e" * 64, content_hash="different")
        code, _, err = self.gab("diff", str(self.before), str(other))
        self.assertEqual(code, 2)
        self.assertIn("refusing", err)

    def test_force_overrides_refusal(self):
        other = write_run(self.base / "other2", [make_record("t")],
                          cc1_sha="f" * 64, content_hash="different")
        code, out, _ = self.gab("diff", str(self.before), str(other),
                                "--force")
        self.assertIn(code, (0, 1))
        self.assertIn("comparing anyway", out)


class TestShowCommand(CLITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.run_dir = cls.tmp / "show-run"
        run_cli("--config", str(cls.config), "run", "-t", "stub",
                "-s", "synthetic", "-o", str(cls.run_dir), "--force", "-q")

    def test_records(self):
        code, out, _ = self.gab("show", str(self.run_dir))
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), 8)
        json.loads(out.strip().splitlines()[0])

    def test_manifest(self):
        code, out, _ = self.gab("show", str(self.run_dir), "--manifest")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["suite"]["name"], "synthetic")

    def test_filter(self):
        _, out, _ = self.gab("show", str(self.run_dir), "--filter", "hit-*")
        self.assertEqual(len(out.strip().splitlines()), 3)


class TestColour(CLITestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(dir=self.tmp))
        self.a = write_run(self.base / "a", [make_record("t", lines=(5,))],
                           cc1_sha="1" * 64)
        self.b = write_run(self.base / "b",
                           [make_record("t", lines=(5,),
                                        findings=[make_finding(line=5)])],
                           cc1_sha="2" * 64)

    def test_never_has_no_escapes(self):
        _, out, _ = self.gab("diff", str(self.a), str(self.b),
                             "--color", "never")
        self.assertNotIn("\033[", out)

    def test_always_colours_improvements_green(self):
        _, out, _ = self.gab("diff", str(self.a), str(self.b),
                             "--color", "always")
        self.assertIn("\033[32m", out)

    def test_regressions_are_red(self):
        _, out, _ = self.gab("diff", str(self.b), str(self.a),
                             "--color", "always")
        self.assertIn("\033[31m", out)

    def test_auto_is_off_when_not_a_tty(self):
        _, out, _ = self.gab("diff", str(self.a), str(self.b))
        self.assertNotIn("\033[", out)

    def test_json_is_never_coloured(self):
        _, out, _ = self.gab("diff", str(self.a), str(self.b),
                             "--json", "--color", "always")
        self.assertNotIn("\033[", out)
        json.loads(out)


if __name__ == "__main__":
    unittest.main()


class TestMultiSuiteRuns(CLITestCase):
    """`gab run -s all`: a parent directory of ordinary run directories."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # A second suite, so "all" has something to expand to.
        cls.suite2 = make_synthetic_suite(cls.tmp / "suite2")
        cfg = json.loads(cls.config.read_text())
        # Same adapter, second instance: exactly how two BenchProctor
        # releases would be configured side by side.
        cfg["suites"]["synthetic2"] = {"path": str(cls.suite2),
                                       "adapter": "synthetic"}
        cls.config2 = cls.tmp / "config-multi.json"
        cls.config2.write_text(json.dumps(cfg))

    def gab2(self, *argv):
        return run_cli("--config", str(self.config2), *argv)

    def _run_all(self, out, *extra):
        return self.gab2("run", "-t", "stub", "-s", "all", "-o", str(out),
                         "--force", "-q", *extra)

    def test_layout_is_a_parent_of_run_directories(self):
        out = self.tmp / "grp-layout"
        code, _, _ = self._run_all(out)
        self.assertEqual(code, 0)
        group = json.loads((out / "run.json").read_text())
        self.assertEqual(group["kind"], "group")
        self.assertEqual([m["suite"] for m in group["members"]],
                         ["synthetic", "synthetic2"])
        # Each child must be a perfectly ordinary run directory.
        for member in group["members"]:
            child = out / member["dir"]
            self.assertTrue((child / "results.jsonl").is_file())
            self.assertEqual(
                json.loads((child / "run.json").read_text())["kind"], "run")

    def test_single_suite_keeps_the_flat_layout(self):
        out = self.tmp / "grp-single"
        self.gab2("run", "-t", "stub", "-s", "synthetic", "-o", str(out),
                  "--force", "-q")
        self.assertTrue((out / "results.jsonl").is_file())
        self.assertEqual(
            json.loads((out / "run.json").read_text())["kind"], "run")

    def test_repeated_and_comma_separated_selection(self):
        for sel in (["-s", "synthetic", "-s", "synthetic2"],
                    ["-s", "synthetic,synthetic2"]):
            with self.subTest(sel=sel):
                out = Path(tempfile.mkdtemp(dir=self.tmp))
                code, _, _ = self.gab2("run", "-t", "stub", *sel, "-o",
                                       str(out), "--force", "-q")
                self.assertEqual(code, 0)
                g = json.loads((out / "run.json").read_text())
                self.assertEqual(len(g["members"]), 2)

    def test_duplicates_are_collapsed(self):
        out = Path(tempfile.mkdtemp(dir=self.tmp))
        self.gab2("run", "-t", "stub", "-s", "synthetic,synthetic",
                  "-o", str(out), "--force", "-q")
        # One suite named twice is still one suite: flat layout.
        self.assertTrue((out / "results.jsonl").is_file())

    def test_unknown_suite_in_a_list_is_an_error(self):
        code, _, err = self.gab2("run", "-t", "stub", "-s", "synthetic,nope",
                                 "-o", str(self.tmp / "x"), "--force", "-q")
        self.assertEqual(code, 2)
        self.assertIn("unknown suite", err)

    def test_json(self):
        out = self.tmp / "grp-json"
        code, text, _ = self.gab2("run", "-t", "stub", "-s", "all", "-o",
                                  str(out), "--force", "--json")
        self.assertEqual(code, 0)
        data = json.loads(text)
        self.assertEqual(data["kind"], "group")
        self.assertEqual(len(data["suites"]), 2)

    def test_a_crash_in_one_suite_fails_the_whole_run(self):
        src = self.suite2 / "src" / "crasher.c"
        src.write_text("/* GAB_ICE */\n")
        truth = json.loads((self.suite2 / "truth.json").read_text())
        truth["tests"].append({"name": "crasher", "vulnerable": True,
                               "category": "leak", "cwe": 401,
                               "lines": [1]})
        (self.suite2 / "truth.json").write_text(json.dumps(truth))
        try:
            code, _, err = self._run_all(self.tmp / "grp-crash")
            self.assertEqual(code, 1)
            self.assertIn("COMPILER FAILURE", err)
        finally:
            src.unlink(missing_ok=True)
            truth["tests"] = [t for t in truth["tests"]
                              if t["name"] != "crasher"]
            (self.suite2 / "truth.json").write_text(json.dumps(truth))


class TestMultiSuiteScoreAndDiff(CLITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.suite2 = make_synthetic_suite(cls.tmp / "msuite2")
        cfg = json.loads(cls.config.read_text())
        cfg["suites"]["synthetic2"] = {"path": str(cls.suite2),
                                       "adapter": "synthetic"}
        cls.config2 = cls.tmp / "config-ms.json"
        cls.config2.write_text(json.dumps(cfg))
        cls.group = cls.tmp / "ms-group"
        run_cli("--config", str(cls.config2), "run", "-t", "stub", "-s",
                "all", "-o", str(cls.group), "--force", "-q")

    def gab2(self, *argv):
        return run_cli("--config", str(self.config2), *argv)

    def test_score_text_lists_each_suite(self):
        code, out, _ = self.gab2("score", str(self.group))
        self.assertEqual(code, 0)
        self.assertIn("synthetic", out)
        self.assertIn("synthetic2", out)
        self.assertIn("combined", out)
        self.assertIn("largest suite dominates", out)

    def test_score_json(self):
        code, out, _ = self.gab2("score", str(self.group), "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["kind"], "group")
        self.assertEqual(set(data["suites"]), {"synthetic", "synthetic2"})
        # Combined is the flat sum of the members.
        total = sum(data["suites"][s]["overall"]["TP"]
                    for s in data["suites"])
        self.assertEqual(data["combined"]["TP"], total)

    def test_score_html(self):
        code, out, _ = self.gab2("score", str(self.group), "--format",
                                 "html")
        self.assertEqual(code, 0)
        self.assert_valid_html(out)
        self.assertIn("Per suite", out)

    def test_scoring_a_child_directly_still_works(self):
        code, out, _ = self.gab2("score", str(self.group / "synthetic"),
                                 "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["overall"]["TP"], 3)

    def test_diff_pairs_suites_by_name(self):
        other = self.tmp / "ms-group-2"
        run_cli("--config", str(self.config2), "run", "-t", "stub", "-s",
                "all", "-o", str(other), "--force", "-q")
        # Same compiler both sides, so force past the identical-cc1 guard.
        code, out, _ = self.gab2("diff", str(self.group), str(other),
                                 "--force")
        self.assertIn("=== synthetic", out)
        self.assertIn("=== synthetic2", out)
        self.assertIn("SUMMARY", out)
        self.assertEqual(code, 0)

    def test_diff_narrows_a_group_to_match_a_single_run(self):
        """A whole multi-suite run against one suite from another run."""
        single = self.tmp / "ms-single"
        run_cli("--config", str(self.config2), "run", "-t", "stub", "-s",
                "synthetic2", "-o", str(single), "--force", "-q")
        code, out, _ = self.gab2("diff", str(self.group), str(single),
                                 "--force")
        self.assertIn("narrowed", out)
        self.assertIn("synthetic2", out)
        # Narrowed to one suite, so no per-suite SUMMARY block.
        self.assertNotIn("=== synthetic", out)
        self.assertIn(code, (0, 1))

    def test_narrowing_works_with_the_group_second(self):
        single = self.tmp / "ms-single-b"
        run_cli("--config", str(self.config2), "run", "-t", "stub", "-s",
                "synthetic2", "-o", str(single), "--force", "-q")
        code, out, _ = self.gab2("diff", str(single), str(self.group),
                                 "--force")
        self.assertIn("narrowed", out)
        self.assertIn(code, (0, 1))

    def test_narrowing_reports_when_the_suite_is_absent(self):
        lone = self.tmp / "ms-lone-group"
        run_cli("--config", str(self.config2), "run", "-t", "stub", "-s",
                "synthetic,synthetic2", "-o", str(lone), "--force", "-q")
        # A run of a suite the group does not contain.
        other_root = make_synthetic_suite(self.tmp / "ms-elsewhere")
        cfg = json.loads(self.config2.read_text())
        cfg["suites"]["synthetic3"] = {"path": str(other_root),
                                       "adapter": "synthetic"}
        path = self.tmp / "config-ms3.json"
        path.write_text(json.dumps(cfg))
        single = self.tmp / "ms-single3"
        run_cli("--config", str(path), "run", "-t", "stub", "-s",
                "synthetic3", "-o", str(single), "--force", "-q")
        code, _, err = run_cli("--config", str(path), "diff", str(lone),
                               str(single), "--force")
        self.assertEqual(code, 2)
        self.assertIn("has no suite", err)
        self.assertIn("synthetic2", err)

    def test_show_on_a_group_explains_itself(self):
        code, _, err = self.gab2("show", str(self.group))
        self.assertEqual(code, 2)
        self.assertIn("multi-suite run", err)


class TestSuiteAdapterIndirection(CLITestCase):
    """One adapter, configured twice -- e.g. two BenchProctor releases."""

    def test_second_instance_is_labelled_by_its_config_key(self):
        other = make_synthetic_suite(self.tmp / "adapter-b")
        cfg = json.loads(self.config.read_text())
        cfg["suites"]["synthetic-b"] = {"path": str(other),
                                        "adapter": "synthetic"}
        path = self.tmp / "config-adapter.json"
        path.write_text(json.dumps(cfg))

        out = self.tmp / "adapter-run"
        code, _, _ = run_cli("--config", str(path), "run", "-t", "stub",
                             "-s", "synthetic-b", "-o", str(out),
                             "--force", "-q")
        self.assertEqual(code, 0)
        manifest = json.loads((out / "run.json").read_text())
        self.assertEqual(manifest["suite"]["name"], "synthetic-b")
        record = json.loads(
            (out / "results.jsonl").read_text().splitlines()[0])
        self.assertEqual(record["suite"], "synthetic-b")

    def test_unknown_adapter_is_reported_clearly(self):
        cfg = json.loads(self.config.read_text())
        cfg["suites"]["bogus"] = {"path": str(self.suite_root),
                                  "adapter": "no-such-adapter"}
        path = self.tmp / "config-bogus.json"
        path.write_text(json.dumps(cfg))
        code, _, err = run_cli("--config", str(path), "run", "-t", "stub",
                               "-s", "bogus", "-o", str(self.tmp / "z"),
                               "--force", "-q")
        self.assertEqual(code, 2)
        self.assertIn("unknown suite adapter", err)


class TestReportMetadata(CLITestCase):
    """What was tested, and what produced the report."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.run_a = cls.tmp / "meta-a"
        cls.run_b = cls.tmp / "meta-b"
        run_cli("--config", str(cls.config), "run", "-t", "stub", "-s",
                "synthetic", "-o", str(cls.run_a), "--force", "-q")
        run_cli("--config", str(cls.config), "run", "-t", "stub", "-s",
                "synthetic", "-o", str(cls.run_b), "--force", "-q")

    def test_score_text_names_the_suite_and_its_version(self):
        _, out, _ = self.gab("score", str(self.run_a))
        self.assertIn("synthetic", out)
        self.assertIn("vtest-1.0", out)
        self.assertIn("8 tests", out)

    def test_score_marks_a_subset(self):
        sub = self.tmp / "meta-subset"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(sub),
                 "--force", "-q", "--limit", "3")
        _, out, _ = self.gab("score", str(sub))
        self.assertIn("[subset]", out)

    def test_diff_text_names_the_suite(self):
        _, out, _ = self.gab("diff", str(self.run_a), str(self.run_b),
                             "--force")
        self.assertIn("suite   :", out)
        self.assertIn("synthetic vtest-1.0", out)
        self.assertIn("8 tests compared", out)
        self.assertIn("content :", out)

    def test_diff_json_reports_suite_identity(self):
        _, out, _ = self.gab("diff", str(self.run_a), str(self.run_b),
                             "--force", "--json")
        s = json.loads(out)["suite"]
        self.assertEqual(s["name"], "synthetic")
        self.assertTrue(s["same_content"])
        self.assertEqual(s["n_tests_compared"], 8)

    def test_diff_warns_loudly_when_the_tests_differ(self):
        other = write_run(self.tmp / "meta-other", [make_record("t")],
                          cc1_sha="9" * 64, content_hash="totally-different")
        _, out, _ = self.gab("diff", str(self.run_a), str(other), "--force")
        self.assertIn("DIFFERENT TESTS", out)

    def test_html_records_the_gab_version(self):
        from gab import __version__
        for argv in (("score", str(self.run_a)),
                     ("diff", str(self.run_a), str(self.run_b), "--force")):
            with self.subTest(cmd=argv[0]):
                _, out, _ = self.gab(*argv, "--format", "html")
                self.assertIn(f'<meta name="generator" content="gab '
                              f'{__version__}" />', out)
                self.assertIn(f"gab {__version__}", out)
                self.assertIn("<meta name=\"date\"", out)

    def test_html_does_not_leak_the_hostname(self):
        """These reports get attached to public bug reports."""
        import socket
        host = socket.gethostname()
        _, out, _ = self.gab("score", str(self.run_a), "--format", "html")
        self.assertNotIn(host, out)

    def test_html_names_the_suite(self):
        _, out, _ = self.gab("diff", str(self.run_a), str(self.run_b),
                             "--force", "--format", "html")
        self.assertIn("synthetic", out)
        self.assertIn("suite content", out)


class TestHTMLStructure(CLITestCase):
    """Disclosure widgets, anchors, and one document per invocation."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.suite2 = make_synthetic_suite(cls.tmp / "hsuite2")
        cfg = json.loads(cls.config.read_text())
        cfg["suites"]["synthetic2"] = {"path": str(cls.suite2),
                                       "adapter": "synthetic"}
        cls.cfg2 = cls.tmp / "config-html.json"
        cls.cfg2.write_text(json.dumps(cfg))
        cls.ga = cls.tmp / "html-grp-a"
        cls.gb = cls.tmp / "html-grp-b"
        for out in (cls.ga, cls.gb):
            run_cli("--config", str(cls.cfg2), "run", "-t", "stub", "-s",
                    "all", "-o", str(out), "--force", "-q")

    def gab2(self, *argv):
        return run_cli("--config", str(self.cfg2), *argv)

    @staticmethod
    def ids_and_links(text):
        ids = set(re.findall(r'id="([^"]+)"', text))
        links = set(re.findall(r'href="#([^"]+)"', text))
        return ids, links

    def test_grouped_diff_is_a_single_document(self):
        _, out, _ = self.gab2("diff", str(self.ga), str(self.gb),
                              "--force", "--format", "html")
        self.assertEqual(out.count("<!DOCTYPE html>"), 1)
        self.assertEqual(out.count("<h1>"), 1)
        self.assert_valid_html(out)

    def test_grouped_diff_names_each_suite_as_a_section(self):
        _, out, _ = self.gab2("diff", str(self.ga), str(self.gb),
                              "--force", "--format", "html")
        for name in ("synthetic", "synthetic2"):
            self.assertIn(f'id="{name}"', out)
            self.assertIn(f"<summary>{name}", out)

    def test_anchors_are_namespaced_per_suite(self):
        _, out, _ = self.gab2("diff", str(self.ga), str(self.gb),
                              "--force", "--format", "html")
        ids, _ = self.ids_and_links(out)
        self.assertIn("synthetic-scoring", ids)
        self.assertIn("synthetic2-scoring", ids)

    def test_every_internal_link_resolves(self):
        """No dangling anchors in any HTML report."""
        cases = [
            ("diff", str(self.ga), str(self.gb), "--force"),
            ("diff", str(self.ga / "synthetic"),
             str(self.gb / "synthetic"), "--force"),
            ("score", str(self.ga)),
            ("score", str(self.ga / "synthetic")),
        ]
        for argv in cases:
            with self.subTest(cmd=argv):
                _, out, _ = self.gab2(*argv, "--format", "html")
                ids, links = self.ids_and_links(out)
                self.assertTrue(links, "expected some internal links")
                self.assertEqual(links - ids, set(),
                                 "links with no matching id")

    def test_sections_are_disclosure_widgets(self):
        _, out, _ = self.gab2("diff", str(self.ga / "synthetic"),
                              str(self.gb / "synthetic"), "--force",
                              "--format", "html")
        self.assertIn("<details", out)
        self.assertIn("<summary>", out)
        # Still no JavaScript: expand/collapse is native.
        self.assertNotIn("<script", out)

    def test_table_of_contents_is_present(self):
        _, out, _ = self.gab2("diff", str(self.ga), str(self.gb),
                              "--force", "--format", "html")
        self.assertIn('<nav class="toc">', out)

    def test_grouped_score_sections_per_suite(self):
        _, out, _ = self.gab2("score", str(self.ga), "--format", "html")
        self.assertEqual(out.count("<!DOCTYPE html>"), 1)
        ids, _ = self.ids_and_links(out)
        self.assertIn("synthetic", ids)
        self.assertIn("synthetic2", ids)
        self.assertIn("synthetic-by-category", ids)

    def test_anchor_links_are_offered_on_each_section(self):
        _, out, _ = self.gab2("score", str(self.ga / "synthetic"),
                              "--format", "html")
        self.assertIn('class="anchor"', out)


class TestHTMLIsXHTML(CLITestCase):
    """Every report shape must parse with a strict XML parser."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.suite2 = make_synthetic_suite(cls.tmp / "xsuite2")
        cfg = json.loads(cls.config.read_text())
        cfg["suites"]["synthetic2"] = {"path": str(cls.suite2),
                                       "adapter": "synthetic"}
        cls.cfg2 = cls.tmp / "config-xhtml.json"
        cls.cfg2.write_text(json.dumps(cfg))
        cls.ga, cls.gb = cls.tmp / "xh-a", cls.tmp / "xh-b"
        for out in (cls.ga, cls.gb):
            run_cli("--config", str(cls.cfg2), "run", "-t", "stub", "-s",
                    "all", "-o", str(out), "--force", "-q")

    def gab2(self, *argv):
        return run_cli("--config", str(self.cfg2), *argv)

    def test_every_report_shape_is_well_formed_xml(self):
        cases = {
            "grouped diff": ("diff", str(self.ga), str(self.gb), "--force"),
            "single diff": ("diff", str(self.ga / "synthetic"),
                            str(self.gb / "synthetic"), "--force"),
            "grouped score": ("score", str(self.ga),),
            "single score": ("score", str(self.ga / "synthetic"),),
        }
        for label, argv in cases.items():
            with self.subTest(report=label):
                _, out, _ = self.gab2(*argv, "--format", "html")
                self.assert_valid_html(out)

    def test_a_report_with_crashes_is_still_well_formed(self):
        crash = write_run(self.tmp / "xh-crash",
                          [make_record("t", status="ice",
                                       argv=("cc", "--opt=a&b<c", "t.c"))],
                          cc1_sha="7" * 64)
        ok = write_run(self.tmp / "xh-ok", [make_record("t")],
                       cc1_sha="8" * 64)
        _, out, _ = self.gab2("diff", str(ok), str(crash), "--force",
                              "--format", "html")
        self.assert_valid_html(out)
        self.assertIn("&amp;b&lt;c", out)

    def test_no_html_only_named_entities(self):
        """&rarr; and friends are undefined in XML."""
        _, out, _ = self.gab2("diff", str(self.ga), str(self.gb),
                              "--force", "--format", "html")
        named = set(re.findall(r"&([a-zA-Z][a-zA-Z0-9]*);", out))
        self.assertEqual(named - {"amp", "lt", "gt", "quot", "apos"}, set())


class TestHTMLShorthandAndSummary(CLITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.suite2 = make_synthetic_suite(cls.tmp / "ssuite2")
        cfg = json.loads(cls.config.read_text())
        cfg["suites"]["synthetic2"] = {"path": str(cls.suite2),
                                       "adapter": "synthetic"}
        cls.cfg2 = cls.tmp / "config-sum.json"
        cls.cfg2.write_text(json.dumps(cfg))
        cls.ga, cls.gb = cls.tmp / "sum-a", cls.tmp / "sum-b"
        for out in (cls.ga, cls.gb):
            run_cli("--config", str(cls.cfg2), "run", "-t", "stub", "-s",
                    "all", "-o", str(out), "--force", "-q")

    def gab2(self, *argv):
        return run_cli("--config", str(self.cfg2), *argv)

    def test_html_shorthand_matches_format_html(self):
        for argv in (("score", str(self.ga / "synthetic")),
                     ("diff", str(self.ga), str(self.gb), "--force")):
            with self.subTest(cmd=argv[0]):
                _, a, _ = self.gab2(*argv, "--html")
                _, b, _ = self.gab2(*argv, "--format", "html")
                # Only the timestamp may differ.
                self.assertEqual(len(a.splitlines()), len(b.splitlines()))
                self.assertIn("<!DOCTYPE html>", a)

    def test_json_shorthand_still_wins_over_html(self):
        _, out, _ = self.gab2("score", str(self.ga / "synthetic"),
                              "--json", "--html")
        json.loads(out)

    def test_summary_counts_are_tinted_and_linked(self):
        # Make one suite regress so the counts are non-zero.
        child = self.gb / "synthetic"
        records = [json.loads(l) for l in
                   (child / "results.jsonl").read_text().splitlines() if l]
        for r in records:
            if r["name"] == "hit-exact":
                r["findings"] = []
                r["n_analyzer_findings"] = 0
        (child / "results.jsonl").write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")

        _, out, _ = self.gab2("diff", str(self.ga), str(self.gb),
                              "--force", "--format", "html")
        self.assertIn('<a class="bad" href="#synthetic-regressed">1</a>',
                      out)
        # A zero count is neither tinted nor linked -- nothing to visit.
        self.assertIn('<span class="muted">0</span>', out)
        self.assert_valid_html(out)


class TestFailuresCommand(CLITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.run_dir = cls.tmp / "fail-run"
        run_cli("--config", str(cls.config), "run", "-t", "stub", "-s",
                "synthetic", "-o", str(cls.run_dir), "--force", "-q")

    def test_text_groups_by_category(self):
        code, out, _ = self.gab("failures", str(self.run_dir))
        self.assertEqual(code, 0)
        # The fixture has 1 FP (clean-noisy) and 2 FN under path+1.
        self.assertIn("1 false positives", out)
        self.assertIn("2 false negatives", out)
        self.assertIn("clean-noisy", out)
        self.assertIn("miss-silent", out)
        # True positives must not be listed.
        self.assertNotIn("hit-exact", out)

    def test_kind_filter(self):
        _, out, _ = self.gab("failures", str(self.run_dir), "-k", "fp")
        self.assertIn("clean-noisy", out)
        self.assertNotIn("miss-silent", out)
        _, out, _ = self.gab("failures", str(self.run_dir), "-k", "fn")
        self.assertNotIn("clean-noisy", out)
        self.assertIn("miss-silent", out)

    def test_verbose_shows_what_was_reported(self):
        _, out, _ = self.gab("failures", str(self.run_dir), "-v")
        self.assertIn("reported nothing", out)
        self.assertIn("-Wanalyzer-", out)

    def test_matcher_changes_the_set(self):
        _, strict, _ = self.gab("failures", str(self.run_dir), "-m", "line",
                                "--json")
        _, loose, _ = self.gab("failures", str(self.run_dir), "-m", "file",
                               "--json")
        self.assertGreater(json.loads(strict)["counts"]["FN"],
                           json.loads(loose)["counts"]["FN"])

    def test_json(self):
        code, out, _ = self.gab("failures", str(self.run_dir), "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["counts"]["FP"], 1)
        entries = [e for v in data["by_category"].values() for e in v]
        fn = next(e for e in entries if e["name"] == "miss-silent")
        self.assertEqual(fn["outcome"], "FN")
        self.assertEqual(fn["lines"], [5])
        self.assertTrue(fn["repro"])

    def test_html(self):
        code, out, _ = self.gab("failures", str(self.run_dir), "--html")
        self.assertEqual(code, 0)
        self.assert_valid_html(out)
        self.assertIn("By category", out)

    def test_category_filter(self):
        _, out, _ = self.gab("failures", str(self.run_dir),
                             "--category", "null", "--json")
        cats = set(json.loads(out)["by_category"])
        self.assertTrue(cats <= {"null"}, cats)

    def test_clean_run_says_so(self):
        run = write_run(self.tmp / "fail-clean",
                        [make_record("t", lines=(5,),
                                     findings=[make_finding(line=5)])])
        _, out, _ = self.gab("failures", str(run))
        self.assertIn("no false results", out)


class TestCastleScoreInCLI(CLITestCase):
    def test_not_shown_for_a_non_castle_suite(self):
        run = self.tmp / "cs-plain"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(run),
                 "--force", "-q")
        _, out, _ = self.gab("score", str(run))
        self.assertNotIn("CASTLE Score", out)

    def test_opt_in_for_any_suite(self):
        run = self.tmp / "cs-optin"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(run),
                 "--force", "-q")
        _, out, _ = self.gab("score", str(run), "--castle-score")
        self.assertIn("CASTLE Score", out)

    def test_shown_automatically_for_the_castle_adapter(self):
        run = write_run(self.tmp / "cs-castle",
                        [make_record("t", cwe=476, lines=(5,),
                                     findings=[make_finding(cwe=476,
                                                            line=5)])],
                        suite_name="castle-c250")
        import json as _json
        m = _json.loads((run / "run.json").read_text())
        m["suite"]["adapter"] = "castle-c250"
        (run / "run.json").write_text(_json.dumps(m))
        _, out, _ = self.gab("score", str(run))
        self.assertIn("CASTLE Score: 6", out)

    def test_json_carries_the_castle_score(self):
        run = self.tmp / "cs-json"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(run),
                 "--force", "-q")
        _, out, _ = self.gab("score", str(run), "--castle-score", "--json")
        cs = json.loads(out)["castle_score"]
        self.assertIn("score", cs)
        self.assertEqual(cs["detect"], "cwe")
        self.assertIn("doi:10.1007", cs["reference"])

    def test_detection_rule_is_selectable(self):
        """Right line, different CWE -- the CASTLE-253 situation, where
        GCC reports CWE-690 against a ground truth of CWE-253."""
        run = write_run(self.tmp / "cs-rule",
                        [make_record("t", cwe=253, lines=(5,),
                                     findings=[make_finding(cwe=690,
                                                            line=5)])])
        _, a, _ = self.gab("score", str(run), "--castle-score", "--json")
        _, b, _ = self.gab("score", str(run), "--castle-score",
                           "--castle-detect", "path+1", "--json")
        # The paper's rule calls this a miss and charges for the finding;
        # a position-based rule credits it.
        self.assertEqual(json.loads(a)["castle_score"]["score"], -1)
        self.assertEqual(json.loads(b)["castle_score"]["score"], 5)


class TestFailuresDefaultScope(CLITestCase):
    """Out-of-scope categories are hidden in `failures` by default."""

    def _run_with_scope(self, out_of_scope):
        run = write_run(
            self.tmp / f"scope-{'-'.join(out_of_scope) or 'none'}",
            [make_record("inscope", category="leak", lines=(5,)),
             make_record("outscope", category="sqli", lines=(5,))])
        m = json.loads((run / "run.json").read_text())
        m["suite"]["out_of_scope_categories"] = list(out_of_scope)
        (run / "run.json").write_text(json.dumps(m))
        return run

    def test_hidden_by_default(self):
        run = self._run_with_scope(["sqli"])
        _, out, _ = self.gab("failures", str(run))
        self.assertIn("inscope", out)
        self.assertNotIn("outscope", out)
        self.assertIn("hidden", out)
        self.assertIn("--all-categories", out)

    def test_all_categories_includes_them(self):
        run = self._run_with_scope(["sqli"])
        _, out, _ = self.gab("failures", str(run), "--all-categories")
        self.assertIn("outscope", out)

    def test_explicit_category_overrides_the_default(self):
        run = self._run_with_scope(["sqli"])
        _, out, _ = self.gab("failures", str(run), "--category", "sqli")
        self.assertIn("outscope", out)

    def test_json_reports_what_was_hidden(self):
        run = self._run_with_scope(["sqli"])
        _, out, _ = self.gab("failures", str(run), "--json")
        self.assertEqual(json.loads(out)["hidden_categories"], ["sqli"])

    def test_no_scope_declared_hides_nothing(self):
        run = self._run_with_scope([])
        _, out, _ = self.gab("failures", str(run))
        self.assertIn("outscope", out)

    def test_score_does_not_hide_anything(self):
        """Scoring must stay over the full set unless asked otherwise:
        a silently narrowed score would be misleading."""
        run = self._run_with_scope(["sqli"])
        _, out, _ = self.gab("score", str(run), "--json")
        self.assertIn("sqli", json.loads(out)["by_category"])


class TestBenchProctorScope(unittest.TestCase):
    def test_adapter_declares_the_injection_categories(self):
        from gab.suites.benchproctor import OUT_OF_SCOPE, BenchProctorC
        self.assertIn("sqli", OUT_OF_SCOPE)
        self.assertIn("weakcipher", OUT_OF_SCOPE)
        self.assertNotIn("null_deref", OUT_OF_SCOPE)
        self.assertEqual(len(OUT_OF_SCOPE), 10)

    def test_castle_declares_the_injection_and_crypto_cwes(self):
        from gab.suites.castle import OUT_OF_SCOPE_CWES, CastleC250
        got = CastleC250.out_of_scope_categories(None)
        self.assertEqual(got, [f"CWE-{c}" for c in OUT_OF_SCOPE_CWES])
        for cwe in (89, 327, 798):          # SQLi, crypto, creds
            self.assertIn(cwe, OUT_OF_SCOPE_CWES)
        for cwe in (401, 416, 476, 835):    # memory safety: in scope
            self.assertNotIn(cwe, OUT_OF_SCOPE_CWES)


class TestCastleGridInCLI(CLITestCase):
    def _castle_run(self, name="grid-run"):
        run = write_run(
            self.tmp / name,
            [make_record("CASTLE-476-1", cwe=476, lines=(5,),
                         findings=[make_finding(cwe=476, line=5)]),
             make_record("CASTLE-476-7", cwe=476, vulnerable=False,
                         lines=())],
            suite_name="castle-c250")
        m = json.loads((run / "run.json").read_text())
        m["suite"]["adapter"] = "castle-c250"
        (run / "run.json").write_text(json.dumps(m))
        return run

    def test_text_grid_is_opt_in(self):
        run = self._castle_run()
        _, plain, _ = self.gab("score", str(run))
        self.assertNotIn("CASTLE score grid", plain)
        _, grid, _ = self.gab("score", str(run), "--castle-grid")
        self.assertIn("CASTLE score grid", grid)
        self.assertIn("6/6", grid)
        self.assertIn("2/2", grid)

    def test_html_always_includes_the_grid(self):
        _, out, _ = self.gab("score", str(self._castle_run("grid-html")),
                             "--html")
        self.assertIn("CASTLE score grid", out)
        self.assertIn("background:hsl", out)
        self.assert_valid_html(out)

    def test_grid_absent_for_non_castle_suites(self):
        run = self.tmp / "grid-plain"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(run),
                 "--force", "-q")
        _, out, _ = self.gab("score", str(run), "--html")
        self.assertNotIn("CASTLE score grid", out)

    def test_grid_flag_on_a_non_castle_run_says_so(self):
        run = self.tmp / "grid-warn"
        self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(run),
                 "--force", "-q")
        _, out, _ = self.gab("score", str(run), "--castle-grid")
        self.assertIn("not a CASTLE run", out)


class TestCastleGridScopeAndDiff(CLITestCase):
    """Out-of-scope marking, and the grid in diff output."""

    def _castle_run(self, name, findings_for_1=()):
        run = write_run(
            self.tmp / name,
            [make_record("CASTLE-476-1", cwe=476, lines=(5,),
                         findings=list(findings_for_1)),
             make_record("CASTLE-476-7", cwe=476, vulnerable=False,
                         lines=()),
             make_record("CASTLE-89-1", cwe=89, lines=(5,)),
             make_record("CASTLE-89-7", cwe=89, vulnerable=False,
                         lines=())],
            suite_name="castle-c250",
            cc1_sha=name.ljust(64, "x"))
        m = json.loads((run / "run.json").read_text())
        m["suite"]["adapter"] = "castle-c250"
        # CWE-89 (SQL injection) is not something -fanalyzer attempts.
        m["suite"]["out_of_scope_categories"] = ["CWE-89"]
        m["suite"]["cwe_names"] = {"476": "NULL Pointer Dereference"}
        (run / "run.json").write_text(json.dumps(m))
        return run

    def test_score_grid_marks_out_of_scope_rows(self):
        run = self._castle_run("oos-score")
        _, out, _ = self.gab("score", str(run), "--castle-grid")
        self.assertIn("out of scope", out)
        self.assertIn("in scope", out)

    def test_score_grid_html_tags_and_greys_them(self):
        run = self._castle_run("oos-html")
        _, out, _ = self.gab("score", str(run), "--html")
        self.assertIn('class="oos"', out)
        self.assertIn("out-of-scope rows", out)
        self.assert_valid_html(out)

    def test_cwe_names_become_hover_titles(self):
        run = self._castle_run("oos-names")
        _, out, _ = self.gab("score", str(run), "--html")
        self.assertIn('title="NULL Pointer Dereference"', out)

    def test_diff_html_has_a_castle_grid(self):
        a = self._castle_run("dg-a")
        b = self._castle_run("dg-b", findings_for_1=[
            make_finding(cwe=476, line=5)])
        _, out, _ = self.gab("diff", str(a), str(b), "--html")
        self.assertIn("CASTLE score grid", out)
        # CASTLE-476-1 went 0 -> 6, so that cell shows the transition.
        self.assertIn("0&#8594;6/6", out)
        self.assertIn("1 cell(s) moved", out)
        self.assert_valid_html(out)

    def test_diff_grid_greys_unchanged_cells(self):
        a = self._castle_run("dg-same-a")
        b = self._castle_run("dg-same-b")
        _, out, _ = self.gab("diff", str(a), str(b), "--html", "--force")
        self.assertIn("No cell moved", out)
        self.assertIn("cell unchanged", out)

    def test_diff_grid_absent_for_non_castle(self):
        run_a = self.tmp / "dg-plain-a"
        run_b = self.tmp / "dg-plain-b"
        for r in (run_a, run_b):
            self.gab("run", "-t", "stub", "-s", "synthetic", "-o", str(r),
                     "--force", "-q")
        _, out, _ = self.gab("diff", str(run_a), str(run_b), "--html",
                             "--force")
        self.assertNotIn("CASTLE score grid", out)


class TestOutOfScopeIsVisuallyDistinct(CLITestCase):
    """Scope and 'unchanged' must not share a visual channel: in a diff
    nearly every row is unchanged, so opacity alone hides scope."""

    def test_scope_uses_tint_not_opacity(self):
        from gab.htmlout import STYLE
        self.assertIn("tr.oos { background:", STYLE)
        self.assertIn("tr.oos > td:first-child { border-left", STYLE)
        # Opacity is reserved for "nothing moved here".
        self.assertNotIn(".oos td { opacity", STYLE)
        self.assertIn("tr.quiet td { opacity", STYLE)

    def test_a_row_can_be_both_and_stay_legible(self):
        from gab.htmlout import render_castle_diff_grid
        from gab.castle_score import castle_score, grid
        recs = [make_record("CASTLE-89-1", cwe=89, lines=(5,)),
                make_record("CASTLE-89-7", cwe=89, vulnerable=False,
                            lines=())]
        rows = grid(castle_score(recs))
        html = render_castle_diff_grid(rows, rows, {}, ["CWE-89"])
        # Unchanged *and* out of scope: both classes, distinct channels.
        self.assertIn('class="oos quiet"', html)


class TestCastleGridInGroupedRuns(CLITestCase):
    """The grid must survive the grouped-run code path, which renders
    one document with a section per suite."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.group = cls.tmp / "grid-group"
        (cls.group / "synthetic").mkdir(parents=True)
        run_cli("--config", str(cls.config), "run", "-t", "stub", "-s",
                "synthetic", "-o", str(cls.group / "synthetic"),
                "--force", "-q")
        castle = write_run(
            cls.group / "castle-c250",
            [make_record("CASTLE-476-1", cwe=476, lines=(5,),
                         findings=[make_finding(cwe=476, line=5)]),
             make_record("CASTLE-89-1", cwe=89, lines=(5,))],
            suite_name="castle-c250")
        m = json.loads((castle / "run.json").read_text())
        m["suite"]["adapter"] = "castle-c250"
        m["suite"]["out_of_scope_categories"] = ["CWE-89"]
        (castle / "run.json").write_text(json.dumps(m))
        (cls.group / "run.json").write_text(json.dumps({
            "kind": "group", "schema": 1,
            "members": [{"suite": "synthetic", "dir": "synthetic"},
                        {"suite": "castle-c250", "dir": "castle-c250"}],
            "toolchain": {"name": "stub", "version": "x"},
        }))

    def test_html_includes_the_grid_for_the_castle_member(self):
        _, out, _ = self.gab("score", str(self.group), "--html")
        self.assertEqual(out.count("CASTLE score grid"), 1)
        # Anchors are namespaced by suite, as elsewhere in group reports.
        self.assertIn('id="castle-c250-castle-grid"', out)
        self.assertIn('<tr class="oos"', out)
        self.assert_valid_html(out)

    def test_text_grid_is_shown_per_suite(self):
        _, out, _ = self.gab("score", str(self.group), "--castle-grid")
        self.assertIn("=== castle-c250", out)
        self.assertIn("CASTLE score grid", out)
        self.assertIn("out of scope", out)

    def test_text_grid_says_so_when_no_castle_suite(self):
        group = self.tmp / "grid-group-none"
        (group / "synthetic").mkdir(parents=True)
        run_cli("--config", str(self.config), "run", "-t", "stub", "-s",
                "synthetic", "-o", str(group / "synthetic"), "--force",
                "-q")
        (group / "run.json").write_text(json.dumps({
            "kind": "group", "schema": 1,
            "members": [{"suite": "synthetic", "dir": "synthetic"}],
            "toolchain": {"name": "stub", "version": "x"}}))
        _, out, _ = self.gab("score", str(group), "--castle-grid")
        self.assertIn("no CASTLE suite", out)
