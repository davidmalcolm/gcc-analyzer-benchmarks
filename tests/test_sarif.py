# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Parsing GCC's SARIF."""

import json
import tempfile
import unittest
from pathlib import Path

from gab import sarif


def write(doc) -> Path:
    p = Path(tempfile.mkdtemp()) / "x.sarif"
    p.write_text(json.dumps(doc) if not isinstance(doc, str) else doc,
                 encoding="utf-8")
    return p


def result(rule="-Wanalyzer-null-dereference", cwe="476", line=12,
           path=(), kind="null_deref"):
    r = {
        "ruleId": rule,
        "level": "warning",
        "message": {"text": "dereference of NULL 'p'"},
        "properties": {"gcc/analyzer/pending_diagnostic/kind": kind},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "t.c"},
            "region": {"startLine": line, "startColumn": 3}}}],
    }
    if cwe:
        r["taxa"] = [{"id": cwe, "toolComponent": {"name": "cwe"}}]
    if path:
        r["codeFlows"] = [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": {
                "artifactLocation": {"uri": "t.c"},
                "region": {"startLine": n}}}} for n in path]}]}]
    return r


def doc(results, invocations=None):
    run = {"tool": {"driver": {"name": "GNU C23"}}, "results": results}
    if invocations is not None:
        run["invocations"] = invocations
    return {"version": "2.1.0", "runs": [run]}


class TestParseFindings(unittest.TestCase):
    def test_basic_fields(self):
        [f] = sarif.parse_findings(write(doc([result()])))
        self.assertEqual(f["rule"], "-Wanalyzer-null-dereference")
        self.assertTrue(f["analyzer"])
        self.assertFalse(f["meta"])
        self.assertEqual(f["cwes"], [476])
        self.assertEqual(f["line"], 12)
        self.assertEqual(f["kind"], "null_deref")

    def test_cwe_comes_from_taxa_not_the_rule_name(self):
        """GCC puts the bare CWE number in taxa, so no scraping."""
        [f] = sarif.parse_findings(write(doc([result(rule="-Wfoo",
                                                     cwe="787")])))
        self.assertEqual(f["cwes"], [787])

    def test_missing_cwe_is_empty_not_an_error(self):
        """Some analyzer warnings carry no CWE taxon at all."""
        [f] = sarif.parse_findings(write(doc([result(cwe=None)])))
        self.assertEqual(f["cwes"], [])

    def test_codeflow_path_lines_are_collected_and_sorted(self):
        [f] = sarif.parse_findings(
            write(doc([result(line=13, path=[10, 4, 7, 4])])))
        self.assertEqual(f["path_lines"], [4, 7, 10])

    def test_no_codeflow_gives_empty_path(self):
        [f] = sarif.parse_findings(write(doc([result()])))
        self.assertEqual(f["path_lines"], [])

    def test_non_analyzer_rule_is_marked(self):
        [f] = sarif.parse_findings(
            write(doc([result(rule="-Wunused-variable")])))
        self.assertFalse(f["analyzer"])

    def test_meta_rules_are_marked(self):
        for rule in sarif.META_RULES:
            with self.subTest(rule=rule):
                [f] = sarif.parse_findings(write(doc([result(rule=rule)])))
                self.assertTrue(f["meta"])

    def test_empty_run_yields_nothing(self):
        self.assertEqual(sarif.parse_findings(write(doc([]))), [])

    def test_malformed_sarif_raises(self):
        """A truncated file means the compiler died; it must not read as
        a clean 'no findings'."""
        with self.assertRaises(ValueError):
            sarif.parse_findings(write('{"runs": [{"resu'))

    def test_real_analyzer_findings_filters_meta_and_other_warnings(self):
        findings = sarif.parse_findings(write(doc([
            result(),
            result(rule="-Wanalyzer-too-complex"),
            result(rule="-Wunused-variable"),
        ])))
        self.assertEqual(len(sarif.real_analyzer_findings(findings)), 1)


class TestParseInvocation(unittest.TestCase):
    def test_timings_and_success(self):
        inv = [{
            "executionSuccessful": True,
            "startTimeUtc": "2026-01-01T00:00:00Z",
            "endTimeUtc": "2026-01-01T00:00:02Z",
            "properties": {"gcc/timeReport": {"timevars": [
                {"name": "analyzer: processing worklist",
                 "elapsed": {"wall": 0.5, "ggc_mem": 999}},
                {"name": "analyzer: emitting diagnostics",
                 "elapsed": {"wall": 0.25}},
                {"name": "phase setup", "elapsed": {"wall": 9.0}},
                {"name": "TOTAL", "elapsed": {"wall": 1.0}},
            ]}},
        }]
        got = sarif.parse_invocation(write(doc([], inv)))
        self.assertTrue(got["execution_successful"])
        self.assertAlmostEqual(got["analyzer_wall"], 0.75)
        self.assertIn("TOTAL", got["timevars"])
        # Individual analyzer line items are kept...
        self.assertIn("analyzer: processing worklist", got["timevars"])
        # ... and unrelated phases are not.
        self.assertNotIn("phase setup", got["timevars"])

    def test_ggc_mem_is_dropped(self):
        """GC-heap figures are near-irrelevant for -fanalyzer; peak RSS
        from wait4 is the number that matters."""
        inv = [{"properties": {"gcc/timeReport": {"timevars": [
            {"name": "analyzer", "elapsed": {"wall": 0.1,
                                             "ggc_mem": 123456}}]}}}]
        got = sarif.parse_invocation(write(doc([], inv)))
        self.assertEqual(got["timevars"], {"analyzer": 0.1})
        self.assertNotIn("123456", json.dumps(got))

    def test_execution_failure_is_reported(self):
        got = sarif.parse_invocation(
            write(doc([], [{"executionSuccessful": False}])))
        self.assertFalse(got["execution_successful"])

    def test_notifications_are_captured(self):
        inv = [{"executionSuccessful": False, "toolExecutionNotifications": [
            {"message": {"text": "internal compiler error: boom"}}]}]
        got = sarif.parse_invocation(write(doc([], inv)))
        self.assertIn("boom", got["notifications"][0])

    def test_malformed_file_returns_empty_rather_than_raising(self):
        self.assertEqual(sarif.parse_invocation(write('{bad')), {})

    def test_missing_invocations_is_empty(self):
        self.assertEqual(sarif.parse_invocation(write(doc([]))), {})


if __name__ == "__main__":
    unittest.main()
