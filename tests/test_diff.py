# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Diffing two runs: outcomes, crashes, churn, compatibility, resources."""

import json
import tempfile
import unittest
from pathlib import Path

from gab import diff
from gab.runner import load_run
from tests.fixtures import make_finding, make_record, write_run


def pair(before_records, after_records, **kw):
    """Diff two record lists through real run directories on disk."""
    tmp = tempfile.mkdtemp()
    b = write_run(Path(tmp) / "b", before_records, toolchain_name="before",
                  cc1_sha="a" * 64, **kw.pop("before_kw", {}))
    a = write_run(Path(tmp) / "a", after_records, toolchain_name="after",
                  cc1_sha="b" * 64, **kw.pop("after_kw", {}))
    mb, rb = load_run(b)
    ma, ra = load_run(a)
    return diff.diff_runs(mb, rb, ma, ra, **kw)


class TestOutcomeTransitions(unittest.TestCase):
    def test_improvement_is_detected(self):
        r = pair([make_record("t", lines=(5,))],
                 [make_record("t", lines=(5,),
                              findings=[make_finding(line=5)])])
        self.assertEqual([d.name for d in r.improved], ["t"])
        self.assertEqual(r.regressed, [])
        self.assertTrue(r.clean)

    def test_regression_is_detected(self):
        r = pair([make_record("t", lines=(5,),
                              findings=[make_finding(line=5)])],
                 [make_record("t", lines=(5,))])
        self.assertEqual([d.name for d in r.regressed], ["t"])
        self.assertFalse(r.clean)

    def test_new_false_positive_is_a_regression(self):
        r = pair([make_record("t", vulnerable=False, lines=())],
                 [make_record("t", vulnerable=False, lines=(),
                              findings=[make_finding(line=5)])])
        self.assertEqual([d.transition for d in r.regressed], [("TN", "FP")])

    def test_removed_false_positive_is_an_improvement(self):
        r = pair([make_record("t", vulnerable=False, lines=(),
                              findings=[make_finding(line=5)])],
                 [make_record("t", vulnerable=False, lines=())])
        self.assertEqual([d.transition for d in r.improved], [("FP", "TN")])

    def test_unchanged_tests_produce_no_delta(self):
        recs = [make_record("t", lines=(5,), findings=[make_finding(line=5)])]
        r = pair(recs, [dict(x) for x in recs])
        self.assertEqual(r.deltas, [])


class TestCrashes(unittest.TestCase):
    def test_new_crash_is_flagged_and_fails(self):
        for status in ("ice", "timeout"):
            with self.subTest(status=status):
                r = pair([make_record("t")],
                         [make_record("t", status=status)])
                self.assertEqual([d.name for d in r.new_crashes], ["t"])
                self.assertFalse(r.clean)

    def test_fixed_crash_is_an_improvement_not_a_regression(self):
        r = pair([make_record("t", status="ice")], [make_record("t")])
        self.assertEqual([d.name for d in r.fixed_crashes], ["t"])
        self.assertEqual(r.new_crashes, [])
        self.assertTrue(r.clean)

    def test_compile_error_is_a_status_change_not_a_crash(self):
        r = pair([make_record("t")],
                 [make_record("t", status="compile-error")])
        self.assertEqual(r.new_crashes, [])
        self.assertEqual([d.name for d in r.other_status_changes], ["t"])

    def test_crash_carries_a_repro_command(self):
        r = pair([make_record("t")],
                 [make_record("t", status="ice",
                              argv=("cc", "-fanalyzer", "t.c"))])
        self.assertEqual(r.new_crashes[0].repro,
                         ["cc", "-fanalyzer", "t.c"])


class TestChurn(unittest.TestCase):
    def test_same_outcome_different_diagnostics(self):
        r = pair([make_record("t", lines=(5,),
                              findings=[make_finding(rule="-Wanalyzer-a",
                                                     line=5)])],
                 [make_record("t", lines=(5,),
                              findings=[make_finding(rule="-Wanalyzer-b",
                                                     line=5)])])
        self.assertEqual([d.name for d in r.churn_only], ["t"])
        self.assertEqual(r.regressed, [])
        self.assertTrue(r.clean)
        d = r.churn_only[0]
        self.assertEqual([f["rule"] for f in d.new_findings],
                         ["-Wanalyzer-b"])
        self.assertEqual([f["rule"] for f in d.gone_findings],
                         ["-Wanalyzer-a"])

    def test_message_rewording_is_not_churn(self):
        """Rewording a diagnostic must not read as a behaviour change."""
        before = make_finding(line=5)
        after = dict(before, message="completely different wording")
        r = pair([make_record("t", lines=(5,), findings=[before])],
                 [make_record("t", lines=(5,), findings=[after])])
        self.assertEqual(r.deltas, [])


class TestMembership(unittest.TestCase):
    def test_tests_only_in_one_run(self):
        r = pair([make_record("a"), make_record("b")],
                 [make_record("b"), make_record("c")])
        self.assertEqual(r.only_in_before, ["a"])
        self.assertEqual(r.only_in_after, ["c"])


class TestCompatibility(unittest.TestCase):
    def test_different_suite_content_is_an_error(self):
        r = pair([make_record("t")], [make_record("t")],
                 after_kw={"content_hash": "different"})
        self.assertFalse(r.compatible)
        self.assertTrue(any("content differs" in m
                            for m in r.incompatibilities))

    def test_identical_cc1_is_an_error(self):
        tmp = tempfile.mkdtemp()
        b = write_run(Path(tmp) / "b", [make_record("t")], cc1_sha="same")
        a = write_run(Path(tmp) / "a", [make_record("t")], cc1_sha="same")
        mb, rb = load_run(b)
        ma, ra = load_run(a)
        r = diff.diff_runs(mb, rb, ma, ra)
        self.assertFalse(r.compatible)

    def test_triplet_spelling_is_only_a_warning(self):
        r = pair([make_record("t")], [make_record("t")],
                 before_kw={"target": "x86_64-redhat-linux"},
                 after_kw={"target": "x86_64-pc-linux-gnu"})
        self.assertTrue(r.compatible)
        self.assertTrue(any("spelling only" in w["message"]
                            for w in r.warnings))

    def test_different_architecture_is_an_error(self):
        r = pair([make_record("t")], [make_record("t")],
                 after_kw={"target": "aarch64-unknown-linux-gnu"})
        self.assertFalse(r.compatible)

    def test_checking_level_warns_about_perf_only(self):
        r = pair([make_record("t")], [make_record("t")],
                 after_kw={"build_type": "checking+extra"})
        self.assertTrue(r.compatible)
        self.assertTrue(diff.warnings_for(r.warnings, "perf"))
        self.assertFalse(any("checking" in m
                             for m in diff.warnings_for(r.warnings,
                                                        "results")))

    def test_revision_skew_warns_with_distance(self):
        r = pair([make_record("t")], [make_record("t")],
                 before_kw={"gcc_descr": "r17-6534-gabc"},
                 after_kw={"gcc_descr": "r17-6305-gdef"})
        msgs = diff.warnings_for(r.warnings, "results")
        self.assertTrue(any("229 trunk revisions apart" in m for m in msgs))

    def test_major_version_difference_warns(self):
        r = pair([make_record("t")], [make_record("t")],
                 before_kw={"dumpversion": "16.2.1"},
                 after_kw={"dumpversion": "17.0.0"})
        msgs = diff.warnings_for(r.warnings, "results")
        self.assertTrue(any("major versions" in m for m in msgs))


class TestResources(unittest.TestCase):
    def test_systematic_shift_is_reported_once_not_per_test(self):
        """A uniform footprint difference between two builds must not
        light up every single test."""
        before = [make_record(f"t{i}", maxrss=30000) for i in range(20)]
        after = [make_record(f"t{i}", maxrss=60000) for i in range(20)]
        r = pair(before, after)
        self.assertAlmostEqual(r.rss_baseline_ratio, 2.0)
        self.assertEqual(r.resources, [])

    def test_outlier_against_the_baseline_is_flagged(self):
        before = [make_record(f"t{i}", maxrss=30000) for i in range(20)]
        after = [make_record(f"t{i}", maxrss=60000) for i in range(19)]
        after.append(make_record("t19", maxrss=300000))
        r = pair(before, after)
        self.assertEqual([x.name for x in r.resources], ["t19"])


class TestScoringDeltas(unittest.TestCase):
    def test_metric_movement_and_direction(self):
        r = pair([make_record("t", lines=(5,))],
                 [make_record("t", lines=(5,),
                              findings=[make_finding(line=5)])])
        by = {d["metric"]: d for d in r.score_deltas()}
        self.assertEqual(by["TP"]["delta"], 1)
        self.assertEqual(by["TP"]["direction"], "better")
        self.assertEqual(by["FN"]["delta"], -1)
        self.assertEqual(by["FN"]["direction"], "better")

    def test_rising_false_positives_read_as_worse(self):
        r = pair([make_record("t", vulnerable=False, lines=())],
                 [make_record("t", vulnerable=False, lines=(),
                              findings=[make_finding(line=5)])])
        by = {d["metric"]: d for d in r.score_deltas()}
        self.assertEqual(by["FP"]["direction"], "worse")

    def test_per_category_deltas_name_the_category(self):
        r = pair([make_record("t", category="leak", lines=(5,))],
                 [make_record("t", category="leak", lines=(5,),
                              findings=[make_finding(line=5)])])
        cats = r.category_score_deltas()
        self.assertEqual([c["category"] for c in cats], ["leak"])
        self.assertEqual(cats[0]["tp_delta"], 1)

    def test_scoring_covers_only_shared_tests(self):
        """A test missing from one side must not swing the aggregate."""
        r = pair([make_record("a", lines=(5,)), make_record("b", lines=(5,))],
                 [make_record("a", lines=(5,))])
        self.assertEqual(r.score_before.overall.scored, 1)
        self.assertEqual(r.score_after.overall.scored, 1)

    def test_skip_category_applies_to_deltas(self):
        r = pair([make_record("t", category="sqli", lines=(5,))],
                 [make_record("t", category="sqli", lines=(5,),
                              findings=[make_finding(line=5)])],
                 skip_categories=["sqli"])
        self.assertEqual(r.score_after.overall.scored, 0)

    def test_as_dict_is_json_safe(self):
        r = pair([make_record("t", lines=(5,))],
                 [make_record("t", lines=(5,),
                              findings=[make_finding(line=5)])])
        json.dumps(r.as_dict())


if __name__ == "__main__":
    unittest.main()
