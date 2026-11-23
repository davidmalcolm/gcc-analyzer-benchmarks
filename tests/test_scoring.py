# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Scoring: matching rules, classification, and the confusion matrix."""

import unittest

from gab import scoring
from tests.fixtures import make_finding, make_record


class TestMatchers(unittest.TestCase):
    def test_file_matcher_ignores_position(self):
        f = make_finding(line=999)
        self.assertTrue(scoring.MATCHERS["file"](f, [5]))

    def test_line_matcher_is_exact(self):
        self.assertTrue(scoring.MATCHERS["line"](make_finding(line=5), [5]))
        self.assertFalse(scoring.MATCHERS["line"](make_finding(line=6), [5]))

    def test_line2_matcher_allows_two(self):
        m = scoring.MATCHERS["line2"]
        self.assertTrue(m(make_finding(line=7), [5]))
        self.assertFalse(m(make_finding(line=8), [5]))

    def test_path_matcher_uses_event_path(self):
        """The leak case: reported at the return, allocated at line 4."""
        f = make_finding(line=9, path_lines=[4, 7, 9])
        self.assertTrue(scoring.MATCHERS["path"](f, [4]))
        self.assertFalse(scoring.MATCHERS["line"](f, [4]))

    def test_path_matcher_rejects_unrelated_long_path(self):
        f = make_finding(line=120, path_lines=list(range(100, 130)))
        self.assertFalse(scoring.MATCHERS["path"](f, [5, 9]))

    def test_path_plus_one_is_the_union(self):
        m = scoring.MATCHERS["path+1"]
        self.assertTrue(m(make_finding(line=9, path_lines=[4]), [4]))
        self.assertTrue(m(make_finding(line=7, path_lines=[]), [6]))
        self.assertFalse(m(make_finding(line=9, path_lines=[]), [6]))

    def test_finding_with_no_line_never_matches(self):
        f = make_finding(line=None)
        self.assertFalse(scoring.MATCHERS["line"](f, [5]))
        self.assertFalse(scoring.MATCHERS["path+1"](f, [5]))


class TestClassify(unittest.TestCase):
    def _c(self, rec, rule="path+1"):
        return scoring.classify(rec, scoring.MATCHERS[rule])

    def test_vulnerable_with_matching_finding_is_tp(self):
        rec = make_record("t", findings=[make_finding(line=5)], lines=(5,))
        self.assertEqual(self._c(rec).outcome, "TP")

    def test_vulnerable_with_no_finding_is_fn(self):
        self.assertEqual(self._c(make_record("t")).outcome, "FN")

    def test_vulnerable_with_distant_finding_is_fn(self):
        rec = make_record("t", findings=[make_finding(line=90)], lines=(5,))
        self.assertEqual(self._c(rec).outcome, "FN")

    def test_clean_file_with_any_finding_is_fp(self):
        """Line matching cannot apply: a clean file has no truth line, so
        any report at all is a false positive."""
        rec = make_record("t", vulnerable=False, lines=(),
                          findings=[make_finding(line=90)])
        self.assertEqual(self._c(rec).outcome, "FP")

    def test_clean_and_quiet_is_tn(self):
        rec = make_record("t", vulnerable=False, lines=())
        self.assertEqual(self._c(rec).outcome, "TN")

    def test_meta_findings_never_count(self):
        """-Wanalyzer-too-complex describes the analysis, not the code."""
        rec = make_record("t", vulnerable=False, lines=(), findings=[
            make_finding(rule="-Wanalyzer-too-complex", meta=True)])
        self.assertEqual(self._c(rec).outcome, "TN")

    def test_non_analyzer_findings_never_count(self):
        rec = make_record("t", vulnerable=False, lines=(),
                          findings=[make_finding(rule="-Wunused-variable")])
        self.assertEqual(self._c(rec).outcome, "TN")

    def test_no_line_truth_falls_back_to_file_level(self):
        """BenchProctor has no line truth; a hit anywhere must count."""
        rec = make_record("t", lines=(), findings=[make_finding(line=77)])
        self.assertEqual(self._c(rec).outcome, "TP")

    def test_crashes_are_excluded_not_counted_as_misses(self):
        for status in ("ice", "timeout", "compile-error", "bad-sarif"):
            with self.subTest(status=status):
                v = self._c(make_record("t", status=status))
                self.assertEqual(v.outcome, "excluded")
                self.assertFalse(v.scored)


class TestCounts(unittest.TestCase):
    def test_metrics(self):
        c = scoring.Counts(TP=30, FP=10, FN=20, TN=40)
        self.assertAlmostEqual(c.precision, 0.75)
        self.assertAlmostEqual(c.recall, 0.6)
        self.assertAlmostEqual(c.fpr, 0.2)
        self.assertAlmostEqual(c.accuracy, 0.7)
        self.assertAlmostEqual(c.f1, 2 * 0.75 * 0.6 / 1.35)

    def test_metrics_are_none_when_undefined(self):
        c = scoring.Counts()
        for attr in ("precision", "recall", "fpr", "accuracy", "f1"):
            self.assertIsNone(getattr(c, attr), attr)


class TestScore(unittest.TestCase):
    def setUp(self):
        self.records = [
            make_record("a", findings=[make_finding(line=5)], lines=(5,)),
            make_record("b", findings=[make_finding(line=5)], lines=(5,)),
            make_record("c", lines=(5,)),
            make_record("d", vulnerable=False, lines=(),
                        findings=[make_finding(line=5)]),
            make_record("e", vulnerable=False, lines=()),
        ]

    def test_overall_counts(self):
        r = scoring.score(self.records)
        self.assertEqual((r.overall.TP, r.overall.FP, r.overall.FN,
                          r.overall.TN), (2, 1, 1, 1))

    def test_category_filtering(self):
        recs = self.records + [
            make_record("x", category="sqli", lines=(5,))]
        full = scoring.score(recs)
        self.assertEqual(full.overall.FN, 2)
        scoped = scoring.score(recs, skip_categories=["sqli"])
        self.assertEqual(scoped.overall.FN, 1)
        self.assertEqual(scoped.scope["n_tests_scored"], 5)

    def test_categories_allowlist(self):
        recs = self.records + [make_record("x", category="sqli", lines=(5,))]
        only = scoring.score(recs, categories=["sqli"])
        self.assertEqual(only.scope["n_tests_scored"], 1)

    def test_macro_average_is_per_category(self):
        """Two categories of very different size must weigh equally."""
        recs = (
            [make_record(f"big{i}", category="big", lines=(5,))
             for i in range(9)]
            + [make_record("big9", category="big", lines=(5,),
                           findings=[make_finding(line=5)])]
            + [make_record("small0", category="small", lines=(5,),
                           findings=[make_finding(line=5)])]
        )
        r = scoring.score(recs)
        # big recall 0.1, small recall 1.0 -> macro 0.55, but flat
        # recall is only 2/11, because 'big' dominates the pool.
        self.assertAlmostEqual(r.macro["tpr"], 0.55)
        self.assertAlmostEqual(r.overall.recall, 2 / 11)

    def test_unknown_matcher_raises(self):
        with self.assertRaises(KeyError):
            scoring.score(self.records, "nope")

    def test_compare_matchers_covers_every_rule(self):
        out = scoring.compare_matchers(self.records)
        self.assertEqual(set(out), set(scoring.MATCHERS))

    def test_as_dict_is_json_safe(self):
        import json
        json.dumps(scoring.score(self.records).as_dict())


if __name__ == "__main__":
    unittest.main()


class TestCastleScore(unittest.TestCase):
    """Section 3.3 of the CASTLE paper, equations (1) and (2)."""

    def test_bonus_bands(self):
        from gab.castle_score import bonus, TOP25_RANK
        # B = 5 - floor((rank-1)/5): five bands of five.
        self.assertEqual(bonus(787), 5)   # rank 2
        self.assertEqual(bonus(22), 5)    # rank 5
        self.assertEqual(bonus(125), 4)   # rank 6
        self.assertEqual(bonus(416), 4)   # rank 8
        self.assertEqual(bonus(134), 3)   # rank 12
        self.assertEqual(bonus(761), 2)   # rank 20
        self.assertEqual(bonus(476), 1)   # rank 21
        self.assertEqual(bonus(835), 1)   # rank 24

    def test_bonus_is_zero_outside_the_top_25(self):
        from gab.castle_score import bonus
        for cwe in (401, 253, 327, 362, 617, 628, 843, 99999):
            self.assertEqual(bonus(cwe), 0, cwe)
        self.assertEqual(bonus(None), 0)

    def _score(self, records, detect="cwe"):
        from gab.castle_score import castle_score
        return castle_score(records, detect)

    def test_detection_scores_five_plus_bonus(self):
        rec = make_record("t", cwe=476, lines=(5,),
                          findings=[make_finding(cwe=476, line=5)])
        r = self._score([rec])
        # one finding: 5 - (1-1) + B(476)=1  ->  6
        self.assertEqual(r.total, 6)
        self.assertEqual(r.per_test[0].case, "detected")

    def test_extra_findings_cost_a_point_each(self):
        rec = make_record("t", cwe=476, lines=(5,), findings=[
            make_finding(cwe=476, line=5),
            make_finding(cwe=476, line=9),
            make_finding(cwe=476, line=11)])
        # 5 - (3-1) + 1 = 4
        self.assertEqual(self._score([rec]).total, 4)

    def test_clean_and_quiet_scores_two(self):
        rec = make_record("t", vulnerable=False, cwe=476, lines=())
        r = self._score([rec])
        self.assertEqual(r.total, 2)
        self.assertEqual(r.per_test[0].case, "clean-and-quiet")

    def test_false_positives_cost_one_each(self):
        rec = make_record("t", vulnerable=False, cwe=476, lines=(), findings=[
            make_finding(cwe=476, line=5), make_finding(cwe=476, line=7)])
        self.assertEqual(self._score([rec]).total, -2)

    def test_silently_missing_a_bug_costs_nothing(self):
        """-|t(d)| is zero when the tool reported nothing."""
        rec = make_record("t", cwe=476, lines=(5,))
        r = self._score([rec])
        self.assertEqual(r.total, 0)
        self.assertEqual(r.per_test[0].case, "missed-or-wrong")

    def test_right_place_wrong_cwe_is_not_a_detection_under_the_paper_rule(self):
        rec = make_record("t", cwe=476, lines=(5,),
                          findings=[make_finding(cwe=690, line=5)])
        self.assertEqual(self._score([rec]).total, -1)
        # ... but it is under a position-based rule.
        self.assertEqual(self._score([rec], "path+1").total, 6)

    def test_a_silent_tool_scores_two_per_clean_test(self):
        recs = ([make_record(f"v{i}", cwe=476, lines=(5,)) for i in range(5)]
                + [make_record(f"c{i}", vulnerable=False, cwe=476, lines=())
                   for i in range(10)])
        self.assertEqual(self._score(recs).total, 20)

    def test_crashed_tests_are_excluded_not_scored(self):
        recs = [make_record("ok", vulnerable=False, cwe=476, lines=()),
                make_record("boom", cwe=476, lines=(5,), status="ice")]
        r = self._score(recs)
        self.assertEqual(r.excluded, ["boom"])
        self.assertEqual(r.total, 2)

    def test_unknown_detection_rule_raises(self):
        with self.assertRaises(KeyError):
            self._score([make_record("t")], "nonsense")

    def test_as_dict_is_json_safe(self):
        import json
        json.dumps(self._score([make_record("t")]).as_dict())
