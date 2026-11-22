<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 David Malcolm -->
<!-- SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant -->

TODO
====

Status as of 2026-11-22.  Run, score and diff all work end to end
against BenchProctor and CASTLE.

What exists: `gab suites`, `gab toolchains`, `gab run`, `gab score`,
`gab diff`, `gab show`.  Run directories hold raw SARIF, flattened
findings (including codeFlow path lines), per-test rusage, SARIF
`invocations` data, embedded ground truth, a suite content hash and full
toolchain identity.  `score` and `diff` both take `--json` and return
meaningful exit codes, for driving from a bisection script.

`gab score` is validated against BenchProctor's own `score_sarif.py`:
both give TP 127 / FP 0 / FN 143 / TN 270 and a category-averaged score
of +47.0% for system GCC over the 9 in-scope categories.


Open decisions
--------------

* **What counts as a detection.**  All five rules below are implemented
  and selectable with `gab score --match`; `path+1` is the current
  default, and `--compare-matchers` prints the whole table.  The default
  still wants your sign-off.  Measured on CASTLE under system GCC,
  ignoring CWE identity:

  | rule | TP | FP | precision | recall |
  |---|---|---|---|---|
  | file-level (any analyzer finding) | 44 | 6 | 0.880 | 0.293 |
  | primary line exact | 32 | 6 | 0.842 | 0.213 |
  | event path touches a truth line | 33 | 6 | 0.846 | 0.220 |
  | path OR primary +-1 | 34 | 6 | 0.850 | 0.227 |

  The 44 vs 34 gap is 11 files where `-fanalyzer` reported a *real but
  different* bug than the labelled one.  Count them as TP, FP, or exclude
  them?  They are good outcomes for GCC but not detections of the flaw
  under test.  Suggested default is `path OR primary +-1`, but this is
  yours to call.

* **Whether to report a CWE-matched variant at all.**  Current steer is
  that TP/FP/FN matter and CWE identity does not.  The data supports
  that: on BenchProctor every reported CWE already equals ground truth
  exactly, so a CWE-aware rule changes nothing there, and on CASTLE it
  mostly penalises adjacent-but-correct CWEs (253 vs 690, 761 vs 401).


Near-term
---------

* Validate `gab score` against the manual numbers in
  https://gcc.gnu.org/bugzilla/show_bug.cgi?id=128852 whenever that bug
  gains a new comparison -- comment #8's manual gcc 16 -> 17 diff was
  reproduced exactly by `gab diff` (uninit_variable 29 -> 30, total
  127 -> 128, +47.0% -> +47.4%, gained test benchmark_test_01026), which
  is the best cross-check we have that the harness agrees with how you
  actually read these results.  Note the bug is behind Anubis
  bot-protection: fetching the HTML fails, but the REST endpoint
  `https://gcc.gnu.org/bugzilla/rest/bug/<id>/comment` works.

* **The CASTLE Score.**  Not implemented -- the CASTLE repo ships no
  scorer, so the formula has to come from the paper (arXiv 2503.09433),
  and guessing at it would be worse than leaving it out.  BenchProctor's
  category-averaged TPR-FPR *is* implemented, as `score` in the
  category-averaged line, and cross-checked against their scorer.

* Add a `--fail-on` selector to `gab diff` so a bisection script can say
  which property it is bisecting for (any regression / new crash only /
  a specific test changing outcome).  Today the exit code is 1 for any
  regression or new crash, 2 for incomparable runs, which covers the
  common cases but not "bisect this one test".

* Scoring currently excludes tests whose compile failed, and `gab score`
  exits 1 when any were excluded.  Check that this is the behaviour you
  want from a bisection script before relying on it.

* `gab score` and `gab diff` on a group accept `--match` and the
  category filters, but apply them uniformly to every suite.  The
  natural scope differs per suite -- BenchProctor wants ten categories
  skipped, CASTLE wants none -- so a per-suite default scope, probably
  declared in config next to the suite, would stop that having to be
  retyped on every invocation.

* Run the 4 toolchains x 2 suites baseline matrix.  Never done; would
  establish whether `symbolic` moves any result against `pristine`, and
  shake out ICEs.  Only `pristine` vs `symbolic` is a clean *timing*
  comparison -- see the checking-level note below.

* Pull BenchProctor's 2026.11.22 release and check what moved.  Version
  pinning via `--suite-version` already exists.

* Confirm or refute the wall-time noise hypothesis.  Run-to-run spread on
  identical work is 6.3% median / 26% p95 for wall, 2.9% / 10.5% for CPU
  time, but only 0.44% / 1.3% for peak RSS.  Suspected cause is `-j8`
  contention; test by repeating at `-j1`.  If confirmed, document that
  timing-sensitive runs must be serial and that RSS is the trustworthy
  metric.

* Extend the test suite as features land.  132 tests exist (`./run-tests`),
  covering every command in every output format, every matching rule, and
  the compiler-failure paths.  They need neither a GCC nor a benchmark
  checkout: `tests/fixtures.py` generates a synthetic suite and a stub
  compiler that fakes ICEs, hangs and truncated SARIF on demand.  Not yet
  covered: the suite adapters against real BenchProctor/CASTLE layouts,
  and `Runner` parallelism under load.

* Keep CITATIONS.md current as suites are added.  Juliet and SARD
  already have entries there, under "Planned"; BenchProctor's entry
  pins a release, which needs updating whenever we move to a new one.


Medium-term
-----------

* **Juliet and SARD adapters.**  These are the reason the architecture is
  shaped the way it is, and both are far larger than anything run so far.
  Expect to need: suite download + caching (README asks for this), a
  less file-per-test-heavy run directory layout (tens of thousands of
  small files), and real attention to wall-clock.  Juliet also has
  multi-file test cases and `omitgood`/`omitbad` build variants, which
  the current single-file `TestCase` model does not express.

* Other suites: the CASTLE paper has a handy catalog of suites (might
  be in the repo also)

* Resource-regression reporting: flag tests whose time or peak RSS moved
  substantially between runs.  Data is captured; nothing consumes it.

* Database export for historical tracking (bunsen, or just SQLite).  The
  JSONL format was chosen partly for this.

* `gab export --sarif` to view a whole run in SARIF tooling.  The earlier
  "should the report format itself be meta-SARIF?" question was settled
  as no -- SARIF has nowhere natural to put peak RSS, TN or FN -- but an
  export path costs little.

* Debug mode adding `analyzer-graphs=yes` to the SARIF output options,
  for investigating a specific false result.

* First-class support for slotting in a custom `cc1`, for bisecting which
  commit changed a result.  Possible today via `extra_args`/`env` in
  config, but undocumented and untested.

* Validate on the aarch64 compile farm box.  Nothing has run outside this
  laptop.  Config already expands `$VAR`/`~` so one file can serve both;
  that is untested.  Note the cfarm box is Rocky Linux and shared, so
  timing there is noisier still.

* Optimization level: GCC's -fanalyzer runs relatively late compared to
  other analysis tools, and is affected by the optimization level, and
  (I believe) by "-g" since this can affect line number information
  seen by the analyzer.  So we may want to test across unoptimized vs
  various optimizations levels and with/without -g as other dimensions
  of the data, and capture these.

* Bisection: I have a (large) collection of builds of cc1 at each revision
  for regression bisection, and a bisection tool that, given a script to
  identify a property of interest, identifies in which cc1 revision the
  property changes (e.g. historically we typically use this for crashes,
  or for false positives of warnings ).  I think I'll eventually want to
  be able to run "gab" within one of these scripts to determine which gcc
  patch affected a benchmark result/property.


Longer-term
-----------

* **Scoring report quality, not just detection.**  The guiding principle
  is that a report must let a GCC user see what the analyzer was
  thinking, and no benchmark suite measures this.  Idea on the table:
  synthesise ground truth for message wording (regexes?) augmenting the
  existing ground truth.  Deliberately not started.

* Historical `-fanalyzer` versions.  SARIF plumbing differs by release:
  `-fdiagnostics-add-output=sarif` exists from GCC 15; GCC 13-14 only
  have `-fdiagnostics-format=`, which takes over stderr; GCC 10-12 have
  no SARIF at all (a custom JSON format, removed in GCC 16).  GCC 16 also
  changed which directory SARIF is written to (PR diagnostics/110522,
  commit 6fe28020cae5), so output location differs for 13-15.  A
  toolchain abstraction over "how do I get machine-readable output from
  this compiler" would be needed.

* Per-test kernel-level performance data (SystemTap / eBPF).  Deferred,
  and the case is weak as stated: `wait4` already gives per-process peak
  RSS stable to under 1%, unprivileged, and works on the cfarm box.  The
  noisy metric is wall time, which tracing would measure rather than fix.
  Worth doing only against a specific question `rusage` cannot answer --
  page-fault profiles, or allocation behaviour over time.

* C++ test cases.  Everything so far is C.   Note that GCC -fanalyzer
  doesn't support C++ yet, or, at least has heavy caveats.  I hope to
  support it in the forthcoming GCC 17 release.  We may need to recommend
  a minimum optimization level to users when using the C++ stdlib since
  without inlining the analyzer burns its analysis budget on trivial constructs.


Issues to raise with the suites
-------------------------------

* **CASTLE: tests whose flaw modern GCC rejects at the front end.**
  `CASTLE-822-1` (untrusted pointer deref) fails `-Wint-conversion` and
  `CASTLE-843-2` (type confusion) fails `-Wincompatible-pointer-types`;
  both became errors in GCC 14, so `-fanalyzer` never runs on them.  We
  work around it with `-Wno-error=` so the analyzer gets a chance.
  Several other files predate C23 (`nullptr` used as an identifier,
  implicit declarations), handled with `-std=gnu17`.

* **CASTLE: mislabelled "not vulnerable" files.**  All 6 apparent false
  positives are correct diagnostics -- mostly unchecked file descriptors
  from `socket()` -- in files labelled not-vulnerable-to-CWE-X.  Anyone
  quoting a CASTLE precision number for GCC should know this.

* **CASTLE: line-number conventions for leaks.**  Ground truth marks the
  allocation site or the faulty check; GCC reports where the last
  reference dies (a `return`, or the closing brace).  Not a bug in either
  party, but worth recording as a known scoring hazard.  Worked examples:
  `CASTLE-401-3`, `CASTLE-253-5/6`, `CASTLE-835-1` (loop header vs body).

* **CASTLE: needs `mysql/mysql.h`** (9 tests).  `mariadb-connector-c-devel`
  on Fedora.  Will need installing on the cfarm box too.

* BenchProctor rotates its contents between releases and deliberately
  changes filenames.  Handled via `--suite-version` and the run's
  `content_hash`, but any cross-release comparison needs care.


GCC findings worth following up
-------------------------------

* **`-Wanalyzer-fd-use-without-check` and `-Wanalyzer-write-to-string-literal`
  emit no CWE taxon** in GCC 16's SARIF; every other analyzer warning
  does.  Costs the analyzer credit under any CWE-aware scoring.

* **BenchProctor use-after-free: 8/30 detected**, against 30/30 for
  double-free, memory-leak and null-deref, and 29/30 for uninitialised
  value.  Stands out sharply from its neighbours; worth understanding
  what those 22 cases have in common.

* The copr build has `-fchecking=2` (trunk's `yes,extra` default), not
  release checking.  Its timings are not comparable with
  `/usr/bin/gcc`'s.  Not a bug, but a trap when reading results.
