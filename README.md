<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 David Malcolm -->

GCC Analyzer Benchmarks
=======================

Intent
------

A harness for automatically running and scoring various C static analyzer
benchmark suites.

In particular, this exists for testing the GCC static analyzer (-fanalyzer).
I want something I can use to validate patches to the GCC analyzer.

Single-file self-contained test cases for now. (TODO: actually, some have a few minimal dependencies; document this)

This harness is MIT-licensed.  The 3rd-party benchmarks it runs may
be under different licenses.  See CITATIONS.md for how to credit them.

Much of the implementation was written by Claude Opus 5 (Anthropic) in
interactive sessions, from my design and under my review; see AUTHORS.
Files produced that way carry an `SPDX-FileContributor` tag, and
commits made with AI assistance carry an `Assisted-by:` trailer.


Requirements
------------

* runs automatically

* doesn't take "too long" to run (it's currently taking me ~3 hours
of testing to validate a set of patches).

* runnable on my bootstrap builds (which I do on an aarch64 machine in
the compile farm, rather than my laptop)

* parallelizable (my test box has 64 cores iirc)

* "ground truth" information for all test cases, so that
we can automatically classify results as true/false positives/negatives,
can generate precision, recall, and accuracy.   Some suites also have their
own scores: CASTLE score, BenchProctor score etc, and also we'll want to
report these.

* detects failures of the tool e.g. ICEs, and flags these visibly

* output of datafiles capturing per test-case reports, in a common format
for ease of reporting/management (JSON? meta-SARIF??), and slurping into a
database (bunsen? see https://sourceware.org/bunsen/)

* "diff"ing tool so that we can compare a patched GCC against a baseline GCC
and see changes, including all test cases that got better and all that got
worse.  Make it easy to investigate such a change; I'll probably want to poke
at in the debugger/file a bug report/etc.

* capture resource usage: peak memory, time taken, so that we can report on
major regressions/improvements.

* no (or few) dependencies: just Python?

* reuse existing suites (if we're writing our own cases by hand, these can
simply live in GCC's DejaGnu-based testsuite).   Will want to be able to
cache the downloading of these suites.

* FLOSS license; can have AI contributions

* runnable on install of gcc, and also on a not-installed build-directory
build of xgcc/cc1 (for ease of debugging GCC).  Would be nice to be able to
slot in a custom cc1 (for bisecting which commit introduced a change).

* easily subsettable: just run a subset of tests (for ease of debugging GCC)

* SARIF-based, but to get at historical data, would be nice to be able to
also test the versions of the GCC analyzer from before SARIF output was added

* maybe a debug mode that adds "analyzer-graphs=yes" to the SARIF-generation
options, to ease debugging of false results.


Suites to investigate
---------------------

* BenchProctor:
  * https://github.com/TheAuditorTool/BenchProctor#readme
  * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=128852
* CASTLE: https://github.com/CASTLE-Benchmark/CASTLE-Benchmark
* Juliet
* SARD


Notes
-----

Do we want the report format to itself be SARIF (a kind of meta-SARIF)?
Or is that overthinking things?
