<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 David Malcolm -->
<!-- SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant -->

Citations
=========

How to credit the benchmark suites this harness runs.  None of them are
vendored into this repository -- `config.json` points at your own
checkouts -- so their licences and citation requirements are theirs, not
ours.  This harness itself is MIT; see LICENSE.

If you publish numbers produced by `gab`, cite the suite, and say which
*version* of it you ran: both suites below change between releases.
Every run directory records the suite version and a `content_hash` over
the exact test data, which is what makes a published number reproducible.


Currently supported
-------------------

### CASTLE-C250

MIT licensed (Copyright (c) 2025 Richard A. Dubniczky).
https://github.com/CASTLE-Benchmark/CASTLE-Benchmark

Dataset version 1.2, dated 2025-03-13: 250 tests, 150 vulnerable,
25 CWEs.

The paper also defines the **CASTLE Score**, implemented in
`gab/castle_score.py` from section 3.3 of the preprint
(https://arxiv.org/abs/2503.09433), since the repository ships the
dataset but no scorer.  Note that it is a reimplementation from the
paper, not a port of reference code, and that our numbers for GCC do
not currently reproduce the paper's -- see TODO.md for the open
questions about how their evaluation counted findings.

```bibtex
@inproceedings{castle2025dubniczky,
author = {Dubniczky, Richard A. and Horv\'{a}t, Krisztofer Zoltan and Bisztray, Tam\'{a}s and Ferrag, Mohamed Amine and Cordeiro, Lucas C. and Tihanyi, Norbert},
title = {CASTLE: Benchmarking Dataset for Static Code Analyzers and LLMs Towards CWE Detection},
year = {2025},
isbn = {978-3-031-98207-1},
publisher = {Springer-Verlag},
address = {Berlin, Heidelberg},
url = {https://doi.org/10.1007/978-3-031-98208-8_15},
doi = {10.1007/978-3-031-98208-8_15},
booktitle = {Theoretical Aspects of Software Engineering: 19th International Symposium, TASE 2025, Limassol, Cyprus, July 14--16, 2025, Proceedings},
pages = {253--272},
numpages = {20},
keywords = {Security, Static Code Analysis, Security Analysis, Generative AI, Large Language Models},
location = {Limassol, Cyprus}
}
```

GCC analyzer improvements driven by this suite are tracked in
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=128964

### BenchProctor

Apache-2.0 licensed; the C test sources carry
`SPDX-License-Identifier: Apache-2.0`.
https://github.com/TheAuditorTool/BenchProctor

**There is no paper.**  Cite the repository and the release, which
matters more here than for most suites: BenchProctor draws a changing
subset from a larger private pool, and deliberately renames test files
between releases so that tools cannot recognise them.  Two releases are
not the same benchmark.

```bibtex
@misc{benchproctor,
  title        = {BenchProctor: a SAST benchmark suite},
  author       = {{TheAuditorTool}},
  howpublished = {\url{https://github.com/TheAuditorTool/BenchProctor}},
  note         = {Release 2026.11.19.1},
  year         = {2026}
}
```

GCC analyzer improvements driven by this suite are tracked in
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=128852 -- note that
Bugzilla's HTML is behind bot protection, but the REST endpoint
`https://gcc.gnu.org/bugzilla/rest/bug/128852/comment` is readable.


Planned
-------

Neither is wired up yet; see TODO.md.

### Juliet

Public domain, developed by the NSA's Center for Assured Software.
Over 81,000 synthetic programs (57,099 C/C++, 23,957 Java) across 181
CWEs -- far larger than anything the harness currently runs, and the
reason the run/score split exists.

```bibtex
@article{boland2012juliet,
  author  = {Boland, Tim and Black, Paul E.},
  title   = {Juliet 1.1 {C/C++} and {Java} Test Suite},
  journal = {Computer},
  volume  = {45},
  number  = {10},
  pages   = {88--90},
  year    = {2012},
  doi     = {10.1109/MC.2012.345}
}
```

NIST's own listing gives the first author as "Frederick Boland Jr." and
titles it "The Juliet 1.1 C/C++ and Java Test Suite"; IEEE uses "Tim
Boland" and omits the leading article.  Same paper.
https://www.nist.gov/publications/juliet-11-cc-and-java-test-suite

### SARD

The Software Assurance Reference Dataset, maintained by NIST SAMATE,
which hosts Juliet among many other test collections.
https://samate.nist.gov/SARD/

Cite the specific test-case set used rather than SARD as a whole.


The tools we check ourselves against
------------------------------------

`gab score` is validated against BenchProctor's own `scripts/score_sarif.py`
(Apache-2.0, in their repository): both report TP 127 / FP 0 / FN 143 /
TN 270 and a category-averaged +47.0% for system GCC over the nine
in-scope categories.  Keeping that agreement is the best evidence we
have that the harness measures what the suite's authors intended.
