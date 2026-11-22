# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""gab -- GCC Analyzer Benchmarks.

An automated benchmarking harness for GCC's static analyzer (-fanalyzer).

The central design split is *run* vs *score*.  `gab run` executes a GCC
over a suite and writes an immutable run directory holding the raw SARIF,
resource usage and exact toolchain identity for every test case.  Scoring,
reporting and diffing then read only run directories, so changing how
results are scored never means re-running the compiler.
"""

__version__ = "0.1.0"
