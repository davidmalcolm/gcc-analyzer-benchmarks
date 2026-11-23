# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Running a suite under a toolchain, and writing a run directory.

Execution notes
---------------

Each test is one compiler invocation.  We spawn it with `os.posix_spawn`
and reap it with `os.wait4`, which hands back that child's own rusage --
peak RSS and user/sys time for this compilation alone.  `subprocess`
cannot do that (`resource.getrusage(RUSAGE_CHILDREN)` is cumulative over
the whole process, which is meaningless once tests run concurrently).

Parallelism is a thread pool: each worker thread spends essentially all
its time blocked in `wait4`, so the GIL is not a factor, and threads
avoid the cost of forking the Python interpreter per test.

Every path handed to the compiler is absolute and output goes to
/dev/null, so no test writes anything into the current directory and
tests cannot collide with each other.

Run directory layout
--------------------

    <run>/run.json          manifest: toolchain identity, suite version, flags
    <run>/results.jsonl     one JSON record per test, ground truth embedded
    <run>/sarif/<name>.sarif
    <run>/logs/<name>.txt   compiler stderr, only when non-empty

Ground truth is embedded in each record deliberately: a run directory is
then self-contained and can be scored, diffed or archived on a machine
that has neither the suite checkout nor the compiler.
"""

from __future__ import annotations

import json
import os
import platform
import signal
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from gab import __version__, sarif
from gab.suite import Suite, TestCase
from gab.toolchain import Toolchain

DEFAULT_ANALYZER_ARGS = ("-fanalyzer",)
DEFAULT_TIMEOUT = 300.0

#: Signals that mean the compiler crashed rather than merely failed.
CRASH_SIGNALS = frozenset({signal.SIGSEGV, signal.SIGABRT, signal.SIGILL,
                           signal.SIGBUS, signal.SIGFPE})

ICE_MARKERS = (
    "internal compiler error",
    "in gcc_unreachable",
    "Please submit a full bug report",
)


@dataclass
class TestResult:
    name: str
    suite: str
    source: str
    ground_truth: dict

    status: str = "ok"
    """ok | compile-error | ice | timeout | spawn-error | bad-sarif"""

    exit_code: Optional[int] = None
    signal: Optional[int] = None
    wall_time: float = 0.0
    user_time: float = 0.0
    sys_time: float = 0.0
    maxrss_kb: int = 0

    findings: List[dict] = field(default_factory=list)
    n_analyzer_findings: int = 0
    too_complex: bool = False
    invocation: dict = field(default_factory=dict)
    """SARIF `invocations` data: cc1 start/end, executionSuccessful, and
    -ftime-report timevars when enabled."""

    sarif: Optional[str] = None
    log: Optional[str] = None
    error: Optional[str] = None
    argv: List[str] = field(default_factory=list)


def _decode_ice(status_text: str, sig: Optional[int], timed_out: bool) -> bool:
    if timed_out:
        return False
    if sig is not None and sig in CRASH_SIGNALS:
        return True
    low = status_text.lower()
    return any(m.lower() in low for m in ICE_MARKERS)


def _spawn_and_wait(argv: Sequence[str], env: Dict[str, str],
                    log_path: Path, timeout: float):
    """Run argv, redirecting stdout+stderr to log_path.

    Returns (exit_code, sig, timed_out, wall, user, sys, maxrss_kb).
    """
    file_actions = [
        (os.POSIX_SPAWN_OPEN, 0, os.devnull, os.O_RDONLY, 0o666),
        (os.POSIX_SPAWN_OPEN, 1, str(log_path),
         os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644),
        (os.POSIX_SPAWN_DUP2, 1, 2),
    ]
    t0 = time.monotonic()
    pid = os.posix_spawn(argv[0], list(argv), env, file_actions=file_actions)

    timed_out = threading.Event()
    reaped = threading.Event()

    def _kill():
        # Guard against racing the normal exit: if wait4 has already
        # returned, the pid may have been recycled by another process.
        if reaped.is_set():
            return
        timed_out.set()
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    timer = threading.Timer(timeout, _kill)
    timer.start()
    try:
        _, status, ru = os.wait4(pid, 0)
    finally:
        reaped.set()
        timer.cancel()
    wall = time.monotonic() - t0

    if os.WIFSIGNALED(status):
        sig, code = os.WTERMSIG(status), None
    else:
        sig, code = None, os.WEXITSTATUS(status)

    return (code, sig, timed_out.is_set(), wall,
            ru.ru_utime, ru.ru_stime, int(ru.ru_maxrss))


class Runner:
    def __init__(
        self,
        toolchain: Toolchain,
        suite: Suite,
        out_dir: Path,
        analyzer_args: Sequence[str] = DEFAULT_ANALYZER_ARGS,
        extra_args: Sequence[str] = (),
        timeout: float = DEFAULT_TIMEOUT,
        jobs: int = 0,
        keep_sarif: bool = True,
        time_report: bool = False,
    ):
        self.toolchain = toolchain
        self.suite = suite
        self.out_dir = Path(out_dir)
        self.analyzer_args = list(analyzer_args)
        self.extra_args = list(extra_args)
        self.timeout = timeout
        self.jobs = jobs or (os.cpu_count() or 1)
        self.keep_sarif = keep_sarif
        # -ftime-report splits analyzer time out of total compile time,
        # at the cost of perturbing that time a little and writing the
        # report to stderr.  Opt-in for that reason.
        self.time_report = time_report
        if time_report:
            self.analyzer_args.append("-ftime-report")
        self._content_hash = None
        self._n_tests_in_suite = 0

        self.sarif_dir = self.out_dir / "sarif"
        self.log_dir = self.out_dir / "logs"

    # -- one test --------------------------------------------------------

    def _argv_for(self, test: TestCase, sarif_path: Path) -> List[str]:
        return [
            *self.toolchain.argv,
            *test.compile_args,
            *self.analyzer_args,
            f"-fdiagnostics-add-output=sarif:file={sarif_path}",
            *self.extra_args,
            "-c",
            "-o", os.devnull,
            str(test.source),
        ]

    def run_one(self, test: TestCase, env: Dict[str, str]) -> TestResult:
        sarif_path = self.sarif_dir / f"{test.name}.sarif"
        log_path = self.log_dir / f"{test.name}.txt"
        argv = self._argv_for(test, sarif_path)

        res = TestResult(
            name=test.name,
            suite=test.suite,
            source=str(test.source),
            ground_truth=test.ground_truth(),
            argv=argv,
        )

        try:
            code, sig, timed_out, wall, utime, stime, maxrss = _spawn_and_wait(
                argv, env, log_path, self.timeout
            )
        except OSError as e:
            res.status = "spawn-error"
            res.error = str(e)
            return res

        res.exit_code = code
        res.signal = sig
        res.wall_time = wall
        res.user_time = utime
        res.sys_time = stime
        res.maxrss_kb = maxrss

        try:
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = ""

        if timed_out:
            res.status = "timeout"
        elif _decode_ice(log_text, sig, timed_out):
            res.status = "ice"
        elif code not in (0, None):
            res.status = "compile-error"

        if sarif_path.is_file():
            res.invocation = sarif.parse_invocation(sarif_path)
            # GCC's crash handler is supposed to record a backtrace here on
            # the way out.  We treat it as corroboration only: a crash is
            # detected from the exit status and stderr, never from the
            # compiler's own cooperation while dying.
            if res.invocation.get("execution_successful") is False \
                    and res.status == "ok":
                res.status = "ice"
            try:
                res.findings = sarif.parse_findings(sarif_path)
            except ValueError as e:
                # A truncated SARIF is itself a tool failure; do not let it
                # masquerade as a clean "no findings" result.
                if res.status == "ok":
                    res.status = "bad-sarif"
                res.error = str(e)
            real = sarif.real_analyzer_findings(res.findings)
            res.n_analyzer_findings = len(real)
            res.too_complex = any(f.get("meta") for f in res.findings)
            res.sarif = str(sarif_path.relative_to(self.out_dir))
            if not self.keep_sarif:
                sarif_path.unlink(missing_ok=True)
                res.sarif = None
        elif res.status == "ok":
            # GCC should always write the file when asked to.
            res.status = "bad-sarif"
            res.error = "compiler produced no SARIF file"

        if log_text.strip():
            res.log = str(log_path.relative_to(self.out_dir))
        else:
            log_path.unlink(missing_ok=True)

        return res

    # -- whole suite -----------------------------------------------------

    def run(
        self,
        tests: Sequence[TestCase],
        progress: Optional[Callable[[int, int, TestResult], None]] = None,
    ) -> List[TestResult]:
        self.sarif_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        env = self.toolchain.env()

        # Hash the tests actually selected, so a subset run is never
        # mistaken for a full one when diffing.
        self._content_hash = self.suite.content_hash(list(tests))
        try:
            self._n_tests_in_suite = len(self.suite.tests())
        except (OSError, ValueError):
            self._n_tests_in_suite = len(tests)

        results: List[TestResult] = []
        started = time.time()
        wall0 = time.monotonic()

        with ThreadPoolExecutor(max_workers=self.jobs) as pool:
            futures = {pool.submit(self.run_one, t, env): t for t in tests}
            for n, fut in enumerate(as_completed(futures), 1):
                res = fut.result()
                results.append(res)
                if progress:
                    progress(n, len(tests), res)

        elapsed = time.monotonic() - wall0
        results.sort(key=lambda r: r.name)
        self._write(results, started, elapsed, len(tests))
        return results

    def _write(self, results: List[TestResult], started: float,
               elapsed: float, n_tests: int) -> None:
        with open(self.out_dir / "results.jsonl", "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(asdict(r), sort_keys=True) + "\n")

        manifest = {
            "kind": "run",
            "gab_version": __version__,
            "schema": 1,
            "started": started,
            "started_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z",
                                         time.localtime(started)),
            "elapsed_wall": elapsed,
            "n_tests": n_tests,
            "jobs": self.jobs,
            "timeout": self.timeout,
            "analyzer_args": self.analyzer_args,
            "extra_args": self.extra_args,
            "toolchain": self.toolchain.identity(),
            "suite": {
                "name": self.suite.name,
                # The adapter behind this instance, which may differ
                # from the name when one adapter is configured twice.
                # Lets scorers tell what kind of suite this really is.
                "adapter": type(self.suite).name,
                "version": self.suite.version(),
                "root": str(self.suite.root),
                # Identifies the exact test data, not just its label.
                # BenchProctor rotates contents between releases, so a
                # version string alone cannot tell you whether two runs
                # saw the same tests.
                "content_hash": self._content_hash,
                "n_tests_in_suite": self._n_tests_in_suite,
                "subset": self._n_tests_in_suite != n_tests,
                # Recorded so that reports can honour the suite's
                # scope without needing the suite checkout present.
                "out_of_scope_categories":
                    self.suite.out_of_scope_categories(),
                "cwe_parents": {str(k): v
                                for k, v in self.suite.cwe_parents().items()},
            },
            "host": {
                "hostname": socket.gethostname(),
                "machine": platform.machine(),
                "system": platform.platform(),
                "cpus": os.cpu_count(),
                "python": sys.version.split()[0],
            },
            "totals": {
                "cpu_time": sum(r.user_time + r.sys_time for r in results),
                "max_maxrss_kb": max((r.maxrss_kb for r in results), default=0),
                "status": _tally(r.status for r in results),
            },
        }
        with open(self.out_dir / "run.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
            f.write("\n")


def _tally(values) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


def load_run(run_dir: Path) -> tuple:
    """Read a run directory back as (manifest, [record dicts])."""
    run_dir = Path(run_dir)
    manifest_path = run_dir / "run.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"{run_dir} is not a run directory "
                                f"(no run.json)")
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    if manifest.get("kind") == "group":
        raise IsADirectoryError(
            f"{run_dir} is a multi-suite run; its suites are "
            f"{', '.join(s['suite'] for s in manifest.get('members', []))}"
        )
    records = []
    with open(run_dir / "results.jsonl", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return manifest, records


def is_group(path: Path) -> bool:
    """True if this directory holds several suites rather than one run."""
    manifest = Path(path) / "run.json"
    if not manifest.is_file():
        return False
    try:
        with open(manifest, encoding="utf-8") as f:
            return json.load(f).get("kind") == "group"
    except (OSError, json.JSONDecodeError):
        return False


def load_group(path: Path) -> tuple:
    """Read a group directory as (manifest, [(suite_name, run_dir)]).

    Members are returned in the manifest's order, and a member whose
    directory has gone missing is dropped rather than raising -- a
    partially-copied group should still report on what it does have.
    """
    path = Path(path)
    with open(path / "run.json", encoding="utf-8") as f:
        manifest = json.load(f)
    members = []
    for entry in manifest.get("members", []):
        child = path / entry["dir"]
        if (child / "run.json").is_file():
            members.append((entry["suite"], child))
    return manifest, members


def write_group_manifest(out_dir: Path, members: Sequence[dict],
                         toolchain_identity: dict, started: float,
                         elapsed: float, analyzer_args: Sequence[str],
                         extra_args: Sequence[str], jobs: int) -> None:
    """Write the top-level manifest tying several suite runs together.

    The group carries the toolchain identity once: every member ran
    under the same compiler, which is the whole point of grouping them.
    """
    manifest = {
        "kind": "group",
        "gab_version": __version__,
        "schema": 1,
        "started": started,
        "started_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z",
                                     time.localtime(started)),
        "elapsed_wall": elapsed,
        "jobs": jobs,
        "analyzer_args": list(analyzer_args),
        "extra_args": list(extra_args),
        "toolchain": toolchain_identity,
        "members": list(members),
        "host": {
            "hostname": socket.gethostname(),
            "machine": platform.machine(),
            "system": platform.platform(),
            "cpus": os.cpu_count(),
            "python": sys.version.split()[0],
        },
    }
    with open(Path(out_dir) / "run.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
