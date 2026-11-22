# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""A GCC under test, and how to identify it precisely.

Two shapes are supported:

  installed    a gcc on PATH or at an absolute path
  build dir    an uninstalled build, driven as `xgcc -B<builddir>/`

Identity matters more than it looks.  When validating a patch, the
baseline and the patched compiler are usually the *same* build directory
at two different times: `xgcc --version` is byte-identical for both.  So
`identity()` also hashes the cc1 binary actually used, and records the
git revision of the source tree.  Two runs whose `identity` differs are
genuinely different compilers; two whose identity matches are not.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


def _run(argv: List[str], env: Optional[dict] = None, timeout: int = 60) -> str:
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, env=env
        )
        return p.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _run_combined(argv: List[str], env: Optional[dict] = None,
                  timeout: int = 60) -> str:
    """Like _run, but `gcc -v` writes its configure line to stderr."""
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, env=env
        )
        return (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def _gcc_descr(src_dir: Path) -> Optional[str]:
    """GCC's own revision naming, e.g. 'r17-6534-gf50574b9c3e37c'.

    Produces the same string as GCC's contrib/git-descr.sh, but is an
    independent implementation of that naming convention rather than a
    translation of the script: we invoke git directly instead of running
    a script out of the source tree under test, which also works when
    contrib/ is absent.  Only the convention itself is shared -- the
    `basepoints/gcc-*` tag scheme and the r<major>-<count>-g<hash> form.

    (Noted because contrib/git-descr.sh is GPLv3 and this project is
    MIT: no code is taken from it.)
    """
    out = _run([
        "git", "-C", str(src_dir), "describe", "--all", "--abbrev=14",
        "--match", "basepoints/gcc-[0-9]*", "HEAD",
    ])
    if not out:
        return None
    out = re.sub(r"^tags/", "", out.strip())
    m = re.match(r"^basepoints/gcc-(.+)$", out)
    if not m:
        return None
    descr = "r" + m.group(1)
    if re.fullmatch(r"r\d+", descr):
        head = _run(["git", "-C", str(src_dir), "rev-parse", "HEAD"])
        descr = f"{descr}-0-g{head}" if head else descr
    return descr


def _sha256(path: Path, limit: int = 512 * 1024 * 1024) -> Optional[str]:
    try:
        h = hashlib.sha256()
        read = 0
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                read += len(chunk)
                if read > limit:
                    return None
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _elf_section_names(path: Path):
    """Section names of an ELF file, or None if it isn't one.

    Used only to tell whether cc1 carries debug info.  Parsing ~30 bytes
    of header by hand beats shelling out to readelf and keeps the "no
    dependencies" promise.
    """
    try:
        with open(path, "rb") as f:
            hdr = f.read(64)
            if len(hdr) < 64 or hdr[:4] != b"\x7fELF":
                return None
            is64 = hdr[4] == 2
            little = hdr[5] == 1
            if not is64:
                return None  # only 64-bit hosts are in scope
            bo = "little" if little else "big"

            def u(off, size):
                return int.from_bytes(hdr[off:off + size], bo)

            e_shoff = u(0x28, 8)
            e_shentsize = u(0x3A, 2)
            e_shnum = u(0x3C, 2)
            e_shstrndx = u(0x3E, 2)
            if not e_shoff or not e_shnum or e_shstrndx >= e_shnum:
                return None

            f.seek(e_shoff + e_shstrndx * e_shentsize)
            sh = f.read(e_shentsize)
            strtab_off = int.from_bytes(sh[0x18:0x20], bo)
            strtab_size = int.from_bytes(sh[0x20:0x28], bo)
            if strtab_size > 1 << 20:
                return None
            f.seek(strtab_off)
            strtab = f.read(strtab_size)

            names = []
            for i in range(e_shnum):
                f.seek(e_shoff + i * e_shentsize)
                sh = f.read(e_shentsize)
                if len(sh) < 8:
                    break
                n = int.from_bytes(sh[0:4], bo)
                end = strtab.find(b"\0", n)
                names.append(strtab[n:end].decode("ascii", "replace"))
            return names
    except OSError:
        return None


def _parse_configure(verbose_output: str) -> dict:
    """Pull build facts out of `gcc -v`'s 'Configured with:' line."""
    info: dict = {}
    for line in verbose_output.splitlines():
        line = line.strip()
        if line.startswith("Target:"):
            info["target_from_v"] = line.split(":", 1)[1].strip()
        elif line.startswith("Configured with:"):
            args = line.split(":", 1)[1].strip()
            info["configure_args"] = args
            for tok in args.split():
                for key in ("--build=", "--host=", "--target="):
                    if tok.startswith(key):
                        info[key.strip("-=")] = tok[len(key):]
                if tok.startswith("--enable-checking="):
                    info["checking"] = tok[len("--enable-checking="):]
                elif tok == "--enable-checking":
                    info["checking"] = "yes"
                elif tok == "--disable-checking":
                    info["checking"] = "none"
                if tok in ("--disable-bootstrap", "--enable-bootstrap"):
                    info["bootstrap"] = tok.startswith("--enable")
    return info


def query_fchecking(argv: List[str], env: Optional[dict] = None) -> Optional[int]:
    """The compiler's own value of -fchecking, via `-Q --help=common`.

    This reports what the binary actually does, rather than what
    configure was asked for.  That matters because the default is not
    fixed: per install.texi it depends on context, with release branches
    and release archives defaulting to `release` and other builds to
    `yes,extra`.  So neither the version banner nor the absence of an
    --enable-checking argument can be read as "release".

    Values follow the misc/extra checking categories: 0 for the `release`
    set, 1 for `yes`, 2 for `yes,extra`.
    """
    out = _run_combined(argv + ["-Q", "--help=common"], env=env)
    m = re.search(r"^\s*-fchecking=\s+(\d+)\s*$", out, re.MULTILINE)
    if m:
        return int(m.group(1))
    # Older compilers print only the boolean form.
    m = re.search(r"^\s*-fchecking\s+\[(enabled|disabled)\]", out, re.MULTILINE)
    if m:
        return 1 if m.group(1) == "enabled" else 0
    return None


#: -fchecking values, per gcc/doc/install.texi's --enable-checking.
#: The flag tracks the misc/extra checking categories, so 0 corresponds
#: to the `release` set and 2 to trunk's `yes,extra` default.
_FCHECKING_LABEL = {
    0: "release",      # assert,runtime only
    1: "checking",     # --enable-checking=yes
    2: "checking+extra",  # yes,extra -- the default for a development build
}


def _classify_build(fchecking, checking_arg) -> str:
    """How much internal consistency checking this compiler does.

    Note that this is *not* "assertions on vs off".  Per install.texi,
    `release` checking is `assert,runtime`: assertions stay enabled in a
    release build, and only an explicit --disable-checking (or
    --enable-checking=no) turns them off.  So an ICE from a tripped
    assertion is possible in any of these builds; what varies is the
    expensive checking (misc, gc, gimple, rtlflag, tree, types, extra)
    and hence the speed.

    The default is context-dependent -- bootstrap stage 1 uses `yes`,
    release branches and release archives use `release`, everything else
    uses `yes,extra` -- which is why this is read back off the binary
    rather than inferred from the version or the configure line.
    """
    if fchecking is None:
        # No runtime answer available (very old GCC): fall back to what
        # configure was told, and mark it as a guess.
        if checking_arg is None:
            return "unknown"
        return "release?" if checking_arg in ("release", "none") else "checking?"
    label = _FCHECKING_LABEL.get(fchecking, f"checking({fchecking})")
    # Only an explicit request turns assertions off.
    if checking_arg in ("no", "none"):
        label += ",no-assert"
    return label


@dataclass
class Toolchain:
    name: str
    argv: List[str]
    """Base command, e.g. ['/usr/bin/gcc'] or ['.../xgcc', '-B.../']."""

    src_dir: Optional[Path] = None
    """GCC source tree, if this is a build-dir toolchain.  Used for
    provenance only."""

    env_overrides: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_config(cls, name: str, cfg: dict) -> "Toolchain":
        env_overrides = dict(cfg.get("env") or {})
        extra = list(cfg.get("extra_args") or [])
        src_dir = cfg.get("src_dir")

        if "build_dir" in cfg:
            build_dir = Path(os.path.expandvars(cfg["build_dir"])).expanduser()
            xgcc = build_dir / "xgcc"
            if not xgcc.is_file():
                raise FileNotFoundError(
                    f"toolchain {name!r}: no xgcc in {build_dir}"
                )
            argv = [str(xgcc), f"-B{build_dir}{os.sep}"]
        elif "cc" in cfg:
            cc = cfg["cc"]
            cc = [cc] if isinstance(cc, str) else list(cc)
            cc = [os.path.expandvars(os.path.expanduser(c)) for c in cc]
            if not Path(cc[0]).is_file():
                raise FileNotFoundError(
                    f"toolchain {name!r}: no such compiler {cc[0]}"
                )
            argv = cc
        else:
            raise ValueError(
                f"toolchain {name!r}: needs either 'cc' or 'build_dir'"
            )

        return cls(
            name=name,
            argv=argv + extra,
            src_dir=Path(os.path.expandvars(src_dir)).expanduser() if src_dir else None,
            env_overrides=env_overrides,
        )

    def env(self) -> Dict[str, str]:
        e = dict(os.environ)
        e.update(self.env_overrides)
        # Keep diagnostics machine-stable regardless of the invoking shell.
        e["LC_ALL"] = "C"
        e.pop("GCC_COLORS", None)
        return e

    # -- identity --------------------------------------------------------

    def identity(self) -> dict:
        env = self.env()
        version_out = _run(self.argv + ["--version"], env=env)
        verbose = _run_combined(self.argv + ["-v"], env=env)
        conf = _parse_configure(verbose)

        ident = {
            "name": self.name,
            "argv": list(self.argv),
            "version": version_out.splitlines()[0] if version_out else None,
            "dumpversion": _run(self.argv + ["-dumpversion"], env=env) or None,
            "target": (_run(self.argv + ["-dumpmachine"], env=env)
                       or conf.get("target") or conf.get("target_from_v")),
            # A native build names neither --host nor --build; in that
            # case host == target by definition.
            "host": (conf.get("host") or conf.get("build")
                     or _run(self.argv + ["-dumpmachine"], env=env) or None),
            "build": conf.get("build"),
            "checking": conf.get("checking"),
            "fchecking": query_fchecking(self.argv, env),
            "bootstrap": conf.get("bootstrap"),
            "configure_args": conf.get("configure_args"),
        }

        cc1 = _run(self.argv + ["-print-prog-name=cc1"], env=env)
        has_debug_info = None
        if cc1 and Path(cc1).is_file():
            p = Path(cc1)
            st = p.stat()
            sections = _elf_section_names(p)
            if sections is not None:
                # Not a build-type signal (use fchecking for that).  It
                # tells you whether a crash from this cc1 will produce a
                # usable backtrace, which is what you want to know the
                # moment the runner reports an ICE.
                has_debug_info = any(s.startswith(".debug_") for s in sections)
            ident["cc1"] = {
                "path": str(p),
                "size": st.st_size,
                "mtime": st.st_mtime,
                "has_debug_info": has_debug_info,
                # The one field that distinguishes a patched build from its
                # baseline when the version string cannot.
                "sha256": _sha256(p),
            }
        else:
            ident["cc1"] = None

        ident["build_type"] = _classify_build(
            ident["fchecking"], conf.get("checking")
        )

        if self.src_dir and (self.src_dir / ".git").exists():
            d = str(self.src_dir)
            ident["git"] = {
                "src_dir": d,
                "head": _run(["git", "-C", d, "rev-parse", "HEAD"]) or None,
                "branch": _run(["git", "-C", d, "rev-parse", "--abbrev-ref", "HEAD"]) or None,
                "describe": _run(["git", "-C", d, "describe", "--always", "--dirty"]) or None,
                "dirty": bool(_run(["git", "-C", d, "status", "--porcelain"])),
                # GCC's own human-readable revision form, e.g. r17-6534-g<hash>.
                "gcc_descr": _gcc_descr(self.src_dir),
            }
        return ident


def load_toolchains(cfg: dict) -> Dict[str, dict]:
    return cfg.get("toolchains") or {}
