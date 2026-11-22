# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
# SPDX-FileContributor: Claude Opus 5 (Anthropic), AI assistant
"""Compiler introspection: configure parsing, build classification, ELF."""

import tempfile
import unittest
from pathlib import Path

from gab import toolchain
from gab.diff import _revision_skew, _target_arch


class TestParseConfigure(unittest.TestCase):
    def test_distro_build(self):
        v = ("Target: x86_64-redhat-linux\n"
             "Configured with: ../configure --enable-bootstrap "
             "--enable-checking=release --build=x86_64-redhat-linux\n")
        info = toolchain._parse_configure(v)
        self.assertEqual(info["checking"], "release")
        self.assertEqual(info["build"], "x86_64-redhat-linux")
        self.assertTrue(info["bootstrap"])

    def test_local_build_without_checking_argument(self):
        v = ("Configured with: ../src/configure --disable-bootstrap "
             "--enable-languages=c,c++\n")
        info = toolchain._parse_configure(v)
        self.assertIsNone(info.get("checking"))
        self.assertFalse(info["bootstrap"])

    def test_bare_enable_and_disable_checking(self):
        self.assertEqual(
            toolchain._parse_configure(
                "Configured with: c --enable-checking")["checking"], "yes")
        self.assertEqual(
            toolchain._parse_configure(
                "Configured with: c --disable-checking")["checking"], "none")


class TestClassifyBuild(unittest.TestCase):
    def test_fchecking_drives_the_label(self):
        self.assertEqual(toolchain._classify_build(0, "release"), "release")
        self.assertEqual(toolchain._classify_build(1, None), "checking")
        self.assertEqual(toolchain._classify_build(2, None),
                         "checking+extra")

    def test_assertions_are_on_unless_explicitly_disabled(self):
        """install.texi: `release` is assert,runtime -- assertions stay
        enabled, so only an explicit no/none may claim otherwise."""
        self.assertEqual(toolchain._classify_build(0, "release"), "release")
        self.assertNotIn("no-assert",
                         toolchain._classify_build(0, "release"))
        self.assertIn("no-assert", toolchain._classify_build(0, "no"))

    def test_falls_back_to_configure_when_binary_cannot_answer(self):
        self.assertEqual(toolchain._classify_build(None, "release"),
                         "release?")
        self.assertEqual(toolchain._classify_build(None, "yes"),
                         "checking?")
        self.assertEqual(toolchain._classify_build(None, None), "unknown")


class TestElfSections(unittest.TestCase):
    def test_detects_debug_info_in_a_real_binary(self):
        import sys
        names = toolchain._elf_section_names(Path(sys.executable))
        if names is None:
            self.skipTest("python is not a 64-bit ELF here")
        self.assertIn(".text", names)

    def test_non_elf_returns_none(self):
        p = Path(tempfile.mkdtemp()) / "x"
        p.write_bytes(b"not an elf at all")
        self.assertIsNone(toolchain._elf_section_names(p))

    def test_missing_file_returns_none(self):
        self.assertIsNone(toolchain._elf_section_names(Path("/no/such")))


class TestRevisionSkew(unittest.TestCase):
    def _t(self, descr):
        return {"git": {"gcc_descr": descr}} if descr else {}

    def test_distance_is_reported(self):
        msg = _revision_skew(self._t("r17-6534-gabc"),
                             self._t("r17-6305-gdef"))
        self.assertIn("229 trunk revisions apart", msg)

    def test_same_revision_is_silent(self):
        self.assertIsNone(_revision_skew(self._t("r17-6534-gabc"),
                                         self._t("r17-6534-gabc")))

    def test_major_version_difference(self):
        msg = _revision_skew(self._t("r16-100-gabc"), self._t("r17-1-gdef"))
        self.assertIn("major versions", msg)

    def test_missing_revision_is_silent(self):
        self.assertIsNone(_revision_skew(self._t(None),
                                         self._t("r17-1-gdef")))


class TestTargetArch(unittest.TestCase):
    def test_same_arch_different_spelling(self):
        a = _target_arch({"target": "x86_64-redhat-linux"})
        b = _target_arch({"target": "x86_64-pc-linux-gnu"})
        self.assertEqual(a, b)

    def test_different_arch(self):
        self.assertNotEqual(_target_arch({"target": "aarch64-linux-gnu"}),
                            _target_arch({"target": "x86_64-linux-gnu"}))

    def test_missing_target(self):
        self.assertIsNone(_target_arch({}))


class TestToolchainConfig(unittest.TestCase):
    def test_build_dir_form_adds_dash_capital_b(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "xgcc").write_text("#!/bin/sh\n")
        tc = toolchain.Toolchain.from_config("t", {"build_dir": str(tmp)})
        self.assertEqual(tc.argv[0], str(tmp / "xgcc"))
        self.assertTrue(tc.argv[1].startswith("-B"))

    def test_missing_compiler_raises(self):
        with self.assertRaises(FileNotFoundError):
            toolchain.Toolchain.from_config("t", {"cc": "/no/such/gcc"})

    def test_needs_cc_or_build_dir(self):
        with self.assertRaises(ValueError):
            toolchain.Toolchain.from_config("t", {})

    def test_env_is_locale_stable(self):
        tc = toolchain.Toolchain("t", ["/bin/true"])
        self.assertEqual(tc.env()["LC_ALL"], "C")
        self.assertNotIn("GCC_COLORS", tc.env())


if __name__ == "__main__":
    unittest.main()
