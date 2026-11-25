# SPDX-License-Identifier: MIT
# Copyright (c) 2026 David Malcolm
"""ITC-Benchmarks from SARD -- C standalone suite.

https://samate.nist.gov/SARD/test-suites/104
Download from https://samate.nist.gov/SARD/downloads/test-suites/2016-09-12-itc-benchmarks.zip
sha256sum: 7940a898b8a0159239e1687e5af0a3db220a2b6fdc8811a87d01e4b6a62f6514
and point the config at a directory containing an unzipped copy
e.g.  unzip 2016-09-12-itc-benchmarks.zip -d 2016-09-12-itc-benchmarks-unzipped

The test cases are Copyright (c) 2012-2014 and distributed under the "BSD License."
See Shin''ichi Shiraishi, Veena Mohan,and Hemalatha Marimuthu,
"Test Suites for Benchmarks of Static Analysis Tools,"
IEEE Int''l Symp. on Software ReliabilityEngineering (ISSRE ''15), DOI: 10.1109/ISSREW.2015.7392027,

SARD obtained these from https://github.com/regehr/itc-benchmarks
and seem to have added .sarif files giving ground-truth labelling beyond
what that git repo had.
"""

from __future__ import annotations

import re
import json
from pathlib import Path
from pprint import pprint # FIXME
from typing import List, Optional

from gab.suite import Suite, TestCase, register

class SardSuite(Suite):
    """
    A suite unpacked from one of the archives downloaded from
    https://samate.nist.gov/SARD/test-suites

    Each contains a manifest.sarif which is a JSON object with a
    "testCases" property, an array of objects with properties of the form:
        'download': 'https://samate-internal.nist.gov/SARD/downloads/versions/199251-v1.0.0.zip',
        'identifier': '199251-v1.0.0',
        'link': 'https://samate-internal.nist.gov/SARD/test-cases/199251/versions/1.0.0',
        'sarif': a SARIF log object
    """
    MANIFEST = Path('manifest.sarif')

    def __init__(self, root: Path, options=None):
        super().__init__(root, options)
        self.manifest_path = self.root / self.MANIFEST
        if not self.manifest_path.is_file():
            raise FileNotFoundError(
                f"{self.name}: expected {self.MANIFEST} under {self.root}"
            )
        with open(self.manifest_path) as f:
            self.manifest_js = json.load(f)

    def tests(self) -> List[TestCase]:
        out: List[TestCase] = []
        missing: List[str] = []
        for tc in self.manifest_js['testCases']:
            sarif = tc['sarif']
            for run in sarif['runs']:
                # There are multiple artifacts per testCases entry
                # For now, pick the first one with a .c extension that
                # doesn't have a '_main.c' suffix
                artifact_paths = [Path(artifact['location']['uri'])
                                  for artifact in run['artifacts']
                                  if artifact['sourceLanguage'] == 'c']

                c_files = [p for p in artifact_paths
                           if p.suffix == '.c' and not str(p).endswith('_main.c')]
                if len(c_files) != 1:
                    # FIXME: we don't yet have a good way to handle this
                    continue

                COMPILE_ARGS = ['-std=gnu11',
                                '-Wno-int-conversion'] # for 199275-v1.0.0
                include_files = filter(lambda p: p.suffix == '.h',
                                       artifact_paths)
                include_paths = set([include_file.parent
                                     for include_file in include_files])
                for include_path in include_paths:
                    COMPILE_ARGS += ['-I', str(self.root / include_path)]

                # FIXME: there can be multiple things to test per file
                # how to express this?

                state = run['properties']['state']
                assert state in {'good', 'bad', 'mixed'}
                if state == 'mixed':
                    continue # FIXME: how to handle this

                description = run['properties']['description']
                m = re.match("Defect Type: (.+)", description)
                category = m.group(1)

                cwes = []
                lines = []
                for result in run['results']:
                    m = re.match('CWE-([0-9]+)', result['ruleId'])
                    assert m
                    cwes.append(int(m.group(1)))

                    for location in result['locations']:
                        assert Path(location['physicalLocation']['artifactLocation']['uri']) == c_files[0]
                        line = location['physicalLocation']['region']['startLine']
                        lines.append(line)

                # TODO: looks like each result/location should be
                # handled as an individual "test result" and we
                # want to consider multiple results per invocation
                # of the tool.
                # For now, do them all as one merged TestCase
                out.append(
                    TestCase(
                        suite=self.name,
                        name=tc['identifier'],
                        source=self.root / c_files[0],
                        compile_args=COMPILE_ARGS,
                        vulnerable=(state != 'good'),
                        cwe=cwes[0] if len(cwes) == 1 else None,
                        category=category,
                        lines=lines,
                    )
                )
        return out

    def version(self) -> str:
        # TODO: is there a better string to use for the version?
        return self.manifest_js['creationDate']


@register
class Itc(SardSuite):
    name = "itc"

    def __init__(self, root: Path, options=None):
        super().__init__(root, options)

# TODO: selftest coverage for this
