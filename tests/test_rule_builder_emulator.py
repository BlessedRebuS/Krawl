"""The docs rule builder's YARA emulator (docs/javascripts/yara-lite.js) agrees
with real YARA: every bundled rule parses cleanly, and a fifth of the fake attack
corpus fires exactly the rules Krawl's engine fires (the whole corpus takes the
emulator about 20s). Skipped without Node.
"""

import json
import shutil
import subprocess
import sys
import urllib.parse
from pathlib import Path

import pytest

from detection import DetectionCoordinator, YaraDetectionEngine

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from fake_attacks import ATTACKS, BENIGN  # noqa: E402

NODE = shutil.which("node")

CHECK = r"""
const fs = require("fs");
const Y = require(process.argv[1]);
const [rulesDir, fixtures] = process.argv.slice(2);
const rules = [], problems = [];
for (const f of fs.readdirSync(rulesDir).filter((f) => /\.yara?$/.test(f))) {
  const r = Y.parse(fs.readFileSync(`${rulesDir}/${f}`, "utf8"));
  rules.push(...r.rules);
  problems.push(...[...r.errors, ...r.warnings].map((p) => `${f}:${p.line} ${p.message}`));
}
const wrong = [];
for (const c of JSON.parse(fs.readFileSync(fixtures))) {
  const req = { method: c.method, fields: c.fields.map(([t, h, v]) => ({ target: t, header: h, values: [v] })) };
  const got = [...new Set(Y.scan(rules, req).map((x) => x.rule))].sort();
  if (JSON.stringify(got) !== JSON.stringify(c.rules)) wrong.push({ name: c.name, want: c.rules, got });
}
console.log(JSON.stringify({ rules: rules.length, problems, wrong: wrong.slice(0, 10) }));
"""


@pytest.mark.skipif(not NODE, reason="node is not installed")
def test_emulator_matches_real_yara(tmp_path):
    detector = DetectionCoordinator(YaraDetectionEngine(ROOT / "rules"))
    cases = []
    for item in (ATTACKS + BENIGN)[::5]:
        headers = {"host": "honeypot.test", **{k.lower(): v for k, v in item.headers.items()}}
        args = dict(
            path=urllib.parse.unquote(item.path),
            query=item.query,
            body=item.body,
            user_agent=item.user_agent,
            headers=headers.items(),
        )
        cases.append(
            {
                "name": item.name,
                "method": item.method,
                "fields": [[t, h or "", v] for t, h, v in detector.scan_inputs(**args)],
                "rules": sorted({f.rule_name for f in detector.iter_findings(method=item.method, **args)}),
            }
        )
    fixtures = tmp_path / "cases.json"
    fixtures.write_text(json.dumps(cases))

    out = subprocess.run(  # noqa: S603 -- fixed arguments, our own script
        [NODE, "-e", CHECK, str(ROOT / "docs/javascripts/yara-lite.js"), str(ROOT / "rules"), str(fixtures)],
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    )
    result = json.loads(out.stdout)

    assert result["problems"] == []
    assert result["wrong"] == []
    assert result["rules"] > 3000
