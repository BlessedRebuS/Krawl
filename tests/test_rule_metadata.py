import re
from pathlib import Path

import pytest

from detection import YaraDetectionEngine

RULES = Path(__file__).resolve().parent.parent / "rules"

BUNDLED_REQUIRED = {
    "attack_type",
    "classification",
    "severity",
    "confidence",
    "description",
    "mitre_attack",
    "version",
    "date",
    "modified",
    "author",
    "false_positives",
}
NAME = re.compile(r"^krawl_[a-z0-9_]+$")
MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _bundled_rules():
    engine = YaraDetectionEngine(RULES)
    collected = []

    def collect(rule):
        collected.append(rule)
        return engine._yara.CALLBACK_CONTINUE

    engine.rules.match(
        data=b"",
        callback=collect,
        which_callbacks=engine._yara.CALLBACK_ALL,
        externals={"scan_target": "metadata_validation", "http_method": "GET"},
    )
    return collected


def _write(tmp_path, meta, name="custom", fname="custom.yar"):
    (tmp_path / fname).write_text(
        f'rule {name} {{ meta: attack_type = "x" classification = "attack" '
        f"severity = 5 {meta} "
        'strings: $a = "needle-text" condition: $a }',
        encoding="utf-8",
    )


def test_bundled_rules_meet_the_full_schema():
    rules = _bundled_rules()
    assert rules
    problems = []
    for rule in rules:
        meta = rule["meta"]
        name = rule["rule"]
        missing = BUNDLED_REQUIRED - set(meta)
        if missing:
            problems.append(f"{name}: missing {sorted(missing)}")
            continue
        if not NAME.match(name):
            problems.append(f"{name}: bad name")
        if meta["confidence"] not in {"high", "medium", "low"}:
            problems.append(f"{name}: confidence")
        if not 1 <= meta["severity"] <= 10:
            problems.append(f"{name}: severity range")
        if len(meta["attack_type"]) > 50:
            problems.append(f"{name}: attack_type too long")
        if not all(MITRE.match(x.strip()) for x in meta["mitre_attack"].split(",")):
            problems.append(f"{name}: mitre_attack")
        if not (DATE.match(meta["date"]) and DATE.match(meta["modified"])):
            problems.append(f"{name}: dates")
        if not meta["description"].strip() or not meta["false_positives"].strip():
            problems.append(f"{name}: empty text")
        if name.startswith("krawl_cve_"):
            if not all(CVE.match(x.strip()) for x in meta.get("cve", "").split(",")):
                problems.append(f"{name}: cve")
            if not meta.get("reference", "").startswith("http"):
                problems.append(f"{name}: reference")
    assert not problems, "\n".join(problems)


def test_rule_names_are_unique_across_bundled_files():
    names = [rule["rule"] for rule in _bundled_rules()]
    assert len(names) == len(set(names))


@pytest.mark.parametrize(
    "meta, message",
    [
        ('confidence = "certain"', "confidence"),
        ('mitre_attack = "1190"', "mitre_attack"),
        ('mitre_attack = "T1190, T1059.99"', "mitre_attack"),
        ('date = "26/10/2026"', "date"),
        ('modified = "2026-13-45x"', "modified"),
        ('cve = "CVE-21-1"', "cve"),
        ('cve = "CVE-2021-44228, nope"', "cve"),
        ('response_type = "does_not_exist"', "response_type"),
        ("confidence = 1", "confidence"),
    ],
)
def test_invalid_optional_metadata_is_rejected(tmp_path, meta, message):
    _write(tmp_path, meta)

    with pytest.raises(RuntimeError, match=message):
        YaraDetectionEngine(tmp_path, known_response_types={"sql_error"})


def test_attack_type_longer_than_column_is_rejected(tmp_path):
    (tmp_path / "long.yar").write_text(
        f'rule long_one {{ meta: attack_type = "{"a" * 51}" '
        'classification = "attack" severity = 5 '
        'strings: $a = "needle-text" condition: $a }',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="attack_type"):
        YaraDetectionEngine(tmp_path)


def test_severity_out_of_range_is_rejected(tmp_path):
    (tmp_path / "sev.yar").write_text(
        'rule sev { meta: attack_type = "x" classification = "attack" '
        'severity = 11 strings: $a = "needle-text" condition: $a }',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="severity"):
        YaraDetectionEngine(tmp_path)


def test_valid_optional_metadata_is_accepted(tmp_path):
    _write(
        tmp_path,
        'confidence = "high" mitre_attack = "T1190, T1059.004" '
        'date = "2026-10-26" modified = "2026-10-26" '
        'cve = "CVE-2021-44228, CVE-2022-1234" response_type = "sql_error"',
    )

    YaraDetectionEngine(tmp_path)


def test_duplicate_rule_names_across_files_are_rejected(tmp_path):
    _write(tmp_path, "", name="same_name", fname="a.yar")
    _write(tmp_path, "", name="same_name", fname="b.yar")

    with pytest.raises(RuntimeError, match="same_name"):
        YaraDetectionEngine(tmp_path)
