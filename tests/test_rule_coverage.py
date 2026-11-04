"""Report which rule patterns the fake attack corpus exercises.

A rule that no sample triggers fails the test, since it is unverified. A single
uncovered pattern only appears in the printed report (run with -s to see it),
because rules often hold several alternative encodings of one indicator.
"""

import sys
import urllib.parse
from pathlib import Path

import pytest

from detection import DetectionCoordinator, YaraDetectionEngine, declared_string_ids

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from fake_attacks import ATTACKS, BENIGN  # noqa: E402

RULES = Path(__file__).resolve().parent.parent / "rules"


def declared_patterns() -> dict[str, list[str]]:
    return {name: sorted(ids) for name, ids in declared_string_ids(RULES).items()}


def matched_patterns(detector: DetectionCoordinator) -> set[str]:
    """Every rule and rule.$pattern hit by any sample, scanned like real traffic."""
    engine = detector.yara
    hit = set()
    for item in ATTACKS + BENIGN:
        method = item.method
        for target, header_name, value in detector.scan_inputs(
            path=urllib.parse.unquote(item.path),
            query=item.query,
            body=item.body,
            user_agent=item.user_agent,
            headers=[(k.lower(), v) for k, v in item.headers.items()],
        ):
            if not value:
                continue
            matches = engine.rules.match(
                data=value.encode("utf-8", errors="replace"),
                externals={
                    "scan_target": target,
                    "http_method": method,
                    "header_name": header_name,
                },
            )
            for match in matches:
                hit.add(match.rule)
                for string_match in match.strings:
                    hit.add(f"{match.rule}.{string_match.identifier}")
    return hit


@pytest.fixture(scope="module")
def coverage():
    detector = DetectionCoordinator(YaraDetectionEngine(RULES))
    declared = declared_patterns()
    hit = matched_patterns(detector)
    return declared, hit


def test_pattern_parser_finds_every_compiled_rule(coverage):
    declared, _ = coverage
    detector = DetectionCoordinator(YaraDetectionEngine(RULES))
    import yara

    compiled = []

    def collect(rule):
        compiled.append(rule["rule"])
        return yara.CALLBACK_CONTINUE

    detector.yara.rules.match(
        data=b"",
        callback=collect,
        which_callbacks=yara.CALLBACK_ALL,
        externals={"scan_target": "", "http_method": "", "header_name": ""},
    )

    assert sorted(declared) == sorted(compiled)


def test_every_rule_is_triggered_by_a_fake_attack(coverage):
    declared, hit = coverage
    uncovered_rules = [name for name in declared if name not in hit]

    assert uncovered_rules == []


def test_pattern_coverage_report(coverage, capsys):
    declared, hit = coverage
    total = sum(len(patterns) for patterns in declared.values())
    uncovered = [
        f"{name}.{pattern}"
        for name, patterns in declared.items()
        for pattern in patterns
        if f"{name}.{pattern}" not in hit
    ]
    with capsys.disabled():
        print(
            f"\nPattern coverage: {total - len(uncovered)}/{total} "
            f"across {len(declared)} rules"
        )
        for entry in uncovered:
            print(f"  uncovered: {entry}")

    assert total > 0
