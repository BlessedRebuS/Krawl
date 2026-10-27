"""Guard against a rule that makes scanning large requests slow.

Locally a 64 KB body scans in about 2 ms with every bundled rule. The budget
is far above that so CI noise cannot fail it, but a pathological regex (which
would cost seconds) still does.
"""

import time
from pathlib import Path

import pytest

from detection import DetectionCoordinator, YaraDetectionEngine

RULES = Path(__file__).resolve().parent.parent / "rules"
BUDGET_SECONDS = 0.25
SIZE = 64 * 1024

BODIES = {
    "prose": " ".join(["lorem", "ipsum", "dolor", "sit", "amet"] * 20000)[:SIZE],
    "repeated_char": "a" * SIZE,
    "slashes": "/a" * (SIZE // 2),
    "form_pairs": "&".join(f"k{i}=v{i}%20x" for i in range(5000))[:SIZE],
    "expression_openers": "${{(#" * (SIZE // 5),
    "near_dropper": "wget http://x " * (SIZE // 14),
}


@pytest.fixture(scope="module")
def detector():
    return DetectionCoordinator(YaraDetectionEngine(RULES))


@pytest.mark.parametrize("name", BODIES)
def test_large_body_scans_within_budget(detector, name):
    body = BODIES[name]

    start = time.perf_counter()
    detector.scan_request(method="POST", path="/submit", body=body)
    elapsed = time.perf_counter() - start

    assert elapsed < BUDGET_SECONDS, f"{name}: {elapsed:.3f}s"


def test_many_large_headers_scan_within_budget(detector):
    headers = [(f"x-h{i}", "a" * 8000) for i in range(64)]

    start = time.perf_counter()
    detector.scan_request(path="/", headers=headers)
    elapsed = time.perf_counter() - start

    assert elapsed < BUDGET_SECONDS, f"{elapsed:.3f}s"
