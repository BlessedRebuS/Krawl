"""Attack type -> severity band + stable shade, for CSS badges, charts and JSON APIs."""

import zlib
from collections.abc import Iterable

import detection


def attack_band(attack_type: str) -> str:
    coordinator = detection.loaded_detection()
    if coordinator is None or not attack_type:
        return "low"
    band = detection.severity_band(
        coordinator.attack_type_severity(str(attack_type).strip())
    )
    return "low" if band == "unknown" else band


def attack_shade(attack_type: str) -> int:
    return zlib.crc32(attack_type.strip().lower().encode()) % 4 + 1


def attack_colour(attack_type: str) -> dict:
    return {"band": attack_band(attack_type), "shade": attack_shade(attack_type)}


def colour_map(attack_types: Iterable[str]) -> dict:
    return {t: attack_colour(t) for t in attack_types}


def attack_badge_class(attack_type: str) -> str:
    c = attack_colour(attack_type)
    return f"atk-badge atk-sev-{c['band']} atk-shade-{c['shade']}"
