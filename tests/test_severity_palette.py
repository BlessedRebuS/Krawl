"""The --sev-<band>-<n> ramp stays legible on --surface and clear of reserved hues."""

import itertools
import math
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CSS = (ROOT / "src/templates/static/css/dashboard.css").read_text()
ROOT_BLOCK = CSS[CSS.index(":root") : CSS.index("}", CSS.index(":root"))]

BANDS = ("critical", "high", "medium", "low")
SHADES = (1, 2, 3, 4)
SURFACE = "#121822"
RESERVED = {"honey": "#ffc94d", "pink": "#f2649f", "accent": "#4da3ff"}

# Machado et al. 2009, severity 1.0, applied to linear sRGB.
CVD = {
    "deuteranopia": ((0.367322, 0.860646, -0.227968), (0.280085, 0.672501, 0.047413), (-0.011820, 0.042940, 0.968881)),
    "protanopia": ((0.152286, 1.052583, -0.204868), (0.114503, 0.786281, 0.099216), (-0.003882, -0.048116, 1.051998)),
}


def token(name):
    m = re.search(rf"--{name}:\s*(#[0-9a-fA-F]{{6}})\s*;", ROOT_BLOCK)
    assert m, f"--{name} missing or not a hex value in :root"
    return m.group(1)


def linear(hexv):
    out = []
    for i in (1, 3, 5):
        c = int(hexv[i : i + 2], 16) / 255
        out.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
    return out


def oklab(rgb):
    r, g, b = rgb
    l = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    return (
        0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
        1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
        0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s,
    )


def delta_e(a, b):
    return 100 * sum((x - y) ** 2 for x, y in zip(a, b)) ** 0.5


def lch(hexv):
    L, a, b = oklab(linear(hexv))
    return L, (a * a + b * b) ** 0.5, math.degrees(math.atan2(b, a)) % 360


def contrast(a, b):
    lum = lambda h: sum(w * c for w, c in zip((0.2126, 0.7152, 0.0722), linear(h)))
    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def simulate(hexv, matrix):
    rgb = linear(hexv)
    return [min(1.0, max(0.0, sum(k * c for k, c in zip(row, rgb)))) for row in matrix]


ALL = [(band, n) for band in BANDS for n in SHADES]


@pytest.mark.parametrize("band,n", ALL)
def test_shade_reads_on_surface(band, n):
    assert contrast(token(f"sev-{band}-{n}"), SURFACE) >= 4.5


@pytest.mark.parametrize("band,n", ALL)
def test_shade_clear_of_reserved_hues(band, n):
    lab = oklab(linear(token(f"sev-{band}-{n}")))
    for name, hexv in RESERVED.items():
        assert delta_e(lab, oklab(linear(hexv))) >= 10, name


@pytest.mark.parametrize("band", BANDS)
def test_adjacent_shades_distinct(band):
    for n in SHADES[:-1]:
        a = oklab(linear(token(f"sev-{band}-{n}")))
        b = oklab(linear(token(f"sev-{band}-{n + 1}")))
        assert delta_e(a, b) >= 4, (band, n)


@pytest.mark.parametrize("n", SHADES)
def test_low_band_not_blue(n):
    assert oklab(linear(token(f"sev-low-{n}")))[2] >= 0


@pytest.mark.parametrize("vision", CVD)
def test_band_anchors_apart_under_cvd(vision):
    labs = {band: oklab(simulate(token(f"sev-{band}-1"), CVD[vision])) for band in BANDS}
    for a, b in itertools.combinations(BANDS, 2):
        assert delta_e(labs[a], labs[b]) >= 8, (vision, a, b)


@pytest.mark.parametrize("band", BANDS)
def test_band_alias_points_at_anchor(band):
    assert re.search(rf"--sev-{band}:\s*var\(--sev-{band}-1\)\s*;", ROOT_BLOCK)


@pytest.mark.parametrize("band", BANDS)
def test_shades_keep_chroma_and_lightness_window(band):
    anchor_l = lch(token(f"sev-{band}-1"))[0]
    floor = 0.035 if band == "low" else 0.10
    for n in SHADES[1:]:
        L, C, _ = lch(token(f"sev-{band}-{n}"))
        assert C >= floor - 0.002, (band, n, C)
        assert abs(L - anchor_l) <= 0.06, (band, n, L)


HUE = {"critical": (15, 32), "high": (45, 70), "medium": (285, 315), "low": (60, 100)}


@pytest.mark.parametrize("band,n", ALL)
def test_shade_hue_window(band, n):
    _, C, H = lch(token(f"sev-{band}-{n}"))
    assert HUE[band][0] <= H <= HUE[band][1], (band, n, H)
    if band == "low":
        assert 0.02 <= C <= 0.05, (n, C)


@pytest.mark.parametrize("band,n", ALL)
def test_shade_closer_to_own_anchor_than_any_other(band, n):
    lab = oklab(linear(token(f"sev-{band}-{n}")))
    own = delta_e(lab, oklab(linear(token(f"sev-{band}-1"))))
    other = min(
        delta_e(lab, oklab(linear(token(f"sev-{o}-1")))) for o in BANDS if o != band
    )
    assert own * 1.5 <= other, (band, n, own, other)
