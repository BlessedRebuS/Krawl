#!/usr/bin/env python3

"""Download z0–z6 dark basemap tiles for the offline dashboard map.

Run once (build-time, not at container startup) and commit the output::

    python scripts/build_tiles.py

The tiles land in ``src/templates/static/tiles/{z}/{x}/{y}.jpg`` and are
served as static assets by the FastAPI app.  No tile provider, API key, or
network access is needed at runtime — the whole pyramid is bundled.

Source: Esri Canvas World Dark Gray Base (keyless, no watermark).
Each tile is a 256×256 JPEG (~5–8 KB).  The full z0–z6 set is 5 461 tiles
(~40 MB uncompressed, ~15 MB after git compression).
"""

from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

# ── configuration ──────────────────────────────────────────────────────

ZOOM_RANGE = range(7)  # z0–z6

# Esri Canvas World Dark Gray Base — keyless, no watermark.
# Note the y/x order (Esri REST API convention).
TILE_URL = (
    "https://server.arcgisonline.com/ArcGIS/rest/services/"
    "Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
)

# Output lives inside the repo so FastAPI can serve it as a static asset.
OUT_DIR = Path(__file__).resolve().parent.parent / "src" / "templates" / "static" / "tiles"

CONCURRENCY = 6
REQUEST_TIMEOUT = 15  # seconds per tile
DELAY_BETWEEN_BATCHES = 0.05  # seconds — gentle on the CDN

# ── helpers ────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "krawl-build-tiles/1"})


def _download(z: int, x: int, y: int) -> Path:
    dest = OUT_DIR / str(z) / str(x) / f"{y}.jpg"
    if dest.exists():
        return dest

    url = TILE_URL.format(z=z, y=y, x=x)
    resp = SESSION.get(url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(resp.content)
    return dest


def main() -> None:
    total = sum(4**z for z in ZOOM_RANGE)

    print(f"Downloading z0–z6 tiles → {OUT_DIR}")
    print(f"  {total} tiles, concurrency={CONCURRENCY}")

    done = 0
    t0 = time.monotonic()

    work = [(z, x, y) for z in ZOOM_RANGE
            for x in range(2**z) for y in range(2**z)]

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = {}
        for z, x, y in work:
            fut = pool.submit(_download, z, x, y)
            futures[fut] = (z, x, y)
            time.sleep(DELAY_BETWEEN_BATCHES)  # stagger initial submits

        for fut in as_completed(futures):
            z, x, y = futures[fut]
            done += 1
            try:
                fut.result()
            except Exception as exc:
                print(f"  FAIL z{z}/{x}/{y}: {exc}", file=sys.stderr)
                continue

            if done % 100 == 0 or done == total:
                elapsed = time.monotonic() - t0
                rate = done / elapsed if elapsed else 0
                print(f"  {done}/{total}  ({rate:.0f} tiles/s)")

    elapsed = time.monotonic() - t0
    print(f"Done — {done}/{total} tiles in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
