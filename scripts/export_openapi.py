"""Write the Dashboard API schema to docs/api/openapi.json for the docs site.

Run after changing an /api route: python scripts/export_openapi.py
tests/test_openapi_export.py fails while the committed file is stale.
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "api" / "openapi.json"
PLACEHOLDER = "/<DASHBOARD-PATH>"


def schema() -> dict:
    os.environ["KRAWL_DASHBOARD_SECRET_PATH"] = PLACEHOLDER
    sys.path.insert(0, str(ROOT / "src"))
    from app import create_app

    result = create_app().openapi()
    # The app reads its version from a Chart.yaml next to src/, which only
    # exists in the image; the repo's copy is under helm/.
    chart = (ROOT / "helm" / "Chart.yaml").read_text()
    result["info"]["version"] = next(
        line.split(":", 1)[1].strip() for line in chart.splitlines() if line.startswith("appVersion:")
    )
    return result


if __name__ == "__main__":
    OUT.write_text(json.dumps(schema(), indent=2) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}")
