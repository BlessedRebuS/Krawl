#!/usr/bin/env python3

"""
HTML template loading for the deception server.

Templates live in the html/ subdirectory and are cached after first read.
Placeholders are substituted with plain string replacement (not str.format)
because template bodies contain literal braces in CSS and JS.
"""

from pathlib import Path

from logger import get_app_logger

_TEMPLATE_DIR = Path(__file__).parent / "html"
_cache: dict[str, str] = {}
_logged_custom_template_path: str | None = None


def load_template(name: str, **kwargs) -> str:
    """Load html/<name>.html (or html/<name> if it has an extension) and
    substitute {key} placeholders for each kwarg.

    Raises:
        FileNotFoundError: if the template file does not exist.
    """
    if name not in _cache:
        path = _TEMPLATE_DIR / (name if "." in name else f"{name}.html")
        _cache[name] = path.read_text(encoding="utf-8")
    return _substitute(_cache[name], kwargs)


def _substitute(text: str, values: dict) -> str:
    for k, v in values.items():
        text = text.replace(f"{{{k}}}", str(v))
    return text


def directory_listing(path: str, dirs: list, files: list) -> str:
    """Generate fake directory listing"""
    row = load_template("directory_row")
    rows = "".join(
        _substitute(
            row, {"href": d, "name": d, "date": "2024-12-01 10:30", "size": "-"}
        )
        for d in dirs
    )
    rows += "".join(
        _substitute(
            row, {"href": f, "name": f, "date": "2024-12-01 14:22", "size": size}
        )
        for f, size in files
    )
    return load_template("directory_listing", path=path, rows=rows)


def main_page(counter: int, content: str) -> str:
    """Generate main Krawl page with links and canary token.

    Uses the operator's custom template when configured (KRAWL_CUSTOM_TEMPLATE_PATH
    or page_template.custom_template_path), falling back to the bundled page.
    """
    import os

    from config import get_config

    custom_path = os.environ.get("KRAWL_CUSTOM_TEMPLATE_PATH")
    if not custom_path:
        try:
            custom_path = get_config().custom_template_path
        except Exception:
            custom_path = None

    if custom_path:
        global _logged_custom_template_path
        if _logged_custom_template_path != custom_path:
            get_app_logger().info(f"Using custom template path: {custom_path}")
            _logged_custom_template_path = custom_path
        try:
            text = Path(custom_path).read_text(encoding="utf-8")
            return _substitute(text, {"counter": counter, "content": content})
        except Exception as err:
            get_app_logger().debug(
                f"Custom template load failed, using bundled template: {err}"
            )

    return load_template("main_page.html", counter=counter, content=content)
