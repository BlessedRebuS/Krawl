#!/usr/bin/env python3

"""
The trap maze page shell.

The bundled shell is responses/trap/main_page.html, loaded with the response
catalogue. Placeholders are substituted with plain string replacement (not
str.format) because the shell contains literal braces in CSS and JS.
"""

from pathlib import Path

from logger import get_app_logger

_logged_custom_template_path: str | None = None


def _substitute(text: str, values: dict) -> str:
    for k, v in values.items():
        text = text.replace(f"{{{k}}}", str(v))
    return text


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

    from detection import get_response_catalog

    return _substitute(
        get_response_catalog().trap_template, {"counter": counter, "content": content}
    )
