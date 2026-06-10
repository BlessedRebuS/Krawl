#!/usr/bin/env python3

"""
HTML templates for the deception server.
Templates are loaded from the html/ subdirectory.
"""

import os
from pathlib import Path

from config import get_config
from logger import get_app_logger

from .template_loader import load_template, load_template_from_path

_logged_custom_template_path: str | None = None


def login_form() -> str:
    """Generate fake login page"""
    return load_template("login_form")


def login_error() -> str:
    """Generate fake login error page"""
    return load_template("login_error")


def wordpress() -> str:
    """Generate fake WordPress page"""
    return load_template("wordpress")


def phpmyadmin() -> str:
    """Generate fake phpMyAdmin page"""
    return load_template("phpmyadmin")


def wp_login() -> str:
    """Generate fake WordPress login page"""
    return load_template("wp_login")


def robots_txt() -> str:
    """Generate juicy robots.txt"""
    return load_template("robots.txt")


def directory_listing(path: str, dirs: list, files: list) -> str:
    """Generate fake directory listing"""
    row_template = load_template("directory_row")

    rows = ""
    for d in dirs:
        rows += row_template.format(href=d, name=d, date="2024-12-01 10:30", size="-")

    for f, size in files:
        rows += row_template.format(href=f, name=f, date="2024-12-01 14:22", size=size)

    return load_template("directory_listing", path=path, rows=rows)


def product_search() -> str:
    """Generate product search page with SQL injection honeypot"""
    return load_template("generic_search")


def input_form() -> str:
    """Generate input form page for XSS honeypot"""
    return load_template("input_form")


def main_page(counter: int, content: str) -> str:
    """Generate main Krawl page with links and canary token"""
    # Prefer explicit environment variable, then config.yaml setting
    custom_path = os.environ.get("KRAWL_CUSTOM_TEMPLATE_PATH")
    if not custom_path:
        try:
            cfg = get_config()
            if cfg.custom_template_path:
                custom_path = cfg.custom_template_path
        except Exception:
            custom_path = None

    if custom_path:
        global _logged_custom_template_path
        if _logged_custom_template_path != custom_path:
            get_app_logger().info(f"Using custom template path: {custom_path}")
            _logged_custom_template_path = custom_path
        try:
            return load_template_from_path(custom_path, counter=counter, content=content)
        except Exception:
            # On any failure, fall back to bundled template
            pass

    bundled_template = Path(__file__).parent / "html" / "main_page.html"
    return load_template_from_path(str(bundled_template), counter=counter, content=content)
