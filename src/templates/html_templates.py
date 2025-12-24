#!/usr/bin/env python3

"""
HTML templates for the deception server.
Templates are loaded from the html/ subdirectory.
"""

from .template_loader import load_template


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
