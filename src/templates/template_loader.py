#!/usr/bin/env python3

"""
Template loader for HTML templates.
Loads templates from the html/ subdirectory and supports string formatting for dynamic content.
"""

from pathlib import Path
from typing import Dict


class TemplateNotFoundError(Exception):
    """Raised when a template file cannot be found."""

    pass


# Module-level cache for loaded templates
_template_cache: Dict[str, str] = {}

# Base directory for template files
_TEMPLATE_DIR = Path(__file__).parent / "html"


def load_template(name: str, **kwargs) -> str:
    """
    Load a template by name and optionally substitute placeholders.

    Args:
        name: Template name (without extension for HTML, with extension for others like .txt)
        **kwargs: Key-value pairs for placeholder substitution using str.format()

    Returns:
        Rendered template string

    Raises:
        TemplateNotFoundError: If template file doesn't exist

    Example:
        >>> load_template("login_form")  # Loads html/login_form.html
        >>> load_template("robots.txt")  # Loads html/robots.txt
        >>> load_template("directory_listing", path="/var/www", rows="<tr>...</tr>")
    """
    # debug
    # print(f"Loading Template: {name}")

    # Check cache first
    if name not in _template_cache:
        # Determine file path based on whether name has an extension
        if "." in name:
            file_path = _TEMPLATE_DIR / name
        else:
            file_path = _TEMPLATE_DIR / f"{name}.html"

        if not file_path.exists():
            raise TemplateNotFoundError(f"Template '{name}' not found at {file_path}")

        _template_cache[name] = file_path.read_text(encoding="utf-8")

    template = _template_cache[name]

    # Apply substitutions if kwargs provided
    if kwargs:
        template = template.format(**kwargs)
    return template


def clear_cache() -> None:
    """Clear the template cache. Useful for testing or development."""
    _template_cache.clear()
