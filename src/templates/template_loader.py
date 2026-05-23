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
        try:
            template = template.format(**kwargs)
        except Exception:
            # If formatting fails, return template unchanged (do not validate placeholders)
            pass
    return template


def load_template_from_path(file_path: str, **kwargs) -> str:
    """
    Load a template from an absolute or relative file path and perform
    non-strict placeholder substitution. Replaces occurrences of
    `{key}` with the provided value for each kwarg. If the file does
    not exist or cannot be read, raises FileNotFoundError.

    This function deliberately does not validate that placeholders
    like `{counter}` or `{content}` are present; it performs simple
    replacements and returns the file contents even if placeholders
    are missing.
    """
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Template file not found: {file_path}")

    text = p.read_text(encoding="utf-8")

    # Perform safe replacements without raising KeyError
    for k, v in kwargs.items():
        text = text.replace(f"{{{k}}}", str(v))

    return text


def clear_cache() -> None:
    """Clear the template cache. Useful for testing or development."""
    _template_cache.clear()
