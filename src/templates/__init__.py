#!/usr/bin/env python3

"""
Templates package for the deception server.
"""

from . import html_templates
from .template_loader import TemplateNotFoundError, clear_cache, load_template

__all__ = [
    "load_template",
    "clear_cache",
    "TemplateNotFoundError",
    "html_templates",
]
