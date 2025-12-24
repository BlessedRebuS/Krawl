#!/usr/bin/env python3

"""
Templates package for the deception server.
"""

from .template_loader import load_template, clear_cache, TemplateNotFoundError
from . import html_templates

__all__ = [
    'load_template',
    'clear_cache',
    'TemplateNotFoundError',
    'html_templates',
]
