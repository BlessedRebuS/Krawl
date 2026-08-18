#!/usr/bin/env python3

"""
Wordlists loader - reads all wordlists from wordlists.json
This allows easy customization without touching Python code.

Accessor names map to a JSON path via _PATHS; unknown attributes raise
AttributeError as usual. The file ships with the image (and is commonly
mounted from a ConfigMap), so a missing or invalid file is a deployment
error and fails loudly at startup.
"""

import json
from pathlib import Path

from logger import get_app_logger

# Used only when wordlists.json is missing or invalid.
_DEFAULTS = {
    "proxy_headers": ["CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"],
    "usernames": {
        "prefixes": ["admin", "user", "root"],
        "suffixes": ["", "_prod", "_dev"],
    },
    "passwords": {
        "prefixes": ["P@ssw0rd", "Admin"],
        "simple": ["test", "demo", "password"],
    },
    "emails": {"domains": ["example.com", "test.com"]},
    "api_keys": {"prefixes": ["sk_live_", "api_", ""]},
    "databases": {
        "names": ["production", "main_db"],
        "hosts": ["localhost", "db.internal"],
    },
    "applications": {"names": ["WebApp", "Dashboard"]},
    "users": {"roles": ["Administrator", "User"]},
    "server_headers": ["Apache/2.4.41 (Ubuntu)", "nginx/1.18.0"],
}

# accessor name -> (json key, nested key or None, default)
_PATHS = {
    "username_prefixes": ("usernames", "prefixes", []),
    "username_suffixes": ("usernames", "suffixes", []),
    "password_prefixes": ("passwords", "prefixes", []),
    "simple_passwords": ("passwords", "simple", []),
    "email_domains": ("emails", "domains", []),
    "api_key_prefixes": ("api_keys", "prefixes", []),
    "database_names": ("databases", "names", []),
    "database_hosts": ("databases", "hosts", []),
    "application_names": ("applications", "names", []),
    "user_roles": ("users", "roles", []),
    "directory_files": ("directory_listing", "files", []),
    "directory_dirs": ("directory_listing", "directories", []),
    "username_fields": ("credential_fields", "username_fields", []),
    "password_fields": ("credential_fields", "password_fields", []),
    "directory_listing": ("directory_listing", None, {}),
    "fake_passwd": ("fake_passwd", None, {}),
    "fake_shadow": ("fake_shadow", None, {}),
    "xxe_responses": ("xxe_responses", None, {}),
    "command_outputs": ("command_outputs", None, {}),
    "sql_errors": ("sql_errors", None, {}),
    "attack_patterns": ("attack_patterns", None, {}),
    "server_errors": ("server_errors", None, {}),
    "scoring_weights": ("scoring_weights", None, {}),
    "error_codes": ("error_codes", None, []),
    "server_headers": ("server_headers", None, []),
    "suspicious_patterns": ("suspicious_patterns", None, []),
    "proxy_headers": ("proxy_headers", None, []),
}


class Wordlists:
    """Loads and provides access to wordlists from wordlists.json"""

    def __init__(self):
        config_path = Path(__file__).parent.parent / "wordlists.json"
        try:
            with open(config_path) as f:
                self._data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            # Commonly mounted from a ConfigMap: a missing or malformed file must
            # not stop the honeypot, so fall back to minimal built-in values.
            get_app_logger().warning(
                f"Could not load {config_path} ({e}), using default wordlists"
            )
            self._data = _DEFAULTS

    def __getattr__(self, name):
        try:
            key, nested, default = _PATHS[name]
        except KeyError:
            raise AttributeError(name) from None
        value = self._data.get(key, default if nested is None else {})
        return value.get(nested, default) if nested else value


_wordlists_instance = None


def get_wordlists():
    """Get the singleton Wordlists instance"""
    global _wordlists_instance
    if _wordlists_instance is None:
        _wordlists_instance = Wordlists()
    return _wordlists_instance
