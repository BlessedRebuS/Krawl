#!/usr/bin/env python3

"""
Wordlists loader - reads all wordlists from wordlists.json
This allows easy customization without touching Python code.
"""

import json
from pathlib import Path

from logger import get_app_logger


class Wordlists:
    """Loads and provides access to wordlists from wordlists.json"""
    
    def __init__(self):
        self._data = self._load_config()
    
    def _load_config(self):
        """Load wordlists from JSON file"""
        config_path = Path(__file__).parent.parent / 'wordlists.json'

        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            get_app_logger().warning(f"Wordlists file {config_path} not found, using default values")
            return self._get_defaults()
        except json.JSONDecodeError as e:
            get_app_logger().warning(f"Invalid JSON in {config_path}: {e}")
            return self._get_defaults()
    
    def _get_defaults(self):
        """Fallback default wordlists if JSON file is missing or invalid"""
        return {
            "usernames": {
                "prefixes": ["admin", "user", "root"],
                "suffixes": ["", "_prod", "_dev"]
            },
            "passwords": {
                "prefixes": ["P@ssw0rd", "Admin"],
                "simple": ["test", "demo", "password"]
            },
            "emails": {
                "domains": ["example.com", "test.com"]
            },
            "api_keys": {
                "prefixes": ["sk_live_", "api_", ""]
            },
            "databases": {
                "names": ["production", "main_db"],
                "hosts": ["localhost", "db.internal"]
            },
            "applications": {
                "names": ["WebApp", "Dashboard"]
            },
            "users": {
                "roles": ["Administrator", "User"]
            },
            "server_headers": ["Apache/2.4.41 (Ubuntu)", "nginx/1.18.0"]
        }
    
    @property
    def username_prefixes(self):
        return self._data.get("usernames", {}).get("prefixes", [])
    
    @property
    def username_suffixes(self):
        return self._data.get("usernames", {}).get("suffixes", [])
    
    @property
    def password_prefixes(self):
        return self._data.get("passwords", {}).get("prefixes", [])
    
    @property
    def simple_passwords(self):
        return self._data.get("passwords", {}).get("simple", [])
    
    @property
    def email_domains(self):
        return self._data.get("emails", {}).get("domains", [])
    
    @property
    def api_key_prefixes(self):
        return self._data.get("api_keys", {}).get("prefixes", [])
    
    @property
    def database_names(self):
        return self._data.get("databases", {}).get("names", [])
    
    @property
    def database_hosts(self):
        return self._data.get("databases", {}).get("hosts", [])
    
    @property
    def application_names(self):
        return self._data.get("applications", {}).get("names", [])
    
    @property
    def user_roles(self):
        return self._data.get("users", {}).get("roles", [])
    
    @property
    def directory_files(self):
        return self._data.get("directory_listing", {}).get("files", [])
    
    @property
    def directory_dirs(self):
        return self._data.get("directory_listing", {}).get("directories", [])
    
    @property
    def error_codes(self):
        return self._data.get("error_codes", [])
    
    @property
    def server_headers(self):
        return self._data.get("server_headers", [])


_wordlists_instance = None

def get_wordlists():
    """Get the singleton Wordlists instance"""
    global _wordlists_instance
    if _wordlists_instance is None:
        _wordlists_instance = Wordlists()
    return _wordlists_instance

