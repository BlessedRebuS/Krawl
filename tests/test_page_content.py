"""The bundled pages: section answers every path the old hard-coded routes served."""

from pathlib import Path

import pytest
import yaml

from responses import ResponseCatalog

RESPONSES = Path(__file__).resolve().parent.parent / "responses"


@pytest.fixture(scope="module")
def catalog():
    return ResponseCatalog.load(RESPONSES)


# (method, path, status, marker): the reply must have that status and contain marker.
CASES = [
    ("GET", "/robots.txt", 200, "Disallow: /admin/"),
    ("GET", "/login", 200, "<title>Admin Login</title>"),
    ("GET", "/admin", 200, "<title>Admin Login</title>"),
    ("GET", "/admin/", 200, "<title>Admin Login</title>"),
    ("GET", "/admin/login", 200, "<title>Admin Login</title>"),
    ("GET", "/wp-login.php", 200, "Log In &lsaquo; WordPress"),
    ("GET", "/wp-login", 200, "Log In &lsaquo; WordPress"),
    ("GET", "/wp-admin", 200, "Log In &lsaquo; WordPress"),
    ("GET", "/wp-admin/", 200, "Log In &lsaquo; WordPress"),
    ("GET", "/wp-content/themes/x/style.css", 200, "Just another WordPress site"),
    ("GET", "/wp-includes/js/a.js", 200, "Just another WordPress site"),
    ("GET", "/phpmyadmin", 200, "<title>phpMyAdmin</title>"),
    ("GET", "/phpmyadmin/sql.php", 200, "<title>phpMyAdmin</title>"),
    ("GET", "/phpMyAdmin", 200, "<title>phpMyAdmin</title>"),
    ("GET", "/phpMyAdmin/index.php", 200, "<title>phpMyAdmin</title>"),
    ("GET", "/pma", 200, "<title>phpMyAdmin</title>"),
    ("GET", "/pma/", 200, "<title>phpMyAdmin</title>"),
    ("GET", "/search", 200, "<title>Search</title>"),
    ("GET", "/users", 200, "<title>Search</title>"),
    ("GET", "/user", 200, "<title>Search</title>"),
    ("GET", "/database", 200, "<title>Search</title>"),
    ("GET", "/db", 200, "<title>Search</title>"),
    ("GET", "/contact", 200, "<title>Contact</title>"),
    ("GET", "/info", 200, "<title>Contact</title>"),
    ("GET", "/input", 200, "<title>Contact</title>"),
    ("GET", "/feedback", 200, "<title>Contact</title>"),
    ("GET", "/comment", 200, "<title>Contact</title>"),
    ("GET", "/server", 500, "Internal Server Error"),
    ("GET", "/backup/", 200, "Index of /backup/"),
    ("GET", "/uploads/", 200, "Index of /uploads/"),
    ("GET", "/private/", 200, "Index of /private/"),
    ("GET", "/config/", 200, "Index of /config/"),
    ("GET", "/database/", 200, "Index of /database/"),
    ("GET", "/credentials.txt", 200, "# Production Credentials"),
    ("GET", "/passwords.txt", 200, "Admin Password:"),
    ("GET", "/admin_notes.txt", 200, "Admin Password:"),
    ("GET", "/users.json", 200, '"users"'),
    ("GET", "/api_keys.json", 200, '"secret_access_key"'),
    ("GET", "/config.json", 200, '"database_url"'),
    ("GET", "/api/config", 200, '"database_url"'),
    ("GET", "/.env", 200, "DB_PASSWORD="),
    ("GET", "/api/users", 200, '"total"'),
    ("GET", "/api/v1/users", 200, '"api_key"'),
    ("GET", "/api/v2/secrets", 200, '"password"'),
    ("GET", "/api/search", 200, '"results"'),
    ("GET", "/api/sql", 200, '"results"'),
    ("GET", "/api/database", 200, '"results"'),
    ("POST", "/api/sql", 200, '"results"'),
    ("GET", "/api/whatever/else", 200, '"Not found"'),
    ("POST", "/api/contact", 200, "Thank you"),
]


@pytest.mark.parametrize("method, path, status, marker", CASES)
def test_page_gets_matching_content(catalog, method, path, status, marker):
    reply = catalog.page(path, method)

    assert reply is not None
    assert reply.status == status
    assert marker.encode() in reply.body


def test_contact_reply_reflects_the_query(catalog):
    reply = catalog.page("/api/contact", "POST", "name=<b>bob</b>")

    assert b"name=<b>bob</b>" in reply.body
    assert ("Content-Security-Policy", "script-src 'none'") in reply.headers


def test_login_failed_page(catalog):
    assert b"<title>Error</title>" in catalog.login_failed("/login").body


def _bodies(page_key):
    manifest = yaml.safe_load((RESPONSES / "manifest.yaml").read_text())
    patterns = manifest["pages"][page_key]["files"]
    return {
        item.read_bytes()
        for pattern in patterns
        for item in RESPONSES.glob(pattern)
        if item.is_file()
    }


@pytest.mark.parametrize(
    "page_key",
    [
        "/credentials.txt",
        "/passwords.txt",
        "/users.json",
        "/api_keys.json",
        "/config.json",
        "/.env",
        "/api/users",
        "/api/v1/users",
        "/api/v2/secrets",
    ],
)
def test_secret_pages_ship_five_files(page_key):
    assert len(_bodies(page_key)) >= 5


def test_robots_matches_the_old_file(catalog):
    assert catalog.robots_disallows == (
        "/admin",
        "/api",
        "/backup",
        "/config",
        "/database",
        "/private",
        "/uploads",
        "/wp-admin",
        "/login",
        "/admin/login",
        "/phpMyAdmin",
        "/admin/login.php",
        "/users",
        "/search",
        "/contact",
        "/info",
        "/input",
        "/feedback",
        "/server",
        "/api/v1/users",
        "/api/v2/secrets",
        "/api/search",
        "/api/sql",
        "/api/database",
        "/.env",
        "/credentials.txt",
        "/passwords.txt",
        "/.git",
        "/backup.sql",
        "/db_backup.sql",
    )
