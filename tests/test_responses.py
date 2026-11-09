import random

import pytest
import yaml

from detection import DetectionFinding
from responses import ECHO_CSP, ResponseCatalog


def _finding(response_type, pattern_ids=(), severity=8, matched="m"):
    return DetectionFinding(
        attack_type=response_type or "x",
        matched_pattern=matched,
        source="yara",
        scan_target="query",
        severity=severity,
        response_type=response_type,
        pattern_ids=tuple(pattern_ids),
    )


def _variant(files, **extra):
    return {"content_type": "text/plain", "status": [200], "files": files, **extra}


def _type(priority, variants, methods=("GET", "HEAD")):
    return {"priority": priority, "methods": list(methods), "variants": variants}


# The smallest valid pages: section, with the files it needs.
BASE_PAGES = {
    "login_failed": {"content_type": "text/html", "files": ["pg/failed.html"]},
    "/robots.txt": {"content_type": "text/plain", "files": ["pg/robots.txt"]},
}
BASE_FILES = {
    "pg/failed.html": "login failed",
    "pg/robots.txt": "User-agent: *\nDisallow: /admin/\nDisallow: /\n",
    "trap/main_page.html": "<html>{counter}{content}</html>",
}


def _catalog(tmp_path, responses, files, version=1, pages=None, base_files=True):
    all_files = {**(BASE_FILES if base_files else {}), **files}
    for name, content in all_files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)
    manifest = {
        "version": version,
        "responses": responses,
        "pages": BASE_PAGES if pages is None else pages,
    }
    (tmp_path / "manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False))
    return ResponseCatalog.load(tmp_path)


def _traversal(tmp_path, variants=None):
    variants = variants or {
        "$passwd": _variant(["pt/passwd/*.txt"]),
        "default": _variant(["pt/default.txt"]),
    }
    return _catalog(
        tmp_path,
        {"path_traversal": _type(80, variants)},
        {
            "pt/passwd/a.txt": "passwd",
            "pt/shadow.txt": "shadow",
            "pt/default.txt": "listing",
        },
    )


def test_variant_chosen_by_matched_string(tmp_path):
    reply = _traversal(tmp_path).select(
        [_finding("path_traversal", ("$parent", "$passwd"))], "GET", "/x", ""
    )

    assert reply.body == b"passwd"
    assert reply.response_type == "path_traversal"


def test_first_listed_variant_wins_when_several_match(tmp_path):
    catalog = _traversal(
        tmp_path,
        {
            "$shadow": _variant(["pt/shadow.txt"]),
            "$passwd": _variant(["pt/passwd/*.txt"]),
            "default": _variant(["pt/default.txt"]),
        },
    )

    reply = catalog.select(
        [_finding("path_traversal", ("$passwd", "$shadow"))], "GET", "/x", ""
    )

    assert reply.body == b"shadow"


def test_variant_keys_use_ids_from_any_finding(tmp_path):
    catalog = _catalog(
        tmp_path,
        {
            "webshell": _type(
                30,
                {
                    "$sel_id": _variant(["ws/id.txt"]),
                    "default": _variant(["ws/page.txt"]),
                },
            ),
            "command_injection": _type(100, {"default": _variant(["ci/default.txt"])}),
        },
        {"ws/id.txt": "uid=33", "ws/page.txt": "page", "ci/default.txt": "sh"},
    )

    reply = catalog.select(
        [
            _finding("webshell", ("$known",)),
            _finding("command_injection", ("$sel_id",)),
        ],
        "GET",
        "/shell.php",
        "cmd=id",
    )

    assert reply.response_type == "webshell"
    assert reply.body == b"uid=33"


def test_default_variant_without_matching_id(tmp_path):
    reply = _traversal(tmp_path).select(
        [_finding("path_traversal", ("$parent",))], "GET", "/x", ""
    )

    assert reply.body == b"listing"


def test_legacy_finding_gets_default(tmp_path):
    reply = _traversal(tmp_path).select(
        [_finding("path_traversal", ())], "GET", "/x", ""
    )

    assert reply.body == b"listing"


def test_lowest_priority_type_wins(tmp_path):
    catalog = _catalog(
        tmp_path,
        {
            "sql_error": _type(110, {"default": _variant(["sql.txt"])}),
            "xxe_injection": _type(10, {"default": _variant(["xxe.txt"])}),
        },
        {"sql.txt": "sql", "xxe.txt": "xxe"},
    )

    reply = catalog.select(
        [_finding("sql_error", severity=9), _finding("xxe_injection", severity=1)],
        "GET",
        "/x",
        "",
    )

    assert reply.response_type == "xxe_injection"


def test_reply_finding_is_highest_severity_of_chosen_type(tmp_path):
    low = _finding("path_traversal", severity=3)
    high = _finding("path_traversal", severity=9)

    reply = _traversal(tmp_path).select([low, high], "GET", "/x", "")

    assert reply.finding is high


def test_disallowed_method_falls_through_to_next_type(tmp_path):
    catalog = _catalog(
        tmp_path,
        {
            "command_injection": _type(
                100,
                {"default": _variant(["ci.txt"])},
                methods=("GET", "HEAD", "POST", "PUT"),
            ),
            "sql_error": _type(90, {"default": _variant(["sql.txt"])}),
        },
        {"ci.txt": "ci", "sql.txt": "sql"},
    )
    both = [_finding("sql_error"), _finding("command_injection")]

    assert catalog.select(both, "POST", "/x", "").response_type == "command_injection"
    assert catalog.select(both, "GET", "/x", "").response_type == "sql_error"
    assert catalog.select([_finding("sql_error")], "POST", "/x", "") is None


def test_findings_without_catalogued_type_get_none(tmp_path):
    catalog = _traversal(tmp_path)

    assert catalog.select([_finding("")], "GET", "/x", "") is None
    assert catalog.select([], "GET", "/x", "") is None


def test_random_choice_covers_every_file(tmp_path):
    catalog = _catalog(
        tmp_path,
        {
            "xss": _type(
                120,
                {"default": _variant(["x/*.txt"], status=[500, 200])},
            )
        },
        {"x/a.txt": "a", "x/b.txt": "b", "x/c.txt": "c"},
    )
    random.seed(1)

    replies = [catalog.select([_finding("xss")], "GET", "/", "") for _ in range(200)]

    assert {reply.body for reply in replies} == {b"a", b"b", b"c"}
    assert {reply.status for reply in replies} == {500, 200}


def _echo(tmp_path, body, echo=True):
    return _catalog(
        tmp_path,
        {"xss": _type(120, {"default": _variant(["x.html"], echo=echo)})},
        {"x.html": body},
    )


def test_echo_substitutes_once(tmp_path):
    catalog = _echo(tmp_path, "<p>{{query}}</p>")

    reply = catalog.select(
        [_finding("xss", matched="evil")], "GET", "/s", "q=%7B%7Bmatch%7D%7D"
    )

    assert reply.body == b"<p>q={{match}}</p>"


def test_echo_fills_path_query_and_match(tmp_path):
    catalog = _echo(tmp_path, "{{path}}|{{query}}|{{match}}")

    reply = catalog.select(
        [_finding("xss", matched="<b>")], "GET", "/a b", "q=%3Cb%3E+x"
    )

    assert reply.body == b"/a b|q=<b> x|<b>"


def test_echo_values_are_cut_to_2048(tmp_path):
    catalog = _echo(tmp_path, "[{{query}}]")

    reply = catalog.select([_finding("xss")], "GET", "/", "q=" + "a" * 5000)

    assert len(reply.body) == 2048 + 2


def test_no_echo_leaves_placeholders(tmp_path):
    catalog = _echo(tmp_path, "{{path}}", echo=False)

    reply = catalog.select([_finding("xss")], "GET", "/s", "")

    assert reply.body == b"{{path}}"


def test_echo_reply_carries_script_blocking_csp(tmp_path):
    reply = _echo(tmp_path, "{{query}}").select([_finding("xss")], "GET", "/", "q=1")

    assert ("Content-Security-Policy", ECHO_CSP) in reply.headers
    assert ECHO_CSP == "script-src 'none'"


def test_plain_reply_has_no_extra_headers(tmp_path):
    reply = _echo(tmp_path, "x", echo=False).select([_finding("xss")], "GET", "/", "")

    assert reply.headers == ()


# --- validation ---------------------------------------------------------------


def _load_one(tmp_path, variant=None, files=None, **type_fields):
    entry = {
        "priority": 1,
        "methods": ["GET"],
        "variants": {"default": variant or _variant(["a.txt"])},
    }
    entry.update(type_fields)
    return _catalog(tmp_path, {"t": entry}, files or {"a.txt": "a"})


def test_unknown_key_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="unknown key"):
        _load_one(tmp_path, colour="red")
    with pytest.raises(RuntimeError, match="unknown key"):
        _load_one(tmp_path, variant=_variant(["a.txt"], template=True))


def test_bad_version_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="version"):
        _catalog(tmp_path, {}, {}, version=2)


def test_missing_default_variant_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="default"):
        _load_one(tmp_path, variants={"$x": _variant(["a.txt"])})


def test_duplicate_priority_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="priority"):
        _catalog(
            tmp_path,
            {
                "a": _type(5, {"default": _variant(["a.txt"])}),
                "b": _type(5, {"default": _variant(["a.txt"])}),
            },
            {"a.txt": "a"},
        )


@pytest.mark.parametrize("status", [[], [99], [600], ["200"], [True], 200])
def test_bad_status_is_rejected(tmp_path, status):
    with pytest.raises(RuntimeError, match="status"):
        _load_one(tmp_path, variant=_variant(["a.txt"], status=status))


def test_glob_matching_nothing_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="no files"):
        _load_one(tmp_path, variant=_variant(["missing/*.txt"]))


def test_empty_file_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="empty"):
        _load_one(tmp_path, files={"a.txt": ""})


def test_oversized_file_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="256"):
        _load_one(tmp_path, files={"a.txt": b"x" * (256 * 1024 + 1)})


def test_file_outside_catalogue_is_rejected(tmp_path):
    root = tmp_path / "responses"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("host file")

    with pytest.raises(RuntimeError, match="outside"):
        _load_one(root, variant=_variant(["../outside.txt"]))


def test_bad_method_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="method"):
        _load_one(tmp_path, methods=["GET", "TRACE"])


def test_missing_manifest_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="manifest"):
        ResponseCatalog.load(tmp_path)


# --- check_rules --------------------------------------------------------------


def test_response_types_lists_catalogued_types(tmp_path):
    assert _traversal(tmp_path).response_types == frozenset({"path_traversal"})


def test_check_rules_accepts_declared_keys(tmp_path):
    _traversal(tmp_path).check_rules(
        {"krawl_path_traversal": "path_traversal"},
        {"krawl_path_traversal": frozenset({"$parent", "$passwd"})},
    )


def test_check_rules_rejects_missing_type(tmp_path):
    with pytest.raises(RuntimeError, match="xss"):
        _traversal(tmp_path).check_rules(
            {"krawl_xss": "xss"}, {"krawl_xss": frozenset({"$a"})}
        )


def test_check_rules_rejects_unknown_variant_key(tmp_path):
    catalog = _traversal(
        tmp_path,
        {"$nope": _variant(["pt/shadow.txt"]), "default": _variant(["pt/default.txt"])},
    )

    with pytest.raises(RuntimeError, match=r"\$nope"):
        catalog.check_rules(
            {"krawl_path_traversal": "path_traversal"},
            {"krawl_path_traversal": frozenset({"$passwd"})},
        )


# --- pages ---------------------------------------------------------------------


def _page(files, **extra):
    return {"content_type": "text/html", "files": files, **extra}


def _pages(tmp_path, pages, files):
    return _catalog(tmp_path, {}, files, pages={**BASE_PAGES, **pages})


def _api_pages(tmp_path):
    return _pages(
        tmp_path,
        {
            "/api/": _page(["p/api.json"]),
            "/api/v2/": _page(["p/v2.json"]),
            "/api/users": _page(["p/users.json"]),
            "/login": _page(["p/login.html"], aliases=["/admin", "/admin/login"]),
        },
        {
            "p/api.json": "api",
            "p/v2.json": "v2",
            "p/users.json": "users",
            "p/login.html": "login",
        },
    )


def test_exact_page_matches(tmp_path):
    reply = _api_pages(tmp_path).page("/login", "GET")

    assert reply.body == b"login"
    assert reply.response_type == "page"
    assert reply.finding is None


def test_alias_matches(tmp_path):
    assert _api_pages(tmp_path).page("/admin/login", "GET").body == b"login"


def test_longest_prefix_wins(tmp_path):
    catalog = _api_pages(tmp_path)

    assert catalog.page("/api/v2/keys", "GET").body == b"v2"
    assert catalog.page("/api/other", "GET").body == b"api"
    assert catalog.page("/api/", "GET").body == b"api"


def test_exact_beats_prefix(tmp_path):
    assert _api_pages(tmp_path).page("/api/users", "GET").body == b"users"


def test_page_does_not_match_other_case(tmp_path):
    assert _api_pages(tmp_path).page("/Login", "GET") is None


def test_unmatched_path_gets_no_page(tmp_path):
    assert _api_pages(tmp_path).page("/apix", "GET") is None


def test_query_is_ignored_for_matching(tmp_path):
    assert _api_pages(tmp_path).page("/login", "GET", "next=/x").body == b"login"


def test_page_respects_methods(tmp_path):
    catalog = _pages(
        tmp_path,
        {"/get": _page(["p/a.html"]), "/post": _page(["p/a.html"], methods=["POST"])},
        {"p/a.html": "a"},
    )

    assert catalog.page("/get", "POST") is None
    assert catalog.page("/post", "GET") is None
    assert catalog.page("/post", "POST").body == b"a"


def test_page_defaults(tmp_path):
    catalog = _pages(tmp_path, {"/a": _page(["p/a.html"])}, {"p/a.html": "a"})

    assert catalog.page("/a", "HEAD").status == 200
    assert catalog.page("/a", "GET").headers == ()


def test_page_status_list(tmp_path):
    catalog = _pages(
        tmp_path, {"/s": _page(["p/a.html"], status=[500])}, {"p/a.html": "a"}
    )

    assert catalog.page("/s", "GET").status == 500


def test_page_echo_has_csp_and_empty_match(tmp_path):
    catalog = _pages(
        tmp_path,
        {"/e": _page(["p/e.html"], echo=True)},
        {"p/e.html": "{{path}}|{{query}}|{{match}}"},
    )

    reply = catalog.page("/e", "GET", "a=1")

    assert reply.body == b"/e|a=1|"
    assert ("Content-Security-Policy", ECHO_CSP) in reply.headers


def test_login_failed_reply(tmp_path):
    reply = _api_pages(tmp_path).login_failed("/login")

    assert reply.body == b"login failed"
    assert reply.status == 200


def test_login_failed_is_not_a_path(tmp_path):
    assert _api_pages(tmp_path).page("login_failed", "GET") is None


def test_trap_template_is_loaded(tmp_path):
    assert _api_pages(tmp_path).trap_template == "<html>{counter}{content}</html>"


def test_robots_disallows_parsed(tmp_path):
    assert _api_pages(tmp_path).robots_disallows == ("/admin", "/")


def _load_pages(tmp_path, pages, files=None, base_files=True):
    return _catalog(tmp_path, {}, files or {}, pages=pages, base_files=base_files)


def test_unknown_page_key_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="unknown key"):
        _pages(tmp_path, {"/a": _page(["pg/failed.html"], colour="red")}, {})


def test_duplicate_page_path_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="duplicate"):
        _pages(
            tmp_path,
            {
                "/a": _page(["pg/failed.html"]),
                "/b": _page(["pg/failed.html"], aliases=["/a"]),
            },
            {},
        )


@pytest.mark.parametrize("key", ["admin", "", "login-failed"])
def test_page_key_must_be_a_path(tmp_path, key):
    with pytest.raises(RuntimeError, match="path"):
        _pages(tmp_path, {key: _page(["pg/failed.html"])}, {})


def test_page_alias_must_be_a_path(tmp_path):
    with pytest.raises(RuntimeError, match="path"):
        _pages(tmp_path, {"/a": _page(["pg/failed.html"], aliases=["b"])}, {})


def test_missing_login_failed_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="login_failed"):
        _load_pages(tmp_path, {"/robots.txt": BASE_PAGES["/robots.txt"]})


def test_missing_robots_page_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="robots"):
        _load_pages(tmp_path, {"login_failed": BASE_PAGES["login_failed"]})


def test_robots_page_must_have_one_file(tmp_path):
    with pytest.raises(RuntimeError, match="robots"):
        _load_pages(
            tmp_path,
            {
                "login_failed": BASE_PAGES["login_failed"],
                "/robots.txt": {"content_type": "text/plain", "files": ["pg/*"]},
            },
        )


def test_bad_page_method_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="method"):
        _pages(tmp_path, {"/a": _page(["pg/failed.html"], methods=["TRACE"])}, {})


def test_bad_page_status_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="status"):
        _pages(tmp_path, {"/a": _page(["pg/failed.html"], status=[700])}, {})


def test_missing_trap_template_is_rejected(tmp_path):
    files = {k: v for k, v in BASE_FILES.items() if not k.startswith("trap/")}
    with pytest.raises(RuntimeError, match="trap"):
        _load_pages(tmp_path, BASE_PAGES, files, base_files=False)


def test_page_file_outside_catalogue_is_rejected(tmp_path):
    root = tmp_path / "responses"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("host file")

    with pytest.raises(RuntimeError, match="outside"):
        _pages(root, {"/a": _page(["../outside.txt"])}, {})


def test_missing_pages_section_is_rejected(tmp_path):
    for name, content in BASE_FILES.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(content)
    (tmp_path / "manifest.yaml").write_text("version: 1\nresponses: {}\n")

    with pytest.raises(RuntimeError, match="pages"):
        ResponseCatalog.load(tmp_path)
