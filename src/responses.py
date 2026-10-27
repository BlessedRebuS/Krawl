"""Fake content served from files: YARA replies, bait pages and the trap shell.

`responses/manifest.yaml` has two sections. `responses:` maps each YARA
`response_type` to variants keyed by YARA string identifiers (`$passwd`).
`pages:` maps request paths to bait pages, plus the reserved `login_failed`
reply. Every entry lists body files; the server picks one, and computes nothing
about the request beyond the opt-in echo placeholders.
"""

from __future__ import annotations

import random
import re
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

from detection import DetectionFinding

MANIFEST_NAME = "manifest.yaml"
MAX_FILE_BYTES = 256 * 1024
ECHO_MAX_CHARS = 2048
# An echoed payload must not run in the operator's browser, which shares the
# honeypot origin with the dashboard.
ECHO_CSP = "script-src 'none'"
ALLOWED_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
)

TOP_KEYS = {"version", "responses", "pages"}
TYPE_KEYS = {"priority", "methods", "variants"}
VARIANT_KEYS = {"content_type", "status", "files", "echo"}
PAGE_KEYS = {"content_type", "status", "files", "echo", "methods", "aliases"}
PAGE_DEFAULT_METHODS = ("GET", "HEAD")
LOGIN_FAILED = "login_failed"
ROBOTS_PAGE = "/robots.txt"
TRAP_TEMPLATE = "trap/main_page.html"
ECHO_PLACEHOLDER = re.compile(rb"\{\{(path|query|match)\}\}")


@dataclass(frozen=True)
class Reply:
    body: bytes
    content_type: str
    status: int
    response_type: str  # "page" for pages: and login_failed
    finding: DetectionFinding | None  # None for pages
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class _Variant:
    key: str
    content_type: str
    statuses: tuple[int, ...]
    bodies: tuple[bytes, ...]
    echo: bool


@dataclass(frozen=True)
class _Page:
    key: str
    content_type: str
    statuses: tuple[int, ...]
    bodies: tuple[bytes, ...]
    echo: bool
    methods: frozenset[str]


@dataclass(frozen=True)
class _ResponseType:
    name: str
    priority: int
    methods: frozenset[str]
    variants: tuple[_Variant, ...]


def _fail(where: str, problem: str):
    raise RuntimeError(f"Response catalogue {where}: {problem}")


def _check_keys(where: str, value, allowed: set[str], required: set[str]) -> None:
    if not isinstance(value, Mapping):
        _fail(where, "must be a mapping")
    unknown = set(value) - allowed
    if unknown:
        _fail(where, f"unknown key {', '.join(sorted(map(str, unknown)))}")
    missing = required - set(value)
    if missing:
        _fail(where, f"missing {', '.join(sorted(missing))}")


def _read_files(root: Path, where: str, patterns) -> tuple[bytes, ...]:
    if not isinstance(patterns, list) or not patterns:
        _fail(where, "files must be a non-empty list")
    bodies = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern:
            _fail(where, f"file pattern {pattern!r} must be a non-empty string")
        pure = PurePosixPath(pattern)
        if pure.is_absolute() or ".." in pure.parts:
            _fail(where, f"file pattern {pattern!r} is outside {root}")
        matches = sorted(item for item in root.glob(pattern) if item.is_file())
        if not matches:
            _fail(where, f"file pattern {pattern!r} matches no files")
        for item in matches:
            if not item.resolve().is_relative_to(root):
                _fail(where, f"file {item} is outside {root}")
            size = item.stat().st_size
            if size == 0:
                _fail(where, f"file {item} is empty")
            if size > MAX_FILE_BYTES:
                _fail(where, f"file {item} is larger than 256 KB")
            bodies.append(item.read_bytes())
    return tuple(bodies)


def _check_statuses(where: str, statuses) -> list[int]:
    if (
        not isinstance(statuses, list)
        or not statuses
        or not all(type(item) is int and 100 <= item <= 599 for item in statuses)
    ):
        _fail(where, f"status must be a non-empty list of 100-599, got {statuses!r}")
    return statuses


def _check_echo(where: str, raw) -> bool:
    echo = raw.get("echo", False)
    if not isinstance(echo, bool):
        _fail(where, "echo must be true or false")
    return echo


def _check_methods(where: str, methods) -> frozenset[str]:
    if not isinstance(methods, list) or not methods:
        _fail(where, "methods must be a non-empty list")
    bad = [item for item in methods if item not in ALLOWED_METHODS]
    if bad:
        _fail(where, f"unknown method {', '.join(map(str, bad))}")
    return frozenset(methods)


def _parse_variant(root: Path, where: str, key, raw) -> _Variant:
    _check_keys(where, raw, VARIANT_KEYS, {"content_type", "status", "files"})
    if not isinstance(key, str) or not (key == "default" or key.startswith("$")):
        _fail(where, "variant key must be 'default' or a YARA string id like $name")
    content_type = raw["content_type"]
    if not isinstance(content_type, str) or not content_type:
        _fail(where, "content_type must be a non-empty string")
    statuses = _check_statuses(where, raw["status"])
    echo = _check_echo(where, raw)
    return _Variant(
        key=key,
        content_type=content_type,
        statuses=tuple(statuses),
        bodies=_read_files(root, where, raw["files"]),
        echo=echo,
    )


def _parse_type(root: Path, name, raw) -> _ResponseType:
    where = f"type {name}"
    _check_keys(where, raw, TYPE_KEYS, TYPE_KEYS)
    priority = raw["priority"]
    if type(priority) is not int:
        _fail(where, f"priority must be an integer, got {priority!r}")
    methods = _check_methods(where, raw["methods"])
    variants = raw["variants"]
    if not isinstance(variants, Mapping) or "default" not in variants:
        _fail(where, "variants must be a mapping that contains default")
    return _ResponseType(
        name=name,
        priority=priority,
        methods=methods,
        variants=tuple(
            _parse_variant(root, f"{where} variant {key}", key, value)
            for key, value in variants.items()
        ),
    )


def _is_path(value) -> bool:
    return isinstance(value, str) and value.startswith("/")


def _parse_page(root: Path, key, raw) -> tuple[_Page, list[str]]:
    """Return the page and every path it answers (its key, unless reserved, and aliases)."""
    where = f"page {key}"
    if not (_is_path(key) or key == LOGIN_FAILED):
        _fail(where, f"key must be a path starting with / or {LOGIN_FAILED}")
    _check_keys(where, raw, PAGE_KEYS, {"content_type", "files"})
    content_type = raw["content_type"]
    if not isinstance(content_type, str) or not content_type:
        _fail(where, "content_type must be a non-empty string")
    aliases = raw.get("aliases", [])
    if not isinstance(aliases, list) or not all(_is_path(item) for item in aliases):
        _fail(where, "aliases must be a list of paths starting with /")
    page = _Page(
        key=key,
        content_type=content_type,
        statuses=tuple(_check_statuses(where, raw.get("status", [200]))),
        bodies=_read_files(root, where, raw["files"]),
        echo=_check_echo(where, raw),
        methods=_check_methods(where, raw.get("methods", list(PAGE_DEFAULT_METHODS))),
    )
    paths = [] if key == LOGIN_FAILED else [key]
    return page, paths + aliases


def _robots_disallows(body: bytes) -> tuple[str, ...]:
    disallows = []
    for line in body.decode("utf-8", "replace").splitlines():
        name, _, value = line.partition(":")
        value = value.strip()
        if name.strip().lower() == "disallow" and value:
            disallows.append(value if value == "/" else value.rstrip("/"))
    return tuple(disallows)


class ResponseCatalog:
    def __init__(
        self,
        types: Sequence[_ResponseType],
        pages: dict[str, _Page] | None = None,
        trap_template: str = "",
    ):
        self._types = sorted(types, key=lambda item: item.priority)
        pages = pages or {}
        self._login_failed = pages.get(LOGIN_FAILED)
        # Paths ending in / are prefixes; the longest prefix is tried first.
        self._exact = {
            p: page
            for p, page in pages.items()
            if p.startswith("/") and not p.endswith("/")
        }
        self._prefixes = sorted(
            ((p, page) for p, page in pages.items() if p.endswith("/")),
            key=lambda item: len(item[0]),
            reverse=True,
        )
        robots = pages.get(ROBOTS_PAGE)
        self.robots_disallows = _robots_disallows(robots.bodies[0]) if robots else ()
        self.trap_template = trap_template

    @classmethod
    def load(cls, path: str | Path) -> ResponseCatalog:
        root = Path(path).resolve()
        manifest = root / MANIFEST_NAME
        try:
            raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        except OSError as exc:
            raise RuntimeError(
                f"Cannot read response manifest {manifest}: {exc}"
            ) from exc
        except yaml.YAMLError as exc:
            raise RuntimeError(f"Invalid response manifest {manifest}: {exc}") from exc
        _check_keys(MANIFEST_NAME, raw, TOP_KEYS, TOP_KEYS)
        if raw["version"] != 1:
            _fail(MANIFEST_NAME, f"version must be 1, got {raw['version']!r}")
        responses = raw["responses"]
        if not isinstance(responses, Mapping):
            _fail(MANIFEST_NAME, "responses must be a mapping")
        types = [_parse_type(root, name, value) for name, value in responses.items()]
        seen: dict[int, str] = {}
        for item in types:
            if item.priority in seen:
                _fail(
                    f"type {item.name}",
                    f"priority {item.priority} is also used by {seen[item.priority]}",
                )
            seen[item.priority] = item.name
        return cls(types, _load_pages(root, raw["pages"]), _load_trap_template(root))

    @property
    def response_types(self) -> frozenset[str]:
        return frozenset(item.name for item in self._types)

    def check_rules(
        self,
        rule_response_types: dict[str, str],
        rule_strings: dict[str, frozenset[str]],
    ) -> None:
        """Fail when a rule names an unknown type or a variant key matches no string."""
        known = self.response_types
        for rule, response_type in sorted(rule_response_types.items()):
            if response_type not in known:
                raise RuntimeError(
                    f"YARA rule {rule} has response_type {response_type!r}, "
                    f"which the response manifest does not define"
                )
        declared = frozenset().union(*rule_strings.values())
        for item in self._types:
            for variant in item.variants:
                if variant.key != "default" and variant.key not in declared:
                    raise RuntimeError(
                        f"Response type {item.name} has variant {variant.key}, "
                        f"which no YARA rule declares"
                    )

    def select(
        self,
        findings: Sequence[DetectionFinding],
        method: str,
        path: str,
        query: str,
    ) -> Reply | None:
        method = method.upper()
        matched_ids = {pid for finding in findings for pid in finding.pattern_ids}
        for item in self._types:
            if method not in item.methods:
                continue
            candidates = [f for f in findings if f.response_type == item.name]
            if not candidates:
                continue
            finding = max(candidates, key=lambda f: f.severity)
            variant = next(
                (v for v in item.variants if v.key in matched_ids),
                next(v for v in item.variants if v.key == "default"),
            )
            # Choosing a decoy file is not security sensitive; tests seed `random`.
            body = random.choice(variant.bodies)  # noqa: S311
            headers = ()
            if variant.echo:
                body = _echo(body, path, query, finding.matched_pattern)
                headers = (("Content-Security-Policy", ECHO_CSP),)
            return Reply(
                body=body,
                content_type=variant.content_type,
                status=random.choice(variant.statuses),  # noqa: S311
                response_type=item.name,
                finding=finding,
                headers=headers,
            )
        return None

    def page(self, path: str, method: str, query: str = "") -> Reply | None:
        """The pages: entry for this path, if it allows the method."""
        page = self._exact.get(path)
        if page is None:
            page = next(
                (p for prefix, p in self._prefixes if path.startswith(prefix)), None
            )
        if page is None or method.upper() not in page.methods:
            return None
        return _page_reply(page, path, query)

    def login_failed(self, path: str, query: str = "") -> Reply:
        """The reply to a POST or PUT that no page answers."""
        return _page_reply(self._login_failed, path, query)


def _page_reply(page: _Page, path: str, query: str) -> Reply:
    body = random.choice(page.bodies)  # noqa: S311
    headers = ()
    if page.echo:
        body = _echo(body, path, query, "")
        headers = (("Content-Security-Policy", ECHO_CSP),)
    return Reply(
        body=body,
        content_type=page.content_type,
        status=random.choice(page.statuses),  # noqa: S311
        response_type="page",
        finding=None,
        headers=headers,
    )


def _load_pages(root: Path, raw) -> dict[str, _Page]:
    """Map every answered path (and login_failed) to its page; fail on duplicates."""
    if not isinstance(raw, Mapping):
        _fail(MANIFEST_NAME, "pages must be a mapping")
    pages: dict[str, _Page] = {}
    for key, value in raw.items():
        page, paths = _parse_page(root, key, value)
        if key == LOGIN_FAILED:
            pages[LOGIN_FAILED] = page
        for path in paths:
            if path in pages:
                _fail(
                    f"page {key}", f"duplicate path {path} (also in {pages[path].key})"
                )
            pages[path] = page
    if LOGIN_FAILED not in pages:
        _fail(MANIFEST_NAME, f"pages must define {LOGIN_FAILED}")
    robots = pages.get(ROBOTS_PAGE)
    if robots is None or robots.key != ROBOTS_PAGE:
        _fail(MANIFEST_NAME, f"pages must define {ROBOTS_PAGE}")
    if len(robots.bodies) != 1:
        _fail(f"page {ROBOTS_PAGE}", "robots.txt must list exactly one file")
    return pages


def _load_trap_template(root: Path) -> str:
    path = root / TRAP_TEMPLATE
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Cannot read trap page template {path}: {exc}") from exc
    if not text.strip():
        _fail(TRAP_TEMPLATE, "trap page template is empty")
    return text


def _echo(body: bytes, path: str, query: str, match: str) -> bytes:
    values = {
        b"path": path,
        b"query": urllib.parse.unquote_plus(query),
        b"match": match,
    }
    # One pass, so echoed text containing a placeholder is never substituted.
    return ECHO_PLACEHOLDER.sub(
        lambda m: values[m.group(1)][:ECHO_MAX_CHARS].encode("utf-8", "replace"),
        body,
    )
