"""Text-filter clauses shared by every Attacks-tab query."""

from urllib.parse import quote

from sqlalchemy import func, not_, or_

from models import AccessLog


def _like(term: str) -> str:
    return f"%{term}%"


def _terms(raw) -> list[str]:
    """Search terms from a comma list or an iterable; every term must match."""
    if not raw:
        return []
    return parse_exclude_terms(raw if isinstance(raw, str) else ",".join(raw))


def access_log_text_clauses(
    search=None, exclude=None, method_filter=None, ip_filter=None
) -> list:
    """AccessLog clauses: search is a substring over ip/path/UA, exclude a NOT list."""
    clauses = []
    if ip_filter:
        clauses.append(AccessLog.ip == ip_filter)
    if method_filter:
        clauses.append(func.upper(AccessLog.method) == method_filter.upper())
    for term in _terms(search):
        like = _like(term)
        clauses.append(
            or_(
                AccessLog.ip.ilike(like),
                AccessLog.path.ilike(like),
                AccessLog.user_agent.ilike(like),
            )
        )
    for term in exclude or ():
        like = _like(term)
        # A NULL user agent must not turn the NOT into NULL.
        clauses.append(
            not_(
                or_(
                    AccessLog.ip.ilike(like),
                    AccessLog.path.ilike(like),
                    func.coalesce(AccessLog.user_agent, "").ilike(like),
                )
            )
        )
    return clauses


def credential_text_clauses(model, search=None, exclude=None) -> list:
    """CredentialAttempt clauses over ip/path/username (no method or UA there)."""
    cols = [model.ip, model.path, model.username]
    clauses = []
    for term in _terms(search):
        clauses.append(or_(*(c.ilike(_like(term)) for c in cols)))
    for term in exclude or ():
        clauses.append(
            not_(or_(*(func.coalesce(c, "").ilike(_like(term)) for c in cols)))
        )
    return clauses


MAX_EXCLUDE_TERMS = 10


def parse_exclude_terms(raw: str | None) -> list[str]:
    """Comma-separated exclude terms, blanks dropped, at most MAX_EXCLUDE_TERMS."""
    terms = [term.strip()[:200] for term in (raw or "").split(",")]
    return [term for term in terms if term][:MAX_EXCLUDE_TERMS]


def clean_text_filters(search, exclude, method_filter, ip_filter) -> dict:
    """Normalised text filters; only the ones set are kept."""
    terms = parse_exclude_terms(exclude)
    out = {
        "search": ",".join(_terms(search)),
        "exclude": ",".join(terms),
        "method_filter": (method_filter or "").strip().upper(),
        "ip_filter": (ip_filter or "").strip(),
    }
    return {k: v for k, v in out.items() if v}


def text_filter_key(f: dict) -> str:
    """Cache-key suffix of the filters, empty when none are set."""
    return "".join(f":{k}={v}" for k, v in f.items())


def text_filter_qs(f: dict) -> str:
    """Query-string suffix carrying the filters through pagination and sort links."""
    return "".join(f"&{k}={quote(v)}" for k, v in f.items())
