#!/usr/bin/env python3

"""The numbers behind the IP Insight scoreboard, read for one IP at a time."""

import math
from typing import Any

from sqlalchemy import case, distinct, func

import detection
from config import get_config
from dashboard_cache import get_cached_short, set_cached_short
from database import get_database
from models import AccessLog, AttackDetection, CapturedPayload, CredentialAttempt

_AGENTS_FOR_FULL_AXIS = 5
_ATTACK_TYPES_FOR_FULL_AXIS = 10
# Fields the template needs that aren't plain scalars.
_TEMPLATE_COLLECTIONS = {"blocklist_memberships", "category_history"}


def _capped(value: float) -> int:
    return max(0, min(100, round(value)))


def behaviour_axes(metrics: dict | None, evidence: int) -> list[dict[str, Any]]:
    """The hexagon's six axes, clockwise from the top, each scored 0-100."""
    metrics = metrics or {}
    agents = len(metrics.get("different_user_agents") or ())
    attacks = len(metrics.get("attack_url") or ())
    return [
        {
            "key": "risky",
            "label": "Risky methods",
            "value": _capped((metrics.get("risky_http_methods") or 0) * 100),
            "hint": "Share of requests using POST, PUT, DELETE, OPTIONS or PATCH",
        },
        {
            "key": "robots",
            "label": "Robots",
            "value": _capped((metrics.get("robots_violations") or 0) * 100),
            "hint": "Share of requests under a robots.txt Disallow path",
        },
        {
            "key": "timing",
            "label": "Timing",
            "value": _capped((metrics.get("request_timing_cv") or 0) * 100),
            "hint": "How uneven recent request timing is",
        },
        {
            "key": "agents",
            "label": "UA variety",
            "value": _capped(agents * 100 / _AGENTS_FOR_FULL_AXIS),
            "hint": f"{agents} distinct user agents; {_AGENTS_FOR_FULL_AXIS} fills the axis",
        },
        {
            "key": "attacks",
            "label": "Attack variety",
            "value": _capped(attacks * 100 / _ATTACK_TYPES_FOR_FULL_AXIS),
            "hint": (
                f"{attacks} distinct attack types; "
                f"{_ATTACK_TYPES_FOR_FULL_AXIS} fills the axis"
            ),
        },
        {
            "key": "evidence",
            "label": "Evidence",
            "value": _capped(20 * math.log2(1 + evidence)),
            "hint": f"{evidence} honeypot hits, credentials and captured files",
        },
    ]


def score_scale(weights: dict[str, dict[str, int]]) -> int:
    """The most points any category can reach."""
    return max((sum(w.values()) for w in weights.values()), default=1)


def _severity_lookup(attack_type: str, rule_name: str | None) -> int:
    """The detection's own rule when stored, else the type's highest rule."""
    coordinator = detection.loaded_detection()
    if coordinator is None:
        return 0
    for rule in coordinator.yara.rule_details.get(attack_type, ()):
        if rule_name and rule["rule"] == rule_name:
            return rule["severity"]
    return coordinator.attack_type_severity(attack_type)


def _attack_stats(session, ip: str) -> dict[str, Any]:
    rows = (
        session.query(
            AttackDetection.attack_type,
            AttackDetection.rule_name,
            func.count(),
        )
        .join(AccessLog, AccessLog.id == AttackDetection.access_log_id)
        .filter(AccessLog.ip == ip)
        .group_by(AttackDetection.attack_type, AttackDetection.rule_name)
        .all()
    )
    per_type: dict[str, int] = {}
    per_rule: dict[str, int] = {}
    rule_severity: dict[str, int] = {}
    type_severity: dict[str, int] = {}
    scored = weighted = peak = 0
    for attack_type, rule_name, count in rows:
        per_type[attack_type] = per_type.get(attack_type, 0) + count
        severity = _severity_lookup(attack_type, rule_name)
        type_severity[attack_type] = max(type_severity.get(attack_type, 0), severity)
        if rule_name:
            per_rule[rule_name] = per_rule.get(rule_name, 0) + count
            rule_severity[rule_name] = severity
        if severity:
            scored += count
            weighted += severity * count
            peak = max(peak, severity)
    top = max(per_type.values(), default=0)
    ranked = sorted(per_type.items(), key=lambda item: (-item[1], item[0]))
    # Per type, because the severity filter selects whole attack types.
    severity_counts = dict.fromkeys(("critical", "high", "medium", "low"), 0)
    for attack_type, count in per_type.items():
        if type_severity[attack_type]:
            severity_counts[
                detection.severity_band(type_severity[attack_type])
            ] += count
    return {
        "severity_counts": severity_counts,
        "rules": [
            {
                "rule": rule,
                "count": count,
                "band": (
                    detection.severity_band(rule_severity[rule])
                    if rule_severity[rule]
                    else None
                ),
            }
            for rule, count in sorted(per_rule.items(), key=lambda i: (-i[1], i[0]))
        ],
        "attacks": sum(per_type.values()),
        "attack_types": [
            {
                "type": attack_type,
                "count": count,
                "share": round(count * 100 / top),
                "band": (
                    detection.severity_band(type_severity[attack_type])
                    if type_severity[attack_type]
                    else None
                ),
            }
            for attack_type, count in ranked
        ],
        "severity_avg": round(weighted / scored, 1) if scored else None,
        "severity_peak": peak or None,
        "severity_band": (
            detection.severity_band(round(weighted / scored)) if scored else None
        ),
    }


def build_ip_overview(ip: str, stats: dict[str, Any]) -> dict[str, Any]:
    """Read one IP's counts. Counts from access_logs cover retained rows only."""
    db = get_database()
    session = db.session
    try:
        hits = func.coalesce(AccessLog.hit_count, 1)
        logs = (
            session.query(
                func.count(),
                func.sum(case((AccessLog.is_suspicious, hits), else_=0)),
                func.sum(case((AccessLog.is_honeypot_trigger, hits), else_=0)),
                func.count(
                    distinct(case((AccessLog.is_honeypot_trigger, AccessLog.path)))
                ),
                func.count(AccessLog.referer),
            )
            .filter(AccessLog.ip == ip)
            .one()
        )
        credentials = (
            session.query(
                func.count(),
                func.count(
                    distinct(
                        func.coalesce(CredentialAttempt.username, "")
                        + "\x00"
                        + func.coalesce(CredentialAttempt.password, "")
                    )
                ),
            )
            .filter(CredentialAttempt.ip == ip)
            .one()
        )
        files = session.query(func.count()).filter(CapturedPayload.ip == ip).scalar()
        campaigns = {
            row[0]
            for row in session.query(CapturedPayload.cluster_id)
            .filter(CapturedPayload.ip == ip, CapturedPayload.cluster_id.isnot(None))
            .distinct()
        } | {
            row[0]
            for row in session.query(AttackDetection.cluster_id)
            .join(AccessLog, AccessLog.id == AttackDetection.access_log_id)
            .filter(AccessLog.ip == ip, AttackDetection.cluster_id.isnot(None))
            .distinct()
        }
        attack_stats = _attack_stats(session, ip)
    finally:
        db.close_session()

    total = int(stats.get("total_requests") or 0)
    bad = int(logs[1] or 0)
    honeypot_hits = int(logs[2] or 0)
    evidence = honeypot_hits + credentials[0] + files
    return {
        "total": total,
        "bad": bad,
        "good": max(total - bad, 0),
        "bad_share": round(bad * 100 / total) if total else 0,
        "deleted": int(stats.get("pruned_total") or 0),
        "access_rows": logs[0],
        "honeypot_hits": honeypot_hits,
        "honeypot_traps": logs[3],
        "referers": logs[4],
        "credentials": credentials[0],
        "credentials_unique": credentials[1],
        "files": files,
        "campaigns": len(campaigns),
        "axes": behaviour_axes(stats.get("analyzed_metrics"), evidence),
        "analysed": bool(stats.get("analyzed_metrics")),
        "scores": stats.get("category_scores") or {},
        "score_max": score_scale(get_config().scoring_weights),
        **attack_stats,
    }


def get_ip_overview(ip: str, stats: dict[str, Any]) -> dict[str, Any]:
    """build_ip_overview behind the short per-IP cache."""
    key = f"ipoverview:{ip}"
    cached = get_cached_short(key)
    if cached:
        return cached
    overview = build_ip_overview(ip, stats)
    set_cached_short(key, overview)
    return overview


def template_stats(stats: dict[str, Any]) -> dict[str, Any]:
    """Stats for the IP detail template: scalars, plus the collections it reads."""
    list_on = stats.get("list_on") or {}
    prepared = {
        **stats,
        "blocklist_memberships": list(list_on),
        "reverse_dns": stats.get("reverse"),
    }
    return {
        key: value
        for key, value in prepared.items()
        if isinstance(value, (int, str, float, type(None), bool))
        or key in _TEMPLATE_COLLECTIONS
    }
