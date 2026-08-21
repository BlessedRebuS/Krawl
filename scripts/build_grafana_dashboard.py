#!/usr/bin/env python3
"""Generate grafana-dashboard.json and the ConfigMap wrapper from one definition.

This script is the source of truth for the dashboard. Run after changing anything
below:

    python3 scripts/build_grafana_dashboard.py

Outputs:
    grafana-dashboard.json            importable dashboard
    helm/files/grafana-dashboard.json generated copy the chart embeds (.Files.Get
                                      cannot reach outside the chart directory)
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DS = {"type": "prometheus", "uid": "${datasource}"}
SEL = '{job=~"$job"}'

# Counters are Redis-shared in scalable mode: every replica exposes the same value,
# so replicas are collapsed with max(), never sum().
MAX = "max"


def target(expr, legend=None, instant=False, ref="A"):
    t = {
        "datasource": DS,
        "editorMode": "code",
        "expr": expr,
        "range": not instant,
        "instant": instant,
        "refId": ref,
    }
    if legend:
        t["legendFormat"] = legend
    return t


def base(kind, title, x, y, w, h, targets, unit="short", desc=None):
    p = {
        "datasource": DS,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": targets,
        "title": title,
        "type": kind,
        "fieldConfig": {"defaults": {"unit": unit, "mappings": []}, "overrides": []},
    }
    if desc:
        p["description"] = desc
    return p


def stat(title, x, y, w, h, expr, unit="short", steps=None, color="blue", desc=None):
    p = base("stat", title, x, y, w, h, [target(expr, instant=True)], unit, desc)
    p["fieldConfig"]["defaults"]["color"] = {"mode": "thresholds"}
    p["fieldConfig"]["defaults"]["thresholds"] = {
        "mode": "absolute",
        "steps": steps or [{"color": color, "value": None}],
    }
    p["options"] = {
        "colorMode": "value",
        # No sparkline: these are single instant values, an "area" graph on one
        # point is decoration that implies a trend the panel does not have.
        "graphMode": "none",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
        "textMode": "auto",
        # Grafana sizes stat text to fill the panel; uncapped it renders a number
        # four lines tall in a three-row panel.
        "text": {"valueSize": 30, "titleSize": 12},
    }
    return p


def timeseries(
    title, x, y, w, h, targets, unit="short", desc=None, stack=False, steps=None,
    legend_table=False, fill=0, log=False,
):
    p = base("timeseries", title, x, y, w, h, targets, unit, desc)
    d = p["fieldConfig"]["defaults"]
    d["color"] = {"mode": "palette-classic"}
    # A log axis cannot include zero; forcing min=0 there breaks the scale.
    if not log:
        d["min"] = 0
    d["custom"] = {
        "axisBorderShow": False,
        "axisCenteredZero": False,
        "axisColorMode": "text",
        "axisLabel": "",
        "axisPlacement": "auto",
        "barAlignment": 0,
        "drawStyle": "line",
        "fillOpacity": fill,
        "gradientMode": "none",
        "hideFrom": {"legend": False, "tooltip": False, "viz": False},
        "insertNulls": False,
        "lineInterpolation": "smooth",
        "lineWidth": 2,
        "pointSize": 5,
        "scaleDistribution": {"log": 10, "type": "log"} if log else {"type": "linear"},
        "showPoints": "never",
        "spanNulls": True,
        "stacking": {"group": "A", "mode": "normal" if stack else "none"},
        # Never "dashed": a threshold line forces the y-axis to span up to the
        # threshold, so a buffer that normally sits near zero renders as a flat
        # line pinned to the floor of an empty 0-10000 chart. The limit lives in
        # the panel description instead.
        "thresholdsStyle": {"mode": "off"},
    }
    # A bare base step: no invented "red above 80" line on panels where 80 means nothing.
    d["thresholds"] = {"mode": "absolute", "steps": steps or [{"color": "green", "value": None}]}
    p["options"] = {
        "legend": {
            "calcs": ["lastNotNull", "max"] if legend_table else [],
            "displayMode": "table" if legend_table else "list",
            "placement": "right" if legend_table else "bottom",
            "showLegend": True,
        },
        "tooltip": {"mode": "multi", "sort": "desc"},
    }
    return p


def bargauge(title, x, y, w, h, expr, legend, unit="short", desc=None):
    p = base("bargauge", title, x, y, w, h, [target(expr, legend, instant=True)], unit, desc)
    p["fieldConfig"]["defaults"]["color"] = {"mode": "palette-classic"}
    p["fieldConfig"]["defaults"]["thresholds"] = {
        "mode": "absolute",
        "steps": [{"color": "green", "value": None}],
    }
    p["options"] = {
        "displayMode": "gradient",
        "orientation": "horizontal",
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
        "showUnfilled": True,
        "valueMode": "text",
        "sortBy": "Value",
        "sortOrder": "Descending",
        "minVizHeight": 16,
        "minVizWidth": 8,
        "namePlacement": "left",
    }
    return p


def multistat(title, x, y, w, h, expr, legend, unit="short", desc=None):
    """One tile per series. A linear bar gauge cannot show categories three orders
    of magnitude apart (288k good crawlers next to 27 regular users renders every
    other bar as a stub), and narrow panels truncate the category names."""
    p = base("stat", title, x, y, w, h, [target(expr, legend, instant=True)], unit, desc)
    p["fieldConfig"]["defaults"]["color"] = {"mode": "palette-classic"}
    p["options"] = {
        "colorMode": "value",
        "graphMode": "none",
        "justifyMode": "auto",
        "orientation": "horizontal",
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
        "textMode": "value_and_name",
        "text": {"valueSize": 22, "titleSize": 11},
        "wideLayout": True,
    }
    return p


def row(title, y):
    return {
        "collapsed": False,
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
        "panels": [],
        "title": title,
        "type": "row",
    }


# Threshold palettes
OK_WARN_CRIT = lambda w, c: [
    {"color": "green", "value": None},
    {"color": "yellow", "value": w},
    {"color": "red", "value": c},
]
OK_CRIT = lambda c: [{"color": "green", "value": None}, {"color": "red", "value": c}]

panels = []

# ---------------------------------------------------------------- Overview
panels.append(row("Overview", 0))

# Row 1: activity inside the selected time range — these follow the time picker.
for i, (title, metric, color) in enumerate(
    [
        ("Accesses", "krawl_accesses_total", "blue"),
        ("Honeypot triggers", "krawl_honeypot_triggers_total", "orange"),
        ("Credentials captured", "krawl_credentials_captured_total", "red"),
        ("Attack detections", "krawl_attack_detections_total", "red"),
    ]
):
    panels.append(
        stat(
            f"{title} (selected range)",
            i * 6,
            1,
            6,
            3,
            f"{MAX}(increase({metric}{SEL}[$__range]))",
            color=color,
            desc="Scoped to the dashboard time range — change the time picker and this "
            "number changes with it.",
        )
    )

# Row 2: lifetime cardinality — deliberately NOT range-scoped, and titled so.
for i, (title, expr, desc) in enumerate(
    [
        (
            "Unique IPs (all time)",
            f"{MAX}(krawl_unique_ips_total{SEL})",
            "Distinct client IPs ever observed. Not affected by the time picker.",
        ),
        (
            "Unique paths (all time)",
            f"{MAX}(krawl_unique_paths_total{SEL})",
            "Distinct request paths ever observed. Not affected by the time picker.",
        ),
        (
            "Honeypot IPs (all time)",
            f"{MAX}(krawl_honeypot_ips_total{SEL})",
            "Distinct IPs that tripped a honeypot at least once. Not affected by the "
            "time picker.",
        ),
        (
            "AI pages generated today",
            f"{MAX}(krawl_generated_pages_today{SEL})",
            "Resets at midnight. Compare against ai.max_daily_requests.",
        ),
    ]
):
    panels.append(stat(title, i * 6, 4, 6, 3, expr, color="text", desc=desc))

# ---------------------------------------------------------- Traffic & Attacks
panels.append(row("Traffic & Attacks", 7))

panels.append(
    timeseries(
        "Access rate",
        0,
        8,
        12,
        7,
        [target(f"{MAX} by (job) (rate(krawl_accesses_total{SEL}[$__rate_interval])) * 60", "{{job}}")],
        unit="cpm",
        fill=10,
        desc="Requests per minute. Honeypots are low-volume by nature; per-second "
        "rates would pin this to zero.",
    )
)
panels.append(
    timeseries(
        "Attack detections by type",
        12,
        8,
        12,
        7,
        [
            target(
                f"{MAX} by (attack_type) (rate(krawl_attack_detections_total{SEL}[$__rate_interval])) * 60",
                "{{attack_type}}",
            )
        ],
        unit="cpm",
        legend_table=True,
        desc="Detections per minute, split by attack classification.",
    )
)
panels.append(
    timeseries(
        "Honeypot & credential capture rate",
        0,
        15,
        12,
        7,
        [
            target(
                f"{MAX} by (job) (rate(krawl_honeypot_triggers_total{SEL}[$__rate_interval])) * 60",
                "honeypot triggers",
            ),
            target(
                f"{MAX} by (job) (rate(krawl_credentials_captured_total{SEL}[$__rate_interval])) * 60",
                "credentials captured",
                ref="B",
            ),
        ],
        unit="cpm",
        fill=10,
        desc="Per minute. A credential line above zero means someone is submitting "
        "logins to the fake forms.",
    )
)
panels.append(
    bargauge(
        "Attack detections by type (selected range)",
        12,
        15,
        12,
        7,
        f"{MAX} by (attack_type) (increase(krawl_attack_detections_total{SEL}[$__range]))",
        "{{attack_type}}",
        desc="Sorted by volume and scoped to the time range. Replaces a donut: bar "
        "length stays comparable past a handful of attack types.",
    )
)

# ------------------------------------------------------------ Classification
panels.append(row("Classification", 22))

panels.append(
    timeseries(
        "Clients by classification over time",
        0,
        23,
        14,
        7,
        [target(f"{MAX} by (category) (krawl_clients_total{SEL})", "{{category}}")],
        log=True,
        desc="Log scale: good crawlers outnumber regular users by orders of "
        "magnitude, and on a linear axis every category but the largest is a flat "
        "line on the floor.",
    )
)
panels.append(
    multistat(
        "Clients by classification (current)",
        14,
        23,
        5,
        7,
        f"{MAX} by (category) (krawl_clients_total{SEL})",
        "{{category}}",
        desc="Current count per reputation category.",
    )
)
panels.append(
    stat(
        "Timed-out IPs",
        19,
        23,
        5,
        4,
        f"{MAX}(krawl_timed_out_ips{SEL})",
        steps=OK_WARN_CRIT(50, 500),
        desc="IPs currently serving an automatic rate-limit time-ban "
        "(crawl.ban_duration_seconds).",
    )
)
panels.append(
    stat(
        "Auth-locked IPs",
        19,
        27,
        5,
        3,
        f"{MAX}(krawl_auth_locked_ips{SEL})",
        steps=OK_CRIT(1),
        desc="IPs locked out of dashboard login by bruteforce protection. Anything "
        "above zero means someone is guessing your dashboard password.",
    )
)

# ------------------------------------------------------------- System health
panels.append(row("System health", 30))

panels.append(
    timeseries(
        "Access-log write buffer depth",
        0,
        31,
        12,
        6,
        # Per-process buffer, NOT the Redis-shared counters: one line per pod, no
        # max() collapse, so a single replica falling behind stays visible.
        [target(f"krawl_write_buffer_rows{SEL}", "{{instance}}")],
        fill=10,
        desc="Rows waiting to be flushed to the database. Normally near zero — the "
        "flush task drains it every 30s, so a sawtooth close to the axis is healthy. "
        "Sustained growth means the "
        "flush task is falling behind and shows up as RSS growth long before "
        "anything else — investigate above 10000.",
    )
)
panels.append(
    timeseries(
        "Dashboard warmup step duration",
        12,
        31,
        12,
        6,
        [target(f"{MAX} by (step) (krawl_dashboard_warmup_duration_seconds{SEL})", "{{step}}")],
        unit="s",
        legend_table=True,
        desc="Time taken by each warmup sub-step. If a step approaches the 5 minute "
        "warmup interval, disable cache_warmup or cut warmup_pages.",
    )
)
panels.append(
    stat(
        "Access-log rows dropped (selected range)",
        0,
        37,
        8,
        3,
        # Each pod drops its own rows, so these genuinely add up across replicas.
        f"sum(increase(krawl_write_buffer_dropped_total{SEL}[$__range]))",
        steps=OK_CRIT(1),
        desc="Rows discarded because the write buffer was full — silent data loss. "
        "Any non-zero value needs attention.",
    )
)
panels.append(
    stat(
        "Unenriched IPs",
        8,
        37,
        8,
        3,
        f"{MAX}(krawl_unenriched_ips{SEL})",
        steps=OK_WARN_CRIT(500, 5000),
        desc="IPs still awaiting geolocation/reputation enrichment (capped at 1000 per "
        "collection).",
    )
)
panels.append(
    stat(
        "IPs needing reevaluation",
        16,
        37,
        8,
        3,
        f"{MAX}(krawl_ips_needing_reevaluation{SEL})",
        steps=OK_WARN_CRIT(100, 1000),
        desc="IPs flagged for rescoring by the analyzer. A persistently high value "
        "means the analyzer cannot keep up with traffic.",
    )
)

dashboard = {
    "annotations": {
        "list": [
            {
                "builtIn": 1,
                "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                "enable": True,
                "hide": True,
                "iconColor": "rgba(0, 211, 255, 1)",
                "name": "Annotations & Alerts",
                "type": "dashboard",
            }
        ]
    },
    "description": (
        "Krawl honeypot metrics. Counters are aggregated with max() because every "
        "replica exposes the same shared (Redis-backed) value, so sum() would multiply "
        "by the pod count. Panels titled '(selected range)' follow the time picker; "
        "'(all time)' panels are lifetime totals and do not."
    ),
    "editable": True,
    "fiscalYearStartMonth": 0,
    "graphTooltip": 1,
    "id": None,
    "links": [],
    "panels": panels,
    "preload": False,
    "refresh": "30s",
    "schemaVersion": 42,
    "tags": ["krawl", "honeypot", "security"],
    "templating": {
        "list": [
            {
                "current": {"text": "Prometheus", "value": "prometheus"},
                "includeAll": False,
                "label": "Datasource",
                "name": "datasource",
                "options": [],
                "query": "prometheus",
                "refresh": 1,
                "regex": "",
                "type": "datasource",
            },
            {
                # Without this, one Prometheus scraping two Krawl deployments merges
                # them inside max() with no visible sign.
                "allValue": ".*",
                "current": {"text": "All", "value": "$__all"},
                "datasource": DS,
                "definition": "label_values(krawl_accesses_total, job)",
                "includeAll": True,
                "label": "Job",
                "multi": True,
                "name": "job",
                "options": [],
                "query": {
                    "qryType": 1,
                    "query": "label_values(krawl_accesses_total, job)",
                    "refId": "PrometheusVariableQueryEditor-VariableQuery",
                },
                "refresh": 1,
                "regex": "",
                "sort": 1,
                "type": "query",
            },
        ]
    },
    "time": {"from": "now-6h", "to": "now"},
    "timepicker": {},
    "timezone": "browser",
    "title": "Krawl Honeypot",
    "uid": "krawl-honeypot",
    "version": 1,
    "weekStart": "",
}

body = json.dumps(dashboard, indent=2) + "\n"
(ROOT / "grafana-dashboard.json").write_text(body)
# Helm ships the same file via .Files.Get; the chart cannot read outside its own
# directory, so it gets a copy rather than a symlink.
(ROOT / "helm" / "files" / "grafana-dashboard.json").write_text(body)

print(f"wrote grafana-dashboard.json and helm/files/grafana-dashboard.json "
      f"({len(panels)} panels)")
