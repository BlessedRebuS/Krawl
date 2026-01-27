#!/usr/bin/env python3

"""
Dashboard template for viewing honeypot statistics.
Customize this template to change the dashboard appearance.
"""

import html
from datetime import datetime
from zoneinfo import ZoneInfo


def _escape(value) -> str:
    """Escape HTML special characters to prevent XSS attacks."""
    if value is None:
        return ""
    return html.escape(str(value))


def format_timestamp(iso_timestamp: str, time_only: bool = False) -> str:
    """Format ISO timestamp for display with timezone conversion

    Args:
        iso_timestamp: ISO format timestamp string (UTC)
        time_only: If True, return only HH:MM:SS, otherwise full datetime
    """
    try:
        # Parse UTC timestamp
        dt = datetime.fromisoformat(iso_timestamp)
        if time_only:
            return dt.strftime("%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        # Fallback for old format
        return (
            iso_timestamp.split("T")[1][:8] if "T" in iso_timestamp else iso_timestamp
        )


def generate_dashboard(stats: dict, dashboard_path: str = "") -> str:
    """Generate dashboard HTML with access statistics

    Args:
        stats: Statistics dictionary
        dashboard_path: The secret dashboard path for generating API URLs
    """

    # Generate suspicious accesses rows with clickable IPs
    suspicious_rows = (
        "\n".join([f"""<tr class="ip-row" data-ip="{_escape(log["ip"])}">
            <td class="ip-clickable">{_escape(log["ip"])}</td>
            <td>{_escape(log["path"])}</td>
            <td style="word-break: break-all;">{_escape(log["user_agent"][:60])}</td>
            <td>{format_timestamp(log["timestamp"], time_only=True)}</td>
        </tr>
        <tr class="ip-stats-row" id="stats-row-suspicious-{_escape(log["ip"]).replace(".", "-")}" style="display: none;">
            <td colspan="4" class="ip-stats-cell">
                <div class="ip-stats-dropdown">
                    <div class="loading">Loading stats...</div>
                </div>
            </td>
        </tr>""" for log in stats["recent_suspicious"][-10:]])
        or '<tr><td colspan="4" style="text-align:center;">No suspicious activity detected</td></tr>'
    )

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Krawl Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css" />
    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            position: relative;
        }}
        h1 {{
            color: #58a6ff;
            text-align: center;
            margin-bottom: 40px;
        }}
        .download-section {{
            position: absolute;
            top: 0;
            right: 0;
        }}
        .download-btn {{
            display: inline-block;
            padding: 8px 14px;
            background: #238636;
            color: #ffffff;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            font-size: 13px;
            transition: background 0.2s;
            border: 1px solid #2ea043;
        }}
        .download-btn:hover {{
            background: #2ea043;
        }}
        .download-btn:active {{
            background: #1f7a2f;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card.alert {{
            border-color: #f85149;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            color: #58a6ff;
        }}
        .stat-value.alert {{
            color: #f85149;
        }}
        .stat-label {{
            font-size: 14px;
            color: #8b949e;
            margin-top: 5px;
        }}
        .table-container {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        h2 {{
            color: #58a6ff;
            margin-top: 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }}
        th {{
            background: #0d1117;
            color: #58a6ff;
            font-weight: 600;
        }}
        tr:hover {{
            background: #1c2128;
        }}
        .rank {{
            color: #8b949e;
            font-weight: bold;
        }}
        .alert-section {{
            background: #1c1917;
            border-left: 4px solid #f85149;
        }}
        th.sortable {{
            cursor: pointer;
            user-select: none;
            position: relative;
            padding-right: 24px;
        }}
        th.sortable:hover {{
            background: #1c2128;
        }}
        th.sortable::after {{
            content: '⇅';
            position: absolute;
            right: 8px;
            opacity: 0.5;
            font-size: 12px;
        }}
        th.sortable.asc::after {{
            content: '▲';
            opacity: 1;
        }}
        th.sortable.desc::after {{
            content: '▼';
            opacity: 1;
        }}
        tbody {{
            transition: opacity 0.1s ease;
        }}
        tbody {{
            animation: fadeIn 0.3s ease-in;
        }}
        .ip-row {{
            transition: background-color 0.2s;
        }}
        .ip-clickable {{
            cursor: pointer;
            color: #58a6ff !important;
            font-weight: 500;
            text-decoration: underline;
            text-decoration-style: dotted;
            text-underline-offset: 3px;
        }}
        .ip-clickable:hover {{
            color: #79c0ff !important;
            text-decoration-style: solid;
            background: #1c2128;
        }}
        .ip-stats-row {{
            background: #0d1117;
        }}
        .ip-stats-cell {{
            padding: 0 !important;
        }}
        .ip-stats-dropdown {{
            margin-top: 10px;
            padding: 15px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            font-size: 13px;
            display: flex;
            gap: 20px;
        }}
        .stats-left {{
            flex: 1;
        }}
        .stats-right {{
            flex: 0 0 200px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }}
        .radar-chart {{
            position: relative;
            width: 220px;
            height: 220px;
            overflow: visible;
        }}
        .radar-legend {{
            margin-top: 10px;
            font-size: 11px;
        }}
        .radar-legend-item {{
            display: flex;
            align-items: center;
            gap: 6px;
            margin: 3px 0;
        }}
        .radar-legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 2px;
        }}
        .ip-stats-dropdown .loading {{
            color: #8b949e;
            font-style: italic;
        }}
        .stat-row {{
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid #21262d;
        }}
        .stat-row:last-child {{
            border-bottom: none;
        }}
        .stat-label-sm {{
            color: #8b949e;
            font-weight: 500;
        }}
        .stat-value-sm {{
            color: #58a6ff;
            font-weight: 600;
        }}
        .category-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .category-attacker {{
            background: #f851491a;
            color: #f85149;
            border: 1px solid #f85149;
        }}
        .category-good-crawler {{
            background: #3fb9501a;
            color: #3fb950;
            border: 1px solid #3fb950;
        }}
        .category-bad-crawler {{
            background: #f0883e1a;
            color: #f0883e;
            border: 1px solid #f0883e;
        }}
        .category-regular-user {{
            background: #58a6ff1a;
            color: #58a6ff;
            border: 1px solid #58a6ff;
        }}
        .category-unknown {{
            background: #8b949e1a;
            color: #8b949e;
            border: 1px solid #8b949e;
        }}
        .timeline-section {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #30363d;
        }}
        .timeline-container {{
            display: flex;
            gap: 20px;
            min-height: 200px;
        }}
        .timeline-column {{
            flex: 1;
            min-width: 0;
            overflow: auto;
            max-height: 350px;
        }}
        .timeline-column:first-child {{
            flex: 1.5;
        }}
        .timeline-column:last-child {{
            flex: 1;
        }}
        .timeline-header {{
            color: #58a6ff;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid #30363d;
        }}
        .reputation-title {{
            color: #8b949e;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 8px;
        }}
        .reputation-badge {{
            display: inline-flex;
            align-items: center;
            gap: 3px;
            padding: 4px 8px;
            background: #161b22;
            border: 1px solid #f851494d;
            border-radius: 4px;
            font-size: 11px;
            color: #f85149;
            text-decoration: none;
            transition: all 0.2s;
            margin-bottom: 6px;
            margin-right: 6px;
            white-space: nowrap;
        }}
        .reputation-badge:hover {{
            background: #1c2128;
            border-color: #f85149;
        }}
        .reputation-clean {{
            display: inline-flex;
            align-items: center;
            gap: 3px;
            padding: 4px 8px;
            background: #161b22;
            border: 1px solid #3fb9504d;
            border-radius: 4px;
            font-size: 11px;
            color: #3fb950;
            margin-bottom: 6px;
        }}
        .timeline {{
            position: relative;
            padding-left: 28px;
        }}
        .timeline::before {{
            content: '';
            position: absolute;
            left: 11px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: #30363d;
        }}
        .timeline-item {{
            position: relative;
            padding-bottom: 12px;
            font-size: 12px;
        }}
        .timeline-item:last-child {{
            padding-bottom: 0;
        }}
        .timeline-marker {{
            position: absolute;
            left: -23px;
            width: 14px;
            height: 14px;
            border-radius: 50%;
            border: 2px solid #0d1117;
        }}
        .timeline-marker.attacker {{ background: #f85149; }}
        .timeline-marker.good-crawler {{ background: #3fb950; }}
        .timeline-marker.bad-crawler {{ background: #f0883e; }}
        .timeline-marker.regular-user {{ background: #58a6ff; }}
        .timeline-marker.unknown {{ background: #8b949e; }}
        .tabs-container {{
            border-bottom: 1px solid #30363d;
            margin-bottom: 30px;
            display: flex;
            gap: 2px;
            background: #161b22;
            border-radius: 6px 6px 0 0;
            overflow-x: auto;
            overflow-y: hidden;
        }}
        .tab-button {{
            padding: 12px 20px;
            background: transparent;
            border: none;
            color: #8b949e;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            white-space: nowrap;
            transition: all 0.2s;
            border-bottom: 3px solid transparent;
            position: relative;
            bottom: -1px;
        }}
        .tab-button:hover {{
            color: #c9d1d9;
            background: #1c2128;
        }}
        .tab-button.active {{
            color: #58a6ff;
            border-bottom-color: #58a6ff;
        }}
        .tab-content {{
            display: none;
        }}
        .tab-content.active {{
            display: block;
        }}
        .ip-stats-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .ip-stats-table th, .ip-stats-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }}
        .ip-stats-table th {{
            background: #0d1117;
            color: #58a6ff;
            font-weight: 600;
        }}
        .ip-stats-table tr:hover {{
            background: #1c2128;
        }}
        .ip-detail-modal {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }}
        .ip-detail-modal.show {{
            display: flex;
        }}
        .ip-detail-content {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 30px;
            max-width: 900px;
            max-height: 90vh;
            overflow-y: auto;
            position: relative;
        }}
        .ip-detail-close {{
            position: absolute;
            top: 15px;
            right: 15px;
            background: none;
            border: none;
            color: #8b949e;
            font-size: 24px;
            cursor: pointer;
            padding: 0;
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .ip-detail-close:hover {{
            color: #c9d1d9;
        }}
        #attacker-map {{
            background: #0d1117 !important;
        }}
        .leaflet-container {{
            background: #0d1117 !important;
        }}
        .leaflet-tile {{
            filter: none;
        }}
        .leaflet-popup-content-wrapper {{
            background-color: #161b22;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 4px;
        }}
        .leaflet-popup-content-wrapper a {{
            color: #58a6ff;
        }}
        .leaflet-popup-tip {{
            background: #161b22;
            border-top: 6px solid #30363d;
        }}
        /* Remove the default leaflet icon background */
        .ip-custom-marker {{
            background: none !important;
            border: none !important;
        }}
        .ip-marker {{
            border: 2px solid #fff;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            font-weight: bold;
            color: white;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .ip-marker:hover {{
            transform: scale(1.15);
        }}
        .marker-attacker {{
            background: #f85149;
            box-shadow: 0 0 8px rgba(248, 81, 73, 0.8), inset 0 0 4px rgba(248, 81, 73, 0.5);
        }}
        .marker-attacker:hover {{
            box-shadow: 0 0 15px rgba(248, 81, 73, 1), inset 0 0 6px rgba(248, 81, 73, 0.7);
        }}
        .marker-bad_crawler {{
            background: #f0883e;
            box-shadow: 0 0 8px rgba(240, 136, 62, 0.8), inset 0 0 4px rgba(240, 136, 62, 0.5);
        }}
        .marker-bad_crawler:hover {{
            box-shadow: 0 0 15px rgba(240, 136, 62, 1), inset 0 0 6px rgba(240, 136, 62, 0.7);
        }}
        .marker-good_crawler {{
            background: #3fb950;
            box-shadow: 0 0 8px rgba(63, 185, 80, 0.8), inset 0 0 4px rgba(63, 185, 80, 0.5);
        }}
        .marker-good_crawler:hover {{
            box-shadow: 0 0 15px rgba(63, 185, 80, 1), inset 0 0 6px rgba(63, 185, 80, 0.7);
        }}
        .marker-regular_user {{
            background: #58a6ff;
            box-shadow: 0 0 8px rgba(88, 166, 255, 0.8), inset 0 0 4px rgba(88, 166, 255, 0.5);
        }}
        .marker-regular_user:hover {{
            box-shadow: 0 0 15px rgba(88, 166, 255, 1), inset 0 0 6px rgba(88, 166, 255, 0.7);
        }}
        .marker-unknown {{
            background: #8b949e;
            box-shadow: 0 0 8px rgba(139, 148, 158, 0.8), inset 0 0 4px rgba(139, 148, 158, 0.5);
        }}
        .marker-unknown:hover {{
            box-shadow: 0 0 15px rgba(139, 148, 158, 1), inset 0 0 6px rgba(139, 148, 158, 0.7);
        }}
        .leaflet-bottom.leaflet-right {{
            display: none !important;
        }}
        #attack-types-chart {{
            max-height: 400px;
        }}

    </style>
</head>
<body>
    <div class="container">
        <div class="download-section">
            <a href="{dashboard_path}/api/download/malicious_ips.txt" class="download-btn" download>
            Export Malicious IPs
            </a>
        </div>
        <h1>Krawl Dashboard</h1>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats['total_accesses']}</div>
                <div class="stat-label">Total Accesses</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['unique_ips']}</div>
                <div class="stat-label">Unique IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['unique_paths']}</div>
                <div class="stat-label">Unique Paths</div>
            </div>
            <div class="stat-card alert">
                <div class="stat-value alert">{stats['suspicious_accesses']}</div>
                <div class="stat-label">Suspicious Accesses</div>
            </div>
            <div class="stat-card alert">
                <div class="stat-value alert">{stats.get('honeypot_ips', 0)}</div>
                <div class="stat-label">Honeypot Caught</div>
            </div>
            <div class="stat-card alert">
                <div class="stat-value alert">{len(stats.get('credential_attempts', []))}</div>
                <div class="stat-label">Credentials Captured</div>
            </div>
            <div class="stat-card alert">
                <div class="stat-value alert">{stats.get('unique_attackers', 0)}</div>
                <div class="stat-label">Unique Attackers</div>
            </div>
        </div>

        <div class="tabs-container">
            <a class="tab-button active" href="#overview">Overview</a>
            <a class="tab-button" href="#ip-stats">Attacks</a>
        </div>

        <div id="overview" class="tab-content active">
            <div class="table-container alert-section">
            <h2>Recent Suspicious Activity</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Path</th>
                        <th>User-Agent</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {suspicious_rows}
                </tbody>
            </table>
        </div>

        <div class="table-container alert-section">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
                <h2 style="margin: 0;">Honeypot Triggers by IP</h2>
                <div class="pagination-controls" id="honeypot-pagination" style="display: flex; align-items: center; gap: 12px; padding: 0; background: transparent;">
                    <div style="display: flex; align-items: center; gap: 6px; color: #6e7681; font-weight: 400; font-size: 12px;">
                        <span>Page <span class="current-page">1</span>/<span class="total-pages">1</span></span>
                        <span style="color: #6e7681;">•</span>
                        <span><span class="total-records">0</span> total</span>
                    </div>
                    <button class="pagination-btn" onclick="previousPage('honeypot')" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">← Prev</button>
                    <button class="pagination-btn" onclick="nextPage('honeypot')" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">Next →</button>
                </div>
            </div>
            <table id="honeypot-table" class="overview-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Accessed Paths</th>
                        <th class="sortable" data-sort="count" data-table="honeypot">Count</th>
                    </tr>
                </thead>
                <tbody id="honeypot-tbody">
                    <tr><td colspan="4" style="text-align: center;">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div style="display: flex; gap: 20px; margin-bottom: 20px;">
        <div class="table-container" style="flex: 1;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
                <h2 style="margin: 0;">Top IP Addresses</h2>
                <div class="pagination-controls" id="top-ips-pagination" style="display: flex; align-items: center; gap: 12px; padding: 0; background: transparent;">
                    <div style="display: flex; align-items: center; gap: 6px; color: #6e7681; font-weight: 400; font-size: 12px;">
                        <span>Page <span class="current-page">1</span>/<span class="total-pages">1</span></span>
                        <span style="color: #6e7681;">•</span>
                        <span><span class="total-records">0</span> total</span>
                    </div>
                    <button class="pagination-btn" onclick="previousPage('top-ips')" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">← Prev</button>
                    <button class="pagination-btn" onclick="nextPage('top-ips')" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">Next →</button>
                </div>
            </div>
            <table id="top-ips-table" class="overview-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th class="sortable" data-sort="count" data-table="top-ips">Access Count</th>
                    </tr>
                </thead>
                <tbody id="top-ips-tbody">
                    <tr><td colspan="3" style="text-align: center;">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="table-container" style="flex: 1;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
                <h2 style="margin: 0;">Top User-Agents</h2>
                <div class="pagination-controls" id="top-ua-pagination" style="display: flex; align-items: center; gap: 12px; padding: 0; background: transparent;">
                    <div style="display: flex; align-items: center; gap: 6px; color: #6e7681; font-weight: 400; font-size: 12px;">
                        <span>Page <span class="current-page">1</span>/<span class="total-pages">1</span></span>
                        <span style="color: #6e7681;">•</span>
                        <span><span class="total-records">0</span> total</span>
                    </div>
                    <button class="pagination-btn" onclick="previousPage('top-ua')" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">← Prev</button>
                    <button class="pagination-btn" onclick="nextPage('top-ua')" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">Next →</button>
                </div>
            </div>
            <table id="top-ua-table" class="overview-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>User-Agent</th>
                        <th class="sortable" data-sort="count" data-table="top-ua">Count</th>
                    </tr>
                </thead>
                <tbody id="top-ua-tbody">
                    <tr><td colspan="3" style="text-align: center;">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        </div>
        </div>

        <div id="ip-stats" class="tab-content">
            <div class="table-container" style="margin-bottom: 30px;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;">
                    <h2 style="margin: 0;">IP Origins Map</h2>
                    <div style="display: flex; gap: 16px; align-items: center; flex-wrap: wrap;">
                        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; color: #c9d1d9; font-size: 13px;">
                            <input type="checkbox" id="filter-attacker" checked onchange="updateMapFilters()" style="cursor: pointer;">
                            <span style="color: #f85149;">● Attackers</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; color: #c9d1d9; font-size: 13px;">
                            <input type="checkbox" id="filter-bad-crawler" checked onchange="updateMapFilters()" style="cursor: pointer;">
                            <span style="color: #f0883e;">● Bad Crawlers</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; color: #c9d1d9; font-size: 13px;">
                            <input type="checkbox" id="filter-good-crawler" checked onchange="updateMapFilters()" style="cursor: pointer;">
                            <span style="color: #3fb950;">● Good Crawlers</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; color: #c9d1d9; font-size: 13px;">
                            <input type="checkbox" id="filter-regular-user" checked onchange="updateMapFilters()" style="cursor: pointer;">
                            <span style="color: #58a6ff;">● Regular Users</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; color: #c9d1d9; font-size: 13px;">
                            <input type="checkbox" id="filter-unknown" checked onchange="updateMapFilters()" style="cursor: pointer;">
                            <span style="color: #8b949e;">● Unknown</span>
                        </label>
                    </div>
                </div>
                <div id="attacker-map" style="height: 500px; border-radius: 6px; overflow: hidden; border: 1px solid #30363d; background: #161b22;">
                    <div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #8b949e;">Loading map...</div>
                </div>
            </div>

            <div class="table-container alert-section" style="position: relative;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
                    <h2 style="margin: 0;">Attackers by Total Requests</h2>
                    <div class="pagination-controls" style="display: flex; align-items: center; gap: 12px; padding: 0; background: transparent;">
                        <div style="display: flex; align-items: center; gap: 6px; color: #6e7681; font-weight: 400; font-size: 12px;">
                            <span>Page <span id="current-page">1</span>/<span id="total-pages">1</span></span>
                            <span style="color: #6e7681;">•</span>
                            <span><span id="total-attackers">0</span> total</span>
                        </div>
                        <button id="prev-page-btn" class="pagination-btn" onclick="previousPageIpStats()" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">← Prev</button>
                        <button id="next-page-btn" class="pagination-btn" onclick="nextPageIpStats()" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">Next →</button>
                    </div>
                </div>

                <table class="ip-stats-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>IP Address</th>
                            <th class="sortable" data-sort="total_requests">Total Requests</th>
                            <th>First Seen</th>
                            <th>Last Seen</th>
                            <th>Location</th>
                        </tr>
                    </thead>
                    <tbody id="ip-stats-tbody">
                        <!-- Dynamically populated -->
                    </tbody>
                </table>
            </div>

            <div class="table-container alert-section">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
                <h2 style="margin: 0;">Captured Credentials</h2>
                <div class="pagination-controls" id="credentials-pagination" style="display: flex; align-items: center; gap: 12px; padding: 0; background: transparent;">
                    <div style="display: flex; align-items: center; gap: 6px; color: #6e7681; font-weight: 400; font-size: 12px;">
                        <span>Page <span class="current-page">1</span>/<span class="total-pages">1</span></span>
                        <span style="color: #6e7681;">•</span>
                        <span><span class="total-records">0</span> total</span>
                    </div>
                    <button class="pagination-btn" onclick="previousPage('credentials')" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">← Prev</button>
                    <button class="pagination-btn" onclick="nextPage('credentials')" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">Next →</button>
                </div>
            </div>
            <table id="credentials-table" class="overview-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Username</th>
                        <th>Password</th>
                        <th>Path</th>
                        <th class="sortable" data-sort="timestamp" data-table="credentials">Time</th>
                    </tr>
                </thead>
                <tbody id="credentials-tbody">
                    <tr><td colspan="6" style="text-align: center;">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="table-container alert-section">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
                <h2 style="margin: 0;">Detected Attack Types</h2>
                <div class="pagination-controls" id="attacks-pagination" style="display: flex; align-items: center; gap: 12px; padding: 0; background: transparent;">
                    <div style="display: flex; align-items: center; gap: 6px; color: #6e7681; font-weight: 400; font-size: 12px;">
                        <span>Page <span class="current-page">1</span>/<span class="total-pages">1</span></span>
                        <span style="color: #6e7681;">•</span>
                        <span><span class="total-records">0</span> total</span>
                    </div>
                    <button class="pagination-btn" onclick="previousPage('attacks')" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">← Prev</button>
                    <button class="pagination-btn" onclick="nextPage('attacks')" style="padding: 6px 12px; background: #0969da; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; font-size: 12px; transition: background 0.2s;">Next →</button>
                </div>
            </div>
            <table id="attacks-table" class="overview-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Path</th>
                        <th>Attack Types</th>
                        <th>User-Agent</th>
                        <th class="sortable" data-sort="timestamp" data-table="attacks">Time</th>
                    </tr>
                </thead>
                <tbody id="attacks-tbody">
                    <tr><td colspan="6" style="text-align: center;">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="table-container alert-section" style="margin-top: 20px;">
            <h2>Most Recurring Attack Types</h2>
            <div style="position: relative; height: 400px; margin-top: 20px;">
                <canvas id="attack-types-chart"></canvas>
            </div>
        </div>
        </div>

        <div id="ip-detail-modal" class="ip-detail-modal">
            <div class="ip-detail-content">
                <button class="ip-detail-close" onclick="closeIpDetailModal()">×</button>
                <div id="ip-detail-body">
                    <!-- Dynamically populated -->
                </div>
            </div>
        </div>
    </div>
    <script>
        const DASHBOARD_PATH = '{dashboard_path}';

        function formatTimestamp(isoTimestamp) {{
            if (!isoTimestamp) return 'N/A';
            try {{
                const date = new Date(isoTimestamp);
                return date.toLocaleString('en-US', {{
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                    hour12: false
                }});
            }} catch (err) {{
                console.error('Error formatting timestamp:', err);
                return new Date(isoTimestamp).toLocaleString();
            }}
        }}

        document.querySelectorAll('th.sortable').forEach(header => {{
            header.addEventListener('click', function() {{
                const table = this.closest('table');
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                const sortType = this.getAttribute('data-sort');
                const columnIndex = Array.from(this.parentElement.children).indexOf(this);

                const isAscending = this.classList.contains('asc');

                table.querySelectorAll('th.sortable').forEach(th => {{
                    th.classList.remove('asc', 'desc');
                }});

                this.classList.add(isAscending ? 'desc' : 'asc');

                rows.sort((a, b) => {{
                    let aValue = a.cells[columnIndex].textContent.trim();
                    let bValue = b.cells[columnIndex].textContent.trim();

                    if (sortType === 'count') {{
                        aValue = parseInt(aValue) || 0;
                        bValue = parseInt(bValue) || 0;
                        return isAscending ? bValue - aValue : aValue - bValue;
                    }}

                    if (sortType === 'ip') {{
                        const ipToNum = ip => {{
                            const parts = ip.split('.');
                            if (parts.length !== 4) return 0;
                            return parts.reduce((acc, part, i) => acc + (parseInt(part) || 0) * Math.pow(256, 3 - i), 0);
                        }};
                        const aNum = ipToNum(aValue);
                        const bNum = ipToNum(bValue);
                        return isAscending ? bNum - aNum : aNum - bNum;
                    }}

                    if (isAscending) {{
                        return bValue.localeCompare(aValue);
                    }} else {{
                        return aValue.localeCompare(bValue);
                    }}
                }});

                rows.forEach(row => tbody.appendChild(row));
            }});
        }});

        document.querySelectorAll('.ip-clickable').forEach(cell => {{
            cell.addEventListener('click', async function(e) {{
                const row = e.currentTarget.closest('.ip-row');
                if (!row) return;

                const ip = row.getAttribute('data-ip');
                const statsRow = row.nextElementSibling;
                if (!statsRow || !statsRow.classList.contains('ip-stats-row')) return;

                const isVisible = getComputedStyle(statsRow).display !== 'none';

                document.querySelectorAll('.ip-stats-row').forEach(r => {{
                    r.style.display = 'none';
                }});

                if (isVisible) return;

                statsRow.style.display = 'table-row';

                const dropdown = statsRow.querySelector('.ip-stats-dropdown');

                if (dropdown) {{
                    dropdown.innerHTML = '<div class="loading">Loading stats...</div>';
                    try {{
                        const response = await fetch(`${{DASHBOARD_PATH}}/api/ip-stats/${{ip}}`, {{
                            cache: 'no-store',
                            headers: {{
                                'Cache-Control': 'no-cache',
                                'Pragma': 'no-cache'
                            }}
                        }});
                        if (!response.ok) throw new Error(`HTTP ${{response.status}}`);

                        const data = await response.json();
                        dropdown.innerHTML = data.error
                            ? `<div style="color:#f85149;">Error: ${{data.error}}</div>`
                            : formatIpStats(data);
                    }} catch (err) {{
                        dropdown.innerHTML = `<div style="color:#f85149;">Failed to load stats: ${{err.message}}</div>`;
                    }}
                }}
            }});
        }});

        function formatIpStats(stats) {{
            let html = '<div class="stats-left">';

            html += '<div class="stat-row">';
            html += '<span class="stat-label-sm">Total Requests:</span>';
            html += `<span class="stat-value-sm">${{stats.total_requests || 0}}</span>`;
            html += '</div>';

            html += '<div class="stat-row">';
            html += '<span class="stat-label-sm">First Seen:</span>';
            html += `<span class="stat-value-sm">${{formatTimestamp(stats.first_seen)}}</span>`;
            html += '</div>';

            html += '<div class="stat-row">';
            html += '<span class="stat-label-sm">Last Seen:</span>';
            html += `<span class="stat-value-sm">${{formatTimestamp(stats.last_seen)}}</span>`;
            html += '</div>';

            if (stats.country_code || stats.city) {{
                html += '<div class="stat-row">';
                html += '<span class="stat-label-sm">Location:</span>';
                html += `<span class="stat-value-sm">${{stats.city ? (stats.country_code ? `${{stats.city}}, ${{stats.country_code}}` : stats.city) : (stats.country_code || 'Unknown')}}</span>`;
                html += '</div>';
            }}

            if (stats.asn_org) {{
                html += '<div class="stat-row">';
                html += '<span class="stat-label-sm">ASN Org:</span>';
                html += `<span class="stat-value-sm">${{stats.asn_org}}</span>`;
                html += '</div>';
            }}

            if (stats.reputation_score !== null && stats.reputation_score !== undefined) {{
                html += '<div class="stat-row">';
                html += '<span class="stat-label-sm">Reputation Score:</span>';
                html += `<span class="stat-value-sm">${{stats.reputation_score}} ${{stats.reputation_source ? '(' + stats.reputation_source + ')' : ''}}</span>`;
                html += '</div>';
            }}

            if (stats.category) {{
                html += '<div class="stat-row">';
                html += '<span class="stat-label-sm">Category:</span>';
                const categoryClass = 'category-' + stats.category.toLowerCase().replace('_', '-');
                html += `<span class="category-badge ${{categoryClass}}">${{stats.category}}</span>`;
                html += '</div>';
            }}

            if (stats.category_history && stats.category_history.length > 0) {{
                html += '<div class="timeline-section">';
                html += '<div class="timeline-container">';
                
                // Timeline column
                html += '<div class="timeline-column">';
                html += '<div class="timeline-header">Behavior Timeline</div>';
                html += '<div class="timeline">';

                stats.category_history.forEach(change => {{
                    const categoryClass = change.new_category.toLowerCase().replace('_', '-');
                    const timestamp = formatTimestamp(change.timestamp);
                    const oldClass = change.old_category ? 'category-' + change.old_category.toLowerCase().replace('_', '-') : '';
                    const newClass = 'category-' + categoryClass;
                    
                    html += '<div class="timeline-item">';
                    html += `<div class="timeline-marker ${{categoryClass}}"></div>`;
                    html += '<div class="timeline-content">';
                    
                    if (change.old_category) {{
                        html += `<span class="category-badge ${{oldClass}}">${{change.old_category}}</span>`;
                        html += '<span style="color: #8b949e; margin: 0 4px;">→</span>';
                    }} else {{
                        html += '<span style="color: #8b949e;">Initial:</span>';
                    }}
                    
                    html += `<span class="category-badge ${{newClass}}">${{change.new_category}}</span>`;
                    html += `<div class="timeline-time">${{timestamp}}</div>`;
                    html += '</div>';
                    html += '</div>';
                }});

                html += '</div>';
                html += '</div>';
                
                // Reputation column
                html += '<div class="timeline-column">';
                
                if (stats.list_on && Object.keys(stats.list_on).length > 0) {{
                    html += '<div class="timeline-header">Listed On</div>';
                    const sortedSources = Object.entries(stats.list_on).sort((a, b) => a[0].localeCompare(b[0]));
                    
                    sortedSources.forEach(([source, url]) => {{
                        if (url && url !== 'N/A') {{
                            html += `<a href="${{url}}" target="_blank" rel="noopener noreferrer" class="reputation-badge" title="${{source}}">${{source}}</a>`;
                        }} else {{
                            html += `<span class="reputation-badge">${{source}}</span>`;
                        }}
                    }});
                }} else if (stats.country_code || stats.asn) {{
                    html += '<div class="timeline-header">Reputation</div>';
                    html += '<span class="reputation-clean" title="Not found on public blacklists">✓ Clean</span>';
                }}
                
                html += '</div>';
                html += '</div>';
                html += '</div>';
            }}

            html += '</div>';

            if (stats.category_scores && Object.keys(stats.category_scores).length > 0) {{
                html += '<div class="stats-right">';
                html += '<div style="font-size: 13px; font-weight: 600; color: #58a6ff; margin-bottom: 10px;">Category Score</div>';
                html += '<svg class="radar-chart" viewBox="-30 -30 260 260" preserveAspectRatio="xMidYMid meet">';

                const scores = {{
                    attacker: stats.category_scores.attacker || 0,
                    good_crawler: stats.category_scores.good_crawler || 0,
                    bad_crawler: stats.category_scores.bad_crawler || 0,
                    regular_user: stats.category_scores.regular_user || 0,
                    unknown: stats.category_scores.unknown || 0
                }};

                const maxScore = Math.max(...Object.values(scores), 1);
                const minVisibleRadius = 0.15;
                const normalizedScores = {{}};

                Object.keys(scores).forEach(key => {{
                    normalizedScores[key] = minVisibleRadius + (scores[key] / maxScore) * (1 - minVisibleRadius);
                }});

                const colors = {{
                    attacker: '#f85149',
                    good_crawler: '#3fb950',
                    bad_crawler: '#f0883e',
                    regular_user: '#58a6ff',
                    unknown: '#8b949e'
                }};

                const labels = {{
                    attacker: 'Attacker',
                    good_crawler: 'Good Bot',
                    bad_crawler: 'Bad Bot',
                    regular_user: 'User',
                    unknown: 'Unknown'
                }};

                const cx = 100, cy = 100, maxRadius = 75;
                for (let i = 1; i <= 5; i++) {{
                    const r = (maxRadius / 5) * i;
                    html += `<circle cx="${{cx}}" cy="${{cy}}" r="${{r}}" fill="none" stroke="#30363d" stroke-width="0.5"/>`;
                }}

                const angles = [0, 72, 144, 216, 288];
                const keys = ['good_crawler', 'regular_user', 'unknown', 'bad_crawler', 'attacker'];

                angles.forEach((angle, i) => {{
                    const rad = (angle - 90) * Math.PI / 180;
                    const x2 = cx + maxRadius * Math.cos(rad);
                    const y2 = cy + maxRadius * Math.sin(rad);
                    html += `<line x1="${{cx}}" y1="${{cy}}" x2="${{x2}}" y2="${{y2}}" stroke="#30363d" stroke-width="0.5"/>`;

                    const labelDist = maxRadius + 35;
                    const lx = cx + labelDist * Math.cos(rad);
                    const ly = cy + labelDist * Math.sin(rad);
                    html += `<text x="${{lx}}" y="${{ly}}" fill="#8b949e" font-size="12" text-anchor="middle" dominant-baseline="middle">${{labels[keys[i]]}}</text>`;
                }});

                let points = [];
                angles.forEach((angle, i) => {{
                    const normalizedScore = normalizedScores[keys[i]];
                    const rad = (angle - 90) * Math.PI / 180;
                    const r = normalizedScore * maxRadius;
                    const x = cx + r * Math.cos(rad);
                    const y = cy + r * Math.sin(rad);
                    points.push(`${{x}},${{y}}`);
                }});

                const dominantKey = Object.keys(scores).reduce((a, b) => scores[a] > scores[b] ? a : b);
                const dominantColor = colors[dominantKey];

                html += `<polygon points="${{points.join(' ')}}" fill="${{dominantColor}}" fill-opacity="0.4" stroke="${{dominantColor}}" stroke-width="2.5"/>`;

                angles.forEach((angle, i) => {{
                    const normalizedScore = normalizedScores[keys[i]];
                    const rad = (angle - 90) * Math.PI / 180;
                    const r = normalizedScore * maxRadius;
                    const x = cx + r * Math.cos(rad);
                    const y = cy + r * Math.sin(rad);
                    html += `<circle cx="${{x}}" cy="${{y}}" r="4.5" fill="${{colors[keys[i]]}}" stroke="#0d1117" stroke-width="2"/>`;
                }});

                html += '</svg>';

                html += '<div class="radar-legend">';
                keys.forEach(key => {{
                    html += '<div class="radar-legend-item">';
                    html += `<div class="radar-legend-color" style="background: ${{colors[key]}};"></div>`;
                    html += `<span style="color: #8b949e;">${{labels[key]}}: ${{scores[key]}} pt</span>`;
                    html += '</div>';
                }});
                html += '</div>';

                html += '</div>';
            }}

            return html;
        }}

        // Tab functionality with hash-based routing
        function switchTab(tabName) {{
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {{
                tab.classList.remove('active');
            }});
            
            // Remove active class from all buttons
            document.querySelectorAll('.tab-button').forEach(btn => {{
                btn.classList.remove('active');
            }});
            
            // Show selected tab
            const selectedTab = document.getElementById(tabName);
            const selectedButton = document.querySelector(`.tab-button[href="#${{tabName}}"]`);
            
            if (selectedTab) {{
                selectedTab.classList.add('active');
            }}
            if (selectedButton) {{
                selectedButton.classList.add('active');
            }}
            
            // Load data for this tab
            if (tabName === 'ip-stats') {{
                loadIpStatistics(1);
                // Load attack and credentials tables if not already loaded
                if (!overviewState.attacks.loaded) {{
                    loadOverviewTable('attacks');
                    overviewState.attacks.loaded = true;
                }}
                if (!overviewState.credentials.loaded) {{
                    loadOverviewTable('credentials');
                    overviewState.credentials.loaded = true;
                }}
            }}
        }}

        // Handle hash changes
        window.addEventListener('hashchange', function() {{
            const hash = window.location.hash.slice(1) || 'overview';
            switchTab(hash);
        }});

        // Initialize tabs on page load
        document.addEventListener('DOMContentLoaded', function() {{
            const hash = window.location.hash.slice(1) || 'overview';
            switchTab(hash);
        }});

        // Prevent default anchor behavior and use hash navigation
        document.querySelectorAll('.tab-button').forEach(button => {{
            button.addEventListener('click', function(e) {{
                e.preventDefault();
                const href = this.getAttribute('href');
                window.location.hash = href;
            }});
        }});

        // Handle sorting for IP stats table
        document.addEventListener('click', function(e) {{
            if (e.target.classList.contains('sortable') && e.target.closest('#ip-stats-tbody')) {{
                return; // Don't sort when inside tbody
            }}
            
            const sortHeader = e.target.closest('th.sortable');
            if (!sortHeader) return;

            const table = sortHeader.closest('table');
            if (!table || !table.classList.contains('ip-stats-table')) return;

            const sortField = sortHeader.getAttribute('data-sort');
            
            // Toggle sort order if clicking the same field
            if (currentSortBy === sortField) {{
                currentSortOrder = currentSortOrder === 'desc' ? 'asc' : 'desc';
            }} else {{
                currentSortBy = sortField;
                currentSortOrder = 'desc';
            }}

            // Update UI indicators
            table.querySelectorAll('th.sortable').forEach(th => {{
                th.classList.remove('asc', 'desc');
            }});
            sortHeader.classList.add(currentSortOrder);

            // Reload with new sort
            loadIpStatistics(1);
        }});

        let currentPage = 1;
        let totalPages = 1;
        let currentSortBy = "total_requests";
        let currentSortOrder = "desc";
        const PAGE_SIZE = 5;

        async function loadIpStatistics(page = 1) {{
            const tbody = document.getElementById('ip-stats-tbody');
            if (!tbody) {{
                console.error('IP stats tbody not found');
                return;
            }}
            
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">Loading...</td></tr>';
            
            try {{
                console.log('Fetching attackers from page:', page, 'sort:', currentSortBy, currentSortOrder);
                const response = await fetch(DASHBOARD_PATH + '/api/attackers?page=' + page + '&page_size=' + PAGE_SIZE + '&sort_by=' + currentSortBy + '&sort_order=' + currentSortOrder, {{
                    cache: 'no-store',
                    headers: {{
                        'Cache-Control': 'no-cache',
                        'Pragma': 'no-cache'
                    }}
                }});
                
                console.log('Response status:', response.status);
                
                if (!response.ok) throw new Error(`HTTP ${{response.status}}`);
                
                const data = await response.json();
                console.log('Received data:', data);
                
                if (!data.attackers || data.attackers.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No attackers on this page.</td></tr>';
                    currentPage = page;
                    totalPages = data.pagination?.total_pages || 1;
                    updatePaginationControls();
                    return;
                }}
                
                // Update pagination info
                currentPage = data.pagination.page;
                totalPages = data.pagination.total_pages;
                document.getElementById('current-page').textContent = currentPage;
                document.getElementById('total-pages').textContent = totalPages;
                document.getElementById('total-attackers').textContent = data.pagination.total_attackers;
                updatePaginationControls();
                
                let html = '';
                data.attackers.forEach((attacker, index) => {{
                    const rank = (currentPage - 1) * PAGE_SIZE + index + 1;
                    html += `<tr class="ip-row" data-ip="${{attacker.ip}}">
                        <td class="rank">${{rank}}</td>
                        <td class="ip-clickable">${{attacker.ip}}</td>
                        <td>${{attacker.total_requests}}</td>
                        <td>${{formatTimestamp(attacker.first_seen)}}</td>
                        <td>${{formatTimestamp(attacker.last_seen)}}</td>
                        <td>${{attacker.city ? (attacker.country_code ? `${{attacker.city}}, ${{attacker.country_code}}` : attacker.city) : (attacker.country_code || 'Unknown')}}</td>
                    </tr>
                    <tr class="ip-stats-row" id="stats-row-${{attacker.ip.replace('.', '-')}}" style="display: none;">
                        <td colspan="6" class="ip-stats-cell">
                            <div class="ip-stats-dropdown">
                                <div class="loading">Loading stats...</div>
                            </div>
                        </td>
                    </tr>`;
                }});
                
                tbody.innerHTML = html;
                console.log('Populated', data.attackers.length, 'attacker records');
                
                // Re-attach click listeners for expandable rows
                attachAttackerClickListeners();
            }} catch (err) {{
                console.error('Error loading attackers:', err);
                tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #f85149;">Failed to load: ${{err.message}}</td></tr>`;
            }}
        }}

        function updatePaginationControls() {{
            const prevBtn = document.getElementById('prev-page-btn');
            const nextBtn = document.getElementById('next-page-btn');
            
            if (prevBtn) prevBtn.disabled = currentPage <= 1;
            if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
        }}

        function previousPageIpStats() {{
            if (currentPage > 1) {{
                loadIpStatistics(currentPage - 1);
            }}
        }}

        function nextPageIpStats() {{
            if (currentPage < totalPages) {{
                loadIpStatistics(currentPage + 1);
            }}
        }}

        function attachAttackerClickListeners() {{
            document.querySelectorAll('#ip-stats-tbody .ip-clickable').forEach(cell => {{
                cell.addEventListener('click', async function(e) {{
                    const row = e.currentTarget.closest('.ip-row');
                    if (!row) return;

                    const ip = row.getAttribute('data-ip');
                    const statsRow = row.nextElementSibling;
                    if (!statsRow || !statsRow.classList.contains('ip-stats-row')) return;

                    const isVisible = getComputedStyle(statsRow).display !== 'none';

                    // Close other open rows
                    document.querySelectorAll('#ip-stats-tbody .ip-stats-row').forEach(r => {{
                        r.style.display = 'none';
                    }});

                    if (isVisible) return;

                    statsRow.style.display = 'table-row';

                    const dropdown = statsRow.querySelector('.ip-stats-dropdown');

                    if (dropdown) {{
                        dropdown.innerHTML = '<div class="loading">Loading stats...</div>';
                        try {{
                            const response = await fetch(`${{DASHBOARD_PATH}}/api/ip-stats/${{ip}}`, {{
                                cache: 'no-store',
                                headers: {{
                                    'Cache-Control': 'no-cache',
                                    'Pragma': 'no-cache'
                                }}
                            }});
                            if (!response.ok) throw new Error(`HTTP ${{response.status}}`);

                            const data = await response.json();
                            dropdown.innerHTML = data.error
                                ? `<div style="color:#f85149;">Error: ${{data.error}}</div>`
                                : formatIpStats(data);
                        }} catch (err) {{
                            dropdown.innerHTML = `<div style="color:#f85149;">Failed to load stats: ${{err.message}}</div>`;
                        }}
                    }}
                }});
            }});
        }}

        function attachTopIpsClickListeners() {{
            document.querySelectorAll('#top-ips-tbody .ip-clickable').forEach(cell => {{
                cell.addEventListener('click', async function(e) {{
                    const row = e.currentTarget.closest('.ip-row');
                    if (!row) return;

                    const ip = row.getAttribute('data-ip');
                    const statsRow = row.nextElementSibling;
                    if (!statsRow || !statsRow.classList.contains('ip-stats-row')) return;

                    const isVisible = getComputedStyle(statsRow).display !== 'none';

                    // Close other open rows in this table
                    document.querySelectorAll('#top-ips-tbody .ip-stats-row').forEach(r => {{
                        r.style.display = 'none';
                    }});

                    if (isVisible) return;

                    statsRow.style.display = 'table-row';

                    const dropdown = statsRow.querySelector('.ip-stats-dropdown');

                    if (dropdown) {{
                        dropdown.innerHTML = '<div class="loading">Loading stats...</div>';
                        try {{
                            const response = await fetch(`${{DASHBOARD_PATH}}/api/ip-stats/${{ip}}`, {{
                                cache: 'no-store',
                                headers: {{
                                    'Cache-Control': 'no-cache',
                                    'Pragma': 'no-cache'
                                }}
                            }});
                            if (!response.ok) throw new Error(`HTTP ${{response.status}}`);

                            const data = await response.json();
                            dropdown.innerHTML = data.error
                                ? `<div style="color:#f85149;">Error: ${{data.error}}</div>`
                                : formatIpStats(data);
                        }} catch (err) {{
                            dropdown.innerHTML = `<div style="color:#f85149;">Failed to load stats: ${{err.message}}</div>`;
                        }}
                    }}
                }});
            }});
        }}

        function attachHoneypotClickListeners() {{
            document.querySelectorAll('#honeypot-tbody .ip-clickable').forEach(cell => {{
                cell.addEventListener('click', async function(e) {{
                    const row = e.currentTarget.closest('.ip-row');
                    if (!row) return;

                    const ip = row.getAttribute('data-ip');
                    const statsRow = row.nextElementSibling;
                    if (!statsRow || !statsRow.classList.contains('ip-stats-row')) return;

                    const isVisible = getComputedStyle(statsRow).display !== 'none';

                    document.querySelectorAll('#honeypot-tbody .ip-stats-row').forEach(r => {{
                        r.style.display = 'none';
                    }});

                    if (isVisible) return;

                    statsRow.style.display = 'table-row';

                    const dropdown = statsRow.querySelector('.ip-stats-dropdown');

                    if (dropdown) {{
                        dropdown.innerHTML = '<div class="loading">Loading stats...</div>';
                        try {{
                            const response = await fetch(`${{DASHBOARD_PATH}}/api/ip-stats/${{ip}}`, {{
                                cache: 'no-store',
                                headers: {{
                                    'Cache-Control': 'no-cache',
                                    'Pragma': 'no-cache'
                                }}
                            }});
                            if (!response.ok) throw new Error(`HTTP ${{response.status}}`);

                            const data = await response.json();
                            dropdown.innerHTML = data.error
                                ? `<div style="color:#f85149;">Error: ${{data.error}}</div>`
                                : formatIpStats(data);
                        }} catch (err) {{
                            dropdown.innerHTML = `<div style="color:#f85149;">Failed to load stats: ${{err.message}}</div>`;
                        }}
                    }}
                }});
            }});
        }}

        function attachCredentialsClickListeners() {{
            document.querySelectorAll('#credentials-tbody .ip-clickable').forEach(cell => {{
                cell.addEventListener('click', async function(e) {{
                    const row = e.currentTarget.closest('.ip-row');
                    if (!row) return;

                    const ip = row.getAttribute('data-ip');
                    const statsRow = row.nextElementSibling;
                    if (!statsRow || !statsRow.classList.contains('ip-stats-row')) return;

                    const isVisible = getComputedStyle(statsRow).display !== 'none';

                    document.querySelectorAll('#credentials-tbody .ip-stats-row').forEach(r => {{
                        r.style.display = 'none';
                    }});

                    if (isVisible) return;

                    statsRow.style.display = 'table-row';

                    const dropdown = statsRow.querySelector('.ip-stats-dropdown');

                    if (dropdown) {{
                        dropdown.innerHTML = '<div class="loading">Loading stats...</div>';
                        try {{
                            const response = await fetch(`${{DASHBOARD_PATH}}/api/ip-stats/${{ip}}`, {{
                                cache: 'no-store',
                                headers: {{
                                    'Cache-Control': 'no-cache',
                                    'Pragma': 'no-cache'
                                }}
                            }});
                            if (!response.ok) throw new Error(`HTTP ${{response.status}}`);

                            const data = await response.json();
                            dropdown.innerHTML = data.error
                                ? `<div style="color:#f85149;">Error: ${{data.error}}</div>`
                                : formatIpStats(data);
                        }} catch (err) {{
                            dropdown.innerHTML = `<div style="color:#f85149;">Failed to load stats: ${{err.message}}</div>`;
                        }}
                    }}
                }});
            }});
        }}

        function attachAttacksClickListeners() {{
            document.querySelectorAll('#attacks-tbody .ip-clickable').forEach(cell => {{
                cell.addEventListener('click', async function(e) {{
                    const row = e.currentTarget.closest('.ip-row');
                    if (!row) return;

                    const ip = row.getAttribute('data-ip');
                    const statsRow = row.nextElementSibling;
                    if (!statsRow || !statsRow.classList.contains('ip-stats-row')) return;

                    const isVisible = getComputedStyle(statsRow).display !== 'none';

                    document.querySelectorAll('#attacks-tbody .ip-stats-row').forEach(r => {{
                        r.style.display = 'none';
                    }});

                    if (isVisible) return;

                    statsRow.style.display = 'table-row';

                    const dropdown = statsRow.querySelector('.ip-stats-dropdown');

                    if (dropdown) {{
                        dropdown.innerHTML = '<div class="loading">Loading stats...</div>';
                        try {{
                            const response = await fetch(`${{DASHBOARD_PATH}}/api/ip-stats/${{ip}}`, {{
                                cache: 'no-store',
                                headers: {{
                                    'Cache-Control': 'no-cache',
                                    'Pragma': 'no-cache'
                                }}
                            }});
                            if (!response.ok) throw new Error(`HTTP ${{response.status}}`);

                            const data = await response.json();
                            dropdown.innerHTML = data.error
                                ? `<div style="color:#f85149;">Error: ${{data.error}}</div>`
                                : formatIpStats(data);
                        }} catch (err) {{
                            dropdown.innerHTML = `<div style="color:#f85149;">Failed to load stats: ${{err.message}}</div>`;
                        }}
                    }}
                }});
            }});
        }}

        // Overview tables state management
        const overviewState = {{
            honeypot: {{ currentPage: 1, totalPages: 1, total: 0, sortBy: 'count', sortOrder: 'desc' }},
            credentials: {{ currentPage: 1, totalPages: 1, total: 0, sortBy: 'timestamp', sortOrder: 'desc', loaded: false }},
            'top-ips': {{ currentPage: 1, totalPages: 1, total: 0, sortBy: 'count', sortOrder: 'desc' }},
            'top-paths': {{ currentPage: 1, totalPages: 1, total: 0, sortBy: 'count', sortOrder: 'desc' }},
            'top-ua': {{ currentPage: 1, totalPages: 1, total: 0, sortBy: 'count', sortOrder: 'desc' }},
            attacks: {{ currentPage: 1, totalPages: 1, total: 0, sortBy: 'timestamp', sortOrder: 'desc', loaded: false }}
        }};

        const tableConfig = {{
            honeypot: {{ endpoint: 'honeypot', dataKey: 'honeypots', cellCount: 4, columns: ['ip', 'paths', 'count'] }},
            credentials: {{ endpoint: 'credentials', dataKey: 'credentials', cellCount: 6, columns: ['ip', 'username', 'password', 'path', 'timestamp'] }},
            'top-ips': {{ endpoint: 'top-ips', dataKey: 'ips', cellCount: 3, columns: ['ip', 'count'] }},
            'top-paths': {{ endpoint: 'top-paths', dataKey: 'paths', cellCount: 3, columns: ['path', 'count'] }},
            'top-ua': {{ endpoint: 'top-user-agents', dataKey: 'user_agents', cellCount: 3, columns: ['user_agent', 'count'] }},
            attacks: {{ endpoint: 'attack-types', dataKey: 'attacks', cellCount: 6, columns: ['ip', 'path', 'attack_types', 'user_agent', 'timestamp'] }}
        }};

        // Load overview table on page load
        async function loadOverviewTable(tableId) {{
            const config = tableConfig[tableId];
            if (!config) return;
            
            const state = overviewState[tableId];
            const tbody = document.getElementById(tableId + '-tbody');
            if (!tbody) return;

            // Just fade out without showing loading text
            tbody.style.opacity = '0';

            try {{
                const url = DASHBOARD_PATH + '/api/' + config.endpoint + '?page=' + state.currentPage + '&page_size=5&sort_by=' + state.sortBy + '&sort_order=' + state.sortOrder;
                const response = await fetch(url, {{ cache: 'no-store', headers: {{ 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' }} }});
                if (!response.ok) throw new Error(`HTTP ${{response.status}}`);

                const data = await response.json();
                const items = data[config.dataKey] || [];
                const pagination = data.pagination || {{}};

                state.currentPage = pagination.page || 1;
                state.totalPages = pagination.total_pages || 1;
                state.total = pagination.total || 0;
                updateOverviewPaginationControls(tableId);

                if (items.length === 0) {{
                    tbody.style.opacity = '0';
                    setTimeout(() => {{
                        tbody.innerHTML = '<tr><td colspan="' + config.cellCount + '" style="text-align: center; color: #6e7681; padding: 20px; font-size: 13px;">No data</td></tr>';
                        tbody.style.opacity = '1';
                    }}, 50);
                    return;
                }}

                let html = '';
                items.forEach((item, index) => {{
                    const rank = (state.currentPage - 1) * 5 + index + 1;
                    
                    if (tableId === 'honeypot') {{
                        html += `<tr class="ip-row" data-ip="${{item.ip}}"><td class="rank">${{rank}}</td><td class="ip-clickable">${{item.ip}}</td><td>${{item.paths.join(', ')}}</td><td>${{item.count}}</td></tr>`;
                        html += `<tr class="ip-stats-row" id="stats-row-honeypot-${{item.ip.replace(/\\./g, '-')}}" style="display: none;">
                            <td colspan="4" class="ip-stats-cell">
                                <div class="ip-stats-dropdown">
                                    <div class="loading">Loading stats...</div>
                                </div>
                            </td>
                        </tr>`;
                    }} else if (tableId === 'credentials') {{
                        html += `<tr class="ip-row" data-ip="${{item.ip}}"><td class="rank">${{rank}}</td><td class="ip-clickable">${{item.ip}}</td><td>${{item.username}}</td><td>${{item.password}}</td><td>${{item.path}}</td><td>${{formatTimestamp(item.timestamp, true)}}</td></tr>`;
                        html += `<tr class="ip-stats-row" id="stats-row-credentials-${{item.ip.replace(/\\./g, '-')}}" style="display: none;">
                            <td colspan="6" class="ip-stats-cell">
                                <div class="ip-stats-dropdown">
                                    <div class="loading">Loading stats...</div>
                                </div>
                            </td>
                        </tr>`;
                    }} else if (tableId === 'top-ips') {{
                        html += `<tr class="ip-row" data-ip="${{item.ip}}"><td class="rank">${{rank}}</td><td class="ip-clickable">${{item.ip}}</td><td>${{item.count}}</td></tr>`;
                        html += `<tr class="ip-stats-row" id="stats-row-top-ips-${{item.ip.replace(/\\./g, '-')}}" style="display: none;">
                            <td colspan="3" class="ip-stats-cell">
                                <div class="ip-stats-dropdown">
                                    <div class="loading">Loading stats...</div>
                                </div>
                            </td>
                        </tr>`;
                    }} else if (tableId === 'top-paths') {{
                        html += `<tr><td class="rank">${{rank}}</td><td>${{item.path}}</td><td>${{item.count}}</td></tr>`;
                    }} else if (tableId === 'top-ua') {{
                        html += `<tr><td class="rank">${{rank}}</td><td style="word-break: break-all;">${{item.user_agent.substring(0, 80)}}</td><td>${{item.count}}</td></tr>`;
                    }} else if (tableId === 'attacks') {{
                        html += `<tr class="ip-row" data-ip="${{item.ip}}"><td class="rank">${{rank}}</td><td class="ip-clickable">${{item.ip}}</td><td>${{item.path}}</td><td>${{item.attack_types.join(', ')}}</td><td style="word-break: break-all;">${{item.user_agent.substring(0, 60)}}</td><td>${{formatTimestamp(item.timestamp, true)}}</td></tr>`;
                        html += `<tr class="ip-stats-row" id="stats-row-attacks-${{item.ip.replace(/\\./g, '-')}}" style="display: none;">
                            <td colspan="6" class="ip-stats-cell">
                                <div class="ip-stats-dropdown">
                                    <div class="loading">Loading stats...</div>
                                </div>
                            </td>
                        </tr>`;
                    }}
                }});

                // Fade in new content
                tbody.style.opacity = '0';
                setTimeout(() => {{
                    tbody.innerHTML = html;
                    tbody.style.opacity = '1';

                    // Attach click listeners for IP cells in tables
                    if (tableId === 'top-ips') {{
                        attachTopIpsClickListeners();
                    }} else if (tableId === 'honeypot') {{
                        attachHoneypotClickListeners();
                    }} else if (tableId === 'credentials') {{
                        attachCredentialsClickListeners();
                    }} else if (tableId === 'attacks') {{
                        attachAttacksClickListeners();
                    }}
                }}, 50);
            }} catch (err) {{
                console.error('Error loading overview table ' + tableId + ':', err);
                tbody.style.opacity = '0';
                setTimeout(() => {{
                    tbody.innerHTML = '<tr><td colspan="' + config.cellCount + '" style="text-align: center; color: #f85149; padding: 20px; font-size: 13px;">Failed to load</td></tr>';
                    tbody.style.opacity = '1';
                }}, 50);
            }}
        }}

        function updateOverviewPaginationControls(tableId) {{
            const state = overviewState[tableId];
            const pagination = document.getElementById(tableId + '-pagination');
            if (!pagination) return;

            const prevBtn = pagination.querySelector('.pagination-btn:nth-child(2)');
            const nextBtn = pagination.querySelector('.pagination-btn:nth-child(3)');
            const currentPageEl = pagination.querySelector('.current-page');
            const totalPagesEl = pagination.querySelector('.total-pages');
            const totalRecordsEl = pagination.querySelector('.total-records');

            if (prevBtn) prevBtn.disabled = state.currentPage <= 1;
            if (nextBtn) nextBtn.disabled = state.currentPage >= state.totalPages;
            if (currentPageEl) currentPageEl.textContent = state.currentPage;
            if (totalPagesEl) totalPagesEl.textContent = state.totalPages;
            if (totalRecordsEl) totalRecordsEl.textContent = state.total;
        }}

        function previousPage(tableId) {{
            if (overviewState[tableId].currentPage > 1) {{
                overviewState[tableId].currentPage--;
                loadOverviewTable(tableId);
            }}
        }}

        function nextPage(tableId) {{
            if (overviewState[tableId].currentPage < overviewState[tableId].totalPages) {{
                overviewState[tableId].currentPage++;
                loadOverviewTable(tableId);
            }}
        }}

        // Handle sorting for overview tables
        document.addEventListener('click', function(e) {{
            const header = e.target.closest('th.sortable[data-table]');
            if (!header) return;

            const tableId = header.getAttribute('data-table');
            const sortField = header.getAttribute('data-sort');
            const state = overviewState[tableId];
            if (!state) return;

            // Toggle sort order if same field
            if (state.sortBy === sortField) {{
                state.sortOrder = state.sortOrder === 'desc' ? 'asc' : 'desc';
            }} else {{
                state.sortBy = sortField;
                state.sortOrder = 'desc';
            }}

            // Update UI and reload
            const table = header.closest('table');
            if (table) {{
                table.querySelectorAll('th.sortable').forEach(th => {{
                    th.classList.remove('asc', 'desc');
                }});
                header.classList.add(state.sortOrder);
            }}

            state.currentPage = 1;
            loadOverviewTable(tableId);
        }});

        // Load all overview tables when page loads
        window.addEventListener('load', function() {{
            // Only load tables that are in the Overview tab
            const overviewTableIds = ['honeypot', 'top-ips', 'top-paths', 'top-ua'];
            overviewTableIds.forEach(tableId => {{
                loadOverviewTable(tableId);
            }});
        }})

        async function showIpDetail(ip) {{
            const modal = document.getElementById('ip-detail-modal');
            const bodyDiv = document.getElementById('ip-detail-body');
            
            if (!modal || !bodyDiv) return;
            
            bodyDiv.innerHTML = '<div class="loading" style="text-align: center;">Loading IP details...</div>';
            modal.classList.add('show');
            
            try {{
                const response = await fetch(`${{DASHBOARD_PATH}}/api/ip-stats/${{ip}}`, {{
                    cache: 'no-store',
                    headers: {{
                        'Cache-Control': 'no-cache',
                        'Pragma': 'no-cache'
                    }}
                }});
                
                if (!response.ok) throw new Error(`HTTP ${{response.status}}`);
                
                const stats = await response.json();
                bodyDiv.innerHTML = '<h2>' + stats.ip + ' - Detailed Statistics</h2>' + formatIpStats(stats);
            }} catch (err) {{
                bodyDiv.innerHTML = `<div style="color: #f85149;">Failed to load details: ${{err.message}}</div>`;
            }}
        }}

        function closeIpDetailModal() {{
            const modal = document.getElementById('ip-detail-modal');
            if (modal) {{
                modal.classList.remove('show');
            }}
        }}

        // Close modal when clicking outside
        document.getElementById('ip-detail-modal')?.addEventListener('click', function(e) {{
            if (e.target === this) {{
                closeIpDetailModal();
            }}
        }});

        // Add CSS for view button
        const style = document.createElement('style');
        style.textContent = `
            .view-btn {{
                padding: 6px 12px;
                background: #238636;
                color: #ffffff;
                border: 1px solid #2ea043;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
                font-weight: 500;
                transition: background 0.2s;
            }}
            .view-btn:hover {{
                background: #2ea043;
            }}
            .view-btn:active {{
                background: #1f7a2f;
            }}
            .pagination-btn:hover:not(:disabled) {{
                background: #1f6feb !important;
            }}
            .pagination-btn:disabled {{
                opacity: 0.5;
                cursor: not-allowed;
            }}
        `;
        document.head.appendChild(style);

        // IP Map Visualization
        let attackerMap = null;
        let allIps = [];
        let mapMarkers = [];
        let markerLayers = {{}};

        const categoryColors = {{
            attacker: '#f85149',
            bad_crawler: '#f0883e',
            good_crawler: '#3fb950',
            regular_user: '#58a6ff',
            unknown: '#8b949e'
        }};

        async function initializeAttackerMap() {{
            const mapContainer = document.getElementById('attacker-map');
            if (!mapContainer || attackerMap) return;

            try {{
                // Initialize map
                attackerMap = L.map('attacker-map', {{
                    center: [20, 0],
                    zoom: 2,
                    layers: [
                        L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
                            attribution: '© CartoDB | © OpenStreetMap contributors',
                            maxZoom: 19,
                            subdomains: 'abcd'
                        }})
                    ]
                }});

                // Fetch all IPs (not just attackers)
                const response = await fetch(DASHBOARD_PATH + '/api/all-ips?page=1&page_size=100&sort_by=total_requests&sort_order=desc', {{
                    cache: 'no-store',
                    headers: {{
                        'Cache-Control': 'no-cache',
                        'Pragma': 'no-cache'
                    }}
                }});

                if (!response.ok) throw new Error('Failed to fetch IPs');

                const data = await response.json();
                allIps = data.ips || [];

                if (allIps.length === 0) {{
                    mapContainer.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #8b949e;\">No IP location data available</div>';
                    return;
                }}

                // Get max request count for scaling
                const maxRequests = Math.max(...allIps.map(ip => ip.total_requests || 0));

                // City coordinates database (major cities worldwide)
                const cityCoordinates = {{
                    // United States
                    'New York': [40.7128, -74.0060], 'Los Angeles': [34.0522, -118.2437],
                    'San Francisco': [37.7749, -122.4194], 'Chicago': [41.8781, -87.6298],
                    'Seattle': [47.6062, -122.3321], 'Miami': [25.7617, -80.1918],
                    'Boston': [42.3601, -71.0589], 'Atlanta': [33.7490, -84.3880],
                    'Dallas': [32.7767, -96.7970], 'Houston': [29.7604, -95.3698],
                    'Denver': [39.7392, -104.9903], 'Phoenix': [33.4484, -112.0740],
                    // Europe
                    'London': [51.5074, -0.1278], 'Paris': [48.8566, 2.3522],
                    'Berlin': [52.5200, 13.4050], 'Amsterdam': [52.3676, 4.9041],
                    'Moscow': [55.7558, 37.6173], 'Rome': [41.9028, 12.4964],
                    'Madrid': [40.4168, -3.7038], 'Barcelona': [41.3874, 2.1686],
                    'Milan': [45.4642, 9.1900], 'Vienna': [48.2082, 16.3738],
                    'Stockholm': [59.3293, 18.0686], 'Oslo': [59.9139, 10.7522],
                    'Copenhagen': [55.6761, 12.5683], 'Warsaw': [52.2297, 21.0122],
                    'Prague': [50.0755, 14.4378], 'Budapest': [47.4979, 19.0402],
                    'Athens': [37.9838, 23.7275], 'Lisbon': [38.7223, -9.1393],
                    'Brussels': [50.8503, 4.3517], 'Dublin': [53.3498, -6.2603],
                    'Zurich': [47.3769, 8.5417], 'Geneva': [46.2044, 6.1432],
                    'Helsinki': [60.1699, 24.9384], 'Bucharest': [44.4268, 26.1025],
                    'Saint Petersburg': [59.9343, 30.3351], 'Manchester': [53.4808, -2.2426],
                    'Roubaix': [50.6942, 3.1746], 'Frankfurt': [50.1109, 8.6821],
                    'Munich': [48.1351, 11.5820], 'Hamburg': [53.5511, 9.9937],
                    // Asia
                    'Tokyo': [35.6762, 139.6503], 'Beijing': [39.9042, 116.4074],
                    'Shanghai': [31.2304, 121.4737], 'Singapore': [1.3521, 103.8198],
                    'Mumbai': [19.0760, 72.8777], 'Delhi': [28.7041, 77.1025],
                    'Bangalore': [12.9716, 77.5946], 'Seoul': [37.5665, 126.9780],
                    'Hong Kong': [22.3193, 114.1694], 'Bangkok': [13.7563, 100.5018],
                    'Jakarta': [6.2088, 106.8456], 'Manila': [14.5995, 120.9842],
                    'Hanoi': [21.0285, 105.8542], 'Ho Chi Minh City': [10.8231, 106.6297],
                    'Taipei': [25.0330, 121.5654], 'Kuala Lumpur': [3.1390, 101.6869],
                    'Karachi': [24.8607, 67.0011], 'Islamabad': [33.6844, 73.0479],
                    'Dhaka': [23.8103, 90.4125], 'Colombo': [6.9271, 79.8612],
                    // South America
                    'São Paulo': [-23.5505, -46.6333], 'Rio de Janeiro': [-22.9068, -43.1729],
                    'Buenos Aires': [-34.6037, -58.3816], 'Bogotá': [4.7110, -74.0721],
                    'Lima': [-12.0464, -77.0428], 'Santiago': [-33.4489, -70.6693],
                    // Middle East & Africa
                    'Cairo': [30.0444, 31.2357], 'Dubai': [25.2048, 55.2708],
                    'Istanbul': [41.0082, 28.9784], 'Tel Aviv': [32.0853, 34.7818],
                    'Johannesburg': [26.2041, 28.0473], 'Lagos': [6.5244, 3.3792],
                    'Nairobi': [-1.2921, 36.8219], 'Cape Town': [-33.9249, 18.4241],
                    // Australia & Oceania
                    'Sydney': [-33.8688, 151.2093], 'Melbourne': [-37.8136, 144.9631],
                    'Brisbane': [-27.4698, 153.0251], 'Perth': [-31.9505, 115.8605],
                    'Auckland': [-36.8485, 174.7633],
                    // Additional cities
                    'Unknown': null
                }};

                // Country center coordinates (fallback when city not found)
                const countryCoordinates = {{
                    'US': [37.1, -95.7], 'GB': [55.4, -3.4], 'CN': [35.9, 104.1], 'RU': [61.5, 105.3],
                    'JP': [36.2, 138.3], 'DE': [51.2, 10.5], 'FR': [46.6, 2.2], 'IN': [20.6, 78.96],
                    'BR': [-14.2, -51.9], 'CA': [56.1, -106.3], 'AU': [-25.3, 133.8], 'MX': [23.6, -102.6],
                    'ZA': [-30.6, 22.9], 'KR': [35.9, 127.8], 'IT': [41.9, 12.6], 'ES': [40.5, -3.7],
                    'NL': [52.1, 5.3], 'SE': [60.1, 18.6], 'CH': [46.8, 8.2], 'PL': [51.9, 19.1],
                    'SG': [1.4, 103.8], 'HK': [22.4, 114.1], 'TW': [23.7, 120.96], 'TH': [15.9, 100.9],
                    'VN': [14.1, 108.8], 'ID': [-0.8, 113.2], 'PH': [12.9, 121.8], 'MY': [4.2, 101.7],
                    'PK': [30.4, 69.2], 'BD': [23.7, 90.4], 'NG': [9.1, 8.7], 'EG': [26.8, 30.8],
                    'TR': [38.9, 35.2], 'IR': [32.4, 53.7], 'AE': [23.4, 53.8], 'KZ': [48.0, 66.9],
                    'UA': [48.4, 31.2], 'BG': [42.7, 25.5], 'RO': [45.9, 24.97], 'CZ': [49.8, 15.5],
                    'HU': [47.2, 19.5], 'AT': [47.5, 14.6], 'BE': [50.5, 4.5], 'DK': [56.3, 9.5],
                    'FI': [61.9, 25.8], 'NO': [60.5, 8.5], 'GR': [39.1, 21.8], 'PT': [39.4, -8.2],
                    'AR': [-38.4161, -63.6167], 'CO': [4.5709, -74.2973], 'CL': [-35.6751, -71.5430],
                    'PE': [-9.1900, -75.0152], 'VE': [6.4238, -66.5897], 'LS': [40.0, -100.0]
                }};

                // Helper function to get coordinates for an IP
                function getIPCoordinates(ip) {{
                    // Try city first
                    if (ip.city && cityCoordinates[ip.city]) {{
                        return cityCoordinates[ip.city];
                    }}
                    // Fall back to country
                    if (ip.country_code && countryCoordinates[ip.country_code]) {{
                        return countryCoordinates[ip.country_code];
                    }}
                    return null;
                }}

                // Track used coordinates to add small offsets for overlapping markers
                const usedCoordinates = {{}};
                function getUniqueCoordinates(baseCoords) {{
                    const key = `${{baseCoords[0].toFixed(4)}},${{baseCoords[1].toFixed(4)}}`;
                    if (!usedCoordinates[key]) {{
                        usedCoordinates[key] = 0;
                    }}
                    usedCoordinates[key]++;

                    // If this is the first marker at this location, use exact coordinates
                    if (usedCoordinates[key] === 1) {{
                        return baseCoords;
                    }}

                    // Add small random offset for subsequent markers
                    // Offset increases with each marker to create a spread pattern
                    const angle = (usedCoordinates[key] * 137.5) % 360; // Golden angle for even distribution
                    const distance = 0.05 * Math.sqrt(usedCoordinates[key]); // Increase distance with more markers
                    const latOffset = distance * Math.cos(angle * Math.PI / 180);
                    const lngOffset = distance * Math.sin(angle * Math.PI / 180);

                    return [
                        baseCoords[0] + latOffset,
                        baseCoords[1] + lngOffset
                    ];
                }}

                // Create layer groups for each category
                markerLayers = {{
                    attacker: L.featureGroup(),
                    bad_crawler: L.featureGroup(),
                    good_crawler: L.featureGroup(),
                    regular_user: L.featureGroup(),
                    unknown: L.featureGroup()
                }};

                // Add markers for each IP
                allIps.slice(0, 100).forEach(ip => {{
                    if (!ip.country_code || !ip.category) return;

                    // Get coordinates (city first, then country)
                    const baseCoords = getIPCoordinates(ip);
                    if (!baseCoords) return;

                    // Get unique coordinates with offset to prevent overlap
                    const coords = getUniqueCoordinates(baseCoords);

                    const category = ip.category.toLowerCase();
                    if (!markerLayers[category]) return;

                    // Calculate marker size based on request count
                    const sizeRatio = (ip.total_requests / maxRequests) * 0.7 + 0.3;
                    const markerSize = Math.max(15, Math.min(40, 20 * sizeRatio));

                    // Create custom marker element with category-specific class
                    const markerElement = document.createElement('div');
                    markerElement.className = `ip-marker marker-${{category}}`;
                    markerElement.style.width = markerSize + 'px';
                    markerElement.style.height = markerSize + 'px';
                    markerElement.style.fontSize = (markerSize * 0.5) + 'px';
                    markerElement.textContent = '●';

                    const marker = L.marker(coords, {{
                        icon: L.divIcon({{
                            html: markerElement.outerHTML,
                            iconSize: [markerSize, markerSize],
                            className: `ip-custom-marker category-${{category}}`
                        }})
                    }});

                    // Create popup content with category badge
                    const categoryColor = categoryColors[category] || '#8b949e';
                    const categoryLabels = {{
                        attacker: 'Attacker',
                        bad_crawler: 'Bad Crawler',
                        good_crawler: 'Good Crawler',
                        regular_user: 'Regular User',
                        unknown: 'Unknown'
                    }};

                    const popupContent = `
                        <div style="padding: 8px; min-width: 220px;">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                                <strong style="color: #58a6ff;">${{ip.ip}}</strong>
                                <span style="background: ${{categoryColor}}1a; color: ${{categoryColor}}; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600;">
                                    ${{categoryLabels[category]}}
                                </span>
                            </div>
                            <span style="color: #8b949e; font-size: 12px;">
                                ${{ip.city ? (ip.country_code ? `${{ip.city}}, ${{ip.country_code}}` : ip.city) : (ip.country_code || 'Unknown')}}
                            </span><br/>
                            <div style="margin-top: 8px; border-top: 1px solid #30363d; padding-top: 8px;">
                                <div><span style="color: #8b949e;">Requests:</span> <span style="color: ${{categoryColor}}; font-weight: bold;">${{ip.total_requests}}</span></div>
                                <div><span style="color: #8b949e;">First Seen:</span> <span style="color: #58a6ff;">${{formatTimestamp(ip.first_seen)}}</span></div>
                                <div><span style="color: #8b949e;">Last Seen:</span> <span style="color: #58a6ff;">${{formatTimestamp(ip.last_seen)}}</span></div>
                            </div>
                        </div>
                    `;

                    marker.bindPopup(popupContent);
                    markerLayers[category].addLayer(marker);
                }});

                // Add all marker layers to map initially
                Object.values(markerLayers).forEach(layer => attackerMap.addLayer(layer));

                // Fit map to all markers
                const allMarkers = Object.values(markerLayers).reduce((acc, layer) => {{
                    acc.push(...layer.getLayers());
                    return acc;
                }}, []);

                if (allMarkers.length > 0) {{
                    const bounds = L.featureGroup(allMarkers).getBounds();
                    attackerMap.fitBounds(bounds, {{ padding: [50, 50] }});
                }}

            }} catch (err) {{
                console.error('Error initializing attacker map:', err);
                mapContainer.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #f85149;">Failed to load map: ' + err.message + '</div>';
            }}
        }}

        // Update map filters based on checkbox selection
        function updateMapFilters() {{
            if (!attackerMap) return;

            const filters = {{
                attacker: document.getElementById('filter-attacker').checked,
                bad_crawler: document.getElementById('filter-bad-crawler').checked,
                good_crawler: document.getElementById('filter-good-crawler').checked,
                regular_user: document.getElementById('filter-regular-user').checked,
                unknown: document.getElementById('filter-unknown').checked
            }};

            // Update marker and circle layers visibility
            Object.entries(filters).forEach(([category, show]) => {{
                if (markerLayers[category]) {{
                    if (show) {{
                        if (!attackerMap.hasLayer(markerLayers[category])) {{
                            attackerMap.addLayer(markerLayers[category]);
                        }}
                    }} else {{
                        if (attackerMap.hasLayer(markerLayers[category])) {{
                            attackerMap.removeLayer(markerLayers[category]);
                        }}
                    }}
                }}
            }});
        }}

        // Initialize map when Attacks tab is opened
        const originalSwitchTab = window.switchTab;
        let attackTypesChartLoaded = false;
        
        window.switchTab = function(tabName) {{
            originalSwitchTab(tabName);
            if (tabName === 'ip-stats') {{
                if (!attackerMap) {{
                    setTimeout(() => {{
                        initializeAttackerMap();
                    }}, 100);
                }}
                if (!attackTypesChartLoaded) {{
                    setTimeout(() => {{
                        loadAttackTypesChart();
                    }}, 100);
                }}
            }}
        }};

        // Load and render attack types bar chart
        let attackTypesChart = null;
        async function loadAttackTypesChart() {{
            try {{
                const canvas = document.getElementById('attack-types-chart');
                if (!canvas) return;

                const response = await fetch(DASHBOARD_PATH + '/api/attack-types?page=1&page_size=100', {{
                    cache: 'no-store',
                    headers: {{
                        'Cache-Control': 'no-cache',
                        'Pragma': 'no-cache'
                    }}
                }});

                if (!response.ok) throw new Error('Failed to fetch attack types');
                
                const data = await response.json();
                const attacks = data.attacks || [];

                if (attacks.length === 0) {{
                    canvas.style.display = 'none';
                    return;
                }}

                // Aggregate attack types
                const attackCounts = {{}};
                attacks.forEach(attack => {{
                    if (attack.attack_types && Array.isArray(attack.attack_types)) {{
                        attack.attack_types.forEach(type => {{
                            attackCounts[type] = (attackCounts[type] || 0) + 1;
                        }});
                    }}
                }});

                // Sort and get top 10
                const sortedAttacks = Object.entries(attackCounts)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 10);

                if (sortedAttacks.length === 0) {{
                    canvas.style.display = 'none';
                    return;
                }}

                const labels = sortedAttacks.map(([type]) => type);
                const counts = sortedAttacks.map(([, count]) => count);

                // Define colors for different attack types
                const colorMap = {{
                    'SQL Injection': '#0969da',
                    'XSS': '#1f6feb',
                    'Directory Traversal': '#2f81f7',
                    'Command Injection': '#54aeff',
                    'Path Traversal': '#79c0ff',
                    'Malware': '#58a6ff',
                    'Brute Force': '#388bfd',
                    'DDoS': '#1a7ae8',
                    'CSRF': '#0860ca',
                    'File Upload': '#1158d4'
                }};

                const backgroundColors = labels.map(label => colorMap[label] || '#58a6ff');
                const borderColors = labels.map(label => colorMap[label] || '#58a6ff');

                // Create or update chart
                if (attackTypesChart) {{
                    attackTypesChart.destroy();
                }}

                const ctx = canvas.getContext('2d');
                attackTypesChart = new Chart(ctx, {{
                    type: 'bar',
                    data: {{
                        labels: labels,
                        datasets: [{{
                            data: counts,
                            backgroundColor: backgroundColors,
                            borderColor: borderColors,
                            borderWidth: 1.5,
                            borderRadius: 4,
                            hoverBackgroundColor: borderColors
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        indexAxis: 'y',
                        plugins: {{
                            legend: {{
                                display: false
                            }},
                            tooltip: {{
                                backgroundColor: '#161b22',
                                titleColor: '#58a6ff',
                                bodyColor: '#c9d1d9',
                                borderColor: '#30363d',
                                borderWidth: 1,
                                padding: 10,
                                titleFont: {{
                                    size: 13,
                                    weight: 'bold'
                                }},
                                bodyFont: {{
                                    size: 12
                                }},
                                callbacks: {{
                                    label: function(context) {{
                                        return 'Occurrences: ' + context.parsed.x;
                                    }}
                                }}
                            }}
                        }},
                        scales: {{
                            x: {{
                                beginAtZero: true,
                                ticks: {{
                                    color: '#8b949e',
                                    font: {{
                                        size: 11
                                    }}
                                }},
                                grid: {{
                                    color: '#30363d',
                                    drawBorder: false
                                }}
                            }},
                            y: {{
                                ticks: {{
                                    color: '#c9d1d9',
                                    font: {{
                                        size: 12
                                    }},
                                    padding: 10
                                }},
                                grid: {{
                                    display: false,
                                    drawBorder: false
                                }}
                            }}
                        }}
                    }}
                }});

                attackTypesChartLoaded = true;
            }} catch (err) {{
                console.error('Error loading attack types chart:', err);
            }}
        }}
    </script>
</body>
</html>
"""
