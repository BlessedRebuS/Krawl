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

def format_timestamp(iso_timestamp: str, timezone: str = 'UTC', time_only: bool = False) -> str:
    """Format ISO timestamp for display with timezone conversion
    
    Args:
        iso_timestamp: ISO format timestamp string (UTC)
        timezone: IANA timezone string to convert to
        time_only: If True, return only HH:MM:SS, otherwise full datetime
    """
    try:
        # Parse UTC timestamp
        dt = datetime.fromisoformat(iso_timestamp)
        # Convert to target timezone
        if dt.tzinfo is not None:
            dt = dt.astimezone(ZoneInfo(timezone))
        
        if time_only:
            return dt.strftime("%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        # Fallback for old format
        return iso_timestamp.split("T")[1][:8] if "T" in iso_timestamp else iso_timestamp


def generate_dashboard(stats: dict, timezone: str = 'UTC', dashboard_path: str = '') -> str:
    """Generate dashboard HTML with access statistics
    
    Args:
        stats: Statistics dictionary
        timezone: IANA timezone string (e.g., 'Europe/Paris', 'America/New_York')
        dashboard_path: The secret dashboard path for generating API URLs
    """
    
    # Generate IP rows with clickable functionality for dropdown stats
    top_ips_rows = '\n'.join([
        f'''<tr class="ip-row" data-ip="{_escape(ip)}">
            <td class="rank">{i+1}</td>
            <td class="ip-clickable">{_escape(ip)}</td>
            <td>{count}</td>
        </tr>
        <tr class="ip-stats-row" id="stats-row-{_escape(ip).replace(".", "-")}" style="display: none;">
            <td colspan="3" class="ip-stats-cell">
                <div class="ip-stats-dropdown">
                    <div class="loading">Loading stats...</div>
                </div>
            </td>
        </tr>'''
        for i, (ip, count) in enumerate(stats['top_ips'])
    ]) or '<tr><td colspan="3" style="text-align:center;">No data</td></tr>'

    # Generate paths rows (CRITICAL: paths can contain XSS payloads)
    top_paths_rows = '\n'.join([
        f'<tr><td class="rank">{i+1}</td><td>{_escape(path)}</td><td>{count}</td></tr>'
        for i, (path, count) in enumerate(stats['top_paths'])
    ]) or '<tr><td colspan="3" style="text-align:center;">No data</td></tr>'

    # Generate User-Agent rows (CRITICAL: user agents can contain XSS payloads)
    top_ua_rows = '\n'.join([
        f'<tr><td class="rank">{i+1}</td><td style="word-break: break-all;">{_escape(ua[:80])}</td><td>{count}</td></tr>'
        for i, (ua, count) in enumerate(stats['top_user_agents'])
    ]) or '<tr><td colspan="3" style="text-align:center;">No data</td></tr>'

    # Generate suspicious accesses rows with clickable IPs
    suspicious_rows = '\n'.join([
        f'''<tr class="ip-row" data-ip="{_escape(log["ip"])}">
            <td class="ip-clickable">{_escape(log["ip"])}</td>
            <td>{_escape(log["path"])}</td>
            <td style="word-break: break-all;">{_escape(log["user_agent"][:60])}</td>
            <td>{format_timestamp(log["timestamp"], timezone, time_only=True)}</td>
        </tr>
        <tr class="ip-stats-row" id="stats-row-suspicious-{_escape(log["ip"]).replace(".", "-")}" style="display: none;">
            <td colspan="4" class="ip-stats-cell">
                <div class="ip-stats-dropdown">
                    <div class="loading">Loading stats...</div>
                </div>
            </td>
        </tr>'''
        for log in stats['recent_suspicious'][-10:]
    ]) or '<tr><td colspan="4" style="text-align:center;">No suspicious activity detected</td></tr>'

    # Generate honeypot triggered IPs rows with clickable IPs
    honeypot_rows = '\n'.join([
        f'''<tr class="ip-row" data-ip="{_escape(ip)}">
            <td class="ip-clickable">{_escape(ip)}</td>
            <td style="word-break: break-all;">{_escape(", ".join(paths))}</td>
            <td>{len(paths)}</td>
        </tr>
        <tr class="ip-stats-row" id="stats-row-honeypot-{_escape(ip).replace(".", "-")}" style="display: none;">
            <td colspan="3" class="ip-stats-cell">
                <div class="ip-stats-dropdown">
                    <div class="loading">Loading stats...</div>
                </div>
            </td>
        </tr>'''
        for ip, paths in stats.get('honeypot_triggered_ips', [])
    ]) or '<tr><td colspan="3" style="text-align:center;">No honeypot triggers yet</td></tr>'

    # Generate attack types rows with clickable IPs
    attack_type_rows = '\n'.join([
        f'''<tr class="ip-row" data-ip="{_escape(log["ip"])}">
            <td class="ip-clickable">{_escape(log["ip"])}</td>
            <td>{_escape(log["path"])}</td>
            <td>{_escape(", ".join(log["attack_types"]))}</td>
            <td style="word-break: break-all;">{_escape(log["user_agent"][:60])}</td>
            <td>{format_timestamp(log["timestamp"], timezone, time_only=True)}</td>
        </tr>
        <tr class="ip-stats-row" id="stats-row-attack-{_escape(log["ip"]).replace(".", "-")}" style="display: none;">
            <td colspan="5" class="ip-stats-cell">
                <div class="ip-stats-dropdown">
                    <div class="loading">Loading stats...</div>
                </div>
            </td>
        </tr>'''
        for log in stats.get('attack_types', [])[-10:]
    ]) or '<tr><td colspan="4" style="text-align:center;">No attacks detected</td></tr>'

    # Generate credential attempts rows with clickable IPs
    credential_rows = '\n'.join([
        f'''<tr class="ip-row" data-ip="{_escape(log["ip"])}">
            <td class="ip-clickable">{_escape(log["ip"])}</td>
            <td>{_escape(log["username"])}</td>
            <td>{_escape(log["password"])}</td>
            <td>{_escape(log["path"])}</td>
            <td>{format_timestamp(log["timestamp"], timezone, time_only=True)}</td>
        </tr>
        <tr class="ip-stats-row" id="stats-row-cred-{_escape(log["ip"]).replace(".", "-")}" style="display: none;">
            <td colspan="5" class="ip-stats-cell">
                <div class="ip-stats-dropdown">
                    <div class="loading">Loading stats...</div>
                </div>
            </td>
        </tr>'''
        for log in stats.get('credential_attempts', [])[-20:]
    ]) or '<tr><td colspan="5" style="text-align:center;">No credentials captured yet</td></tr>'

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Krawl Dashboard</title>
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
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
        .timeline-container {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #30363d;
        }}
        .timeline-title {{
            color: #58a6ff;
            font-size: 13px;
            font-weight: 600;
        }}
        .timeline-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }}
        .timeline {{
            position: relative;
            padding-left: 30px;
        }}
        .timeline::before {{
            content: '';
            position: absolute;
            left: 12px;
            top: 5px;
            bottom: 5px;
            width: 3px;
            background: #30363d;
        }}
        .timeline-item {{
            position: relative;
            padding-bottom: 15px;
        }}
        .timeline-item:last-child {{
            padding-bottom: 0;
        }}
        .timeline-marker {{
            position: absolute;
            left: -26px;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            border: 2px solid #0d1117;
        }}
        .timeline-marker.attacker {{
            background: #f85149;
        }}
        .timeline-marker.good-crawler {{
            background: #3fb950;
        }}
        .timeline-marker.bad-crawler {{
            background: #f0883e;
        }}
        .timeline-marker.regular-user {{
            background: #58a6ff;
        }}
        .timeline-marker.unknown {{
            background: #8b949e;
        }}
        .timeline-content {{
            font-size: 12px;
        }}
        .timeline-category {{
            font-weight: 600;
        }}
        .timeline-timestamp {{
            color: #8b949e;
            font-size: 11px;
            margin-top: 2px;
        }}
        .timeline-arrow {{
            color: #8b949e;
            margin: 0 7px;
        }}
        .reputation-container {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #30363d;
        }}
        .reputation-title {{
            color: #58a6ff;
            font-size: 13px;
            font-weight: 600;
        }}
        .reputation-badges {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            align-items: center;
        }}
        .reputation-badge {{
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 4px 8px;
            background: #161b22;
            border: 1px solid #f851494d;
            border-radius: 4px;
            font-size: 11px;
            color: #f85149;
            text-decoration: none;
            transition: all 0.2s;
        }}
        .reputation-badge:hover {{
            background: #1c2128;
            border-color: #f85149;
        }}
        .reputation-badge-icon {{
            font-size: 12px;
        }}
        .reputation-clean {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            background: #161b22;
            border: 1px solid #3fb9504d;
            border-radius: 4px;
            font-size: 11px;
            color: #3fb950;
        }}
        .reputation-clean-icon {{
            font-size: 13px;
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
        </div>

        <div class="table-container alert-section">
            <h2>Honeypot Triggers by IP</h2>
            <table id="honeypot-table">
                <thead>
                    <tr>
                        <th class="sortable" data-sort="ip">IP Address</th>
                        <th>Accessed Paths</th>
                        <th class="sortable" data-sort="count">Count</th>
                    </tr>
                </thead>
                <tbody>
                    {honeypot_rows}
                </tbody>
            </table>
        </div>

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
            <h2>Captured Credentials</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Username</th>
                        <th>Password</th>
                        <th>Path</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {credential_rows}
                </tbody>
            </table>
        </div>

        <div class="table-container alert-section">
            <h2>Detected Attack Types</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Path</th>
                        <th>Attack Types</th>
                        <th>User-Agent</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {attack_type_rows}
                </tbody>
            </table>
        </div>

        <div class="table-container">
            <h2>Top IP Addresses</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Access Count</th>
                    </tr>
                </thead>
                <tbody>
                    {top_ips_rows}
                </tbody>
            </table>
        </div>

        <div class="table-container">
            <h2>Top Paths</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Path</th>
                        <th>Access Count</th>
                    </tr>
                </thead>
                <tbody>
                    {top_paths_rows}
                </tbody>
            </table>
        </div>

        <div class="table-container">
            <h2>Top User-Agents</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>User-Agent</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                    {top_ua_rows}
                </tbody>
            </table>
        </div>
    </div>
    <script>
        const SERVER_TIMEZONE = '{timezone}';
        const DASHBOARD_PATH = '{dashboard_path}';
        
        function formatTimestamp(isoTimestamp) {{
            if (!isoTimestamp) return 'N/A';
            try {{
                const date = new Date(isoTimestamp);
                return date.toLocaleString('en-US', {{ 
                    timeZone: SERVER_TIMEZONE,
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
                html += `<span class="stat-value-sm">${{stats.city || ''}}${{stats.city && stats.country_code ? ', ' : ''}}${{stats.country_code || 'Unknown'}}</span>`;
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
                html += '<div class="timeline-container">';
                
                html += '<div class="timeline-header">';
                html += '<div class="timeline-title">Behavior Timeline</div>';

                if (stats.list_on && Object.keys(stats.list_on).length > 0) {{
                    html += '<div class="reputation-badges">';
                    html += '<span class="reputation-title" style="margin-bottom:0; margin-right:4px;">Listed on</span>';

                    const sortedSources = Object.entries(stats.list_on).sort((a, b) => a[0].localeCompare(b[0]));

                    sortedSources.forEach(([source, url]) => {{
                        if (url && url !== 'N/A') {{
                            html += `<a href="${{url}}" target="_blank" rel="noopener noreferrer" class="reputation-badge" title="Listed on ${'{'}source{'}'}">`;
                            html += '<span class="reputation-badge-icon"></span>';
                            html += `<span>${{source}}</span>`;
                            html += '</a>';
                        }} else {{
                            html += '<span class="reputation-badge" style="cursor: default;" title="Listed on">';
                            html += '<span class="reputation-badge-icon"></span>';
                            html += `<span>${{source}}</span>`;
                            html += '</span>';
                        }}
                    }});

                    html += '</div>';
                }} else if (stats.country_code || stats.asn) {{
                    html += '<div class="reputation-badges">';
                    html += '<span class="reputation-title" style="margin-bottom:0; margin-right:4px;">Reputation</span>';
                    html += '<span class="reputation-clean" title="Not found on public blacklists">';
                    html += '<span class="reputation-clean-icon">✓</span>';
                    html += '<span>Clean</span>';
                    html += '</span>';
                    html += '</div>';
                }}

                html += '</div>';

                html += '<div class="timeline">';

                stats.category_history.forEach((change, index) => {{
                    const categoryClass = change.new_category.toLowerCase().replace('_', '-');
                    const timestamp = formatTimestamp(change.timestamp);

                    html += '<div class="timeline-item">';
                    html += `<div class="timeline-marker ${{categoryClass}}"></div>`;
                    html += '<div class="timeline-content">';

                    if (change.old_category) {{
                        const oldCategoryBadge = 'category-' + change.old_category.toLowerCase().replace('_', '-');
                        html += `<span class="category-badge ${{oldCategoryBadge}}">${{change.old_category}}</span>`;
                        html += '<span class="timeline-arrow">→</span>';
                    }} else {{
                        html += '<span style="color: #8b949e;">Initial:</span> ';
                    }}

                    const newCategoryBadge = 'category-' + change.new_category.toLowerCase().replace('_', '-');
                    html += `<span class="category-badge ${{newCategoryBadge}}">${{change.new_category}}</span>`;
                    html += `<div class="timeline-timestamp">${{timestamp}}</div>`;
                    html += '</div>';
                    html += '</div>';
                }});

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
    </script>
</body>
</html>
"""
