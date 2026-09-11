// Chart.js Attack Types Chart
// Extracted from dashboard_template.py (lines ~3370-3550)

let attackTypesChart = null;
let attackTypesChartLoaded = false;

/**
 * Load an attack types doughnut chart into a canvas element.
 * @param {string} [canvasId='attack-types-chart'] - Canvas element ID
 * @param {string} [ipFilter] - Optional IP address to scope results
 * @param {string} [legendPosition='right'] - Legend position
 */
async function loadAttackTypesChart(canvasId, ipFilter, legendPosition) {
    canvasId = canvasId || 'attack-types-chart';
    legendPosition = legendPosition || 'right';
    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';

    try {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        let url = DASHBOARD_PATH + '/api/attack-types-stats?limit=10';
        if (ipFilter) url += '&ip_filter=' + encodeURIComponent(ipFilter);

        const response = await fetch(url, {
            cache: 'no-store',
            headers: {
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
        });

        if (!response.ok) throw new Error('Failed to fetch attack types');

        const data = await response.json();
        const attackTypes = data.attack_types || [];

        if (attackTypes.length === 0) {
            canvas.parentElement.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-dim);font-size:13px;">No attack data</div>';
            return;
        }

        const labels = attackTypes.map(item => item.type);
        const counts = attackTypes.map(item => item.count);
        const maxCount = Math.max(...counts);

        // Hash function to generate consistent color from string
        function hashCode(str) {
            let hash = 0;
            for (let i = 0; i < str.length; i++) {
                const char = str.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash; // Convert to 32bit integer
            }
            return Math.abs(hash);
        }

        // Dynamic color generator based on hash
        function generateColorFromHash(label) {
            const hash = hashCode(label);
            const hue = (hash % 360); // 0-360 for hue
            const saturation = 70 + (hash % 20); // 70-90 for vibrant colors
            const lightness = 50 + (hash % 10); // 50-60 for brightness

            const bgColor = `hsl(${hue}, ${saturation}%, ${lightness}%)`;
            const borderColor = `hsl(${hue}, ${saturation + 5}%, ${lightness - 10}%)`; // Darker border
            const hoverColor = `hsl(${hue}, ${saturation - 10}%, ${lightness + 8}%)`; // Lighter hover

            return { bg: bgColor, border: borderColor, hover: hoverColor };
        }

        // Generate colors dynamically for each attack type
        const backgroundColors = labels.map(label => generateColorFromHash(label).bg);
        const borderColors = labels.map(label => generateColorFromHash(label).border);
        const hoverColors = labels.map(label => generateColorFromHash(label).hover);

        // Create or update chart (track per canvas)
        if (!loadAttackTypesChart._instances) loadAttackTypesChart._instances = {};
        if (loadAttackTypesChart._instances[canvasId]) {
            loadAttackTypesChart._instances[canvasId].destroy();
        }

        const ctx = canvas.getContext('2d');
        const chartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: backgroundColors,
                    borderColor: krawlToken('--bg'),
                    borderWidth: 3,
                    hoverBorderColor: krawlToken('--accent'),
                    hoverBorderWidth: 4,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: legendPosition,
                        labels: {
                            color: krawlToken('--text'),
                            font: {
                                size: 12,
                                weight: '500',
                                family: "'Segoe UI', Tahoma, Geneva, Verdana"
                            },
                            padding: 16,
                            usePointStyle: true,
                            pointStyle: 'circle',
                            generateLabels: (chart) => {
                                const data = chart.data;
                                return data.labels.map((label, i) => ({
                                    text: `${label} (${data.datasets[0].data[i]})`,
                                    fillStyle: data.datasets[0].backgroundColor[i],
                                    hidden: false,
                                    index: i,
                                    pointStyle: 'circle'
                                }));
                            }
                        }
                    },
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(22, 27, 34, 0.95)',
                        titleColor: krawlToken('--accent'),
                        bodyColor: krawlToken('--text'),
                        borderColor: krawlToken('--accent'),
                        borderWidth: 2,
                        padding: 14,
                        titleFont: {
                            size: 14,
                            weight: 'bold',
                            family: "'Segoe UI', Tahoma, Geneva, Verdana"
                        },
                        bodyFont: {
                            size: 13,
                            family: "'Segoe UI', Tahoma, Geneva, Verdana"
                        },
                        caretSize: 8,
                        caretPadding: 12,
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((context.parsed / total) * 100).toFixed(1);
                                return `${context.label}: ${percentage}%`;
                            }
                        }
                    }
                },
                animation: {
                    enabled: false
                },
                onHover: (event, activeElements) => {
                    canvas.style.cursor = activeElements.length > 0 ? 'pointer' : 'default';
                }
            },
            plugins: [{
                id: 'customCanvasBackgroundColor',
                beforeDraw: (chart) => {
                    if (chart.ctx) {
                        chart.ctx.save();
                        chart.ctx.globalCompositeOperation = 'destination-over';
                        chart.ctx.fillStyle = 'rgba(0,0,0,0)';
                        chart.ctx.fillRect(0, 0, chart.width, chart.height);
                        chart.ctx.restore();
                    }
                }
            }]
        });

        loadAttackTypesChart._instances[canvasId] = chartInstance;
        attackTypesChart = chartInstance;
        attackTypesChartLoaded = true;
    } catch (err) {
        console.error('Error loading attack types chart:', err);
    }
}


/**
 * Attack Trends line chart with period navigation, totals sidebar,
 * and interactive legend that filters the Detected Attack Types table.
 */
let attackTrendsChart = null;
let _trendsOffsetDays = 0;
let _trendsDays = 7;

// Hash-based consistent colors (shared with doughnut chart)
function _trendsHashCode(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash = hash & hash;
    }
    return Math.abs(hash);
}

function _trendsColor(label, alpha) {
    const h = _trendsHashCode(label);
    const hue = h % 360;
    const sat = 70 + (h % 20);
    const lit = 50 + (h % 10);
    return alpha !== undefined
        ? `hsla(${hue}, ${sat}%, ${lit}%, ${alpha})`
        : `hsl(${hue}, ${sat}%, ${lit}%)`;
}

async function loadAttackTrendsChart(canvasId) {
    canvasId = canvasId || 'attack-trends-chart';
    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';

    try {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const url = `${DASHBOARD_PATH}/api/attack-types-daily?limit=10&days=${_trendsDays}&offset_days=${_trendsOffsetDays}`;
        const response = await fetch(url, {
            cache: 'no-store',
            headers: { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' }
        });

        if (!response.ok) throw new Error('Failed to fetch daily attack data');

        const data = await response.json();
        const attackTypes = data.attack_types || [];
        const dates = data.dates || [];

        // Update period label
        _updateTrendsPeriodLabel(dates);

        // Update totals sidebar
        _updateTrendsTotals(attackTypes);

        if (attackTrendsChart) {
            attackTrendsChart.destroy();
            attackTrendsChart = null;
        }

        if (attackTypes.length === 0) {
            canvas.style.display = 'none';
            let emptyMsg = canvas.parentElement.querySelector('.trends-empty-msg');
            if (!emptyMsg) {
                emptyMsg = document.createElement('div');
                emptyMsg.className = 'trends-empty-msg';
                emptyMsg.style.cssText = 'display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-dim);font-size:13px;';
                canvas.parentElement.appendChild(emptyMsg);
            }
            emptyMsg.textContent = 'No attack data for this period';
            emptyMsg.style.display = 'flex';
            return;
        }

        // Restore canvas if previously hidden
        canvas.style.display = '';
        const oldMsg = canvas.parentElement.querySelector('.trends-empty-msg');
        if (oldMsg) oldMsg.style.display = 'none';

        const isHourly = dates.length > 0 && dates[0].includes(':');
        const shortLabels = dates.map(d => {
            if (isHourly) {
                // "2026-04-02 14:00" → "Apr 2 14:00"
                const [datePart, timePart] = d.split(' ');
                const dt = new Date(datePart + 'T00:00:00');
                const dayLabel = dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                return `${dayLabel} ${timePart}`;
            }
            const dt = new Date(d + 'T00:00:00');
            return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        });

        const datasets = attackTypes.map(at => ({
            label: `${at.type} (${at.total})`,
            data: at.daily,
            borderColor: _trendsColor(at.type),
            backgroundColor: _trendsColor(at.type, 0.05),
            borderWidth: 2,
            pointRadius: 0,
            pointHitRadius: 8,
            pointHoverRadius: 4,
            pointHoverBackgroundColor: _trendsColor(at.type),
            tension: 0.15,
            fill: false,
            _attackType: at.type,
        }));

        const ctx = canvas.getContext('2d');
        attackTrendsChart = new Chart(ctx, {
            type: 'line',
            data: { labels: shortLabels, datasets: datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(22, 27, 34, 0.95)',
                        titleColor: krawlToken('--accent'),
                        bodyColor: krawlToken('--text'),
                        borderColor: krawlToken('--line'),
                        borderWidth: 1,
                        padding: 10,
                        titleFont: { size: 12, weight: 'bold' },
                        bodyFont: { size: 11 },
                        callbacks: {
                            label: function(context) {
                                return `${context.dataset._attackType}: ${context.parsed.y}`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: krawlToken('--text-dim'), font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 15 },
                        grid: { color: 'rgba(48, 54, 61, 0.3)' },
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: krawlToken('--text-dim'), font: { size: 10 }, precision: 0 },
                        grid: { color: 'rgba(48, 54, 61, 0.3)' },
                    }
                },
                animation: { enabled: false },
            }
        });

    } catch (err) {
        console.error('Error loading attack trends chart:', err);
    }
}

function _updateTrendsPeriodLabel(dates) {
    const label = document.getElementById('trends-period-label');

    // Always update button states regardless of data
    const nextBtn = document.getElementById('trends-next');
    if (nextBtn) nextBtn.disabled = (_trendsOffsetDays <= 0);

    if (!label) return;

    if (dates.length === 0) {
        // Show computed date range even when no data exists
        const end = new Date();
        end.setDate(end.getDate() - _trendsOffsetDays);
        const start = new Date(end);
        start.setDate(start.getDate() - _trendsDays);
        const fmt = { month: 'short', day: 'numeric' };
        label.textContent = `${start.toLocaleDateString('en-US', fmt)} — ${end.toLocaleDateString('en-US', fmt)}`;
        return;
    }

    const isHourly = dates[0].includes(':');
    const parseDate = d => isHourly ? new Date(d.replace(' ', 'T')) : new Date(d + 'T00:00:00');
    const start = parseDate(dates[0]);
    const end = parseDate(dates[dates.length - 1]);
    const fmt = isHourly
        ? { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }
        : { month: 'short', day: 'numeric' };
    label.textContent = `${start.toLocaleDateString('en-US', fmt)} — ${end.toLocaleDateString('en-US', fmt)}`;
}

function _updateTrendsTotals(attackTypes) {
    const container = document.getElementById('trends-totals');
    if (!container) return;

    if (attackTypes.length === 0) {
        container.innerHTML = '<span style="color: var(--text-dim); font-size: 0.8em;">No data</span>';
        return;
    }

    let html = '<span style="color: var(--text-dim); font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px;">Totals (period)</span>';
    attackTypes.forEach(at => {
        const color = _trendsColor(at.type);
        html += `<div style="display: flex; align-items: center; gap: 8px; padding: 4px 0; cursor: pointer; border-radius: 4px; transition: background 0.15s;"
                      onmouseover="this.style.background='rgba(255,255,255,0.03)'"
                      onmouseout="this.style.background='transparent'"
                      onclick="filterAttackTableByType('${at.type.replace(/'/g, "\\'")}')">
            <span style="width: 8px; height: 8px; border-radius: 50%; background: ${color}; flex-shrink: 0;"></span>
            <span style="color: var(--text); font-size: 0.8em; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${at.type}">${at.type}</span>
            <span style="color: ${color}; font-size: 0.85em; font-weight: 600; font-variant-numeric: tabular-nums;">${at.total.toLocaleString()}</span>
        </div>`;
    });
    container.innerHTML = html;
}

/** Shift the trends chart period by N windows (negative = older, positive = newer) */
function shiftTrendsPeriod(direction) {
    _trendsOffsetDays = Math.max(0, _trendsOffsetDays - (direction * _trendsDays));
    loadAttackTrendsChart();
}

/** Switch the trends time span (7, 30, 90 days) and reset to current period */
function setTrendsSpan(days, btn) {
    _trendsDays = days;
    _trendsOffsetDays = 0;
    document.querySelectorAll('#trends-span-selector .map-limit-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    loadAttackTrendsChart();
}

/** Active attack type filter (null = show all) */
let _activeAttackTypeFilter = null;

/**
 * Filter the Detected Attack Types table by a specific attack type.
 * Clicking the same type again clears the filter.
 */
function filterAttackTableByType(attackType) {
    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';
    const container = document.getElementById('attacks-htmx-container');
    if (!container) return;

    if (_activeAttackTypeFilter === attackType) {
        _activeAttackTypeFilter = null;
        htmx.ajax('GET', DASHBOARD_PATH + '/htmx/attacks?page=1', { target: container, swap: 'innerHTML' });
    } else {
        _activeAttackTypeFilter = attackType;
        htmx.ajax('GET', DASHBOARD_PATH + '/htmx/attacks?page=1&attack_type_filter=' + encodeURIComponent(attackType), { target: container, swap: 'innerHTML' });
    }
}

/**
 * Attack Campaigns horizontal bar chart (Threats tab).
 * One bar per payload cluster, sized by captures; distinct IPs ride in the
 * tooltip so the bars stay comparable. Bars are named by the target the
 * campaign hits, since a TLSH prefix says nothing to a reader. Clicking a bar
 * opens the campaign events overlay. Day-navigable like the attack trends
 * chart: each view is the top campaigns active on the selected day.
 */
let campaignsChart = null;
let _campaignDays = 1;
let _campaignOffset = 0;

function _campaignEndDate() {
    const d = new Date();
    d.setDate(d.getDate() - (_campaignOffset * _campaignDays));
    return d;
}

function _campaignStartDate() {
    const d = _campaignEndDate();
    d.setDate(d.getDate() - (_campaignDays - 1));
    return d;
}

function _campaignLabel() {
    const label = document.getElementById('campaigns-period-label');
    if (label) {
        const end = _campaignEndDate();
        if (_campaignDays === 1) {
            label.textContent = end.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        } else {
            label.textContent = `${_campaignStartDate().toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} — ${end.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`;
        }
    }
    const next = document.getElementById('campaigns-period-next');
    if (next) next.disabled = _campaignOffset === 0;
}

/** Human-readable bar name: the target hit, falling back to the digest prefix. */
function _campaignTick(label) {
    const max = 30;
    return label.length > max ? '…' + label.slice(-(max - 1)) : label;
}

/** Campaigns shown, what they captured, and which one reached furthest.
 *  Counts cover the charted campaigns only — distinct IPs cannot be summed
 *  across campaigns without double-counting, so the widest one is named
 *  instead of a total. */
function _renderCampaignSummary(campaigns) {
    const box = document.getElementById('campaigns-summary');
    if (!box) return;
    if (!campaigns.length) {
        box.innerHTML = '';
        return;
    }
    const captures = campaigns.reduce((sum, c) => sum + (c.captures || 0), 0);
    const widest = campaigns.reduce((a, b) => ((b.ips || 0) > (a.ips || 0) ? b : a));
    const stat = (value, label) =>
        `<div class="chart-stat"><span class="chart-stat-value">${value.toLocaleString()}</span>` +
        `<span class="chart-stat-label">${label}</span></div>`;
    box.innerHTML =
        stat(campaigns.length, campaigns.length === 1 ? 'campaign' : 'campaigns') +
        stat(captures, captures === 1 ? 'capture' : 'captures') +
        `<div class="chart-note">Widest reach<br><span class="data-mono">` +
        `${_escapeHtml(_campaignTick(_campaignName(widest)))}</span><br>` +
        `${widest.ips} distinct ${widest.ips === 1 ? 'IP' : 'IPs'}</div>`;
}

function _escapeHtml(value) {
    const el = document.createElement('span');
    el.textContent = value;
    return el.innerHTML;
}

function _campaignName(c) {
    const target = c.path || c.top_path || '';
    if (!target) return `campaign ${c.label}`;
    return target.length > 38 ? target.slice(0, 37) + '…' : target;
}

async function loadCampaignsChart() {
    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';

    try {
        const canvas = document.getElementById('campaigns-chart');
        if (!canvas) return;

        _campaignLabel();

        const response = await fetch(
            DASHBOARD_PATH + `/api/campaign-stats?limit=5&days=${_campaignDays}&offset=${_campaignOffset}`,
            {
                cache: 'no-store',
                headers: { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' }
            }
        );
        if (!response.ok) throw new Error('Failed to fetch campaign stats');

        const data = await response.json();
        const campaigns = data.campaigns || [];

        if (campaignsChart) campaignsChart.destroy();

        // Toggle a sibling instead of replacing the wrapper's markup: blowing
        // away the canvas left the next span switch with nothing to draw on.
        const empty = document.getElementById('campaigns-chart-empty');
        if (empty) empty.hidden = campaigns.length > 0;
        canvas.hidden = campaigns.length === 0;
        _renderCampaignSummary(campaigns);
        if (campaigns.length === 0) return;

        const labels = campaigns.map(_campaignName);

        const ctx = canvas.getContext('2d');
        campaignsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Captures',
                        data: campaigns.map(c => c.captures),
                        backgroundColor: krawlToken('--accent'),
                        hoverBackgroundColor: krawlToken('--accent-hi'),
                        borderRadius: 4,
                        borderSkipped: false,
                        // Thin bars with a gap, so five campaigns do not read
                        // as one solid block.
                        categoryPercentage: 0.7,
                        barPercentage: 0.8
                    }
                ]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(22, 27, 34, 0.95)',
                        titleColor: krawlToken('--accent'),
                        bodyColor: krawlToken('--text'),
                        borderColor: krawlToken('--accent'),
                        borderWidth: 2,
                        padding: 14,
                        callbacks: {
                            label: (context) =>
                                `${context.parsed.x} captures`,
                            afterLabel: (context) => {
                                const c = campaigns[context.dataIndex];
                                const parts = [
                                    `distinct IPs: ${c.ips}`,
                                    `source: ${c.sources}`,
                                    `digest: ${c.label}`
                                ];
                                if (c.top_path && c.top_path !== c.path) parts.push(`most hit target: ${c.top_path}`);
                                if (c.first_seen) parts.push(`first: ${new Date(c.first_seen).toLocaleString()}`);
                                if (c.last_seen) parts.push(`last: ${new Date(c.last_seen).toLocaleString()}`);
                                return parts;
                            }
                        }
                    }
                },
                animation: { enabled: false },
                onClick: (evt, elements) => {
                    if (!elements.length) return;
                    const c = campaigns[elements[0].index];
                    window.openExpandOverlay(_campaignName(c), 'campaign', '', c.id);
                },
                onHover: (event, activeElements) => {
                    const canvas = event.native && event.native.target;
                    if (canvas) canvas.style.cursor = activeElements.length > 0 ? 'pointer' : 'default';
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255,255,255,0.06)' },
                        ticks: { color: krawlToken('--text-dim'), precision: 0 }
                    },
                    y: {
                        grid: { display: false },
                        ticks: {
                            color: krawlToken('--text-dim'),
                            font: { size: 11 },
                            callback: function (value) {
                                return _campaignTick(String(this.getLabelForValue(value)));
                            }
                        }
                    }
                }
            },
            plugins: [{
                id: 'customCanvasBackgroundColor',
                beforeDraw: (chart) => {
                    if (chart.ctx) {
                        chart.ctx.save();
                        chart.ctx.globalCompositeOperation = 'destination-over';
                        chart.ctx.fillStyle = 'rgba(0,0,0,0)';
                        chart.ctx.fillRect(0, 0, chart.width, chart.height);
                        chart.ctx.restore();
                    }
                }
            }]
        });
    } catch (err) {
        console.error('Error loading campaigns chart:', err);
    }
}

/** Shift the campaigns chart period by N spans (negative = newer, towards now) */
function shiftCampaignPeriod(direction) {
    _campaignOffset = Math.max(0, _campaignOffset + direction);
    loadCampaignsChart();
}

/** Switch the campaigns chart span (1, 7, 30 days) and reset to the current period */
function setCampaignSpan(days, btn) {
    _campaignDays = days;
    _campaignOffset = 0;
    document.querySelectorAll('#campaigns-span-selector .map-limit-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    loadCampaignsChart();
}
