// Chart.js Attack Types Chart
// Extracted from dashboard_template.py (lines ~3370-3550)

let attackTypesChart = null;
let attackTypesChartLoaded = false;

// Ordered for clear separation on the dark canvas.
const KRAWL_CHART_SERIES_COLORS = [
    '#3ad6d1', '#ff5c52', '#35d07f', '#ffc94d', '#b083f5',
    '#4da3ff', '#f2649f', '#f28e2b', '#a0cbe8', '#9c755f'
];

function krawlSeriesColor(index, alpha) {
    const hex = KRAWL_CHART_SERIES_COLORS[index % KRAWL_CHART_SERIES_COLORS.length];
    if (alpha === undefined) return hex;
    const value = parseInt(hex.slice(1), 16);
    const red = (value >> 16) & 255;
    const green = (value >> 8) & 255;
    const blue = value & 255;
    return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
}

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
        const backgroundColors = labels.map((_, index) => krawlSeriesColor(index));

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

        const datasets = attackTypes.map((at, index) => ({
            label: `${at.type} (${at.total})`,
            data: at.daily,
            borderColor: krawlSeriesColor(index),
            backgroundColor: krawlSeriesColor(index, 0.05),
            borderWidth: 2,
            pointRadius: 0,
            pointHitRadius: 8,
            pointHoverRadius: 4,
            pointHoverBackgroundColor: krawlSeriesColor(index),
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
        // The chart wrapper already renders the empty-state message. Keeping
        // a second "No data" label in the totals gutter made the mobile chart
        // look like two unrelated empty visualizations.
        container.innerHTML = '';
        return;
    }

    let html = '<span style="color: var(--text-dim); font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px;">Totals (period)</span>';
    attackTypes.forEach((at, index) => {
        const color = krawlSeriesColor(index);
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
 * Campaign activity (Threats tab).
 * One row per campaign, one cell per time slot: hours for 1D, quarter-days for
 * 7D, days for 30D. Cell shade is hits in that slot on a single-hue ramp, so
 * the reader sees *when* each campaign fired, not only how much. Rows are
 * ranked and totalled by hits inside the period (the API does both), and are
 * named by the target they hit, since a TLSH prefix says nothing to a reader.
 * Selecting a row opens that campaign's events in the expand overlay.
 */
let _campaignDays = 1;
let _campaignOffset = 0;
let _campaignRequest = 0;
const CAMPAIGN_ROWS = 8;
const CAMPAIGN_SHADES = 5;

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
        const fmt = { month: 'short', day: 'numeric' };
        const end = _campaignEndDate();
        if (_campaignDays === 1) {
            label.textContent = _campaignOffset === 0 ? `Today, ${end.toLocaleDateString('en-US', fmt)}` : end.toLocaleDateString('en-US', { weekday: 'short', ...fmt });
        } else {
            label.textContent = `${_campaignStartDate().toLocaleDateString('en-US', fmt)} – ${end.toLocaleDateString('en-US', fmt)}`;
        }
    }
    const next = document.getElementById('campaigns-period-next');
    if (next) next.disabled = _campaignOffset === 0;
}

function _escapeHtml(value) {
    const el = document.createElement('span');
    el.textContent = value;
    return el.innerHTML;
}

/** Shorten from the middle: both the root of a path and its leaf identify it
 *  (/.git/objects/0a/e719… differ only at the end). */
function _middleEllipsis(text, max) {
    if (text.length <= max) return text;
    const keep = max - 1;
    const head = Math.ceil(keep * 0.45);
    return text.slice(0, head) + '…' + text.slice(text.length - (keep - head));
}

function _campaignName(c) {
    return c.top_path || c.path || `campaign ${c.label}`;
}

/** Slot start + width -> "Sep 27, 14:00–15:00" / "Sep 21, 06:00–12:00" / "Sep 21". */
function _campaignSlotText(iso, slotHours) {
    const start = new Date(iso);
    const day = start.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
    if (slotHours >= 24) return day;
    const end = new Date(start.getTime() + slotHours * 3600 * 1000);
    const hm = d => d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    return `${day}, ${hm(start)}–${hm(end)}`;
}

/** Axis ticks: every 6h for a day, each midnight for a week, weekly for 30D. */
function _campaignTickLabel(iso, index, slotHours) {
    const d = new Date(iso);
    if (slotHours === 1) return index % 6 === 0 ? d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }) : '';
    if (slotHours === 6) return d.getHours() === 0 ? d.toLocaleDateString('en-US', { weekday: 'short', day: 'numeric' }) : '';
    return index % 7 === 0 ? d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '';
}

/** Hits -> shade 1..5. Square-root scale: one loud campaign would otherwise
 *  flatten every other row to the lightest shade. */
function _campaignShade(count, max) {
    if (!count) return 0;
    return Math.max(1, Math.ceil(Math.sqrt(count / max) * CAMPAIGN_SHADES));
}

function _renderCampaignSummary(data) {
    const box = document.getElementById('campaigns-summary');
    if (!box) return;
    const campaigns = data.campaigns || [];
    if (!campaigns.length) {
        box.innerHTML = '';
        return;
    }
    const hits = campaigns.reduce((sum, c) => sum + c.hits, 0);
    // Busiest slot across the shown campaigns: when the pressure peaked.
    const slotTotals = (data.slots || []).map((_, i) => campaigns.reduce((s, c) => s + (c.activity[i] || 0), 0));
    let peak = 0;
    slotTotals.forEach((v, i) => { if (v > slotTotals[peak]) peak = i; });
    const stat = (value, label) =>
        `<div class="activity-stat"><span class="activity-stat-value">${value}</span>` +
        `<span class="activity-stat-label">${label}</span></div>`;
    const total = data.total_campaigns || campaigns.length;
    box.innerHTML =
        stat(total.toLocaleString(), total === 1 ? 'campaign active' : 'campaigns active') +
        stat(hits.toLocaleString(), campaigns.length < total ? `hits from the top ${campaigns.length}` : 'hits') +
        (slotTotals[peak]
            ? stat(_escapeHtml(_campaignSlotText(data.slots[peak], data.slot_hours)), `busiest, ${slotTotals[peak].toLocaleString()} hits`)
            : '');
}

function _renderCampaignActivity(data) {
    const grid = document.getElementById('campaigns-activity');
    if (!grid) return;
    const campaigns = data.campaigns || [];
    const slots = data.slots || [];
    const slotHours = data.slot_hours || 1;
    const max = Math.max(1, ...campaigns.flatMap(c => c.activity));
    const maxHits = Math.max(1, ...campaigns.map(c => c.hits));
    grid.style.setProperty('--slots', slots.length);
    // Slots that have not started yet are outlined, not filled: "no hits
    // yet" must not read the same as "quiet".
    const now = Date.now();
    const future = slots.map(iso => new Date(iso).getTime() > now);

    const head =
        `<div class="activity-row activity-head" role="row">` +
        `<span role="columnheader">Target</span>` +
        `<span class="activity-strip activity-axis" role="columnheader" aria-label="Hits over time">` +
        slots.map((iso, i) => `<span>${_campaignTickLabel(iso, i, slotHours)}</span>`).join('') +
        `</span><span class="num" role="columnheader">Hits</span>` +
        `<span class="num" role="columnheader" title="Distinct source IPs in this period">IPs</span></div>`;

    const rows = campaigns.map((c, row) => {
        const name = _campaignName(c);
        const types = (c.attack_types || []).map(t => t.replace(/_/g, ' '));
        const typeText = types.length > 2 ? `${types.slice(0, 2).join(', ')} +${types.length - 2}` : types.join(', ');
        const cells = c.activity.map((n, i) =>
            `<span class="activity-cell shade-${_campaignShade(n, max)}${future[i] ? ' is-future' : ''}" data-row="${row}" data-slot="${i}"></span>`
        ).join('');
        return `<div class="activity-row" role="row" tabindex="0" data-row="${row}"` +
            ` aria-label="${_escapeHtml(name)}: ${c.hits} hits from ${c.ips} IPs. Open events.">` +
            `<span class="activity-name" role="cell" title="${_escapeHtml(name)}">` +
            `<span class="activity-target">${_escapeHtml(_middleEllipsis(name, 44))}</span>` +
            `<span class="activity-types">${_escapeHtml(typeText || c.sources)}</span></span>` +
            `<span class="activity-strip" role="cell">${cells}</span>` +
            `<span class="num activity-hits" role="cell"><span class="num-bar" style="--pct:${(c.hits / maxHits * 100).toFixed(1)}%">${c.hits.toLocaleString()}</span></span>` +
            `<span class="num" role="cell">${c.ips.toLocaleString()}</span></div>`;
    }).join('');

    const legend =
        `<div class="activity-legend" aria-hidden="true"><span>Fewer hits</span>` +
        Array.from({ length: CAMPAIGN_SHADES }, (_, i) => `<span class="activity-cell shade-${i + 1}"></span>`).join('') +
        `<span>More</span>` +
        (data.total_campaigns > campaigns.length
            ? `<span class="activity-more">Top ${campaigns.length} of ${data.total_campaigns} by hits. The table below lists every campaign.</span>`
            : '') +
        `</div>`;

    grid.innerHTML = head + rows + legend;
    grid._campaignData = data;
}

function _bindCampaignActivity() {
    const grid = document.getElementById('campaigns-activity');
    const tip = document.getElementById('campaigns-tooltip');
    if (!grid || grid._bound) return;
    grid._bound = true;

    const open = (rowEl) => {
        const data = grid._campaignData;
        const c = data && data.campaigns[Number(rowEl.dataset.row)];
        if (c && window.openExpandOverlay) window.openExpandOverlay(_campaignName(c), 'campaign', '', c.id);
    };
    grid.addEventListener('click', (e) => {
        const rowEl = e.target.closest('.activity-row[data-row]');
        if (rowEl) open(rowEl);
    });
    grid.addEventListener('keydown', (e) => {
        const rowEl = e.target.closest('.activity-row[data-row]');
        if (!rowEl) return;
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(rowEl); }
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            const sib = e.key === 'ArrowDown' ? rowEl.nextElementSibling : rowEl.previousElementSibling;
            if (sib && sib.dataset.row !== undefined) sib.focus();
        }
    });
    if (!tip) return;
    grid.addEventListener('mouseover', (e) => {
        const cell = e.target.closest('.activity-cell[data-slot]');
        const data = grid._campaignData;
        if (!cell || !data) return;
        const c = data.campaigns[Number(cell.dataset.row)];
        const i = Number(cell.dataset.slot);
        const n = c.activity[i] || 0;
        tip.innerHTML =
            `<div class="activity-tooltip-title">${_escapeHtml(_campaignSlotText(data.slots[i], data.slot_hours))}</div>` +
            `<div class="data-mono">${_escapeHtml(_middleEllipsis(_campaignName(c), 56))}</div>` +
            `<div><strong>${n.toLocaleString()}</strong> ${n === 1 ? 'hit' : 'hits'}</div>`;
        tip.hidden = false;
        const host = tip.offsetParent || grid;
        const hostBox = host.getBoundingClientRect();
        const box = cell.getBoundingClientRect();
        const left = Math.min(
            Math.max(0, box.left - hostBox.left + box.width / 2 - tip.offsetWidth / 2),
            hostBox.width - tip.offsetWidth
        );
        tip.style.left = `${left}px`;
        tip.style.top = `${box.top - hostBox.top - tip.offsetHeight - 8}px`;
    });
    grid.addEventListener('mouseleave', () => { tip.hidden = true; });
    grid.addEventListener('mouseout', (e) => {
        if (!e.relatedTarget || !e.relatedTarget.closest || !e.relatedTarget.closest('.activity-cell[data-slot]')) tip.hidden = true;
    });
}

async function loadCampaignsChart() {
    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';
    const grid = document.getElementById('campaigns-activity');
    if (!grid) return;
    _bindCampaignActivity();
    _campaignLabel();
    // Rapid period clicks race; only the latest response may paint.
    const request = ++_campaignRequest;
    grid.setAttribute('aria-busy', 'true');
    grid.classList.add('is-loading');

    try {
        const response = await fetch(
            DASHBOARD_PATH + `/api/campaign-stats?limit=${CAMPAIGN_ROWS}&days=${_campaignDays}&offset=${_campaignOffset}`,
            { cache: 'no-store', headers: { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' } }
        );
        if (!response.ok) throw new Error('Failed to fetch campaign stats');
        const data = await response.json();
        if (request !== _campaignRequest) return;
        if (data.error) throw new Error(data.error);

        const campaigns = data.campaigns || [];
        const empty = document.getElementById('campaigns-chart-empty');
        if (empty) empty.hidden = campaigns.length > 0;
        grid.hidden = campaigns.length === 0;
        _renderCampaignSummary(data);
        if (campaigns.length) _renderCampaignActivity(data);
    } catch (err) {
        console.error('Error loading campaign activity:', err);
    } finally {
        if (request === _campaignRequest) {
            grid.removeAttribute('aria-busy');
            grid.classList.remove('is-loading');
        }
    }
}

/** Shift the campaign period by N spans (negative = newer, towards now) */
function shiftCampaignPeriod(direction) {
    _campaignOffset = Math.max(0, _campaignOffset + direction);
    loadCampaignsChart();
}

/** Switch the campaign span (1, 7, 30 days) and reset to the current period */
function setCampaignSpan(days, btn) {
    _campaignDays = days;
    _campaignOffset = 0;
    document.querySelectorAll('#campaigns-span-selector .map-limit-btn').forEach(b => {
        b.classList.toggle('active', b === btn);
        b.setAttribute('aria-pressed', b === btn ? 'true' : 'false');
    });
    loadCampaignsChart();
}
