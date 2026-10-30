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

    let release = () => {};
    try {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        release = window.krawlBusy ? krawlBusy(canvas.parentElement) : release;

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
            canvas.parentElement.innerHTML = '<div class="chart-empty">No attacks detected for this IP yet.</div>';
            return;
        }

        const labels = attackTypes.map(item => item.type);
        const counts = attackTypes.map(item => item.count);
        const backgroundColors = labels.map(type => krawlTypeColor(data.colours, type));

        // Create or update chart (track per canvas)
        if (!loadAttackTypesChart._instances) loadAttackTypesChart._instances = {};
        if (loadAttackTypesChart._instances[canvasId]) {
            loadAttackTypesChart._instances[canvasId].destroy();
        }

        const ctx = canvas.getContext('2d');
        const chartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels.map(krawlAttackLabel),
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
                                weight: '500'
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
                        backgroundColor: krawlToken('--raised'),
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
    } finally {
        release();
    }
}


/**
 * Attack Trends line chart for the Attacks tab's period (attacks.js state).
 * Clicking a bucket narrows the tab to that slot; the totals sidebar then
 * totals the slot, and pressing a total narrows to that type.
 */
let attackTrendsChart = null;
let _trendsRequest = 0;

// Shades the selected slot's bucket behind the lines.
const _trendsSlotBand = {
    id: 'trendsSlotBand',
    beforeDatasetsDraw(chart) {
        const i = chart.$slotIndex;
        if (i === undefined || i < 0) return;
        const x = chart.scales.x, area = chart.chartArea;
        const step = chart.data.labels.length > 1 ? x.getPixelForValue(1) - x.getPixelForValue(0) : area.right - area.left;
        const cx = x.getPixelForValue(i);
        const left = Math.max(area.left, cx - step / 2), right = Math.min(area.right, cx + step / 2);
        chart.ctx.save();
        chart.ctx.fillStyle = krawlToken('--tint-accent');
        chart.ctx.fillRect(left, area.top, right - left, area.bottom - area.top);
        chart.ctx.restore();
    },
};

async function loadAttackTrendsChart(canvasId) {
    canvasId = canvasId || 'attack-trends-chart';
    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';
    const req = ++_trendsRequest;
    const s = window.attacksState;
    loadAttackTrendsChart.key = _attacksChartKey();

    let release = () => {};
    try {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        release = window.krawlBusy ? krawlBusy(canvas.parentElement) : release;

        const q = new URLSearchParams({ limit: 10, days: s.days, offset_days: s.offset });
        if (s.slot) q.set('slot', s.slot);
        const url = `${DASHBOARD_PATH}/api/attack-types-daily?${q}`;
        // A stuck query must not leave the panel spinning forever.
        const timeout = new AbortController();
        const timer = setTimeout(() => timeout.abort(), 20000);
        let response;
        try {
            response = await fetch(url, {
                cache: 'no-store',
                headers: { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' },
                signal: timeout.signal,
            });
        } finally {
            clearTimeout(timer);
        }

        if (!response.ok) throw new Error('Failed to fetch daily attack data');

        const data = await response.json();
        if (req !== _trendsRequest) return;  // a newer state already asked
        const attackTypes = data.attack_types || [];
        const dates = data.dates || [];

        _updateTrendsTotals(s.slot ? (data.slot_totals || []) : attackTypes, data.colours);

        if (attackTrendsChart) {
            attackTrendsChart.destroy();
            attackTrendsChart = null;
        }

        if (attackTypes.length === 0) {
            _fillTrendsSlots([], []);
            _showTrendsMessage(canvas, 'No attacks detected in this period. Try a longer span or step back a period.');
            return;
        }

        // Restore canvas if previously hidden
        _showTrendsMessage(canvas, null);

        const bh = data.bucket_hours || 24;
        const shortLabels = dates.map(d => _trendsSlotText(d, bh));

        // Critical/High lead; Medium/Low stay recessive; same band+shade differ by dash.
        const dashes = [[], [6, 4], [2, 3]], seen = {};
        const datasets = attackTypes.map(at => {
            const c = (data.colours && data.colours[at.type]) || { band: 'low', shade: 1 };
            const strong = c.band === 'critical' || c.band === 'high';
            const key = `${c.band}-${c.shade}`;
            seen[key] = (seen[key] || 0) + 1;
            return {
                label: `${krawlAttackLabel(at.type)} (${krawlNum(at.total)})`,
                data: at.daily,
                borderColor: krawlTypeColor(data.colours, at.type, strong ? 1 : 0.55),
                borderWidth: strong ? 2.5 : 1.25,
                borderDash: dashes[Math.min(seen[key], 3) - 1],
                pointRadius: 0,
                pointHitRadius: 8,
                pointHoverRadius: 4,
                pointHoverBackgroundColor: krawlTypeColor(data.colours, at.type),
                tension: 0.15,
                fill: false,
                _attackType: at.type,
                _base: { alpha: strong ? 1 : 0.55, width: strong ? 2.5 : 1.25 },
            };
        });

        const ctx = canvas.getContext('2d');
        attackTrendsChart = new Chart(ctx, {
            type: 'line',
            data: { labels: shortLabels, datasets: datasets },
            plugins: [_trendsSlotBand],
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                // Click a bucket to narrow the tab to it; click it again to widen.
                onClick(evt, _els, chart) {
                    const hit = chart.getElementsAtEventForMode(evt, 'index', { intersect: false }, false);
                    if (!hit.length) return;
                    const slot = dates[hit[0].index];
                    setAttacksState({ slot: window.attacksState.slot === slot ? null : slot, type: null });
                },
                onHover(evt, els) { evt.native.target.style.cursor = els.length ? 'pointer' : ''; },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        enabled: true,
                        backgroundColor: krawlToken('--raised'),
                        titleColor: krawlToken('--accent'),
                        bodyColor: krawlToken('--text'),
                        borderColor: krawlToken('--line'),
                        borderWidth: 1,
                        padding: 10,
                        titleFont: { size: 12, weight: 'bold' },
                        bodyFont: { size: 11 },
                        itemSort: (a, b) => b.parsed.y - a.parsed.y,
                        filter: item => item.parsed.y > 0,
                        callbacks: {
                            label: context => `${krawlAttackLabel(context.dataset._attackType)}: ${krawlNum(context.parsed.y)}`,
                            // Full-strength swatch even for recessive lines.
                            labelColor: context => {
                                const c = krawlTypeColor(data.colours, context.dataset._attackType);
                                return { borderColor: c, backgroundColor: c };
                            },
                        }
                    }
                },
                scales: {
                    x: {
                        // Fewer ticks on a phone, so hourly labels never collide.
                        ticks: { color: krawlToken('--text-dim'), font: { size: 11 }, maxRotation: 0, autoSkip: true, autoSkipPadding: 24, maxTicksLimit: canvas.clientWidth < 480 ? 3 : 8 },
                        grid: { color: krawlToken('--line-soft') },
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: krawlToken('--text-dim'), font: { size: 11 }, precision: 0, callback: v => krawlNum(v) },
                        grid: { color: krawlToken('--line-soft') },
                        title: { display: true, text: bh === 1 ? 'per hour' : bh === 4 ? 'per 4 hours' : 'per day', color: krawlToken('--text-dim'), font: { size: 11 } },
                    }
                },
                animation: { enabled: false },
            }
        });
        attackTrendsChart.$slotIndex = s.slot ? dates.indexOf(s.slot) : -1;
        attackTrendsChart.$colours = data.colours;
        _trendsEmphasise(s.type);
        _fillTrendsSlots(dates, datasets);

    } catch (err) {
        if (req !== _trendsRequest) return;  // a newer request owns the chart
        console.error('Error loading attack trends chart:', err);
        const canvas = document.getElementById(canvasId);
        if (canvas) {
            if (attackTrendsChart) { attackTrendsChart.destroy(); attackTrendsChart = null; }
            _showTrendsMessage(canvas, err.name === 'AbortError'
                ? 'Attack trends took too long to load.'
                : 'Attack trends could not be loaded.', true);
        }
    } finally {
        release();
    }
}

// One place for the chart's empty and error text. `retry` adds a button that
// reloads the same period.
function _showTrendsMessage(canvas, text, retry = false) {
    const wrapper = canvas.parentElement;
    let msg = wrapper.querySelector('.trends-empty-msg');
    if (!text) {
        canvas.style.display = '';
        if (msg) msg.hidden = true;
        return;
    }
    canvas.style.display = 'none';
    if (!msg) {
        msg = document.createElement('div');
        msg.className = 'trends-empty-msg chart-empty';
        msg.setAttribute('role', 'status');
        wrapper.appendChild(msg);
    }
    msg.hidden = false;
    msg.textContent = text;
    if (retry) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'pagination-btn';
        btn.textContent = 'Try again';
        btn.onclick = () => loadAttackTrendsChart();
        msg.append(' ', btn);
    }
}

// Highlights one type's line and dims the rest; null restores the severity emphasis.
function _trendsEmphasise(type) {
    const chart = attackTrendsChart;
    if (!chart) return;
    chart.data.datasets.forEach(d => {
        const on = d._attackType === type;
        d.borderColor = krawlTypeColor(chart.$colours, d._attackType, !type ? d._base.alpha : on ? 1 : 0.15);
        d.borderWidth = type && on ? Math.max(d._base.width, 2.5) : d._base.width;
    });
    chart.update('none');
}

// Screen-reader and keyboard twin of the chart: one row per bucket, its button narrows to that slot.
function _fillTrendsSlots(dates, datasets) {
    const body = document.querySelector('#trends-slots tbody');
    if (!body) return;
    const s = window.attacksState;
    body.replaceChildren(...dates.map((slot, i) => {
        const tr = document.createElement('tr');
        const label = attacksSlotLabel(slot, s.days);
        const th = document.createElement('th');
        th.scope = 'row';
        th.textContent = label;
        const total = document.createElement('td');
        total.textContent = krawlNum(datasets.reduce((n, d) => n + (d.data[i] || 0), 0));
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = `Show ${label}`;
        btn.setAttribute('aria-pressed', String(s.slot === slot));
        btn.onclick = () => setAttacksState({ slot: s.slot === slot ? null : slot, type: null });  // toggles, like a chart click
        // Focus shows the bucket's tooltip, so sighted keyboard users see where they are.
        btn.onfocus = () => _trendsActivate(i);
        btn.onblur = () => _trendsActivate(-1);
        const cell = document.createElement('td');
        cell.append(btn);
        tr.append(th, total, cell);
        return tr;
    }));
}

function _trendsActivate(i) {
    const chart = attackTrendsChart;
    if (!chart) return;
    const els = i < 0 ? [] : chart.data.datasets.map((_, d) => ({ datasetIndex: d, index: i }));
    chart.setActiveElements(els);
    chart.tooltip.setActiveElements(els, { x: i < 0 ? 0 : chart.scales.x.getPixelForValue(i), y: chart.chartArea.top });
    chart.update('none');
}

// Slot "YYYY-MM-DDTHH" (UTC) to "Apr 2 14:00" for 1h/4h buckets, "Apr 2" for daily.
function _trendsSlotText(slot, bh) {
    const dt = new Date(slot.slice(0, 10) + 'T00:00:00');
    const day = dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    return bh < 24 ? `${day} ${slot.slice(11, 13)}:00` : day;
}

function _updateTrendsTotals(totals, colours) {
    const container = document.getElementById('trends-totals');
    if (!container) return;
    const s = window.attacksState;

    // The chart wrapper already shows the empty period message.
    if (totals.length === 0 && !s.slot) {
        container.innerHTML = '';
        return;
    }

    // Each total is a button: pressing it narrows the tab to that type.
    container.innerHTML = '<span class="trends-totals-title"></span>';
    container.firstChild.textContent = s.slot ? `Totals in ${attacksSlotLabel(s.slot, s.days)}` : 'Totals in period';
    if (totals.length === 0) {
        container.insertAdjacentHTML('beforeend', '<span class="trends-totals-empty">No attacks in this slot.</span>');
        return;
    }
    totals.forEach(at => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'trends-total';
        btn.dataset.type = at.type;
        btn.style.setProperty('--type-c', krawlTypeColor(colours, at.type));
        btn.setAttribute('aria-pressed', String(s.type === at.type));
        btn.title = `Show only ${krawlAttackLabel(at.type)}`;
        btn.innerHTML = '<span class="trends-total-dot"></span><span class="trends-total-name"></span><span class="trends-total-count"></span>';
        btn.querySelector('.trends-total-name').textContent = krawlAttackLabel(at.type);
        btn.querySelector('.trends-total-count').textContent = krawlNum(at.total);
        btn.onclick = () => setAttacksState({ type: s.type === at.type ? null : at.type });
        // Hover or focus previews the line; leaving restores the pressed one.
        btn.onmouseenter = btn.onfocus = () => _trendsEmphasise(at.type);
        btn.onmouseleave = btn.onblur = () => _trendsEmphasise(s.type);
        container.appendChild(btn);
    });
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
// Rows the heatmap offers: a glanceable top, a longer list, and every
// campaign the API ranks (it considers up to 200).
const CAMPAIGN_ROW_OPTIONS = [[8, 'Top 8'], [20, 'Top 20'], [200, 'All']];
let _campaignRows = 8;
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

/** Attack type -> inline style setting --atk to its severity shade (low if unknown). */
function _atkStyle(type, colours) {
    return `--atk: ${krawlTypeColor(colours, type)}`;
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
    // One sentence, not a row of stat tiles: the grid below is the figure,
    // this only says what it adds up to and when it peaked.
    const b = (v) => `<strong>${v}</strong>`;
    const total = data.total_campaigns || campaigns.length;
    const noun = (n, one, many) => (n === 1 ? one : many);
    let text = campaigns.length < total
        ? `${b(krawlNum(total))} campaigns active; the ${b(campaigns.length)} shown hit ${b(krawlNum(hits))} times.`
        : `${b(krawlNum(total))} ${noun(total, 'campaign', 'campaigns')} hit ${b(krawlNum(hits))} ${noun(hits, 'time', 'times')}.`;
    if (slotTotals[peak]) {
        text += ` Busiest: ${b(_escapeHtml(_campaignSlotText(data.slots[peak], data.slot_hours)))}, with ${krawlNum(slotTotals[peak])} ${noun(slotTotals[peak], 'hit', 'hits')}.`;
    }
    box.innerHTML = text;
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
        const types = c.attack_types || [];
        // The row takes the hue of its main attack type (types arrive sorted
        // by count); file-only campaigns stay in the neutral bucket.
        const hue = _atkStyle(types.length ? types[0] : 'other', data.colours);
        const typeList = types.slice(0, 3).map(t =>
            `<span class="atk-tag"><span class="atk-swatch" style="${_atkStyle(t, data.colours)}"></span>${_escapeHtml(krawlAttackLabel(t))}</span>`
        ).join('') + (types.length > 3 ? `<span class="atk-tag">+${types.length - 3}</span>` : '');
        const cells = c.activity.map((n, i) =>
            `<span class="activity-cell shade-${_campaignShade(n, max)}${future[i] ? ' is-future' : ''}" data-row="${row}" data-slot="${i}"></span>`
        ).join('');
        return `<div class="activity-row" style="${hue}" role="row" tabindex="0" data-row="${row}"` +
            ` aria-label="${_escapeHtml(name)}: ${c.hits} hits from ${c.ips} IPs. Open events.">` +
            `<span class="activity-name" role="cell" title="${_escapeHtml(name)}">` +
            `<span class="activity-target">${_escapeHtml(_middleEllipsis(name, 44))}</span>` +
            `<span class="activity-types">${typeList || _escapeHtml(c.sources)}</span></span>` +
            `<span class="activity-strip" role="cell">${cells}</span>` +
            `<span class="num activity-hits" role="cell"><span class="num-bar" style="--pct:${(c.hits / maxHits * 100).toFixed(1)}%">${krawlNum(c.hits)}</span></span>` +
            `<span class="num" role="cell">${krawlNum(c.ips)}</span></div>`;
    }).join('');

    // Legend: the intensity ramp, then one swatch per row colour on screen.
    // Probes and uploads share the grey bucket, so they share one entry.
    const shown = [...new Set(campaigns.map(c => {
        const t = (c.attack_types || [])[0];
        return !t || t === 'common_probes' || t === 'scanner_probe' ? 'other' : t;
    }))];
    const legend =
        `<div class="activity-foot">` +
        `<span class="activity-legend" aria-hidden="true"><span>Fewer hits</span>` +
        Array.from({ length: CAMPAIGN_SHADES }, (_, i) => `<span class="activity-cell shade-${i + 1}"></span>`).join('') +
        `<span>More</span><span class="activity-legend-key">Row colour is the main attack type:</span>` +
        shown.map(t => `<span class="atk-tag"><span class="atk-swatch" style="${_atkStyle(t, data.colours)}"></span>${_escapeHtml(t === 'other' ? 'Probes, uploads, other' : krawlAttackLabel(t))}</span>`).join('') +
        `</span>` +
        `<span class="activity-rows"><span class="activity-rows-label">${campaigns.length} of ${data.total_campaigns} shown</span>` +
        `<span class="row gap-1" role="group" aria-label="Campaigns shown">` +
        CAMPAIGN_ROW_OPTIONS.map(([n, label], i) => {
            // An option that would show nothing new stays visible but off.
            const idle = i > 0 && data.total_campaigns <= CAMPAIGN_ROW_OPTIONS[i - 1][0] && _campaignRows !== n;
            return `<button type="button" class="map-limit-btn${_campaignRows === n ? ' active' : ''}"` +
                ` aria-pressed="${_campaignRows === n}" data-rows="${n}"${idle ? ' disabled' : ''}>${label}</button>`;
        }).join('') +
        `</span></span></div>`;

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
        const rowsBtn = e.target.closest('[data-rows]');
        if (rowsBtn) {
            _campaignRows = Number(rowsBtn.dataset.rows);
            loadCampaignsChart();
            return;
        }
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
            ((c.attack_types || []).length ? `<div class="activity-tooltip-title">${_escapeHtml(c.attack_types.map(krawlAttackLabel).join(', '))}</div>` : '') +
            `<div><strong>${krawlNum(n)}</strong> ${n === 1 ? 'hit' : 'hits'}</div>`;
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
    const release = window.krawlBusy ? krawlBusy(grid) : () => {};

    try {
        const response = await fetch(
            DASHBOARD_PATH + `/api/campaign-stats?limit=${_campaignRows}&days=${_campaignDays}&offset=${_campaignOffset}`,
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
        release();
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
