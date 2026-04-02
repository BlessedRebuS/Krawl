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
            canvas.parentElement.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#8b949e;font-size:13px;">No attack data</div>';
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
                    borderColor: '#0d1117',
                    borderWidth: 3,
                    hoverBorderColor: '#58a6ff',
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
                            color: '#c9d1d9',
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
                        titleColor: '#58a6ff',
                        bodyColor: '#c9d1d9',
                        borderColor: '#58a6ff',
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
                emptyMsg.style.cssText = 'display:flex;align-items:center;justify-content:center;height:100%;color:#8b949e;font-size:13px;';
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
                        titleColor: '#58a6ff',
                        bodyColor: '#c9d1d9',
                        borderColor: '#30363d',
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
                        ticks: { color: '#8b949e', font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 15 },
                        grid: { color: 'rgba(48, 54, 61, 0.3)' },
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#8b949e', font: { size: 10 }, precision: 0 },
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
        container.innerHTML = '<span style="color: #8b949e; font-size: 0.8em;">No data</span>';
        return;
    }

    let html = '<span style="color: #8b949e; font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px;">Totals (period)</span>';
    attackTypes.forEach(at => {
        const color = _trendsColor(at.type);
        html += `<div style="display: flex; align-items: center; gap: 8px; padding: 4px 0; cursor: pointer; border-radius: 4px; transition: background 0.15s;"
                      onmouseover="this.style.background='rgba(255,255,255,0.03)'"
                      onmouseout="this.style.background='transparent'"
                      onclick="filterAttackTableByType('${at.type.replace(/'/g, "\\'")}')">
            <span style="width: 8px; height: 8px; border-radius: 50%; background: ${color}; flex-shrink: 0;"></span>
            <span style="color: #c9d1d9; font-size: 0.8em; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${at.type}">${at.type}</span>
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
