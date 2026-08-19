// Radar chart generation for IP stats
// Used by map popups and IP detail partials
// Extracted from dashboard_template.py (lines ~2092-2181)

/**
 * Generate an SVG radar chart for category scores.
 * This is a reusable function that can be called from:
 *   - Map popup panels (generateMapPanelRadarChart in map.js)
 *   - IP detail partials (server-side or client-side rendering)
 *
 * @param {Object} categoryScores - Object with keys: attacker, good_crawler, bad_crawler, regular_user, unknown
 * @param {number} [size=200] - Width/height of the SVG in pixels
 * @param {boolean} [showLegend=true] - Whether to show the legend below the chart
 * @param {string} [legendPosition='below'] - 'below' or 'side' (side = legend to the right of the chart)
 * @returns {string} HTML string containing the SVG radar chart
 */
function generateRadarChart(categoryScores, size, showLegend, legendPosition) {
    size = size || 200;
    if (showLegend === undefined) showLegend = true;
    legendPosition = legendPosition || 'below';

    if (!categoryScores || Object.keys(categoryScores).length === 0) {
        return '<div style="color: var(--text-dim); text-align: center; padding: 20px;">No category data available</div>';
    }

    const scores = {
        attacker: categoryScores.attacker || 0,
        good_crawler: categoryScores.good_crawler || 0,
        bad_crawler: categoryScores.bad_crawler || 0,
        regular_user: categoryScores.regular_user || 0,
        unknown: categoryScores.unknown || 0
    };

    const maxScore = Math.max(...Object.values(scores), 1);
    const minVisibleRadius = 0.15;
    const normalizedScores = {};

    Object.keys(scores).forEach(key => {
        normalizedScores[key] = minVisibleRadius + (scores[key] / maxScore) * (1 - minVisibleRadius);
    });

    const colors = { ...krawlCategoryColors(), unknown: krawlToken('--text-dim') };

    const labels = {
        attacker: 'Attacker',
        good_crawler: 'Good Bot',
        bad_crawler: 'Bad Bot',
        regular_user: 'User',
        unknown: 'Unknown'
    };

    const cx = 100, cy = 100, maxRadius = 75;

    const flexDir = legendPosition === 'side' ? 'row' : 'column';
    let html = `<div style="display: flex; flex-direction: ${flexDir}; align-items: center; gap: 16px; justify-content: center;">`;
    html += `<svg class="radar-chart" viewBox="-30 -30 260 260" preserveAspectRatio="xMidYMid meet" style="width: ${size}px; height: ${size}px;">`;

    // Draw concentric circles (grid)
    for (let i = 1; i <= 5; i++) {
        const r = (maxRadius / 5) * i;
        html += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--line)" stroke-width="0.5"/>`;
    }

    const angles = [0, 72, 144, 216, 288];
    const keys = ['good_crawler', 'regular_user', 'unknown', 'bad_crawler', 'attacker'];

    // Draw axis lines and labels
    angles.forEach((angle, i) => {
        const rad = (angle - 90) * Math.PI / 180;
        const x2 = cx + maxRadius * Math.cos(rad);
        const y2 = cy + maxRadius * Math.sin(rad);
        html += `<line x1="${cx}" y1="${cy}" x2="${x2}" y2="${y2}" stroke="var(--line)" stroke-width="0.5"/>`;

        const labelDist = maxRadius + 35;
        const lx = cx + labelDist * Math.cos(rad);
        const ly = cy + labelDist * Math.sin(rad);
        html += `<text x="${lx}" y="${ly}" fill="var(--text-dim)" font-size="12" text-anchor="middle" dominant-baseline="middle">${labels[keys[i]]}</text>`;
    });

    // Calculate polygon points
    let points = [];
    angles.forEach((angle, i) => {
        const normalizedScore = normalizedScores[keys[i]];
        const rad = (angle - 90) * Math.PI / 180;
        const r = normalizedScore * maxRadius;
        const x = cx + r * Math.cos(rad);
        const y = cy + r * Math.sin(rad);
        points.push(`${x},${y}`);
    });

    // Determine dominant category for color
    const dominantKey = Object.keys(scores).reduce((a, b) => scores[a] > scores[b] ? a : b);
    const dominantColor = colors[dominantKey];

    // Draw filled polygon
    html += `<polygon points="${points.join(' ')}" fill="${dominantColor}" fill-opacity="0.4" stroke="${dominantColor}" stroke-width="2.5"/>`;

    // Draw data point dots
    angles.forEach((angle, i) => {
        const normalizedScore = normalizedScores[keys[i]];
        const rad = (angle - 90) * Math.PI / 180;
        const r = normalizedScore * maxRadius;
        const x = cx + r * Math.cos(rad);
        const y = cy + r * Math.sin(rad);
        html += `<circle cx="${x}" cy="${y}" r="4.5" fill="${colors[keys[i]]}" stroke="var(--bg)" stroke-width="2"/>`;
    });

    html += '</svg>';

    // Optional legend
    if (showLegend) {
        html += '<div class="radar-legend">';
        keys.forEach(key => {
            html += '<div class="radar-legend-item">';
            html += `<div class="radar-legend-color" style="background: ${colors[key]};"></div>`;
            html += `<span style="color: var(--text-dim);">${labels[key]}: ${scores[key]} pt</span>`;
            html += '</div>';
        });
        html += '</div>';
    }

    html += '</div>';
    return html;
}
