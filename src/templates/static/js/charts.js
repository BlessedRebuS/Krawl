// Chart.js Attack Types Chart
// Extracted from dashboard_template.py (lines ~3370-3550)

let attackTypesChart = null;
let attackTypesChartLoaded = false;

async function loadAttackTypesChart() {
    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';

    try {
        const canvas = document.getElementById('attack-types-chart');
        if (!canvas) return;

        const response = await fetch(DASHBOARD_PATH + '/api/attack-types-stats?limit=10', {
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
            canvas.style.display = 'none';
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

        // Create or update chart
        if (attackTypesChart) {
            attackTypesChart.destroy();
        }

        const ctx = canvas.getContext('2d');
        attackTypesChart = new Chart(ctx, {
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
                        position: 'right',
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

        attackTypesChartLoaded = true;
    } catch (err) {
        console.error('Error loading attack types chart:', err);
    }
}
