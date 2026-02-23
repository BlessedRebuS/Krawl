// IP Map Visualization
// Extracted from dashboard_template.py (lines ~2978-3348)

let attackerMap = null;
let allIps = [];
let mapMarkers = [];       // all marker objects, each tagged with .options.category
let clusterGroup = null;   // single shared MarkerClusterGroup
let hiddenCategories = new Set();

const categoryColors = {
    attacker: '#f85149',
    bad_crawler: '#f0883e',
    good_crawler: '#3fb950',
    regular_user: '#58a6ff',
    unknown: '#8b949e'
};

// Build a conic-gradient pie icon showing the category mix inside a cluster
function createClusterIcon(cluster) {
    const children = cluster.getAllChildMarkers();
    const counts = {};
    children.forEach(m => {
        const cat = m.options.category || 'unknown';
        counts[cat] = (counts[cat] || 0) + 1;
    });

    const total = children.length;
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    let gradientStops = [];
    let cumulative = 0;
    sorted.forEach(([cat, count]) => {
        const start = (cumulative / total) * 360;
        cumulative += count;
        const end = (cumulative / total) * 360;
        const color = categoryColors[cat] || '#8b949e';
        gradientStops.push(`${color} ${start.toFixed(1)}deg ${end.toFixed(1)}deg`);
    });

    const size = Math.max(32, Math.min(50, 32 + Math.log2(total) * 5));
    const inner = size - 10;
    const offset = 5; // (size - inner) / 2

    return L.divIcon({
        html: `<div style="position:relative;width:${size}px;height:${size}px;">` +
            `<div style="position:absolute;top:0;left:0;width:${size}px;height:${size}px;border-radius:50%;background:conic-gradient(${gradientStops.join(', ')});box-shadow:0 0 6px rgba(0,0,0,0.5);"></div>` +
            `<div style="position:absolute;top:${offset}px;left:${offset}px;width:${inner}px;height:${inner}px;border-radius:50%;background:rgba(13,17,23,0.85);color:#e6edf3;font-size:11px;font-weight:700;line-height:${inner}px;text-align:center;">${total}</div>` +
            `</div>`,
        className: 'ip-cluster-icon',
        iconSize: L.point(size, size)
    });
}

// City coordinates database (major cities worldwide)
const cityCoordinates = {
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
};

// Country center coordinates (fallback when city not found)
const countryCoordinates = {
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
};

// Helper function to get coordinates for an IP
function getIPCoordinates(ip) {
    if (ip.latitude != null && ip.longitude != null) {
        return [ip.latitude, ip.longitude];
    }
    if (ip.city && cityCoordinates[ip.city]) {
        return cityCoordinates[ip.city];
    }
    if (ip.country_code && countryCoordinates[ip.country_code]) {
        return countryCoordinates[ip.country_code];
    }
    return null;
}

// Fetch IPs from the API, handling pagination for "all"
async function fetchIpsForMap(limit) {
    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';
    const headers = { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' };

    if (limit === 'all') {
        // Fetch in pages of 1000 until we have everything
        let collected = [];
        let page = 1;
        const pageSize = 1000;
        while (true) {
            const response = await fetch(
                `${DASHBOARD_PATH}/api/all-ips?page=${page}&page_size=${pageSize}&sort_by=total_requests&sort_order=desc`,
                { cache: 'no-store', headers }
            );
            if (!response.ok) throw new Error('Failed to fetch IPs');
            const data = await response.json();
            collected = collected.concat(data.ips || []);
            if (page >= data.pagination.total_pages) break;
            page++;
        }
        return collected;
    }

    const pageSize = parseInt(limit, 10);
    const response = await fetch(
        `${DASHBOARD_PATH}/api/all-ips?page=1&page_size=${pageSize}&sort_by=total_requests&sort_order=desc`,
        { cache: 'no-store', headers }
    );
    if (!response.ok) throw new Error('Failed to fetch IPs');
    const data = await response.json();
    return data.ips || [];
}

// Build markers from an IP list and add them to the map
function buildMapMarkers(ips) {
    // Clear existing cluster group
    if (clusterGroup) {
        attackerMap.removeLayer(clusterGroup);
        clusterGroup.clearLayers();
    }
    mapMarkers = [];

    // Single cluster group with custom pie-chart icons
    clusterGroup = L.markerClusterGroup({
        maxClusterRadius: 20,
        spiderfyOnMaxZoom: true,
        showCoverageOnHover: false,
        zoomToBoundsOnClick: true,
        disableClusteringAtZoom: 10,
        iconCreateFunction: createClusterIcon
    });

    // Track used coordinates to add small offsets for overlapping markers
    const usedCoordinates = {};
    function getUniqueCoordinates(baseCoords) {
        const key = `${baseCoords[0].toFixed(4)},${baseCoords[1].toFixed(4)}`;
        if (!usedCoordinates[key]) {
            usedCoordinates[key] = 0;
        }
        usedCoordinates[key]++;

        if (usedCoordinates[key] === 1) {
            return baseCoords;
        }

        const angle = (usedCoordinates[key] * 137.5) % 360;
        const distance = 0.05 * Math.sqrt(usedCoordinates[key]);
        const latOffset = distance * Math.cos(angle * Math.PI / 180);
        const lngOffset = distance * Math.sin(angle * Math.PI / 180);

        return [
            baseCoords[0] + latOffset,
            baseCoords[1] + lngOffset
        ];
    }

    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';

    ips.forEach(ip => {
        if (!ip.country_code || !ip.category) return;

        const baseCoords = getIPCoordinates(ip);
        if (!baseCoords) return;

        const coords = getUniqueCoordinates(baseCoords);
        const category = ip.category.toLowerCase();
        if (!categoryColors[category]) return;

        const requestsForScale = Math.min(ip.total_requests, 10000);
        const sizeRatio = Math.pow(requestsForScale / 10000, 0.5);
        const markerSize = Math.max(10, Math.min(30, 10 + (sizeRatio * 20)));

        const markerElement = document.createElement('div');
        markerElement.className = `ip-marker marker-${category}`;
        markerElement.style.width = markerSize + 'px';
        markerElement.style.height = markerSize + 'px';
        markerElement.style.fontSize = (markerSize * 0.5) + 'px';
        markerElement.textContent = '\u25CF';

        const marker = L.marker(coords, {
            icon: L.divIcon({
                html: markerElement.outerHTML,
                iconSize: [markerSize, markerSize],
                className: `ip-custom-marker category-${category}`
            }),
            category: category
        });

        const categoryColor = categoryColors[category] || '#8b949e';
        const categoryLabels = {
            attacker: 'Attacker',
            bad_crawler: 'Bad Crawler',
            good_crawler: 'Good Crawler',
            regular_user: 'Regular User',
            unknown: 'Unknown'
        };

        marker.bindPopup('', {
            maxWidth: 550,
            className: 'ip-detail-popup'
        });

        marker.on('click', async function(e) {
            const loadingPopup = `
                <div style="padding: 12px; min-width: 280px; max-width: 320px;">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                        <strong style="color: #58a6ff; font-size: 14px;">${ip.ip}</strong>
                        <span style="background: ${categoryColor}1a; color: ${categoryColor}; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600;">
                            ${categoryLabels[category]}
                        </span>
                    </div>
                    <div style="text-align: center; padding: 20px; color: #8b949e;">
                        <div style="font-size: 12px;">Loading details...</div>
                    </div>
                </div>
            `;

            marker.setPopupContent(loadingPopup);
            marker.openPopup();

            try {
                const response = await fetch(`${DASHBOARD_PATH}/api/ip-stats/${ip.ip}`);
                if (!response.ok) throw new Error('Failed to fetch IP stats');

                const stats = await response.json();

                let popupContent = `
                    <div style="padding: 12px; min-width: 200px;">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                            <strong style="color: #58a6ff; font-size: 14px;">${ip.ip}</strong>
                            <span style="background: ${categoryColor}1a; color: ${categoryColor}; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600;">
                                ${categoryLabels[category]}
                            </span>
                        </div>
                        <span style="color: #8b949e; font-size: 12px;">
                            ${ip.city ? (ip.country_code ? `${ip.city}, ${ip.country_code}` : ip.city) : (ip.country_code || 'Unknown')}
                        </span><br/>
                        <div style="margin-top: 8px; border-top: 1px solid #30363d; padding-top: 8px;">
                            <div style="margin-bottom: 4px;"><span style="color: #8b949e;">Requests:</span> <span style="color: ${categoryColor}; font-weight: bold;">${ip.total_requests}</span></div>
                            <div style="margin-bottom: 4px;"><span style="color: #8b949e;">First Seen:</span> <span style="color: #58a6ff; font-size: 11px;">${formatTimestamp(ip.first_seen)}</span></div>
                            <div style="margin-bottom: 4px;"><span style="color: #8b949e;">Last Seen:</span> <span style="color: #58a6ff; font-size: 11px;">${formatTimestamp(ip.last_seen)}</span></div>
                        </div>
                `;

                if (stats.category_scores && Object.keys(stats.category_scores).length > 0) {
                    const chartHtml = generateMapPanelRadarChart(stats.category_scores);
                    popupContent += `
                        <div style="margin-top: 12px; border-top: 1px solid #30363d; padding-top: 12px;">
                            ${chartHtml}
                        </div>
                    `;
                }

                popupContent += '</div>';
                marker.setPopupContent(popupContent);
            } catch (err) {
                console.error('Error fetching IP stats:', err);
                const errorPopup = `
                    <div style="padding: 12px; min-width: 280px; max-width: 320px;">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                            <strong style="color: #58a6ff; font-size: 14px;">${ip.ip}</strong>
                            <span style="background: ${categoryColor}1a; color: ${categoryColor}; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600;">
                                ${categoryLabels[category]}
                            </span>
                        </div>
                        <span style="color: #8b949e; font-size: 12px;">
                            ${ip.city ? (ip.country_code ? `${ip.city}, ${ip.country_code}` : ip.city) : (ip.country_code || 'Unknown')}
                        </span><br/>
                        <div style="margin-top: 8px; border-top: 1px solid #30363d; padding-top: 8px;">
                            <div style="margin-bottom: 4px;"><span style="color: #8b949e;">Requests:</span> <span style="color: ${categoryColor}; font-weight: bold;">${ip.total_requests}</span></div>
                            <div style="margin-bottom: 4px;"><span style="color: #8b949e;">First Seen:</span> <span style="color: #58a6ff; font-size: 11px;">${formatTimestamp(ip.first_seen)}</span></div>
                            <div style="margin-bottom: 4px;"><span style="color: #8b949e;">Last Seen:</span> <span style="color: #58a6ff; font-size: 11px;">${formatTimestamp(ip.last_seen)}</span></div>
                        </div>
                        <div style="margin-top: 12px; border-top: 1px solid #30363d; padding-top: 12px; text-align: center; color: #f85149; font-size: 11px;">
                            Failed to load chart: ${err.message}
                        </div>
                    </div>
                `;
                marker.setPopupContent(errorPopup);
            }
        });

        mapMarkers.push(marker);
        // Only add to cluster if category is not hidden
        if (!hiddenCategories.has(category)) {
            clusterGroup.addLayer(marker);
        }
    });

    attackerMap.addLayer(clusterGroup);

    // Fit map to visible markers
    const visibleMarkers = mapMarkers.filter(m => !hiddenCategories.has(m.options.category));
    if (visibleMarkers.length > 0) {
        const bounds = L.featureGroup(visibleMarkers).getBounds();
        attackerMap.fitBounds(bounds, { padding: [50, 50] });
    }
}

async function initializeAttackerMap() {
    const mapContainer = document.getElementById('attacker-map');
    if (!mapContainer || attackerMap) return;

    try {
        attackerMap = L.map('attacker-map', {
            center: [20, 0],
            zoom: 2,
            layers: [
                L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                    attribution: '&copy; CartoDB | &copy; OpenStreetMap contributors',
                    maxZoom: 19,
                    subdomains: 'abcd'
                })
            ]
        });

        // Get the selected limit from the dropdown (default 100)
        const limitSelect = document.getElementById('map-ip-limit');
        const limit = limitSelect ? limitSelect.value : '100';

        allIps = await fetchIpsForMap(limit);

        if (allIps.length === 0) {
            mapContainer.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #8b949e;">No IP location data available</div>';
            return;
        }

        buildMapMarkers(allIps);

        // Force Leaflet to recalculate container size after the tab becomes visible.
        setTimeout(() => {
            if (attackerMap) attackerMap.invalidateSize();
        }, 300);

    } catch (err) {
        console.error('Error initializing attacker map:', err);
        mapContainer.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #f85149;">Failed to load map: ' + err.message + '</div>';
    }
}

// Reload map markers when the user changes the IP limit selector
async function reloadMapWithLimit(limit) {
    if (!attackerMap) return;

    // Show loading state
    const mapContainer = document.getElementById('attacker-map');
    const overlay = document.createElement('div');
    overlay.id = 'map-loading-overlay';
    overlay.style.cssText = 'position:absolute;top:0;left:0;right:0;bottom:0;background:rgba(13,17,23,0.7);display:flex;align-items:center;justify-content:center;z-index:1000;color:#8b949e;font-size:14px;';
    overlay.textContent = 'Loading IPs...';
    mapContainer.style.position = 'relative';
    mapContainer.appendChild(overlay);

    try {
        allIps = await fetchIpsForMap(limit);
        buildMapMarkers(allIps);
    } catch (err) {
        console.error('Error reloading map:', err);
    } finally {
        const existing = document.getElementById('map-loading-overlay');
        if (existing) existing.remove();
    }
}

// Update map filters based on checkbox selection
function updateMapFilters() {
    if (!attackerMap || !clusterGroup) return;

    hiddenCategories.clear();
    document.querySelectorAll('.map-filter').forEach(cb => {
        const category = cb.getAttribute('data-category');
        if (category && !cb.checked) hiddenCategories.add(category);
    });

    // Rebuild cluster group with only visible markers
    clusterGroup.clearLayers();
    const visible = mapMarkers.filter(m => !hiddenCategories.has(m.options.category));
    clusterGroup.addLayers(visible);
}

// Generate radar chart SVG for map panel popups
function generateMapPanelRadarChart(categoryScores) {
    if (!categoryScores || Object.keys(categoryScores).length === 0) {
        return '<div style="color: #8b949e; text-align: center; padding: 20px;">No category data available</div>';
    }

    let html = '<div style="display: flex; flex-direction: column; align-items: center;">';
    html += '<svg class="radar-chart" viewBox="-30 -30 260 260" preserveAspectRatio="xMidYMid meet" style="width: 160px; height: 160px;">';

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

    const colors = {
        attacker: '#f85149',
        good_crawler: '#3fb950',
        bad_crawler: '#f0883e',
        regular_user: '#58a6ff',
        unknown: '#8b949e'
    };

    const labels = {
        attacker: 'Attacker',
        good_crawler: 'Good Bot',
        bad_crawler: 'Bad Bot',
        regular_user: 'User',
        unknown: 'Unknown'
    };

    const cx = 100, cy = 100, maxRadius = 75;
    for (let i = 1; i <= 5; i++) {
        const r = (maxRadius / 5) * i;
        html += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#30363d" stroke-width="0.5"/>`;
    }

    const angles = [0, 72, 144, 216, 288];
    const keys = ['good_crawler', 'regular_user', 'unknown', 'bad_crawler', 'attacker'];

    angles.forEach((angle, i) => {
        const rad = (angle - 90) * Math.PI / 180;
        const x2 = cx + maxRadius * Math.cos(rad);
        const y2 = cy + maxRadius * Math.sin(rad);
        html += `<line x1="${cx}" y1="${cy}" x2="${x2}" y2="${y2}" stroke="#30363d" stroke-width="0.5"/>`;

        const labelDist = maxRadius + 35;
        const lx = cx + labelDist * Math.cos(rad);
        const ly = cy + labelDist * Math.sin(rad);
        html += `<text x="${lx}" y="${ly}" fill="#8b949e" font-size="12" text-anchor="middle" dominant-baseline="middle">${labels[keys[i]]}</text>`;
    });

    let points = [];
    angles.forEach((angle, i) => {
        const normalizedScore = normalizedScores[keys[i]];
        const rad = (angle - 90) * Math.PI / 180;
        const r = normalizedScore * maxRadius;
        const x = cx + r * Math.cos(rad);
        const y = cy + r * Math.sin(rad);
        points.push(`${x},${y}`);
    });

    const dominantKey = Object.keys(scores).reduce((a, b) => scores[a] > scores[b] ? a : b);
    const dominantColor = colors[dominantKey];

    html += `<polygon points="${points.join(' ')}" fill="${dominantColor}" fill-opacity="0.4" stroke="${dominantColor}" stroke-width="2.5"/>`;

    angles.forEach((angle, i) => {
        const normalizedScore = normalizedScores[keys[i]];
        const rad = (angle - 90) * Math.PI / 180;
        const r = normalizedScore * maxRadius;
        const x = cx + r * Math.cos(rad);
        const y = cy + r * Math.sin(rad);
        html += `<circle cx="${x}" cy="${y}" r="4.5" fill="${colors[keys[i]]}" stroke="#0d1117" stroke-width="2"/>`;
    });

    html += '</svg>';
    html += '</div>';
    return html;
}
