// Alpine.js Dashboard Application
document.addEventListener('alpine:init', () => {
    Alpine.data('dashboardApp', () => ({
        // State
        tab: 'overview',
        dashboardPath: window.__DASHBOARD_PATH__ || '',

        // Banlist dropdown
        banlistOpen: false,

        // Raw request modal
        rawModal: { show: false, content: '', logId: null },

        // Map state
        mapInitialized: false,

        // Chart state
        chartLoaded: false,

        init() {
            // Handle hash-based tab routing
            const hash = window.location.hash.slice(1);
            if (hash === 'ip-stats' || hash === 'attacks') {
                this.switchToAttacks();
            }

            window.addEventListener('hashchange', () => {
                const h = window.location.hash.slice(1);
                if (h === 'ip-stats' || h === 'attacks') {
                    this.switchToAttacks();
                } else {
                    this.switchToOverview();
                }
            });
        },

        switchToAttacks() {
            this.tab = 'attacks';
            window.location.hash = '#ip-stats';

            // Delay initialization to ensure the container is visible and
            // the browser has reflowed after x-show removes display:none.
            // Leaflet and Chart.js need visible containers with real dimensions.
            this.$nextTick(() => {
                setTimeout(() => {
                    if (!this.mapInitialized && typeof initializeAttackerMap === 'function') {
                        initializeAttackerMap();
                        this.mapInitialized = true;
                    }
                    if (!this.chartLoaded && typeof loadAttackTypesChart === 'function') {
                        loadAttackTypesChart();
                        this.chartLoaded = true;
                    }
                }, 200);
            });
        },

        switchToOverview() {
            this.tab = 'overview';
            window.location.hash = '#overview';
        },

        async viewRawRequest(logId) {
            try {
                const resp = await fetch(
                    `${this.dashboardPath}/api/raw-request/${logId}`,
                    { cache: 'no-store' }
                );
                if (resp.status === 404) {
                    alert('Raw request not available');
                    return;
                }
                const data = await resp.json();
                this.rawModal.content = data.raw_request || 'No content available';
                this.rawModal.logId = logId;
                this.rawModal.show = true;
            } catch (err) {
                alert('Failed to load raw request');
            }
        },

        closeRawModal() {
            this.rawModal.show = false;
            this.rawModal.content = '';
            this.rawModal.logId = null;
        },

        downloadRawRequest() {
            if (!this.rawModal.content) return;
            const blob = new Blob([this.rawModal.content], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `raw-request-${this.rawModal.logId || Date.now()}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        },

        toggleIpDetail(event) {
            const row = event.target.closest('tr');
            if (!row) return;
            const detailRow = row.nextElementSibling;
            if (detailRow && detailRow.classList.contains('ip-stats-row')) {
                detailRow.style.display =
                    detailRow.style.display === 'table-row' ? 'none' : 'table-row';
            }
        },
    }));
});

// Utility function for formatting timestamps (used by map popups)
function formatTimestamp(isoTimestamp) {
    if (!isoTimestamp) return 'N/A';
    try {
        const date = new Date(isoTimestamp);
        return date.toLocaleString('en-US', {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
        });
    } catch {
        return isoTimestamp;
    }
}
