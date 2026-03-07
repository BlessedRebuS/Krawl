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

        // IP Insight state
        insightIp: null,

        // Auth state (UI only — actual security enforced server-side via cookie)
        authenticated: false,
        authModal: { show: false, password: '', error: '', loading: false },

        async init() {
            // Check if already authenticated (cookie-based)
            try {
                const resp = await fetch(`${this.dashboardPath}/api/auth/check`, { credentials: 'same-origin' });
                if (resp.ok) this.authenticated = true;
            } catch {}

            // Handle hash-based tab routing
            const hash = window.location.hash.slice(1);
            if (hash === 'ip-stats' || hash === 'attacks') {
                this.switchToAttacks();
            }
            // ip-insight tab is only accessible via lens buttons, not direct hash navigation

            window.addEventListener('hashchange', () => {
                const h = window.location.hash.slice(1);
                if (h === 'ip-stats' || h === 'attacks') {
                    this.switchToAttacks();
                } else if (h === 'admin') {
                    if (this.authenticated) this.switchToAdmin();
                } else if (h !== 'ip-insight') {
                    if (this.tab !== 'ip-insight') {
                        this.switchToOverview();
                    }
                }
            });
        },

        switchToAttacks() {
            this.tab = 'attacks';
            window.location.hash = '#ip-stats';

            // Delay chart initialization to ensure the container is visible
            this.$nextTick(() => {
                setTimeout(() => {
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

        switchToAdmin() {
            if (!this.authenticated) return;
            this.tab = 'admin';
            window.location.hash = '#admin';
            this.$nextTick(() => {
                const container = document.getElementById('admin-htmx-container');
                if (container && typeof htmx !== 'undefined') {
                    htmx.ajax('GET', `${this.dashboardPath}/htmx/admin`, {
                        target: '#admin-htmx-container',
                        swap: 'innerHTML'
                    });
                }
            });
        },

        async logout() {
            try {
                await fetch(`${this.dashboardPath}/api/auth/logout`, {
                    method: 'POST',
                    credentials: 'same-origin',
                });
            } catch {}
            this.authenticated = false;
            if (this.tab === 'admin') this.switchToOverview();
        },

        promptAuth() {
            this.authModal = { show: true, password: '', error: '', loading: false };
            this.$nextTick(() => {
                if (this.$refs.authPasswordInput) this.$refs.authPasswordInput.focus();
            });
        },

        closeAuthModal() {
            this.authModal.show = false;
            this.authModal.password = '';
            this.authModal.error = '';
            this.authModal.loading = false;
        },

        async submitAuth() {
            const password = this.authModal.password;
            if (!password) {
                this.authModal.error = 'Please enter a password';
                return;
            }
            this.authModal.error = '';
            this.authModal.loading = true;
            try {
                const msgBuf = new TextEncoder().encode(password);
                const hashBuf = await crypto.subtle.digest('SHA-256', msgBuf);
                const fingerprint = Array.from(new Uint8Array(hashBuf))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                const resp = await fetch(`${this.dashboardPath}/api/auth`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ fingerprint }),
                });
                if (resp.ok) {
                    this.authenticated = true;
                    this.closeAuthModal();
                    this.switchToAdmin();
                } else {
                    const data = await resp.json().catch(() => ({}));
                    this.authModal.error = data.error || 'Invalid password';
                    this.authModal.password = '';
                    this.authModal.loading = false;
                    if (data.locked && data.retry_after) {
                        let remaining = data.retry_after;
                        const interval = setInterval(() => {
                            remaining--;
                            if (remaining <= 0) {
                                clearInterval(interval);
                                this.authModal.error = '';
                            } else {
                                this.authModal.error = `Too many attempts. Try again in ${remaining}s`;
                            }
                        }, 1000);
                    }
                }
            } catch {
                this.authModal.error = 'Authentication failed';
                this.authModal.loading = false;
            }
        },

        switchToIpInsight() {
            // Only allow switching if an IP is selected
            if (!this.insightIp) return;
            this.tab = 'ip-insight';
            window.location.hash = '#ip-insight';
        },

        openIpInsight(ip) {
            // Set the IP and load the insight content
            this.insightIp = ip;
            this.tab = 'ip-insight';
            window.location.hash = '#ip-insight';

            // Load IP insight content via HTMX
            this.$nextTick(() => {
                const container = document.getElementById('ip-insight-htmx-container');
                if (container && typeof htmx !== 'undefined') {
                    htmx.ajax('GET', `${this.dashboardPath}/htmx/ip-insight/${encodeURIComponent(ip)}`, {
                        target: '#ip-insight-htmx-container',
                        swap: 'innerHTML'
                    });
                }
            });
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

        async copyRawRequest(event) {
            if (!this.rawModal.content) return;
            const btn = event.currentTarget;
            const originalHTML = btn.innerHTML;
            const checkIcon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" fill="#3fb950"><path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.751.751 0 0 1 .018-1.042.751.751 0 0 1 1.042-.018L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0Z"/></svg>';
            try {
                await navigator.clipboard.writeText(this.rawModal.content);
                btn.innerHTML = checkIcon;
            } catch {
                btn.style.color = '#f85149';
            }
            setTimeout(() => { btn.innerHTML = originalHTML; btn.style.color = ''; }, 1500);
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

// Global function for opening IP Insight (used by map popups)
window.openIpInsight = function(ip) {
    // Find the Alpine component and call openIpInsight
    const container = document.querySelector('[x-data="dashboardApp()"]');
    if (container) {
        // Try Alpine 3.x API first, then fall back to older API
        const data = Alpine.$data ? Alpine.$data(container) : (container._x_dataStack && container._x_dataStack[0]);
        if (data && typeof data.openIpInsight === 'function') {
            data.openIpInsight(ip);
        }
    }
};

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
