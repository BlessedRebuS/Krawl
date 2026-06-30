// Alpine.js Dashboard Application
document.addEventListener('alpine:init', () => {

    // Register HTMX-loaded panel components here (not in partials)
    // so they are available before Alpine processes the DOM.
    Alpine.data('banManagement', () => ({
        newBanIp: '',
        banLoading: false,
        banMessage: '',
        banSuccess: false,

        init() {},

        async forceBan() {
            if (!this.newBanIp) return;
            this.banLoading = true;
            this.banMessage = '';
            try {
                const resp = await fetch(`${window.__DASHBOARD_PATH__}/api/ban-override`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ ip: this.newBanIp, action: 'ban' }),
                });
                const data = await resp.json();
                if (resp.ok) {
                    this.banSuccess = true;
                    this.banMessage = `IP ${this.newBanIp} added to banlist`;
                    this.newBanIp = '';
                    this.refreshOverrides();
                } else {
                    this.banSuccess = false;
                    this.banMessage = data.error || 'Failed to ban IP';
                }
            } catch {
                this.banSuccess = false;
                this.banMessage = 'Request failed';
            }
            this.banLoading = false;
        },

        refreshOverrides() {
            const container = document.getElementById('overrides-container');
            if (container && typeof htmx !== 'undefined') {
                htmx.ajax('GET', `${window.__DASHBOARD_PATH__}/htmx/ban/overrides?page=1`, {
                    target: '#overrides-container',
                    swap: 'innerHTML'
                });
            }
        },
    }));

    Alpine.data('trackManagement', () => ({
        newTrackIp: '',
        trackLoading: false,
        trackMessage: '',
        trackSuccess: false,

        init() {},

        async trackIp() {
            if (!this.newTrackIp) return;
            this.trackLoading = true;
            this.trackMessage = '';
            try {
                const resp = await fetch(`${window.__DASHBOARD_PATH__}/api/track-ip`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ ip: this.newTrackIp, action: 'track' }),
                });
                const data = await resp.json();
                if (resp.ok) {
                    this.trackSuccess = true;
                    this.trackMessage = `IP ${this.newTrackIp} is now being tracked`;
                    this.newTrackIp = '';
                    this.refreshList();
                } else {
                    this.trackSuccess = false;
                    this.trackMessage = data.error || 'Failed to track IP';
                }
            } catch {
                this.trackSuccess = false;
                this.trackMessage = 'Request failed';
            }
            this.trackLoading = false;
        },

        refreshList() {
            const container = document.getElementById('tracked-ips-container');
            if (container && typeof htmx !== 'undefined') {
                htmx.ajax('GET', `${window.__DASHBOARD_PATH__}/htmx/tracked-ips/list?page=1`, {
                    target: '#tracked-ips-container',
                    swap: 'innerHTML'
                });
            }
        },
    }));

    Alpine.data('dashboardApp', () => ({
        // State
        tab: 'overview',
        dashboardPath: window.__DASHBOARD_PATH__ || '',

        // Export IPs modal
        exportModal: { show: false, categories: ['attacker'], fwtype: 'raw', error: '', loading: false },

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
        uploadModal: { show: false, path: '', fileName: '', fileContent: '', error: '', success: '', loading: false, dragging: false },

        // Expand overlay state
        expandOverlay: { show: false, title: '', endpoint: '', pageSize: 25, search: '', categories: [], honeypotOnly: false },

        // Flag to prevent double-triggering during init
        _initializingHash: false,

        async init() {
            // Check if already authenticated (cookie-based)
            try {
                const resp = await fetch(`${this.dashboardPath}/api/auth/check`, { credentials: 'same-origin' });
                if (resp.ok) this.authenticated = true;
            } catch {}

            // Sync ban action button visibility with auth state
            this.$watch('authenticated', (val) => updateBanActionVisibility(val));
            updateBanActionVisibility(this.authenticated);

            // Set flag to prevent double-triggering during initialization
            this._initializingHash = true;

            // Handle hash-based tab routing on page load
            const hash = window.location.hash.slice(1);
            if (hash === 'ip-stats' || hash === 'attacks') {
                this.switchToAttacks();
            } else if (hash === 'banlist' && this.authenticated) {
                this.switchToBanlist();
            } else if (hash === 'timedout' && this.authenticated) {
                this.switchToTimedOut();
            } else if (hash === 'tracked-ips' && this.authenticated) {
                this.switchToTrackedIps();
            } else if (hash === 'deception' && this.authenticated) {
                this.switchToDeception();
            } else if (hash === 'overview' || !hash) {
                this.switchToOverview();
            } else {
                // Default to overview if hash is unrecognized
                this.switchToOverview();
            }

            // Wait for this tick to complete, then allow hashchange events
            this.$nextTick(() => {
                this._initializingHash = false;
                
                // Listen for hash changes (after initialization)
                window.addEventListener('hashchange', () => {
                    const h = window.location.hash.slice(1);
                    if (h === 'ip-stats' || h === 'attacks') {
                        this.switchToAttacks();
                    } else if (h === 'banlist') {
                        if (this.authenticated) this.switchToBanlist();
                    } else if (h === 'timedout') {
                        if (this.authenticated) this.switchToTimedOut();
                    } else if (h === 'tracked-ips') {
                        if (this.authenticated) this.switchToTrackedIps();
                    } else if (h === 'deception') {
                        if (this.authenticated) this.switchToDeception();
                    } else if (h !== 'ip-insight') {
                        if (this.tab !== 'ip-insight') {
                            this.switchToOverview();
                        }
                    }
                });
            });
        },

        switchToAttacks() {
            if (this.tab === 'attacks') return;  // Prevent duplicate loading
            this.tab = 'attacks';
            window.location.hash = '#attacks';

            // x-if inserts new DOM — HTMX must process it for hx-trigger to work
            this.$nextTick(() => {
                setTimeout(() => {
                    if (typeof loadAttackTrendsChart === 'function') {
                        loadAttackTrendsChart();
                    }
                    // Process all HTMX containers in the attacks tab
                    document.querySelectorAll('.alert-section .htmx-container[hx-get]').forEach(el => {
                        htmx.process(el);
                    });
                }, 200);
            });
        },

        switchToOverview() {
            if (this.tab === 'overview') return;  // Prevent duplicate loading
            this.tab = 'overview';
            window.location.hash = '#overview';
        },

        switchToBanlist() {
            if (!this.authenticated) return;
            if (this.tab === 'banlist') return;  // Prevent duplicate loading
            this.tab = 'banlist';
            window.location.hash = '#banlist';
            this.$nextTick(() => {
                const container = document.getElementById('banlist-htmx-container');
                if (container && typeof htmx !== 'undefined') {
                    htmx.ajax('GET', `${this.dashboardPath}/htmx/banlist`, {
                        target: '#banlist-htmx-container',
                        swap: 'innerHTML'
                    });
                }
            });
        },

        switchToTimedOut() {
            if (!this.authenticated) return;
            if (this.tab === 'timedout') return;  // Prevent duplicate loading
            this.tab = 'timedout';
            window.location.hash = '#timedout';
            this.$nextTick(() => {
                const container = document.getElementById('timedout-htmx-container');
                if (container && typeof htmx !== 'undefined') {
                    htmx.ajax('GET', `${this.dashboardPath}/htmx/timedout`, {
                        target: '#timedout-htmx-container',
                        swap: 'innerHTML'
                    });
                }
            });
        },

        switchToTrackedIps() {
            if (!this.authenticated) return;
            if (this.tab === 'tracked-ips') return;  // Prevent duplicate loading
            this.tab = 'tracked-ips';
            window.location.hash = '#tracked-ips';
            this.$nextTick(() => {
                const container = document.getElementById('tracked-ips-htmx-container');
                if (container && typeof htmx !== 'undefined') {
                    htmx.ajax('GET', `${this.dashboardPath}/htmx/tracked-ips`, {
                        target: '#tracked-ips-htmx-container',
                        swap: 'innerHTML'
                    });
                }
            });
        },

        switchToDeception() {
            if (!this.authenticated) return;
            if (this.tab === 'deception') return;  // Prevent duplicate loading
            this.tab = 'deception';
            window.location.hash = '#deception';
            this.$nextTick(() => {
                const container = document.getElementById('deception-htmx-container');
                if (container && typeof htmx !== 'undefined') {
                    htmx.ajax('GET', `${this.dashboardPath}/htmx/deception`, {
                        target: '#deception-htmx-container',
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
            if (this.tab === 'banlist' || this.tab === 'tracked-ips' || this.tab === 'deception' || this.tab === 'timedout') this.switchToOverview();
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

        exportUrl() {
            const params = new URLSearchParams({
                categories: (this.exportModal.categories.slice().sort()).join(','),
                fwtype: this.exportModal.fwtype,
            });
            return `${window.location.origin}${this.dashboardPath}/api/export-ips?${params}`;
        },

        async copyExportUrl(event) {
            const btn = event.currentTarget;
            const originalHTML = btn.innerHTML;
            const checkIcon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" fill="#3fb950"><path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.751.751 0 0 1 .018-1.042.751.751 0 0 1 1.042-.018L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0Z"/></svg>';
            try {
                await navigator.clipboard.writeText(this.exportUrl());
                btn.innerHTML = checkIcon;
            } catch {
                btn.style.color = '#f85149';
            }
            setTimeout(() => { btn.innerHTML = originalHTML; btn.style.color = ''; }, 1500);
        },

        async submitExport() {
            if (this.exportModal.categories.length === 0) {
                this.exportModal.error = 'Select at least one category';
                return;
            }
            this.exportModal.error = '';
            this.exportModal.loading = true;
            try {
                const params = new URLSearchParams({
                    categories: this.exportModal.categories.join(','),
                    fwtype: this.exportModal.fwtype,
                });
                const resp = await fetch(`${this.dashboardPath}/api/export-ips?${params}`, {
                    credentials: 'same-origin',
                });
                if (!resp.ok) {
                    const data = await resp.json().catch(() => ({}));
                    this.exportModal.error = data.error || 'Export failed';
                    return;
                }
                const blob = await resp.blob();
                const disposition = resp.headers.get('Content-Disposition') || '';
                const match = disposition.match(/filename="?([^"]+)"?/);
                const filename = match ? match[1] : 'export.txt';
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
                this.exportModal.show = false;
            } catch (e) {
                this.exportModal.error = 'Network error';
            } finally {
                this.exportModal.loading = false;
            }
        },

        async submitAuth() {
            const password = this.authModal.password.trim();
            if (!password) {
                this.authModal.error = 'Please enter a password';
                return;
            }
            this.authModal.error = '';
            this.authModal.loading = true;
            try {
                const resp = await fetch(`${this.dashboardPath}/api/auth`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ password }),
                });
                if (resp.ok) {
                    this.authenticated = true;
                    this.closeAuthModal();
                    this.switchToBanlist();
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

        collapseSearch() {
            // Collapse the search results down to just the summary header.
            // The full results stay in the DOM so the summary can re-expand them.
            const results = document.querySelector('#search-results-container .search-results');
            if (results) results.classList.add('search-collapsed');
        },

        toggleSearchCollapse() {
            // Expand/collapse the search results when the summary header is clicked
            const results = document.querySelector('#search-results-container .search-results');
            if (results) results.classList.toggle('search-collapsed');
        },

        openIpInsight(ip) {
            // Collapse any open search results before switching to the insight tab
            this.collapseSearch();

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
                    krawlModal.error('Raw request not available');
                    return;
                }
                const data = await resp.json();
                this.rawModal.content = data.raw_request || 'No content available';
                this.rawModal.logId = logId;
                this.rawModal.show = true;
            } catch (err) {
                krawlModal.error('Failed to load raw request');
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

// Helper to access Alpine.js component data
function getAlpineData(selector) {
    const container = document.querySelector(selector);
    if (!container) return null;
    return Alpine.$data ? Alpine.$data(container) : (container._x_dataStack && container._x_dataStack[0]);
}

// Global function for opening IP Insight (used by map popups)
window.openIpInsight = function(ip) {
    const data = getAlpineData('[x-data="dashboardApp()"]');
    if (data && typeof data.openIpInsight === 'function') {
        data.openIpInsight(ip);
    }
};

// Deception panel delete functions
window.reloadGeneratedPagesTable = function() {
    const dashboardPath = document.querySelector('[x-data="dashboardApp()"]')?.__alpine_data?.dashboardPath || window.__DASHBOARD_PATH__ || '';
    const htmxContainer = document.querySelector('#deception-htmx-container .htmx-container');
    if (htmxContainer && typeof htmx !== 'undefined') {
        const tableUrl = dashboardPath + '/htmx/generated-pages?page=1&sort_by=created_at&sort_order=desc';
        htmx.ajax('GET', tableUrl, {
            target: htmxContainer,
            swap: 'innerHTML'
        });
    }
};



window.deleteSelectedPages = async function() {
    const dashboardPath = document.querySelector('[x-data="dashboardApp()"]')?.__alpine_data?.dashboardPath || window.__DASHBOARD_PATH__ || '';
    const container = document.getElementById('deception-htmx-container');

    if (!container) {
        krawlModal.error('Table not loaded. Please wait a moment.');
        return;
    }

    // Check if "select all pages" flag is set
    const selectAllFlag = container.dataset.selectAllPages === 'true';
    const checkboxes = container.querySelectorAll('input[name="page-checkbox"]:checked');
    const dateInput = document.getElementById('deception-date-filter');

    // Check if we have selected pages OR a date filter OR select all flag
    if (!selectAllFlag && checkboxes.length === 0 && (!dateInput || !dateInput.value)) {
        krawlModal.error('Please select at least one page to delete or set a date filter');
        return;
    }

    // Build delete request
    let url = dashboardPath + '/api/delete-generated-pages?';
    let confirmMsg = '';

    if (selectAllFlag) {
        // Delete ALL pages
        url += 'delete_all=true';
        confirmMsg = 'Delete ALL generated pages? This cannot be undone.';
    } else if (checkboxes.length > 0) {
        // Delete selected pages
        const ids = [];
        checkboxes.forEach(cb => {
            const val = cb.value || cb.getAttribute('value');
            if (val && val.trim()) {
                ids.push(val.trim());
            }
        });

        if (ids.length === 0) {
            console.error('No valid checkbox values found. Checkbox values:',
                Array.from(checkboxes).map(cb => ({ value: cb.value, attr: cb.getAttribute('value') })));
            krawlModal.error('No valid page IDs found. Please try again.');
            return;
        }

        const idsString = ids.join(',');
        url += 'ids=' + encodeURIComponent(idsString);
        confirmMsg = 'Delete ' + ids.length + ' selected page(s)? This cannot be undone.';
    } else if (dateInput && dateInput.value) {
        // Delete pages before specified date
        url += 'before_date=' + encodeURIComponent(dateInput.value);
        confirmMsg = 'Delete all pages created before ' + dateInput.value + '? This cannot be undone.';
    }

    const confirmed = await krawlModal.confirm(confirmMsg);
    if (!confirmed) return;

    fetch(url, { method: 'POST' })
        .then(response => response.text())
        .then(html => {
            container.innerHTML = html;
            // Reload table after a brief delay to ensure new DOM is ready
            setTimeout(window.reloadGeneratedPagesTable, 100);
        })
        .catch(error => {
            console.error('Delete error:', error);
            krawlModal.error('Error deleting pages');
        });
};

window.deleteAllPages = async function() {
    const dashboardPath = document.querySelector('[x-data="dashboardApp()"]')?.__alpine_data?.dashboardPath || window.__DASHBOARD_PATH__ || '';
    const confirmed = await krawlModal.confirm('Delete ALL generated pages? This cannot be undone.');
    if (!confirmed) return;
    const url = dashboardPath + '/api/delete-generated-pages?delete_all=true';

    fetch(url, { method: 'POST' })
        .then(response => response.text())
        .then(html => {
            document.getElementById('deception-htmx-container').innerHTML = html;
            // Reload table after a brief delay to ensure new DOM is ready
            setTimeout(window.reloadGeneratedPagesTable, 100);
        })
        .catch(error => {
            console.error('Delete error:', error);
            krawlModal.error('Error deleting pages');
        });
};

window.selectAllPages = function() {
    const selectAllCheckbox = document.getElementById('select-all-pages');
    if (!selectAllCheckbox) return;
    document.querySelectorAll('#deception-htmx-container input[name="page-checkbox"]').forEach(checkbox => {
        checkbox.checked = selectAllCheckbox.checked;
    });
};

window.downloadGeneratedPage = function(path) {
    const dashboardPath = window.__DASHBOARD_PATH__ || '';
    window.open(dashboardPath + '/api/download-generated-page?path=' + encodeURIComponent(path), '_blank');
};

window.deleteGeneratedPage = async function(path) {
    const dashboardPath = window.__DASHBOARD_PATH__ || '';
    const confirmed = await krawlModal.confirm('Delete this generated page? This cannot be undone.');
    if (!confirmed) return;
    fetch(dashboardPath + '/api/delete-generated-pages?ids=' + encodeURIComponent(path), { method: 'POST' })
        .then(response => response.text())
        .then(html => {
            document.getElementById('deception-htmx-container').innerHTML = html;
            setTimeout(window.reloadGeneratedPagesTable, 100);
        })
        .catch(error => {
            console.error('Delete error:', error);
            krawlModal.error('Error deleting page');
        });
};

window.deleteSearchGeneratedPage = async function(btn, path) {
    const dashboardPath = window.__DASHBOARD_PATH__ || '';
    const confirmed = await krawlModal.confirm('Delete "' + path + '"? This cannot be undone.');
    if (!confirmed) return;
    try {
        await fetch(dashboardPath + '/api/delete-generated-pages?ids=' + encodeURIComponent(path), { method: 'POST' });
        krawlModal.success('Deleted ' + path);
        const row = btn.closest('tr');
        if (row) row.remove();
        const summary = document.querySelector('.search-results-summary');
        if (summary) {
            const match = summary.innerHTML.match(/and <strong>(\d+)<\/strong> deception page/);
            if (match) {
                const count = parseInt(match[1]) - 1;
                summary.innerHTML = summary.innerHTML.replace(
                    /and <strong>\d+<\/strong> deception page/,
                    'and <strong>' + count + '</strong> deception page' + (count !== 1 ? 's' : '')
                );
            }
        }
    } catch (error) {
        console.error('Delete error:', error);
        krawlModal.error('Error deleting page');
    }
};

// Toggle danger state on deception delete buttons based on conditions
window.toggleDeceptionBtnState = function() {
    const dateInput = document.getElementById('deception-date-filter');
    const container = document.getElementById('deception-htmx-container');
    const checked = document.querySelectorAll('#deception-htmx-container input[name="page-checkbox"]:checked');
    const selectAllFlag = container && container.dataset.selectAllPages === 'true';
    const hasSelection = checked.length > 0 || selectAllFlag;
    const hasDateFilter = dateInput && dateInput.value;

    const selectedBtn = document.getElementById('btn-delete-selected');
    if (selectedBtn) {
        selectedBtn.classList.toggle('deception-action-btn-danger', hasSelection || hasDateFilter);
    }

    const downloadBtn = document.getElementById('btn-download-selected');
    if (downloadBtn) {
        downloadBtn.classList.toggle('deception-action-btn-active', hasSelection || hasDateFilter);
    }
};

// Listen for checkbox changes inside HTMX-loaded deception table
document.addEventListener('change', function(e) {
    if (e.target.name === 'page-checkbox') {
        // If an individual checkbox is unchecked, clear the "select all" flag
        // This handles the case where user clicks Select All then unchecks some items
        const container = document.getElementById('deception-htmx-container');
        if (container && container.dataset.selectAllPages === 'true' && !e.target.checked) {
            delete container.dataset.selectAllPages;
            // Also uncheck the "Select All" checkbox to match the new state
            const selectAllCheckbox = document.getElementById('select-all-pages');
            if (selectAllCheckbox) {
                selectAllCheckbox.checked = false;
            }
        }
        toggleDeceptionBtnState();
    } else if (e.target.id === 'select-all-pages') {
        toggleDeceptionBtnState();
    }
});

window.downloadSelectedPages = function() {
    const dashboardPath = window.__DASHBOARD_PATH__ || '';
    const container = document.getElementById('deception-htmx-container');
    if (!container) return;

    // Check if "select all pages" flag is set
    const selectAllFlag = container.dataset.selectAllPages === 'true';
    const checkboxes = container.querySelectorAll('input[name="page-checkbox"]:checked');
    const dateInput = document.getElementById('deception-date-filter');

    console.log('Download: Select all flag:', selectAllFlag);
    console.log('Download: Found', checkboxes.length, 'selected pages');
    console.log('Download: Date filter value:', dateInput ? dateInput.value : 'not found');

    // Check if we have selected pages OR a date filter OR select all flag
    if (!selectAllFlag && checkboxes.length === 0 && (!dateInput || !dateInput.value)) {
        krawlModal.error('Please select at least one page to download or set a date filter');
        return;
    }

    let url = dashboardPath + '/api/download-generated-pages-zip?';

    if (selectAllFlag) {
        // Download ALL pages
        console.log('Download: Using select all');
        url += 'select_all=true';
    } else if (checkboxes.length > 0) {
        // Download selected pages as ZIP
        const paths = Array.from(checkboxes).map(cb => cb.value).filter(p => p && p.trim()).join(',');
        if (!paths) {
            krawlModal.error('No valid pages selected');
            return;
        }
        console.log('Download: Using paths:', paths);
        url += 'paths=' + encodeURIComponent(paths);
    } else if (dateInput && dateInput.value) {
        // Download pages before specified date
        console.log('Download: Using date:', dateInput.value);
        url += 'before_date=' + encodeURIComponent(dateInput.value);
    }

    console.log('Download URL:', url);

    fetch(url, { method: 'POST' })
        .then(response => {
            console.log('Download response status:', response.status);
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || 'Download failed');
                });
            }
            return response.blob();
        })
        .then(blob => {
            console.log('Download: Got blob of size:', blob.size);
            // Create download link
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = downloadUrl;
            a.download = 'deception_pages.zip';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(downloadUrl);
            document.body.removeChild(a);
        })
        .catch(err => {
            console.error('Download error:', err);
            krawlModal.error('Failed to download: ' + err.message);
        });
};

// Upload page modal handlers
const _allowedUploadExts = ['.html', '.htm', '.xml', '.json', '.txt', '.css', '.js', '.zip'];

function _getAlpineData() {
    const el = document.querySelector('[x-data="dashboardApp()"]');
    return el && el._x_dataStack ? el._x_dataStack[0] : null;
}

window.openUploadModal = function() {
    const app = _getAlpineData();
    if (!app) return;
    Object.assign(app.uploadModal, { show: true, path: '', fileName: '', fileContent: '', error: '', success: '', loading: false, dragging: false });
};

window.handleUploadFile = function(event) {
    const file = event.target.files[0];
    if (file) _processUploadFile(file);
};

window.handleUploadDrop = function(event) {
    const file = event.dataTransfer.files[0];
    if (file) _processUploadFile(file);
};

function _processUploadFile(file) {
    const app = _getAlpineData();
    if (!app) return;
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!_allowedUploadExts.includes(ext)) {
        app.uploadModal.error = 'Unsupported file type. Use: ' + _allowedUploadExts.join(', ');
        app.uploadModal.fileName = '';
        app.uploadModal.fileContent = '';
        return;
    }
    
    // Handle ZIP files
    if (ext === '.zip') {
        _processZipFile(file);
        return;
    }

    app.uploadModal.error = '';
    app.uploadModal.fileName = file.name;

    const reader = new FileReader();
    reader.onload = function(e) {
        app.uploadModal.fileContent = e.target.result;
        // Auto-fill path from filename if empty
        if (!app.uploadModal.path) {
            app.uploadModal.path = file.name;
        }
    };
    reader.readAsText(file);
}

async function _processZipFile(file) {
    const app = _getAlpineData();
    if (!app) return;

    try {
        // Load JSZip library if not already loaded
        if (typeof JSZip === 'undefined') {
            await _loadJSZip();
        }

        const reader = new FileReader();
        reader.onload = async function(e) {
            try {
                const zip = new JSZip();
                const zipData = await zip.loadAsync(e.target.result);
                
                const pages = {};
                const htmlExts = ['.html', '.htm', '.xml', '.json', '.txt', '.css', '.js'];
                let fileCount = 0;
                const filePaths = [];

                // First pass: collect all valid file paths
                for (const [filename, file] of Object.entries(zipData.files)) {
                    // Skip directories
                    if (file.dir) continue;

                    // Skip macOS system files and folders
                    if (filename.startsWith('__MACOSX/') || filename.endsWith('.DS_Store')) continue;

                    const fileExt = '.' + filename.split('.').pop().toLowerCase();
                    if (!htmlExts.includes(fileExt)) continue;

                    filePaths.push(filename);
                }

                if (filePaths.length === 0) {
                    app.uploadModal.error = 'No supported HTML files found in ZIP';
                    return;
                }

                // Check if all files share a common first directory (ZIP wrapper)
                let stripFirstDir = false;
                const firstPathParts = filePaths[0].split('/');
                if (firstPathParts.length > 1) {
                    const firstDir = firstPathParts[0];
                    // If all files start with the same first directory, strip it
                    if (filePaths.every(p => p.startsWith(firstDir + '/'))) {
                        stripFirstDir = true;
                    }
                }

                // Second pass: process files
                for (const filename of filePaths) {
                    fileCount++;

                    try {
                        const fileObj = zipData.files[filename];
                        const content = await fileObj.async('text');
                        
                        // Strip first directory if it's a wrapper
                        let finalPath = filename;
                        if (stripFirstDir) {
                            const parts = filename.split('/');
                            finalPath = parts.slice(1).join('/');
                        }
                        
                        // Decode double underscores to forward slashes (path encoding from filenames)
                        finalPath = finalPath.replace(/__/g, '/');
                        
                        // Ensure path starts with /
                        finalPath = '/' + finalPath.replace(/\\/g, '/');
                        pages[finalPath] = content;
                    } catch (err) {
                        console.warn(`Failed to read file ${filename}: ${err}`);
                    }
                }

                app.uploadModal.error = '';
                app.uploadModal.fileName = file.name + ` (${Object.keys(pages).length} files)`;
                app.uploadModal.fileContent = JSON.stringify(pages);
                app.uploadModal.path = '__ZIP_UPLOAD__';  // Special marker for ZIP
            } catch (err) {
                app.uploadModal.error = 'Failed to extract ZIP: ' + err.message;
            }
        };
        reader.readAsArrayBuffer(file);
    } catch (err) {
        app.uploadModal.error = 'Failed to process ZIP: ' + err.message;
    }
}

function _loadJSZip() {
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
        script.onload = resolve;
        script.onerror = () => reject(new Error('Failed to load JSZip library'));
        document.head.appendChild(script);
    });
}

window.submitUploadPage = async function() {
    const app = _getAlpineData();
    if (!app) return;
    const modal = app.uploadModal;
    modal.error = '';
    modal.success = '';

    if (!modal.fileContent) { modal.error = 'Please select a file'; return; }

    modal.loading = true;
    const dashboardPath = window.__DASHBOARD_PATH__ || '';

    try {
        // Check if this is a ZIP upload (marked with __ZIP_UPLOAD__)
        if (modal.path === '__ZIP_UPLOAD__') {
            const pages = JSON.parse(modal.fileContent);
            const resp = await fetch(dashboardPath + '/api/upload-generated-pages-bulk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ pages: pages }),
            });
            const data = await resp.json();
            if (resp.ok) {
                modal.success = `Uploaded ${data.uploaded} pages from ZIP`;
                if (data.errors && data.errors.length > 0) {
                    modal.success += ` (${data.errors.length} errors)`;
                }
                modal.error = '';
                // Reset form after short delay
                setTimeout(() => {
                    modal.show = false;
                    if (typeof window.reloadGeneratedPagesTable === 'function') {
                        window.reloadGeneratedPagesTable();
                    }
                }, 1200);
            } else {
                modal.error = data.error || 'Upload failed';
            }
        } else {
            // Single file upload
            let path = modal.path.trim();
            if (!path) { modal.error = 'Please enter a path'; return; }

            // Ensure path starts with /
            if (!path.startsWith('/')) path = '/' + path;

            const resp = await fetch(dashboardPath + '/api/upload-generated-page', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ path: path, content: modal.fileContent }),
            });
            const data = await resp.json();
            if (resp.ok) {
                modal.success = 'Page uploaded to ' + path;
                modal.error = '';
                // Reset form after short delay
                setTimeout(() => {
                    modal.show = false;
                    if (typeof window.reloadGeneratedPagesTable === 'function') {
                        window.reloadGeneratedPagesTable();
                    }
                }, 1200);
            } else {
                modal.error = data.error || 'Upload failed';
            }
        }
    } catch (err) {
        modal.error = 'Request failed: ' + err.message;
    }
    modal.loading = false;
};

// === Expand overlay for Top X tables ===
window.openExpandOverlay = function(title, endpoint, pageSize) {
    const app = _getAlpineData();
    if (!app) return;
    Object.assign(app.expandOverlay, {
        show: true, title: title, endpoint: endpoint,
        pageSize: pageSize || 25, search: '',
        categories: [], honeypotOnly: false,
    });
    _reloadExpandOverlay();
};

window.triggerExpandSearch = function() {
    _reloadExpandOverlay();
};

window.toggleExpandCategory = function(cat) {
    const app = _getAlpineData();
    if (!app) return;
    const cats = app.expandOverlay.categories;
    const idx = cats.indexOf(cat);
    if (idx >= 0) cats.splice(idx, 1);
    else cats.push(cat);
    _reloadExpandOverlay();
};

window.toggleExpandHoneypot = function() {
    const app = _getAlpineData();
    if (!app) return;
    app.expandOverlay.honeypotOnly = !app.expandOverlay.honeypotOnly;
    _reloadExpandOverlay();
};

function _reloadExpandOverlay() {
    const app = _getAlpineData();
    if (!app) return;
    const ov = app.expandOverlay;
    const dashboardPath = window.__DASHBOARD_PATH__ || '';
    const container = document.getElementById('expand-overlay-table');
    if (!container) return;

    const params = new URLSearchParams({
        page: '1',
        page_size: String(ov.pageSize),
        search: ov.search || '',
    });

    // Contextual filters
    if (ov.endpoint === 'top-ips' && ov.categories.length > 0) {
        params.set('categories', ov.categories.join(','));
    }
    if (ov.endpoint === 'top-paths' && ov.honeypotOnly) {
        params.set('honeypot_only', '1');
    }

    const url = `${dashboardPath}/htmx/${ov.endpoint}?${params}`;
    container.innerHTML = '<div style="text-align: center; padding: 40px; color: #8b949e;">Loading...</div>';
    htmx.ajax('GET', url, { target: container, swap: 'innerHTML' });
}

// Escape HTML to prevent XSS when inserting into innerHTML
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Custom modal system (replaces native confirm/alert)
window.krawlModal = {
    _create(icon, iconClass, message, buttons) {
        return new Promise(resolve => {
            const overlay = document.createElement('div');
            overlay.className = 'krawl-modal-overlay';
            overlay.innerHTML = `
                <div class="krawl-modal-box">
                    <div class="krawl-modal-icon ${iconClass}">
                        <span class="material-symbols-outlined">${icon}</span>
                    </div>
                    <div class="krawl-modal-message">${message}</div>
                    <div class="krawl-modal-actions" id="krawl-modal-actions"></div>
                </div>`;
            const actions = overlay.querySelector('#krawl-modal-actions');
            buttons.forEach(btn => {
                const el = document.createElement('button');
                el.className = `auth-modal-btn ${btn.cls}`;
                el.textContent = btn.label;
                el.onclick = () => { overlay.remove(); resolve(btn.value); };
                actions.appendChild(el);
            });
            overlay.addEventListener('click', e => {
                if (e.target === overlay) { overlay.remove(); resolve(false); }
            });
            document.body.appendChild(overlay);
        });
    },
    confirm(message) {
        return this._create('warning', 'krawl-modal-icon-warn', message, [
            { label: 'Cancel', cls: 'auth-modal-btn-cancel', value: false },
            { label: 'Confirm', cls: 'auth-modal-btn-submit', value: true },
        ]);
    },
    success(message) {
        return this._create('check_circle', 'krawl-modal-icon-success', message, [
            { label: 'OK', cls: 'auth-modal-btn-submit', value: true },
        ]);
    },
    error(message) {
        return this._create('error', 'krawl-modal-icon-error', message, [
            { label: 'OK', cls: 'auth-modal-btn-cancel', value: true },
        ]);
    },
};

// Global ban action for IP insight page (auth-gated)
window.ipBanAction = async function(ip, action) {
    // Check if authenticated
    const data = getAlpineData('[x-data="dashboardApp()"]');
    if (!data || !data.authenticated) {
        if (data && typeof data.promptAuth === 'function') data.promptAuth();
        return;
    }
    const safeIp = escapeHtml(ip);
    const safeAction = escapeHtml(action);
    const confirmed = await krawlModal.confirm(`Are you sure you want to ${safeAction} IP <strong>${safeIp}</strong>?`);
    if (!confirmed) return;
    try {
        const resp = await fetch(`${window.__DASHBOARD_PATH__}/api/ban-override`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ ip, action }),
        });
        const result = await resp.json().catch(() => ({}));
        if (resp.ok) {
            krawlModal.success(escapeHtml(result.message || `${action} successful for ${ip}`));
            const overrides = document.getElementById('overrides-container');
            if (overrides) {
                htmx.ajax('GET', `${window.__DASHBOARD_PATH__}/htmx/ban/overrides?page=1`, {
                    target: '#overrides-container',
                    swap: 'innerHTML'
                });
            }
        } else {
            krawlModal.error(escapeHtml(result.error || `Failed to ${action} IP ${ip}`));
        }
    } catch {
        krawlModal.error('Request failed');
    }
};

// Global timeout exempt/reset action (auth-gated)
window.timeoutExemptAction = async function(ip, action) {
    const data = getAlpineData('[x-data="dashboardApp()"]');
    if (!data || !data.authenticated) {
        if (data && typeof data.promptAuth === 'function') data.promptAuth();
        return;
    }
    const safeIp = escapeHtml(ip);
    const label = action === 'exempt' ? 'exempt from timeout' : 're-enable timeout for';
    const confirmed = await krawlModal.confirm(`Are you sure you want to ${label} IP <strong>${safeIp}</strong>?`);
    if (!confirmed) return;
    try {
        const resp = await fetch(`${window.__DASHBOARD_PATH__}/api/timeout-exempt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ ip, action }),
        });
        const result = await resp.json().catch(() => ({}));
        if (resp.ok) {
            krawlModal.success(escapeHtml(result.message || `${action} successful for ${ip}`));
            // Refresh both tables so the IP moves between them
            const active = document.getElementById('timedout-active-container');
            if (active && typeof htmx !== 'undefined') {
                htmx.ajax('GET', `${window.__DASHBOARD_PATH__}/htmx/timedout/active?page=1`, {
                    target: '#timedout-active-container', swap: 'innerHTML'
                });
            }
            const exempt = document.getElementById('timeout-exempt-container');
            if (exempt && typeof htmx !== 'undefined') {
                htmx.ajax('GET', `${window.__DASHBOARD_PATH__}/htmx/timeout-exempt?page=1`, {
                    target: '#timeout-exempt-container', swap: 'innerHTML'
                });
            }
        } else {
            krawlModal.error(escapeHtml(result.error || `Failed to ${action} IP ${ip}`));
        }
    } catch {
        krawlModal.error('Request failed');
    }
};

// Live per-row countdown for the Timed Out IPs table.
let _timeoutCountdownTimer = null;

function _formatRemaining(secs) {
    if (secs <= 0) return 'Expired';
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`;
    if (m > 0) return `${m}m ${String(s).padStart(2, '0')}s`;
    return `${s}s`;
}

function _tickTimeoutCountdowns() {
    const cells = document.querySelectorAll('.timeout-countdown');
    if (cells.length === 0) {
        if (_timeoutCountdownTimer) { clearInterval(_timeoutCountdownTimer); _timeoutCountdownTimer = null; }
        return;
    }
    cells.forEach((cell) => {
        let remaining = parseInt(cell.getAttribute('data-remaining'), 10);
        if (isNaN(remaining)) return;
        cell.textContent = _formatRemaining(remaining);
        if (remaining > 0) {
            cell.setAttribute('data-remaining', String(remaining - 1));
        }
    });
}

// Called from the table fragment after each HTMX swap, and on tab enter.
window.startTimeoutCountdowns = function() {
    _tickTimeoutCountdowns();  // paint immediately
    if (!_timeoutCountdownTimer) {
        _timeoutCountdownTimer = setInterval(_tickTimeoutCountdowns, 1000);
    }
};

// Global track action for IP insight page (auth-gated)
window.ipTrackAction = async function(ip, action) {
    const data = getAlpineData('[x-data="dashboardApp()"]');
    if (!data || !data.authenticated) {
        if (data && typeof data.promptAuth === 'function') data.promptAuth();
        return;
    }
    const safeIp = escapeHtml(ip);
    const label = action === 'track' ? 'track' : 'untrack';
    const confirmed = await krawlModal.confirm(`Are you sure you want to ${label} IP <strong>${safeIp}</strong>?`);
    if (!confirmed) return;
    try {
        const resp = await fetch(`${window.__DASHBOARD_PATH__}/api/track-ip`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ ip, action }),
        });
        const result = await resp.json().catch(() => ({}));
        if (resp.ok) {
            krawlModal.success(escapeHtml(result.message || `${label} successful for ${ip}`));
            // Refresh tracked IPs list if visible
            const container = document.getElementById('tracked-ips-container');
            if (container && typeof htmx !== 'undefined') {
                htmx.ajax('GET', `${window.__DASHBOARD_PATH__}/htmx/tracked-ips/list?page=1`, {
                    target: '#tracked-ips-container',
                    swap: 'innerHTML'
                });
            }
        } else {
            krawlModal.error(escapeHtml(result.error || `Failed to ${label} IP ${ip}`));
        }
    } catch {
        krawlModal.error('Request failed');
    }
};

// Show/hide ban action buttons based on auth state
function updateBanActionVisibility(authenticated) {
    document.querySelectorAll('.ip-ban-actions').forEach(el => {
        el.style.display = authenticated ? 'inline-flex' : 'none';
    });
}
// Update visibility after HTMX swaps in new content
document.addEventListener('htmx:afterSwap', () => {
    const data = getAlpineData('[x-data="dashboardApp()"]');
    if (data) updateBanActionVisibility(data.authenticated);
});

// Download credentials as ZIP with usernames.txt and passwords.txt
window.downloadCredentials = function() {
    const dashboardPath = window.__DASHBOARD_PATH__ || '';
    window.open(dashboardPath + '/api/download-credentials', '_blank');
};

// Utility function for formatting timestamps (used by map popups)
function formatTimestamp(isoTimestamp) {
    if (!isoTimestamp) return 'N/A';
    try {
        const date = new Date(isoTimestamp);
        return date.toLocaleString('en-GB', {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
        });
    } catch {
        return isoTimestamp;
    }
}
