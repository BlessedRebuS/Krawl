// IP Insight: the Requests filter bar. Same controls as Detected attacks, with
// its own state, so filtering one IP never touches the Attacks tab.
function initIpRequests(uid) {
    const bar = document.getElementById(`${uid}-requests-bar`);
    const box = document.getElementById(`${uid}-requests-box`);
    if (!bar || !box) return;
    const input = bar.querySelector('.panel-filter-input');
    const pills = bar.querySelector('.ip-filter-pills');
    const state = { view: 'all', not: false, search: [], exclude: [], method: '', type: '', severities: [], rule: '' };

    function url() {
        const q = new URLSearchParams({ page: '1', ip_filter: bar.dataset.ip });
        if (state.search.length) q.set('search', state.search.join(','));
        if (state.exclude.length) q.set('exclude', state.exclude.join(','));
        if (state.method) q.set('method_filter', state.method);
        if (state.view === 'all') {
            q.set('sort_by', 'timestamp');
            q.set('sort_order', 'desc');
            return `${bar.dataset.path}/htmx/access-logs?${q}`;
        }
        q.set('embed', '1');
        if (state.type) q.set('attack_type_filter', state.type);
        if (state.severities.length) q.set('severity_filter', state.severities.join(','));
        if (state.rule) q.set('rule_filter', state.rule);
        return `${bar.dataset.path}/htmx/attacks?${q}`;
    }

    function pill(label, clear) {
        const el = document.createElement('span');
        el.className = 'filter-pill';
        el.textContent = label;
        const x = document.createElement('button');
        x.type = 'button';
        x.className = 'filter-pill-clear';
        x.textContent = '×';
        x.setAttribute('aria-label', `Remove filter: ${label}`);
        x.addEventListener('click', clear);
        el.appendChild(x);
        return el;
    }

    function render() {
        bar.querySelectorAll('[data-view]').forEach(b => {
            const on = b.dataset.view === state.view;
            b.classList.toggle('active', on);
            b.setAttribute('aria-checked', on ? 'true' : 'false');
        });
        bar.querySelectorAll('[data-mode]').forEach(b => {
            const on = (b.dataset.mode === 'hide') === state.not;
            b.classList.toggle('active', on);
            b.setAttribute('aria-checked', on ? 'true' : 'false');
        });
        bar.querySelectorAll('[data-attacks-only]').forEach(el => { el.hidden = state.view !== 'attacks'; });
        bar.querySelectorAll('[data-severity]').forEach(b => {
            const on = state.severities.includes(b.dataset.severity);
            b.classList.toggle('active', on);
            b.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        input.classList.toggle('is-not', state.not);
        input.placeholder = state.not ? 'Hide requests containing… Enter to add' : 'Show only requests containing… Enter to add';
        pills.replaceChildren(
            ...state.search.map(t => pill(`only “${t}”`, () => removeTerm('search', t))),
            ...state.exclude.map(t => pill(`hide “${t}”`, () => removeTerm('exclude', t))),
        );
    }

    function apply() {
        render();
        if (typeof htmx !== 'undefined') htmx.ajax('GET', url(), { target: box, swap: 'innerHTML' });
    }

    function removeTerm(key, term) {
        state[key] = state[key].filter(t => t !== term);
        apply();
    }

    bar.addEventListener('click', e => {
        const b = e.target.closest('button');
        if (!b || b.disabled) return;
        if (b.dataset.view && b.dataset.view !== state.view) {
            state.view = b.dataset.view;
            apply();
        } else if (b.dataset.mode) {
            state.not = b.dataset.mode === 'hide';
            render();
            input.focus();
        } else if (b.dataset.severity) {
            const band = b.dataset.severity;
            state.severities = state.severities.includes(band)
                ? state.severities.filter(s => s !== band)
                : [...state.severities, band];
            apply();
        }
    });
    bar.addEventListener('change', e => {
        const key = e.target.dataset.filter;
        if (!key) return;
        state[key] = e.target.value;
        apply();
    });
    input.addEventListener('keydown', e => {
        if (e.key === 'Escape') { input.value = ''; return; }
        if (e.key !== 'Enter') return;
        e.preventDefault();
        // Terms travel as a comma list, so a comma would split one in two.
        const term = input.value.trim().slice(0, 200).replaceAll(',', ' ').trim();
        if (!term) return;
        input.value = '';
        const key = state.not ? 'exclude' : 'search';
        if (!state[key].includes(term)) { state[key] = [...state[key], term]; apply(); }
    });
    render();
}
