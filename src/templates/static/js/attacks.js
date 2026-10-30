/* Attacks tab: one period and filter state shared by the trends chart, every
   panel, the expand overlay and the URL hash. */

const ATTACKS_SEVERITIES = ['critical', 'high', 'medium', 'low'];
const ATTACKS_SPANS = [1, 7, 30];
const _attacksDefaults = () => ({ days: 7, offset: 0, slot: null, type: null, rule: null, severities: [], ip: null, search: '', method: '', exclude: [] });
window.attacksState = _attacksDefaults();

const ATTACKS_PERIOD_KEYS = ['days', 'offset_days', 'slot'];
const ATTACKS_TEXT_KEYS = ['search', 'exclude', 'method_filter', 'ip_filter'];
// Backend params each panel understands (null = all of them).
const ATTACKS_PANEL_KEYS = {
    attacks: null,
    attackers: [...ATTACKS_PERIOD_KEYS, 'attack_type_filter', 'rule_filter', 'severity_filter', ...ATTACKS_TEXT_KEYS],
    credentials: [...ATTACKS_PERIOD_KEYS, 'search', 'exclude', 'ip_filter'],
    honeypot: [...ATTACKS_PERIOD_KEYS, ...ATTACKS_TEXT_KEYS],
    'targeted-domains': [...ATTACKS_PERIOD_KEYS, ...ATTACKS_TEXT_KEYS],
    chart: [...ATTACKS_PERIOD_KEYS, ...ATTACKS_TEXT_KEYS],
};
// Domains keep `search` for the host name; the log search goes as log_search.
const ATTACKS_PARAM_RENAME = { 'targeted-domains': { search: 'log_search' } };
const ATTACKS_PARAM_NAMES = { attack_type_filter: 'type', rule_filter: 'rule', severity_filter: 'severity', method_filter: 'method' };
const ATTACKS_STORE = 'krawl.attacks.filters';

const _MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const _pad = n => String(n).padStart(2, '0');
const _utcDay = d => `${_MONTHS[d.getUTCMonth()]} ${_pad(d.getUTCDate())}`;
const _utcTime = d => `${_pad(d.getUTCHours())}:${_pad(d.getUTCMinutes())}`;

function _attacksBucketHours(days) { return days === 1 ? 1 : days <= 7 ? 4 : 24; }

// [since, until] in UTC ms, as resolve_period computes it.
function _attacksWindow(days, offset) {
    const until = Date.now() - offset * 864e5;
    return [until - days * 864e5, until];
}

function _attacksSlotValid(slot, days, offset) {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}$/.test(slot || '')) return false;
    const start = Date.parse(slot + ':00:00Z'), bh = _attacksBucketHours(days);
    const [since, until] = _attacksWindow(days, offset);
    return !isNaN(start) && new Date(start).getUTCHours() % bh === 0 && start + bh * 36e5 > since && start < until;
}

function attacksParams() {
    const s = attacksState;
    const p = new URLSearchParams({ days: s.days, offset_days: s.offset });
    if (s.slot) p.set('slot', s.slot);
    if (s.type) p.set('attack_type_filter', s.type);
    if (s.rule) p.set('rule_filter', s.rule);
    if (s.severities.length) p.set('severity_filter', s.severities.join(','));
    if (s.ip) p.set('ip_filter', s.ip);
    if (s.search.trim()) p.set('search', s.search.trim());
    if (s.method) p.set('method_filter', s.method);
    if (s.exclude.length) p.set('exclude', s.exclude.join(','));
    return p;
}

// Valid fields of "#attacks?days=7&offset=0&slot=…&type=…&sev=high,critical…"; bad ones are dropped.
function readAttacksHash(hash) {
    const q = new URLSearchParams((hash = String(hash || '')).includes('?') ? hash.slice(hash.indexOf('?') + 1) : '');
    const get = k => (q.get(k) || '').trim();
    const word = /^[\w.-]{1,128}$/;
    const out = {};
    if (ATTACKS_SPANS.includes(Number(get('days')))) out.days = Number(get('days'));
    if (/^\d{1,4}$/.test(get('offset'))) out.offset = Number(get('offset'));
    if (word.test(get('type'))) out.type = get('type');
    if (word.test(get('rule'))) out.rule = get('rule');
    const sev = [...new Set(get('sev').toLowerCase().split(','))].filter(b => ATTACKS_SEVERITIES.includes(b));
    if (sev.length) out.severities = sev;
    if (/^[0-9a-fA-F:.]{2,45}$/.test(get('ip'))) out.ip = get('ip');
    if (get('search')) out.search = get('search').slice(0, 200);
    if (/^[A-Z]{3,7}$/.test(get('method'))) out.method = get('method');
    const ex = [...new Set(get('exclude').split(',').map(t => t.trim().slice(0, 200)).filter(Boolean))];
    if (ex.length) out.exclude = ex;
    if (_attacksSlotValid(get('slot'), out.days ?? 7, out.offset ?? 0)) out.slot = get('slot');
    return out;
}

function _attacksHash() {
    const s = attacksState;
    const q = new URLSearchParams({ days: s.days, offset: s.offset });
    if (s.slot) q.set('slot', s.slot);
    if (s.type) q.set('type', s.type);
    if (s.rule) q.set('rule', s.rule);
    if (s.severities.length) q.set('sev', s.severities.join(','));
    if (s.ip) q.set('ip', s.ip);
    if (s.search.trim()) q.set('search', s.search.trim());
    if (s.method) q.set('method', s.method);
    if (s.exclude.length) q.set('exclude', s.exclude.join(','));
    return '#attacks?' + q.toString().replace(/%2C/g, ',');
}

// Arriving on the tab adds a history entry; drill-down edits replace it.
function writeAttacksHash() {
    const h = _attacksHash();
    if (location.hash === h) return;
    history[/^#(attacks|ip-stats)/.test(location.hash) ? 'replaceState' : 'pushState'](null, '', h);
}

function setAttacksState(patch) {
    // A new span or offset makes the old slot meaningless.
    if ('days' in patch || 'offset' in patch) patch = { slot: null, ...patch };
    Object.assign(attacksState, patch);
    _attacksNormalise();
    _attacksRefresh(true);
}

// Rule -> severity band, learnt from the Detected attacks fragment.
const attacksRuleBands = {};

// A rule whose band is not among the selected severities is dropped; unknown bands are kept.
function _attacksNormalise() {
    const s = attacksState, band = s.rule && attacksRuleBands[s.rule];
    if (band && s.severities.length && !s.severities.includes(band)) s.rule = null;
}

// Replace the whole state from a hash (reload, back, a shared link).
function applyAttacksHash(hash, refresh = true) {
    Object.assign(attacksState, _attacksDefaults(), readAttacksHash(hash));
    _attacksNormalise();
    if (refresh) _attacksRefresh(true);  // writes back the normalised hash
}

function shiftAttacksPeriod(direction) {
    setAttacksState({ offset: Math.max(0, attacksState.offset - direction * attacksState.days) });
}

const _attacksKeysOf = name => (name in ATTACKS_PANEL_KEYS ? ATTACKS_PANEL_KEYS[name] : ATTACKS_PERIOD_KEYS);
const _attacksPanelKeys = el => _attacksKeysOf(el.dataset.attacksPanel);

// The params a panel understands, named as its endpoint expects.
function attacksPanelParams(name) {
    const keys = _attacksKeysOf(name), rename = ATTACKS_PARAM_RENAME[name] || {};
    return new URLSearchParams([...attacksParams()].filter(([k]) => !keys || keys.includes(k)).map(([k, v]) => [rename[k] || k, v]));
}

const _attacksPanelQs = el => attacksPanelParams(el.dataset.attacksPanel).toString();

const _attacksChartKey = () => attacksPanelParams('chart').toString();

// Active filters a panel does not apply, as people name them ("type, severity").
function _attacksIgnored(name) {
    const keys = _attacksKeysOf(name);
    if (!keys) return '';
    const off = [...attacksParams().keys()].filter(k => !keys.includes(k)).map(k => ATTACKS_PARAM_NAMES[k] || k);
    return [...new Set(off)].join(', ');
}

// The filter part of the state survives reloads; slot and offset are drill-downs.
function _attacksSaveFilters() {
    const q = new URLSearchParams(_attacksHash().slice('#attacks?'.length));
    q.delete('slot');
    q.delete('offset');
    try { localStorage.setItem(ATTACKS_STORE, q.toString()); } catch (_) { /* private mode */ }
}

// Arriving without filters in the hash brings back the last ones used.
function attacksRestoreFilters() {
    let saved = '';
    try { saved = localStorage.getItem(ATTACKS_STORE) || ''; } catch (_) { /* private mode */ }
    applyAttacksHash('#attacks?' + saved, false);
}

let _attacksNot = false;
let _attacksSearchTimer = null;

function toggleAttacksNot() {
    _attacksNot = !_attacksNot;
    clearTimeout(_attacksSearchTimer);
    renderAttacksBar();
    const input = document.getElementById('attacks-search');
    if (input) { input.value = _attacksNot ? '' : attacksState.search; input.focus(); }
}

function attacksSearchInput(input) {
    if (_attacksNot) return;
    clearTimeout(_attacksSearchTimer);
    _attacksSearchTimer = setTimeout(() => setAttacksState({ search: input.value }), 300);
}

// Enter applies at once; with Not on it adds an exclude term. Escape clears.
function attacksSearchKey(e, input) {
    if (e.key === 'Escape') {
        input.value = '';
        if (!_attacksNot && attacksState.search) setAttacksState({ search: '' });
        return;
    }
    if (e.key !== 'Enter') return;
    e.preventDefault();
    clearTimeout(_attacksSearchTimer);
    const term = input.value.trim().slice(0, 200);
    if (!_attacksNot) return setAttacksState({ search: input.value });
    if (!term) return;
    input.value = '';
    if (!attacksState.exclude.includes(term)) setAttacksState({ exclude: [...attacksState.exclude, term].slice(0, 10) });
}

let _attacksTypesLoading = false;

// The type picker lists the attack types seen, labelled as people say them.
function attacksLoadTypes() {
    const pick = document.getElementById('attacks-type');
    if (!pick || pick.options.length > 2 || _attacksTypesLoading) return;
    _attacksTypesLoading = true;
    fetch(`${window.__DASHBOARD_PATH__ || ''}/htmx/attack-types-list`)
        .then(r => (r.ok ? r.json() : { attack_types: [] }))
        .then(data => {
            const sel = document.getElementById('attacks-type');
            if (!sel) return;
            const types = (Array.isArray(data.attack_types) ? data.attack_types : []).filter(t => !sel.querySelector(`option[value="${CSS.escape(t)}"]`));
            sel.append(...types.map(t => new Option(krawlAttackLabel(t), t)));
            sel.value = attacksState.type || '';
        })
        .catch(() => {})
        .finally(() => { _attacksTypesLoading = false; });
}

// Keep the bar's controls showing the state, without fighting someone typing.
function _attacksSyncControls() {
    const s = attacksState;
    const not = document.getElementById('attacks-not');
    if (not) not.setAttribute('aria-pressed', String(_attacksNot));
    if (not) not.classList.toggle('active', _attacksNot);
    const input = document.getElementById('attacks-search');
    if (input) {
        input.classList.toggle('is-not', _attacksNot);
        input.placeholder = _attacksNot ? 'Exclude… (Enter to add)' : 'Filter IP, path, user agent…';
        if (!_attacksNot && document.activeElement !== input) input.value = s.search;
    }
    const method = document.getElementById('attacks-method');
    if (method) method.value = s.method || '';
    const type = document.getElementById('attacks-type');
    if (type) {
        if (s.type && !type.querySelector(`option[value="${CSS.escape(s.type)}"]`)) type.append(new Option(krawlAttackLabel(s.type), s.type));
        type.value = s.type || '';
    }
}

function _attacksRefresh(writeHash) {
    const app = typeof _getAlpineData === 'function' ? _getAlpineData() : null;
    const onTab = app && app.tab === 'attacks';
    if (onTab && writeHash) writeAttacksHash();
    if (onTab) _attacksSaveFilters();
    renderAttacksBar();
    _syncAttacksOverlay(app);
    // While the overlay covers the tab, the tab catches up when it closes.
    if (app && app.expandOverlay.show && app.expandOverlay.shared) return;
    if (onTab && typeof loadAttackTrendsChart === 'function' && loadAttackTrendsChart.key !== _attacksChartKey()) loadAttackTrendsChart();
    // Only panels whose params changed reload; unrevealed ones load fresh when revealed.
    document.querySelectorAll('[data-attacks-panel][data-hx-revealed]').forEach(el => {
        if (el.dataset.attacksQs !== _attacksPanelQs(el)) htmx.trigger(el, 'attacks-reload');
    });
}

// The attacks expand overlay mirrors the shared state.
function _syncAttacksOverlay(app) {
    const ov = app && app.expandOverlay;
    if (!ov || !ov.show || !ov.shared) return;
    const s = attacksState;
    Object.assign(ov, { search: s.search, method: s.method, attackType: s.type || '', excludes: [...s.exclude], ipFilter: s.ip || '' });
    _reloadExpandOverlay();
}

// Rule ids as people say them; credential_fields is a pseudo-rule.
// Mirrors rule_label in dependencies.py.
function attacksRuleLabel(rule) {
    if (rule === 'credential_fields') return 'Credential capture';
    const key = String(rule).trim().toLowerCase().replace(/^krawl_/, '');
    const m = key.match(/^(cve[_-]\d{4}[_-]\d{4,})(?:[_-](.+))?$/);
    return m ? krawlAttackLabel(m[1]) + (m[2] ? ' ' + m[2].replace(/_/g, ' ') : '') : krawlAttackLabel(key);
}

function toggleAttacksSeverity(band) {
    const sev = attacksState.severities;
    setAttacksState({ severities: sev.includes(band) ? sev.filter(b => b !== band) : [...sev, band] });
}

function attacksSlotLabel(slot, days) {
    const bh = _attacksBucketHours(days);
    const start = new Date(Date.parse(slot + ':00:00Z'));
    if (bh === 24) return `${_utcDay(start)} UTC`;
    return `${_utcDay(start)} ${_utcTime(start)}–${_utcTime(new Date(start.getTime() + bh * 36e5))} UTC`;
}

function _attacksRangeText() {
    const [since, until] = _attacksWindow(attacksState.days, attacksState.offset).map(t => new Date(t));
    return `${_utcDay(since)} ${_utcTime(since)} – ${_utcDay(until)} ${_utcTime(until)} UTC`;
}

function _attacksPill(text, patch, tone, dot) {
    const pill = document.createElement('span');
    pill.className = 'filter-pill' + (tone ? ` filter-pill-${tone}` : '');
    if (dot) {
        const d = document.createElement('span');
        d.className = 'filter-pill-dot';
        d.style.background = dot;
        pill.append(d);
    }
    const x = document.createElement('button');
    x.type = 'button';
    x.className = 'filter-pill-clear';
    x.textContent = '×';
    x.title = 'Remove filter';
    x.setAttribute('aria-label', `Remove filter ${text}`);
    x.onclick = () => {
        const i = [...pill.parentNode.children].indexOf(pill);
        setAttacksState(patch);
        // Keep keyboard focus in the bar: the next pill, else the span key.
        const rest = document.querySelectorAll('#attacks-pills .filter-pill-clear');
        const to = rest[Math.min(i, rest.length - 1)] || document.querySelector('#attacks-span .active');
        if (to) to.focus();
    };
    pill.append(text, x);
    return pill;
}

function renderAttacksBar() {
    const s = attacksState;
    document.querySelectorAll('#attacks-span [data-days]').forEach(b => {
        const on = Number(b.dataset.days) === s.days;
        b.classList.toggle('active', on);
        b.setAttribute('aria-pressed', String(on));
    });
    document.querySelectorAll('#trends-totals .trends-total').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.type === s.type)));
    if (typeof _trendsEmphasise === 'function') _trendsEmphasise(s.type);
    const next = document.getElementById('attacks-next');
    if (next) next.disabled = s.offset <= 0;
    const range = document.getElementById('attacks-range');
    if (range) range.textContent = _attacksRangeText();
    // Panels say which active filters they do not apply ("type, severity not applied").
    document.querySelectorAll('[data-attacks-panel]').forEach(el => {
        const off = _attacksIgnored(el.dataset.attacksPanel);
        if (off) el.dataset.ignored = off;
        else delete el.dataset.ignored;
    });
    const scope = document.getElementById('trends-scope');
    if (scope) {
        const off = _attacksIgnored('chart');
        scope.textContent = off ? `${off} not applied` : '';
        scope.hidden = !off;
    }
    _attacksSyncControls();
    const pills = document.getElementById('attacks-pills');
    if (!pills) return;
    const list = [];
    if (s.slot) list.push(_attacksPill(attacksSlotLabel(s.slot, s.days), { slot: null }));
    if (s.type) list.push(_attacksPill(krawlAttackLabel(s.type), { type: null }));
    if (s.rule) list.push(_attacksPill(attacksRuleLabel(s.rule), { rule: null }));
    s.severities.forEach(b => list.push(_attacksPill(b[0].toUpperCase() + b.slice(1), { severities: s.severities.filter(x => x !== b) }, '', krawlSeverityColor(b, 1))));
    if (s.ip) list.push(_attacksPill(s.ip, { ip: null }));
    if (s.method) list.push(_attacksPill(s.method, { method: '' }, 'ok'));
    if (s.search.trim()) list.push(_attacksPill(`“${s.search.trim()}”`, { search: '' }, 'danger'));
    s.exclude.forEach(t => list.push(_attacksPill(`not “${t}”`, { exclude: s.exclude.filter(x => x !== t) })));
    pills.replaceChildren(...list);
    pills.hidden = !list.length;
}

// A fresh fragment teaches the rule bands; a restored rule they exclude is dropped then.
document.addEventListener('htmx:afterSwap', (e) => {
    const picker = e.detail.target.querySelector && e.detail.target.querySelector('.rule-picker[data-rules]');
    if (!picker) return;
    JSON.parse(picker.dataset.rules).forEach(r => { attacksRuleBands[r.rule] = r.band; });
    const before = attacksState.rule;
    _attacksNormalise();
    if (attacksState.rule !== before) _attacksRefresh(true);
});

// Panel loads (reveal or reload) carry the state the endpoint understands.
document.addEventListener('htmx:configRequest', (e) => {
    const el = e.detail.elt;
    if (!el || !el.dataset || !el.dataset.attacksPanel) return;
    const qs = _attacksPanelQs(el);
    el.dataset.attacksQs = qs;
    for (const [k, v] of new URLSearchParams(qs)) e.detail.parameters[k] = v;
});

// The period bar sticks right under the tab strip, whatever its height.
const _tabbar = document.querySelector('.tabbar');
if (_tabbar) new ResizeObserver(() => document.documentElement.style.setProperty('--tabbar-h', _tabbar.offsetHeight + 'px')).observe(_tabbar);
