/* Design tokens, read from CSS. Loaded before every other script so the
   map, radar and charts share one definition of each threat category. */

// Threat-category colors come from the CSS tokens, so the tables, the map,
// the radar and the charts can never disagree about what a category looks like.
function krawlToken(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}
function krawlCategoryColors() {
    return {
        attacker: krawlToken('--cat-attacker'),
        bad_crawler: krawlToken('--cat-bad-crawler'),
        good_crawler: krawlToken('--cat-good-crawler'),
        regular_user: krawlToken('--cat-regular-user'),
        timed_out: krawlToken('--cat-timed-out'),
    };
}

// Severity shade from --sev-<band>-<shade>; unknown bands fall back to low-1.
function krawlSeverityColor(band, shade, alpha) {
    const hex = krawlToken(`--sev-${band}-${shade}`) || krawlToken('--sev-low-1');
    if (alpha === undefined) return hex;
    const value = parseInt(hex.slice(1), 16);
    return `rgba(${(value >> 16) & 255}, ${(value >> 8) & 255}, ${value & 255}, ${alpha})`;
}

// Colour of an attack type from the API's colours map; missing or 'other' is low-1.
function krawlTypeColor(colours, type, alpha) {
    const c = (colours && colours[type]) || { band: 'low', shade: 1 };
    return krawlSeverityColor(c.band, c.shade, alpha);
}

// Dot-grouped integer (12.166.543), identical to the `num` Jinja filter; non-integers pass through.
function krawlNum(n) {
    if (n === null || n === undefined) return '';
    const ok = typeof n === 'number' ? Number.isFinite(n) : /^\s*[-+]?\d+\s*$/.test(String(n));
    return ok ? String(Math.trunc(Number(n))).replace(/\B(?=(\d{3})+(?!\d))/g, '.') : n;
}

// Detector ids as people say them; mirrors the attack_label Jinja filter.
const KRAWL_ATTACK_LABELS = {
    sql_injection: 'SQL injection', command_injection: 'Command injection',
    ldap_injection: 'LDAP injection', xxe_injection: 'XXE injection',
    xss_attempt: 'XSS attempt', lfi_rfi: 'LFI / RFI', path_traversal: 'Path traversal',
    login_attempt: 'Login attempt', common_probes: 'Common probes',
    scanner_probe: 'Scanner probe',
};
function krawlAttackLabel(type) {
    const key = String(type || '').trim().toLowerCase();
    if (KRAWL_ATTACK_LABELS[key]) return KRAWL_ATTACK_LABELS[key];
    // Per-CVE rule types ("cve_2019_0193") read as the CVE ID.
    if (/^cve[_-]\d{4}[_-]\d{4,}$/.test(key)) return key.toUpperCase().replace(/_/g, '-');
    const words = key.replace(/[_-]/g, ' ');
    return words.charAt(0).toUpperCase() + words.slice(1);
}

// Charts set their text in the UI face. Chart.js is a deferred script and
// this file is not, so apply the default once deferred scripts have run.
document.addEventListener('DOMContentLoaded', () => {
    if (window.Chart && Chart.defaults && Chart.defaults.font) {
        Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    }
});
