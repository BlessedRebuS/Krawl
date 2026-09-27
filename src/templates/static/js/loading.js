/* Busy feedback, everywhere.
   While data is on its way, the control that was pressed and the region
   that will change both show the search bar's spinner, so a press never
   looks like it did nothing. CSS delays the spinner by a beat, so fast
   (cached) responses never flash it.

   - krawl-pending: on the pressed control (button, pager, sort header, link)
   - krawl-loading: on the region being filled (table container, chart, map)

   Three sources feed it: every htmx request, any fetch() started by a
   press, and explicit krawlBusy() calls from the chart and map loaders.
   Loaded before the other scripts so the fetch wrapper sees every call. */
(function () {
    const PRESSABLE = 'button, a, th.sortable, [role="button"], [role="switch"], .map-legend-item';
    // A fetch or htmx request that starts this soon after a press was caused
    // by it. Long enough for a debounced handler, short enough that a poll
    // timer firing later is not blamed on the button.
    const PRESS_WINDOW_MS = 600;
    // Nothing should spin forever if a request never reports back.
    const MAX_BUSY_MS = 30000;

    const counts = new Map();
    let lastPress = null;

    function set(el, cls, on) {
        if (!el || !el.classList) return;
        const key = el;
        const byClass = counts.get(key) || {};
        const n = Math.max(0, (byClass[cls] || 0) + (on ? 1 : -1));
        byClass[cls] = n;
        counts.set(key, byClass);
        el.classList.toggle(cls, n > 0);
        const busy = Object.values(byClass).some(v => v > 0);
        if (busy) el.setAttribute('aria-busy', 'true');
        else {
            el.removeAttribute('aria-busy');
            counts.delete(key);
        }
    }

    /** Mark `el` busy until released. Returns the release function; safe to
     *  call more than once. */
    function hold(el, cls) {
        if (!el) return () => {};
        set(el, cls, true);
        let done = false;
        const release = () => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            set(el, cls, false);
        };
        const timer = setTimeout(release, MAX_BUSY_MS);
        return release;
    }

    function recentPress() {
        if (!lastPress) return null;
        if (performance.now() - lastPress.at > PRESS_WINDOW_MS) return null;
        return lastPress.el.isConnected ? lastPress.el : null;
    }

    // Capture phase: record the press before any handler starts a request.
    document.addEventListener('click', (e) => {
        const el = e.target.closest && e.target.closest(PRESSABLE);
        lastPress = el ? { el, at: performance.now() } : null;
    }, true);

    // ---- htmx: every table, pager, sort header, filter and overlay ----
    const releases = new WeakMap();
    document.addEventListener('htmx:beforeRequest', (e) => {
        const { elt, target, xhr } = e.detail;
        // Elements with their own hx-indicator (the search bar) already
        // show exactly this spinner.
        if (elt && elt.closest && elt.closest('[hx-indicator]')) return;
        const pressed = elt && elt.matches && elt.matches(PRESSABLE) ? elt : recentPress();
        const list = [hold(target, 'krawl-loading')];
        if (pressed && pressed !== target) list.push(hold(pressed, 'krawl-pending'));
        releases.set(xhr, list);
    });
    const finish = (e) => {
        const list = e.detail && releases.get(e.detail.xhr);
        if (list) {
            list.forEach(release => release());
            releases.delete(e.detail.xhr);
        }
    };
    // afterRequest covers success and HTTP errors; the others cover requests
    // that never got a response.
    ['htmx:afterRequest', 'htmx:sendError', 'htmx:timeout', 'htmx:abort']
        .forEach(name => document.addEventListener(name, finish));

    // ---- fetch: any request a press started (modal actions, toggles) ----
    const nativeFetch = window.fetch.bind(window);
    window.fetch = function (...args) {
        const pressed = recentPress();
        const request = nativeFetch(...args);
        if (!pressed) return request;
        const release = hold(pressed, 'krawl-pending');
        return request.finally(release);
    };

    /** Explicit hook for loaders that fetch without a press (charts, map):
     *  krawlBusy(el) marks the region and returns its release function. */
    window.krawlBusy = (el) => hold(el, 'krawl-loading');
})();
