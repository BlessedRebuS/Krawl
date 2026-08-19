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
