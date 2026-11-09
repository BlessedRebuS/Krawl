---
hide:
  - navigation
  - toc
---

# Config builder

Change any setting and copy the result as `config.yaml`, environment
variables, or Helm values. Every field comes from Krawl's own
[config.yaml](https://github.com/BlessedRebuS/Krawl/blob/main/config.yaml),
with its comment as help, so the list always matches the current release.
Nothing you type leaves your browser. What each setting does is covered in
[Configuration](configuration.md).

<div id="kcb" class="kcb" data-schema="../assets/config-schema.json">
  <div class="kcb-toolbar">
    <input id="kcb-search" type="search" placeholder="Filter settings, e.g. retention or KRAWL_PORT" aria-label="Filter settings">
    <label class="kcb-toggle"><input id="kcb-changed" type="checkbox" checked> Only changed</label>
    <button type="button" class="kcb-reset md-button">Reset</button>
  </div>
  <div class="kcb-layout">
    <div class="kcb-form">Loading settings…</div>
    <aside class="kcb-panel">
      <div class="kcb-tabs" role="tablist">
        <button type="button" role="tab" data-tab="yaml" aria-selected="true">config.yaml</button>
        <button type="button" role="tab" data-tab="env" aria-selected="false">Environment</button>
        <button type="button" role="tab" data-tab="helm" aria-selected="false">Helm values</button>
        <span class="kcb-count"></span>
      </div>
      <pre class="kcb-output"><code></code></pre>
      <button type="button" class="kcb-copy md-button md-button--primary">Copy</button>
    </aside>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/js-yaml@4.1.0/dist/js-yaml.min.js"></script>
<script src="../javascripts/config-builder.js"></script>
