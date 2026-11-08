// Rule builder: a form that writes a Krawl YARA rule, checked and tested with
// yara-lite.js. The source pane is the truth; the form only writes into it.
(function () {
  const root = document.getElementById("krb");
  if (!root || !window.YaraLite) return;
  const Y = window.YaraLite;
  const $ = (s) => root.querySelector(s);
  const $$ = (s) => [...root.querySelectorAll(s)];
  const source = $(".krb-source");
  const request = $(".krb-request");
  let meta = { responses: {}, ruleNames: [] };
  let dirty = false;
  let strings = [{ id: "$bak", kind: "regex", value: "wp-config\\.php(\\.bak|\\.old|\\.save|\\.swp|~)", nocase: true }];

  const field = (name) => root.querySelector(`[data-f="${name}"]`);
  const quote = (s) => '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  const today = () => new Date().toISOString().slice(0, 10);

  function renderStrings() {
    const box = $(".krb-strings");
    box.textContent = "";
    strings.forEach((s, i) => {
      const row = document.createElement("div");
      row.className = "krb-string";
      row.innerHTML = `
        <input type="text" class="krb-sid" aria-label="String id" spellcheck="false">
        <select class="krb-skind" aria-label="String type"><option value="text">text</option><option value="regex">regex</option></select>
        <input type="text" class="krb-sval" aria-label="String value" spellcheck="false">
        <label class="krb-nocase"><input type="checkbox"> nocase</label>
        <button type="button" class="krb-remove" aria-label="Remove string" title="Remove">✕</button>`;
      const [id, kind, val] = [row.querySelector(".krb-sid"), row.querySelector(".krb-skind"), row.querySelector(".krb-sval")];
      const nocase = row.querySelector(".krb-nocase input");
      id.value = s.id;
      kind.value = s.kind;
      val.value = s.value;
      nocase.checked = s.nocase;
      val.placeholder = s.kind === "regex" ? "regular expression, without slashes" : "text to find";
      id.oninput = () => ((s.id = id.value), fromForm());
      kind.onchange = () => ((s.kind = kind.value), renderStrings(), fromForm());
      val.oninput = () => ((s.value = val.value), fromForm());
      nocase.onchange = () => ((s.nocase = nocase.checked), fromForm());
      row.querySelector(".krb-remove").onclick = () => (strings.splice(i, 1), renderStrings(), fromForm());
      box.append(row);
    });
  }

  function build() {
    const m = [];
    const add = (k, v, raw) => v !== "" && v !== undefined && m.push(`        ${k} = ${raw ? v : quote(v)}`);
    add("attack_type", field("attack_type").value.trim());
    add("classification", field("classification").value);
    add("severity", field("severity").value, true);
    add("confidence", field("confidence").value);
    add("description", field("description").value.trim());
    add("mitre_attack", field("mitre_attack").value.trim());
    add("version", "1.0");
    add("date", today());
    add("modified", today());
    add("author", field("author").value.trim());
    add("cve", field("cve").value.trim());
    add("reference", field("reference").value.trim());
    add("response_type", field("response_type").value);

    const s = strings.map((x) => {
      const id = x.id.startsWith("$") ? x.id : "$" + x.id;
      const value = x.kind === "regex" ? "/" + x.value.replace(/(^|[^\\])\//g, "$1\\/") + "/" : quote(x.value);
      return `        ${id} = ${value}${x.nocase ? " nocase" : ""}`;
    });

    const targets = $$("[data-t]:checked").map((c) => c.dataset.t);
    const parts = [];
    if (targets.length) {
      const t = targets.map((x) =>
        x === "header" && field("header_name").value.trim()
          ? `(scan_target == "header" and header_name == ${quote(field("header_name").value.trim().toLowerCase())})`
          : `scan_target == ${quote(x)}`
      );
      parts.push(t.length > 1 ? `(${t.join(" or ")})` : t[0]);
    }
    if (field("method").value) parts.push(`http_method == ${quote(field("method").value)}`);
    parts.push(strings.length ? `${field("match").value} of them` : "true");

    return [
      `rule ${field("name").value.trim() || "unnamed"} {`,
      "    meta:",
      ...m,
      ...(s.length ? ["    strings:", ...s] : []),
      "    condition:",
      `        ${parts.join(" and ")}`,
      "}",
      "",
    ].join("\n");
  }

  function fromForm() {
    $("[data-out=severity]").textContent = field("severity").value;
    field("header_name").hidden = !$('[data-t="header"]').checked;
    const variants = meta.responses[field("response_type").value];
    const note = $(".krb-variants");
    note.hidden = !variants;
    if (variants) {
      const keyed = variants.filter((v) => v !== "default");
      note.textContent = keyed.length
        ? `Name a string ${keyed.join(", ")} to pick that variant of the reply; any other match gets the default.`
        : "This reply has only a default variant.";
    }
    if (dirty) return;
    source.value = build();
    check();
  }

  function check() {
    const { rules, errors, warnings } = Y.parse(source.value);
    const krawl = errors.length ? [] : Y.checkKrawl(rules, { ...meta, bundled: $(".krb-bundled").checked });
    const list = $(".krb-problems");
    list.textContent = "";
    const items = [
      ...errors.map((e) => ["error", e]),
      ...krawl.map((e) => ["error", e]),
      // Krawl compiles with warnings as errors.
      ...warnings.map((e) => ["warn", e]),
    ];
    if (!items.length) items.push(["ok", { message: `Valid: ${rules.length} rule${rules.length === 1 ? "" : "s"}, ready to upload.` }]);
    for (const [kind, p] of items) {
      const li = document.createElement("li");
      li.className = "krb-" + kind;
      li.textContent = (p.line ? `Line ${p.line}: ` : "") + p.message + (kind === "warn" ? " Krawl rejects rules with warnings." : "");
      if (p.line) {
        li.tabIndex = 0;
        li.onclick = li.onkeydown = (e) => (e.type === "click" || e.key === "Enter") && goto(p.line);
      }
      list.append(li);
    }
    test(errors.length ? [] : rules, errors.length > 0);
  }

  function goto(line) {
    const lines = source.value.split("\n");
    const start = lines.slice(0, line - 1).join("\n").length + (line > 1 ? 1 : 0);
    source.focus();
    source.setSelectionRange(start, start + (lines[line - 1] || "").length);
  }

  function test(rules, broken) {
    const out = $(".krb-results");
    out.textContent = "";
    if (broken) {
      out.innerHTML = `<p class="krb-none">Fix the errors above to test the rule.</p>`;
      return;
    }
    const findings = Y.scan(rules, Y.parseRequest(request.value));
    if (!findings.length) {
      out.innerHTML = `<p class="krb-none">No match. Krawl would answer this request with its normal page.</p>`;
      return;
    }
    for (const f of findings) {
      const card = document.createElement("div");
      card.className = "krb-hit";
      const where = f.target === "header" ? `header ${f.header}` : f.target.replace("_", " ");
      const reply = f.meta.response_type ? replyFor(f) : "no fake reply: the normal page answers";
      card.innerHTML = `<p class="krb-hit-title"></p><p class="krb-hit-where"></p><ul></ul><p class="krb-hit-reply"></p>`;
      card.querySelector(".krb-hit-title").textContent = `${f.rule} matched`;
      card.querySelector(".krb-hit-where").textContent = `in the ${where}${f.decoded ? " (after URL-decoding)" : ""}, as ${f.meta.attack_type || "?"}, severity ${f.meta.severity ?? "?"}`;
      const ul = card.querySelector("ul");
      for (const m of f.matched) {
        const li = document.createElement("li");
        const code = document.createElement("code");
        code.textContent = m.evidence.length > 120 ? m.evidence.slice(0, 120) + "…" : m.evidence;
        li.append(m.id + " ", code);
        ul.append(li);
      }
      card.querySelector(".krb-hit-reply").textContent = reply;
      out.append(card);
    }
  }

  function replyFor(f) {
    const variants = meta.responses[f.meta.response_type] || [];
    const hit = variants.find((v) => f.matched.some((m) => m.id === v));
    return `Reply: ${f.meta.response_type}, variant ${hit || "default"}.`;
  }

  // Wiring
  root.addEventListener("input", (e) => {
    if (e.target === source) {
      dirty = true;
      $(".krb-dirty").hidden = false;
      return check();
    }
    if (e.target === request) return check();
    if (e.target.closest(".krb-form")) fromForm();
  });
  root.addEventListener("change", (e) => {
    if (e.target.closest(".krb-form")) fromForm();
    if (e.target.classList.contains("krb-bundled")) check();
    if (e.target.classList.contains("krb-sample") && e.target.value) {
      request.value = e.target.value;
      e.target.value = "";
      check();
    }
  });
  $(".krb-add").onclick = () => {
    strings.push({ id: "$s" + (strings.length + 1), kind: "text", value: "", nocase: true });
    renderStrings();
    fromForm();
    $$(".krb-sval").at(-1).focus();
  };
  $(".krb-regen").onclick = () => {
    dirty = false;
    $(".krb-dirty").hidden = true;
    fromForm();
  };
  $(".krb-copy").onclick = async () => {
    const b = $(".krb-copy");
    try {
      await navigator.clipboard.writeText(source.value);
      b.textContent = "Copied";
    } catch {
      b.textContent = "Select and copy";
    }
    setTimeout(() => (b.textContent = "Copy"), 1500);
  };
  $(".krb-download").onclick = () => {
    const name = (Y.parse(source.value).rules[0]?.name || "rule") + ".yar";
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([source.value], { type: "text/plain" }));
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  renderStrings();
  fromForm();
  fetch(root.dataset.meta)
    .then((r) => r.json())
    .then((m) => {
      meta = m;
      const sel = field("response_type");
      for (const t of Object.keys(m.responses).sort()) sel.append(new Option(t, t));
      fromForm();
      if (dirty) check();
    })
    .catch(() => {});
})();
