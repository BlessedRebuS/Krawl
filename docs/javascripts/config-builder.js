// Config builder: renders every config.yaml key from assets/config-schema.json
// (built by scripts/docs_hooks.py) and prints the matching YAML, env or Helm.
(function () {
  const root = document.getElementById("kcb");
  if (!root) return;

  const $ = (sel, el = root) => el.querySelector(sel);
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  let fields = [];
  let sectionHelp = {};
  let tab = "yaml";

  fetch(root.dataset.schema)
    .then((r) => r.json())
    .then((schema) => {
      fields = schema.fields.map((f) => ({ ...f, value: structuredClone(f.default) }));
      sectionHelp = schema.sections;
      render();
      update();
    })
    .catch(() => {
      $(".kcb-form").textContent = "Could not load the settings list.";
    });

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (v !== undefined && v !== null && v !== false) node.setAttribute(k, v);
    }
    node.append(...children.filter(Boolean));
    return node;
  }

  function input(f) {
    const id = "kcb-" + f.path.replace(/[^\w]/g, "-");
    let node;
    if (f.kind === "bool") {
      node = el("input", { type: "checkbox", id });
      node.checked = !!f.value;
      node.onchange = () => set(f, node.checked);
    } else if (f.kind === "enum") {
      node = el("select", { id }, ...f.options.map((o) => el("option", { value: o, text: o })));
      node.value = f.value;
      node.onchange = () => set(f, node.value);
    } else if (f.kind === "number") {
      node = el("input", { type: "number", step: "any", id });
      node.value = f.value;
      node.oninput = () => node.value !== "" && set(f, Number(node.value));
    } else if (f.kind === "list" || f.kind === "numbers" || f.kind === "text") {
      const lines = f.kind === "text" ? String(f.value ?? "") : (f.value || []).join("\n");
      node = el("textarea", { id, rows: f.kind === "text" ? 10 : Math.min(Math.max(lines.split("\n").length, 2), 10), spellcheck: "false" });
      node.value = lines;
      node.placeholder = f.kind === "text" ? "" : "one per line";
      node.oninput = () => {
        if (f.kind === "text") return set(f, node.value);
        const items = node.value.split("\n").map((s) => s.trim()).filter(Boolean);
        if (f.kind === "numbers") {
          const ok = f.pattern ? new RegExp(f.pattern).test(items.join(",")) : items.every((s) => /^\d+$/.test(s));
          node.setCustomValidity(ok ? "" : "Whole numbers, one per line");
          if (!ok) return;
          return set(f, items.map(Number));
        }
        set(f, items);
      };
    } else {
      node = el("input", { type: "text", id, spellcheck: "false", pattern: f.pattern });
      node.value = f.value ?? "";
      node.placeholder = f.default === null ? "null (unset)" : "";
      node.oninput = () => set(f, node.value === "" && f.default === null ? null : node.value);
    }
    f.input = node;
    return node;
  }

  function render() {
    const form = $(".kcb-form");
    form.textContent = "";
    const groups = new Map();
    for (const f of fields) {
      const top = f.path.includes(".") ? f.path.split(".")[0] : "general";
      if (!groups.has(top)) groups.set(top, []);
      groups.get(top).push(f);
    }
    for (const [name, list] of groups) {
      const body = el("div", { class: "kcb-fields" });
      for (const f of list) {
        const label = f.path.includes(".") ? f.path.split(".").slice(1).join(".") : f.path;
        const row = el(
          "div",
          { class: "kcb-field" + (f.kind === "text" || f.kind === "list" || f.kind === "numbers" ? " kcb-wide" : "") },
          el("label", { for: "kcb-" + f.path.replace(/[^\w]/g, "-") }, el("code", { text: label })),
          input(f),
          f.help ? el("p", { class: "kcb-help", text: f.help }) : null,
          el("p", { class: "kcb-env", text: f.env ? f.env : "config.yaml only" })
        );
        row.dataset.search = (f.path + " " + f.help + " " + (f.env || "")).toLowerCase();
        f.row = row;
        body.append(row);
      }
      const details = el(
        "details",
        { class: "kcb-section", open: "" },
        el("summary", {}, el("span", { text: name === "general" ? "General" : name })),
        sectionHelp[name] ? el("p", { class: "kcb-section-help", text: sectionHelp[name] }) : null,
        body
      );
      details.dataset.group = name;
      form.append(details);
    }
  }

  function set(f, value) {
    f.value = value;
    update();
  }

  function chosen() {
    const all = !$("#kcb-changed").checked;
    return fields.filter((f) => all || !same(f.value, f.default));
  }

  function nest(list) {
    const out = {};
    for (const f of list) {
      const keys = f.path.split(".");
      let node = out;
      keys.slice(0, -1).forEach((k) => (node = node[k] ??= {}));
      node[keys.at(-1)] = f.value;
    }
    return out;
  }

  function envValue(v) {
    if (v === null || v === undefined) return "";
    if (Array.isArray(v)) return v.join(",");
    return String(v);
  }

  function envQuote(s) {
    return /^[\w.,:/@*+-]*$/.test(s) ? s : JSON.stringify(s);
  }

  function envText(list) {
    const lines = [];
    const done = new Set();
    for (const f of list) {
      if (!f.env) {
        lines.push(`# ${f.path}: config.yaml only`);
        continue;
      }
      if (done.has(f.env)) continue;
      done.add(f.env);
      // min,max pairs share one variable: always print both halves.
      const parts = fields.filter((g) => g.env === f.env).sort((a, b) => a.envPos - b.envPos);
      lines.push(`${f.env}=${envQuote(parts.map((p) => envValue(p.value)).join(","))}`);
    }
    return lines.join("\n");
  }

  function update() {
    const list = chosen();
    for (const f of fields) f.row?.classList.toggle("kcb-changed", !same(f.value, f.default));
    const changed = fields.filter((f) => !same(f.value, f.default)).length;
    $(".kcb-count").textContent = changed ? `${changed} changed` : "defaults";
    let text;
    if (!list.length) {
      text = "# Nothing changed yet: edit a setting to see it here.";
    } else if (tab === "env") {
      text = envText(list);
    } else {
      const data = tab === "helm" ? { config: nest(list) } : nest(list);
      text = jsyaml.dump(data, { lineWidth: -1, noRefs: true, quotingType: '"' }).trimEnd();
      if (tab === "helm") text = "# values.yaml for the Helm chart\n" + text;
    }
    $(".kcb-output code").textContent = text;
  }

  root.addEventListener("click", (e) => {
    const t = e.target.closest("[data-tab]");
    if (t) {
      tab = t.dataset.tab;
      root.querySelectorAll("[data-tab]").forEach((b) => b.setAttribute("aria-selected", b === t));
      update();
    }
  });
  $("#kcb-changed").onchange = update;
  $(".kcb-copy").onclick = async () => {
    const btn = $(".kcb-copy");
    try {
      await navigator.clipboard.writeText($(".kcb-output code").textContent);
      btn.textContent = "Copied";
    } catch {
      btn.textContent = "Select and copy";
    }
    setTimeout(() => (btn.textContent = "Copy"), 1500);
  };
  $(".kcb-reset").onclick = () => {
    for (const f of fields) f.value = structuredClone(f.default);
    render();
    update();
    $("#kcb-search").value = "";
  };
  $("#kcb-search").oninput = (e) => {
    const q = e.target.value.trim().toLowerCase();
    for (const f of fields) f.row.hidden = q && !f.row.dataset.search.includes(q);
    root.querySelectorAll(".kcb-section").forEach((d) => {
      const any = [...d.querySelectorAll(".kcb-field")].some((r) => !r.hidden);
      d.hidden = !any;
      if (q && any) d.open = true;
    });
  };
})();
