// yara-lite: a YARA subset for the docs' rule builder, enough for Krawl rules.
// Parses rules, reports the errors YARA would, and matches them against the
// request fields Krawl scans. Real YARA still compiles uploads; this is a
// preview. Supported: text, regex and hex strings (nocase, ascii, wide,
// fullword, private); conditions with and/or/not, parentheses, ==, !=, <, >,
// <=, >=, contains, icontains, startswith, endswith, iequals, $a, #a,
// $a at N, any/all/none/N of (them | $a, $b*), true/false, and Krawl's
// scan_target, http_method and header_name variables.
(function (global) {
  const VARIABLES = ["scan_target", "http_method", "header_name"];
  const MITRE_ID = /^T\d{4}(\.\d{3})?$/;
  const CVE_ID = /^CVE-\d{4}-\d{4,}$/;
  const DATE = /^\d{4}-\d{2}-\d{2}$/;

  class YaraError extends Error {
    constructor(message, line) {
      super(message);
      this.line = line;
    }
  }

  // ── Bytes: YARA matches UTF-8 bytes; keep them as a latin1 JS string. ──
  const utf8 = (s) => String.fromCharCode(...new TextEncoder().encode(s));
  const reEscape = (s) => s.replace(/[\\^$.*+?()[\]{}|/-]/g, (c) => "\\" + c).replace(/[\x00-\x1f\x7f-\xff]/g, (c) => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0"));

  // ── Scanner ──
  function Scanner(src) {
    let pos = 0;
    const breaks = [];
    for (let i = src.indexOf("\n"); i >= 0; i = src.indexOf("\n", i + 1)) breaks.push(i);
    const lineAt = (p) => {
      let lo = 0, hi = breaks.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (breaks[mid] < p) lo = mid + 1;
        else hi = mid;
      }
      return lo + 1;
    };
    const fail = (msg, p = pos) => {
      throw new YaraError(msg, lineAt(p));
    };
    function skip() {
      for (;;) {
        const m = /^(\s+|\/\/[^\n]*|\/\*[\s\S]*?\*\/)/.exec(src.slice(pos));
        if (!m) return;
        pos += m[0].length;
      }
    }
    function peek(re) {
      skip();
      const m = re.exec(src.slice(pos));
      return m ? m[0] : null;
    }
    function take(re, what) {
      const t = peek(re);
      if (t === null) fail(`syntax error, expected ${what}` + (pos < src.length ? ` near "${src.slice(pos, pos + 12).split("\n")[0]}"` : ""));
      pos += t.length;
      return t;
    }
    function textString() {
      const start = pos;
      take(/^"/, '"');
      let out = "";
      while (pos < src.length && src[pos] !== '"') {
        if (src[pos] === "\n") fail("unterminated string", start);
        if (src[pos] === "\\") {
          const n = src[pos + 1];
          const map = { n: "\n", t: "\t", r: "\r", '"': '"', "\\": "\\" };
          if (n in map) {
            out += map[n];
            pos += 2;
          } else if (n === "x" && /^[0-9a-fA-F]{2}/.test(src.slice(pos + 2))) {
            out += String.fromCharCode(parseInt(src.slice(pos + 2, pos + 4), 16));
            pos += 4;
          } else fail(`illegal escape sequence \\${n}`);
        } else out += src[pos++];
      }
      if (src[pos] !== '"') fail("unterminated string", start);
      pos++;
      return out;
    }
    function regex() {
      const start = pos;
      take(/^\//, "/");
      let body = "";
      let inClass = false;
      while (pos < src.length) {
        const c = src[pos];
        if (c === "\n") break;
        if (c === "\\") {
          body += c + src[pos + 1];
          pos += 2;
          continue;
        }
        if (c === "[") inClass = true;
        else if (c === "]") inClass = false;
        else if (c === "/" && !inClass) break;
        body += c;
        pos++;
      }
      if (src[pos] !== "/") fail("unterminated regular expression", start);
      pos++;
      const flags = /^[is]*/.exec(src.slice(pos))[0];
      pos += flags.length;
      return { body, flags };
    }
    function hex() {
      const start = pos;
      take(/^\{/, "{");
      const end = src.indexOf("}", pos);
      if (end < 0) fail("unterminated hex string", start);
      const body = src.slice(pos, end);
      pos = end + 1;
      return body;
    }
    return { peek, take, textString, regex, hex, fail, lineAt, get pos() { return pos; }, get done() { skip(); return pos >= src.length; } };
  }

  // ── Strings ──
  function hexToRegex(body, fail) {
    const toks = body.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, " ").match(/~?[0-9A-Fa-f?]{2}|\[\s*\d*\s*(-\s*\d*\s*)?\]|[()|]|\S/g) || [];
    let out = "";
    for (const t of toks) {
      if (/^~?[0-9A-Fa-f?]{2}$/.test(t)) {
        const neg = t.startsWith("~");
        const [hi, lo] = t.replace("~", "");
        if (hi === "?" && lo === "?") out += neg ? fail("~?? is not allowed") : "[\\s\\S]";
        else if (hi === "?" || lo === "?") {
          const set = [];
          for (let i = 0; i < 16; i++) set.push(parseInt(hi === "?" ? i.toString(16) + lo : hi + i.toString(16), 16));
          out += (neg ? "[^" : "[") + set.map((b) => "\\x" + b.toString(16).padStart(2, "0")).join("") + "]";
        } else out += (neg ? "[^" : "") + "\\x" + (hi + lo).toLowerCase() + (neg ? "]" : "");
      } else if (t.startsWith("[")) {
        const m = /\[\s*(\d*)\s*(-)?\s*(\d*)\s*\]/.exec(t);
        out += m[2] ? `[\\s\\S]{${m[1] || 0},${m[3]}}` : `[\\s\\S]{${m[1]}}`;
      } else if (t === "(") out += "(?:";
      else if (t === ")" || t === "|") out += t;
      else fail(`invalid hex string token "${t}"`);
    }
    if (!out) fail("empty hex string");
    return out;
  }

  // Longest literal run YARA could use as an atom: a rough stand-in for its
  // "may slow down scanning" warning, which Krawl treats as an error.
  function literalRun(body) {
    let best = 0;
    function walk(s) {
      // Split top-level alternatives: the weakest one decides.
      const alts = [];
      let depth = 0, cls = false, cur = "";
      for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (c === "\\") { cur += c + (s[i + 1] || ""); i++; continue; }
        if (cls) { if (c === "]") cls = false; cur += c; continue; }
        if (c === "[") cls = true;
        if (c === "(") depth++;
        if (c === ")") depth--;
        if (c === "|" && depth === 0) { alts.push(cur); cur = ""; continue; }
        cur += c;
      }
      alts.push(cur);
      return Math.min(...alts.map(run));
    }
    function run(s) {
      let longest = 0, n = 0;
      for (let i = 0; i < s.length; i++) {
        let c = s[i], lit = null;
        if (c === "\\") {
          const e = s[++i];
          if (/[^a-zA-Z0-9]/.test(e)) lit = e;
          else if (e === "x") { lit = "x"; i += 2; }
          else if ("ntr".includes(e)) lit = e;
        } else if (c === "(") {
          let depth = 1, j = i + 1;
          for (; j < s.length && depth; j++) { if (s[j] === "\\") j++; else if (s[j] === "(") depth++; else if (s[j] === ")") depth--; }
          const inner = s.slice(i + 1, j - 1).replace(/^\?:/, "");
          const q = s[j];
          const optional = q === "?" || q === "*" || (q === "{" && /^\{0/.test(s.slice(j)));
          const g = optional ? 0 : walk(inner);
          longest = Math.max(longest, n, g);
          n = 0;
          i = j - 1;
          continue;
        } else if (c === "[") {
          i = s.indexOf("]", i + 2);
          if (i < 0) i = s.length;
        } else if (!".^$*+?{}|)".includes(c)) lit = c;
        const next = s[i + 1];
        const optional = next === "?" || next === "*" || (next === "{" && /^\{0/.test(s.slice(i + 1)));
        if (lit !== null && !optional) n++;
        else { longest = Math.max(longest, n); n = 0; }
      }
      return Math.max(longest, n);
    }
    best = walk(body);
    return best;
  }

  function compileString(s, fail, warnings) {
    const mods = new Set(s.mods);
    for (const m of mods) if (["xor", "base64", "base64wide"].includes(m)) fail(`modifier "${m}" is not supported by this preview`, s.line);
    const wide = mods.has("wide");
    const ascii = mods.has("ascii") || !wide;
    let flags = "g";
    let source;
    if (s.kind === "text") {
      if (!s.value) fail(`empty string "${s.id}"`, s.line);
      source = reEscape(utf8(s.value));
      if (mods.has("nocase")) flags += "i";
    } else if (s.kind === "regex") {
      if (/\(\?[=!<]/.test(s.value.body)) fail(`${s.id}: YARA does not support lookahead or lookbehind`, s.line);
      if (/\\[1-9]/.test(s.value.body)) fail(`${s.id}: YARA does not support backreferences`, s.line);
      source = s.value.body;
      if (mods.has("nocase") || s.value.flags.includes("i")) flags += "i";
      if (s.value.flags.includes("s")) flags += "s";
      if (/(^|[^\\])\.(\*|\+|\{\d+,\})/.test(source)) warnings.push({ line: s.line, message: `string "${s.id}" contains .*, .+ or .{x,}: use a bound such as .{1,64}` });
      else if (literalRun(source) < 2) warnings.push({ line: s.line, message: `string "${s.id}" may slow down scanning: start it with a literal of 2 or more characters` });
    } else {
      source = hexToRegex(s.value, (m) => fail(`${s.id}: ${m}`, s.line));
    }
    if (mods.has("fullword")) source = `(?<![A-Za-z0-9])(?:${source})(?![A-Za-z0-9])`;
    const parts = [];
    if (ascii || s.kind === "hex") parts.push(source);
    if (wide && s.kind === "text") parts.push(reEscape(utf8(s.value)).replace(/(\\x[0-9a-f]{2}|\\.|.)/g, "$1\\x00"));
    try {
      return new RegExp(parts.map((p) => `(?:${p})`).join("|"), flags);
    } catch (e) {
      fail(`invalid regular expression in "${s.id}": ${e.message.replace(/^Invalid regular expression: /, "")}`, s.line);
    }
  }

  // ── Condition parser (precedence: or < and < not < comparison < primary) ──
  function parseCondition(sc, rule) {
    const used = rule.used;
    const strings = rule.strings;
    function ref(id, line) {
      if (id === "$") return;
      if (!strings.some((s) => s.id === id)) throw new YaraError(`undefined string identifier "${id}"`, line);
      used.add(id);
    }
    function set() {
      if (sc.peek(/^them\b/)) {
        sc.take(/^them\b/);
        strings.forEach((s) => used.add(s.id));
        return () => strings.map((s) => s.id);
      }
      sc.take(/^\(/, "(");
      const ids = [];
      do {
        const line = sc.lineAt(sc.pos);
        const t = sc.take(/^\$\w*\*?/, "a string identifier");
        if (t.endsWith("*")) {
          const pre = t.slice(0, -1);
          const hit = strings.filter((s) => s.id.startsWith(pre));
          if (!hit.length) throw new YaraError(`no strings match "${t}"`, line);
          hit.forEach((s) => (used.add(s.id), ids.push(s.id)));
        } else {
          ref(t, line);
          ids.push(t);
        }
      } while (sc.peek(/^,/) && sc.take(/^,/));
      sc.take(/^\)/, ")");
      return () => ids;
    }
    function primary() {
      const line = sc.lineAt(sc.pos);
      if (sc.peek(/^\(/)) {
        sc.take(/^\(/);
        const e = or();
        sc.take(/^\)/, ")");
        return e;
      }
      const q = sc.peek(/^(any|all|none)\b|^\d+%?(?=\s+of\b)/);
      if (q) {
        sc.take(/^(any|all|none)\b|^\d+%?/);
        sc.take(/^of\b/, '"of"');
        const ids = set();
        const hit = (ctx) => (id) => ctx.hits(id).length > 0;
        if (q === "any") return (ctx) => ids().some(hit(ctx));
        if (q === "all") return (ctx) => ids().every(hit(ctx));
        if (q === "none") return (ctx) => !ids().some(hit(ctx));
        return (ctx) => {
          const list = ids();
          const need = q.endsWith("%") ? Math.ceil((parseInt(q) * list.length) / 100) : parseInt(q);
          let n = 0;
          for (const id of list) if (hit(ctx)(id) && ++n >= need) return true;
          return n >= need;
        };
      }
      if (sc.peek(/^(true|false)\b/)) {
        const v = sc.take(/^(true|false)\b/) === "true";
        return () => v;
      }
      if (sc.peek(/^"/)) {
        const v = sc.textString();
        return () => v;
      }
      if (sc.peek(/^-?\d+/)) {
        const v = parseInt(sc.take(/^-?\d+/));
        return () => v;
      }
      if (sc.peek(/^#\w*/)) {
        const id = "$" + sc.take(/^#\w*/).slice(1);
        ref(id, line);
        return (ctx) => ctx.hits(id).length;
      }
      if (sc.peek(/^\$\w*/)) {
        const id = sc.take(/^\$\w*/);
        ref(id, line);
        if (sc.peek(/^at\b/)) {
          sc.take(/^at\b/);
          const at = primary();
          return (ctx) => ctx.hits(id).some((h) => h.offset === at(ctx));
        }
        return (ctx) => ctx.hits(id).length > 0;
      }
      if (sc.peek(/^filesize\b/)) {
        sc.take(/^filesize\b/);
        return (ctx) => ctx.data.length;
      }
      const ident = sc.peek(/^[A-Za-z_]\w*/);
      if (ident && VARIABLES.includes(ident)) {
        sc.take(/^[A-Za-z_]\w*/);
        return (ctx) => ctx.vars[ident];
      }
      if (ident) throw new YaraError(`undefined identifier "${ident}"`, line);
      sc.take(/^$/, "an expression");
    }
    const OPS = /^(==|!=|<=|>=|<|>|contains\b|icontains\b|startswith\b|istartswith\b|endswith\b|iendswith\b|iequals\b|matches\b)/;
    function comparison() {
      const left = primary();
      const op = sc.peek(OPS);
      if (!op) return left;
      if (op === "matches") sc.fail('"matches" is not supported by this preview');
      sc.take(OPS);
      const right = primary();
      const low = (v) => String(v).toLowerCase();
      return (ctx) => {
        const a = left(ctx), b = right(ctx);
        switch (op) {
          case "==": return a === b;
          case "!=": return a !== b;
          case "<": return a < b;
          case ">": return a > b;
          case "<=": return a <= b;
          case ">=": return a >= b;
          case "contains": return String(a).includes(b);
          case "icontains": return low(a).includes(low(b));
          case "startswith": return String(a).startsWith(b);
          case "istartswith": return low(a).startsWith(low(b));
          case "endswith": return String(a).endsWith(b);
          case "iendswith": return low(a).endsWith(low(b));
          case "iequals": return low(a) === low(b);
        }
      };
    }
    function not() {
      if (sc.peek(/^not\b/)) {
        sc.take(/^not\b/);
        const e = not();
        return (ctx) => !e(ctx);
      }
      return comparison();
    }
    function and() {
      let e = not();
      while (sc.peek(/^and\b/)) {
        sc.take(/^and\b/);
        const l = e, r = not();
        e = (ctx) => l(ctx) && r(ctx);
      }
      return e;
    }
    function or() {
      let e = and();
      while (sc.peek(/^or\b/)) {
        sc.take(/^or\b/);
        const l = e, r = and();
        e = (ctx) => l(ctx) || r(ctx);
      }
      return e;
    }
    return or();
  }

  // ── Rules ──
  function parse(src) {
    const sc = Scanner(src);
    const rules = [];
    const errors = [];
    const warnings = [];
    try {
      while (!sc.done) {
        const line = sc.lineAt(sc.pos);
        if (sc.peek(/^(import|include)\b/)) throw new YaraError(`"${sc.peek(/^\w+/)}" is not allowed: Krawl rules see only request fields`, line);
        const flags = [];
        while (sc.peek(/^(private|global)\b/)) flags.push(sc.take(/^\w+/));
        sc.take(/^rule\b/, '"rule"');
        const name = sc.take(/^[A-Za-z_]\w*/, "a rule name");
        if (name.length > 128) throw new YaraError("rule name too long", line);
        if (rules.some((r) => r.name === name)) throw new YaraError(`duplicated identifier "${name}"`, line);
        const rule = { name, line, flags, tags: [], meta: {}, metaLines: {}, strings: [], used: new Set() };
        if (sc.peek(/^:/)) {
          sc.take(/^:/);
          while (sc.peek(/^[A-Za-z_]\w*/)) rule.tags.push(sc.take(/^\w+/));
        }
        sc.take(/^\{/, "{");
        if (sc.peek(/^meta\b/)) {
          sc.take(/^meta\b/);
          sc.take(/^:/, ":");
          while (sc.peek(/^[A-Za-z_]\w*\s*=/)) {
            const l = sc.lineAt(sc.pos);
            const key = sc.take(/^[A-Za-z_]\w*/);
            sc.take(/^=/);
            let value;
            if (sc.peek(/^"/)) value = sc.textString();
            else if (sc.peek(/^-?\d+\b/)) value = parseInt(sc.take(/^-?\d+/));
            else if (sc.peek(/^(true|false)\b/)) value = sc.take(/^\w+/) === "true";
            else sc.take(/^$/, "a string, number or boolean");
            rule.meta[key] = value;
            rule.metaLines[key] = l;
          }
        }
        if (sc.peek(/^strings\b/)) {
          sc.take(/^strings\b/);
          sc.take(/^:/, ":");
          while (sc.peek(/^\$\w*\s*=/)) {
            const l = sc.lineAt(sc.pos);
            const id = sc.take(/^\$\w*/);
            sc.take(/^=/);
            if (id !== "$" && rule.strings.some((s) => s.id === id)) throw new YaraError(`duplicated string identifier "${id}"`, l);
            let kind, value;
            if (sc.peek(/^"/)) (kind = "text"), (value = sc.textString());
            else if (sc.peek(/^\//)) (kind = "regex"), (value = sc.regex());
            else if (sc.peek(/^\{/)) (kind = "hex"), (value = sc.hex());
            else sc.take(/^$/, "a text, regex or hex string");
            const mods = [];
            while (sc.peek(/^(nocase|ascii|wide|fullword|private|xor|base64wide|base64)\b/)) {
              const m = sc.take(/^\w+/);
              if (mods.includes(m)) throw new YaraError(`duplicated modifier "${m}"`, l);
              if (kind === "hex" && m !== "private") throw new YaraError(`modifier "${m}" is not allowed on hex strings`, l);
              mods.push(m);
              if (sc.peek(/^\(/)) sc.take(/^\([^)]*\)/);
            }
            const s = { id, kind, value, mods, line: l };
            s.re = compileString(s, (m, ln) => { throw new YaraError(m, ln ?? l); }, warnings);
            rule.strings.push(s);
          }
        }
        sc.take(/^condition\b/, '"condition"');
        sc.take(/^:/, ":");
        rule.condition = parseCondition(sc, rule);
        sc.take(/^\}/, "}");
        for (const s of rule.strings) if (s.id !== "$" && !rule.used.has(s.id)) throw new YaraError(`unreferenced string "${s.id}"`, s.line);
        rules.push(rule);
      }
      if (!rules.length) errors.push({ line: 1, message: "no rules found" });
    } catch (e) {
      if (!(e instanceof YaraError)) throw e;
      errors.push({ line: e.line, message: e.message });
    }
    return { rules, errors, warnings };
  }

  // Krawl's metadata contract (src/detection.py), plus its upload checks.
  function checkKrawl(rules, { responses = {}, ruleNames = [], bundled = false } = {}) {
    const out = [];
    const known = new Set(ruleNames);
    const err = (r, key, message) => out.push({ line: r.metaLines[key] || r.line, message: `${r.name}: ${message}` });
    const list = (v) => String(v).split(",").map((x) => x.trim());
    for (const r of rules) {
      const m = r.meta;
      if (known.has(r.name)) err(r, null, "a bundled rule already uses this name; prefix yours (acme_..., krawl_custom_...)");
      const required = ["attack_type", "classification", "severity"];
      if (bundled) {
        required.push("confidence", "description", "mitre_attack", "version", "date", "modified", "author", "false_positives");
        if (r.name.startsWith("krawl_cve_")) required.push("cve", "reference");
      }
      for (const k of required) if (!(k in m)) err(r, null, `missing required meta "${k}"`);
      if ("attack_type" in m && (typeof m.attack_type !== "string" || !m.attack_type || m.attack_type.length > 50)) err(r, "attack_type", "attack_type must be a non-empty string of at most 50 characters");
      if ("classification" in m && !["attack", "suspicious"].includes(m.classification)) err(r, "classification", 'classification must be "attack" or "suspicious"');
      if ("severity" in m && (!Number.isInteger(m.severity) || m.severity < 1 || m.severity > 10)) err(r, "severity", "severity must be an integer from 1 to 10 (no quotes)");
      if ("confidence" in m && !["high", "medium", "low"].includes(m.confidence)) err(r, "confidence", "confidence must be high, medium or low");
      if ("mitre_attack" in m && !list(m.mitre_attack).every((x) => MITRE_ID.test(x))) err(r, "mitre_attack", "mitre_attack must be T1234 or T1234.567, comma-separated");
      if ("cve" in m && !list(m.cve).every((x) => CVE_ID.test(x))) err(r, "cve", "cve must be CVE-YYYY-NNNN, comma-separated");
      for (const k of ["date", "modified"]) if (k in m && !(DATE.test(m[k]) && !isNaN(Date.parse(m[k])))) err(r, k, `${k} must be YYYY-MM-DD`);
      if ("response_type" in m && !(m.response_type in responses)) err(r, "response_type", `unknown response_type "${m.response_type}"`);
    }
    return out;
  }

  // ── Matching against a request, the way Krawl splits it ──
  function decode(s, plus) {
    if (plus) s = s.replace(/\+/g, " ");
    // Like Python's unquote: each run of escapes is UTF-8, invalid bytes become U+FFFD.
    return s.replace(/(%[0-9a-fA-F]{2})+/g, (seq) =>
      new TextDecoder().decode(Uint8Array.from(seq.slice(1).split("%"), (h) => parseInt(h, 16)))
    );
  }

  function variants(raw, times, plus) {
    const out = [raw];
    let cur = raw;
    for (let i = 0; i < times; i++) {
      cur = decode(cur, plus);
      if (!out.includes(cur)) out.push(cur);
    }
    return out;
  }

  function parseRequest(text) {
    const norm = text.replace(/\r\n/g, "\n");
    const split = norm.indexOf("\n\n");
    const head = split < 0 ? norm : norm.slice(0, split);
    const body = split < 0 ? "" : norm.slice(split + 2);
    const [first, ...headerLines] = head.split("\n");
    const [method = "GET", target = "/"] = first.trim().split(/\s+/);
    const q = target.indexOf("?");
    // The web server percent-decodes the path once before Krawl sees it.
    const path = decode(q < 0 ? target : target.slice(0, q), false);
    const fields = [{ target: "path", header: "", values: variants(path, 2, false) }];
    // Krawl scans query and body even when empty.
    fields.push({ target: "query", header: "", values: variants(q < 0 ? "" : target.slice(q + 1), 2, true) });
    fields.push({ target: "body", header: "", values: variants(body, 1, true) });
    for (const line of headerLines) {
      const i = line.indexOf(":");
      if (i <= 0) continue;
      const name = line.slice(0, i).trim().toLowerCase();
      const value = line.slice(i + 1).trim();
      if (name === "user-agent") fields.push({ target: "user_agent", header: "", values: variants(value, 1, false) });
      else fields.push({ target: "header", header: name, values: variants(value, 1, false) });
    }
    return { method: method.toUpperCase(), fields };
  }

  function scan(rules, request) {
    const findings = [];
    const active = rules.filter((r) => !r.flags.includes("private"));
    for (const field of request.fields) {
      const seen = new Set(); // one finding per rule and field
      for (const [vi, value] of field.values.entries()) {
        const data = utf8(value);
        const cache = new Map();
        const ctx = {
          data,
          rule: null,
          vars: { scan_target: field.target, http_method: request.method, header_name: field.header },
          hits(id) {
            let byRule = cache.get(ctx.rule);
            if (!byRule) cache.set(ctx.rule, (byRule = new Map()));
            if (!byRule.has(id)) {
              const s = ctx.rule.strings.find((x) => x.id === id);
              const found = [];
              s.re.lastIndex = 0;
              for (let m; (m = s.re.exec(data)) && found.length < 100; ) {
                found.push({ offset: m.index, data: m[0] });
                if (!m[0].length) s.re.lastIndex++;
              }
              byRule.set(id, found);
            }
            return byRule.get(id);
          },
        };
        for (const rule of active) {
          if (seen.has(rule)) continue;
          ctx.rule = rule;
          if (!rule.condition(ctx)) continue;
          seen.add(rule);
          const matched = rule.strings.filter((s) => s.id !== "$" && ctx.hits(s.id).length).map((s) => ({ id: s.id, evidence: ctx.hits(s.id)[0].data }));
          findings.push({ rule: rule.name, meta: rule.meta, target: field.target, header: field.header, decoded: vi > 0, value, matched });
        }
      }
    }
    return findings;
  }

  const api = { parse, checkKrawl, parseRequest, scan, literalRun };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else global.YaraLite = api;
})(typeof window !== "undefined" ? window : globalThis);
