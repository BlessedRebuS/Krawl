# Attack detection and fake replies

Krawl recognizes attacks with [YARA](https://virustotal.github.io/yara/) rules
and answers them with fake content picked from files. Both live outside the
code, so you can add a detection or change what an attacker sees without
touching Python:

| What | Where | Decides |
|------|-------|---------|
| YARA rules | `rules/*.yar` | whether a request is an attack, its type and severity, and which reply it gets |
| Response catalogue | `responses/manifest.yaml` + files under `responses/` | which file is sent back, with which status and content type |
| Fake attack corpus | `scripts/fake_attacks.py` | the sample requests the test suite uses to prove every rule fires, and that normal traffic does not |

```yaml
detection:
  yara_rules_path: rules
  responses_path: responses
```

Rules and responses are loaded once at startup. Krawl does not start when a rule
is invalid or when the rules and the catalogue disagree (see
[Startup validation](#startup-validation)). Restart Krawl after changing either.

Bait pages that are not attack replies (login forms, fake credential files, the
fake API) live in the same manifest under `pages:`; see
[Honeypot](honeypot.md#the-pages-section).

## How a request flows

```
 request
    │
    ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ 1. Scan    path, query, body, user agent and every header are         │
 │            scanned separately (raw and URL-decoded) by every rule     │
 └──────────────────────────────────────────────────────────────────────┘
    │  findings: rule name, attack_type, severity, response_type,
    │            matched string ids ($passwd, $sel_mysql, ...), evidence
    ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ 2. Record  one detection per attack type is stored in                 │
 │            attack_detections (attack_type, evidence, rule_name)       │
 └──────────────────────────────────────────────────────────────────────┘
    │
    ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ 3. Reply   response_type → manifest type (lowest priority wins)       │
 │            matched string id → variant (else default)                 │
 │            random file + random status from the variant               │
 └──────────────────────────────────────────────────────────────────────┘
    │  no rule with a response_type, or the method is not allowed
    ▼
   pages: entry for the path  →  else trap maze (GET) / login_failed (POST)
```

1. **Scan.** Each request field is scanned on its own, so a rule sees one field
   at a time and knows which one through the `scan_target` variable. A rule that
   fires produces a *finding* carrying its metadata and the ids of the strings
   that matched (`$passwd`, `$sel_mysql`, ...).
2. **Record.** Krawl keeps one finding per attack type (the highest severity)
   and stores it in `attack_detections` with the name of the rule that matched.
   The IP analyzer counts these stored detections when it scores an attacker
   (see [Algorithms](algorithms.md)), and the dashboard shows them on the raw
   request and in the Rules tab.
3. **Reply.** A rule's `response_type` meta names an entry in
   `responses/manifest.yaml`. Among the request's findings, the type with the
   lowest `priority` that allows the request method answers. Inside that type,
   the first variant whose key is one of the matched string ids is used, else
   `default`. One file and one status are picked at random from the variant.
   A rule without `response_type` still records the attack; the request is then
   answered by a `pages:` entry or the trap maze, like any other request.

So a rule is connected to its reply in two places: `response_type` picks the
reply *type*, and the rule's string ids pick the *variant* inside it.

```
rule krawl_path_traversal                responses/manifest.yaml
  response_type = "path_traversal"  ──▶    path_traversal:
  $passwd = "/etc/passwd"           ──▶      $passwd:  files: [path_traversal/passwd/*.txt]
  $shadow = "/etc/shadow"           ──▶      $shadow:  files: [path_traversal/shadow/*.txt]
  $parent = /\.\.[\/\\]/                     default:  files: [path_traversal/listing/*.html]
```

`GET /download?file=../../etc/shadow` matches `$parent` and `$shadow`, so the
reply is one of the five fake `shadow` files. `GET /static/../../` matches only
`$parent` and gets a fake directory listing.

## Walkthrough: a new detection with a fake reply

The example detects a (fictional) camera exploit, CVE-2099-00001, that
downloads the device configuration from `/cgi-bin/export_config.cgi` or
`/api/v1/config/export`, and answers with a fake configuration file that
contains a fake admin password. Every step ends with something you can check.

### 1. Write the rule

Put the rule in the file for its family: `cve_iot.yar` for routers and cameras,
`cve_enterprise.yar` for enterprise and edge products, `cve_php_cms.yar` for PHP
apps and CMS plugins, `web_attacks.yar` / `exploits.yar` for generic attack
syntax, `recon.yar` for exposure probes. Any `.yar` file in `rules/` is loaded,
so your own rules can also go in a new file.

```yara
rule krawl_cve_2099_00001_examplecam_config_export {
    meta:
        attack_type = "cve_2099_00001"
        classification = "attack"
        severity = 8
        confidence = "high"
        description = "ExampleCam unauthenticated configuration export, which includes the admin password."
        mitre_attack = "T1190, T1552.001"
        version = "1.0"
        date = "2099-01-01"
        modified = "2099-01-01"
        author = "Your name"
        false_positives = "None known; the endpoints exist only on the device."
        cve = "CVE-2099-00001"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2099-00001"
        response_type = "examplecam_config"
    strings:
        $cgi = "/cgi-bin/export_config.cgi" ascii nocase
        $api = "/api/v1/config/export" ascii nocase
    condition:
        scan_target == "path" and any of them
}
```

- The name is the rule ID: lowercase `krawl_<family>_<what>`, and CVE rules
  `krawl_cve_<year>_<number>_<product>`. Never rename a shipped rule; stored
  detections and SIEM content key on the name.
- `attack_type` is what the dashboard groups by and what is stored (50
  characters at most). CVE rules use the CVE id in lowercase.
- Match exploit syntax, not keywords (see [Writing good rules](#writing-good-rules)),
  and gate the condition on the field the indicator arrives in.
- `response_type` is optional. Leave it out when the normal page is the better
  answer, or point it at an existing type: the shellshock rule reuses
  `command_injection`, and the Grafana and Splunk traversal CVEs get the
  `path_traversal` reply because their payload also fires `krawl_path_traversal`.

The [rule contract](#rule-contract) lists every metadata field.

### 2. Write the fake files

```
responses/examplecam_config/
  ini/config-1.ini ... config-5.ini
  json/config-1.json ... config-5.json
```

- Keep the real format, so the reply looks like the product, but make every
  secret invalid. Private keys must not decode to real keys and AWS key ids
  must be 20 characters (the tests check both).
- Hosts and addresses come from the documentation ranges (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`), loopback, `example.com` or `.internal`
  names. The tests reject any other IPv4 address.
- A variant that contains accounts or secrets ships at least five files, so
  repeated requests do not get identical bodies.
- Each file must be non-empty and at most 256 KB, inside `responses/`.

### 3. Add the type to the manifest

```yaml
responses:
  examplecam_config:
    priority: 47              # unique; lower wins when several types match
    methods: [GET, HEAD]
    variants:
      $api:                   # a string id of the rule: used when $api matched
        content_type: application/json
        status: [200]
        files: [examplecam_config/json/*.json]
      default:                # required: everything else
        content_type: text/plain
        status: [200]
        files: [examplecam_config/ini/*.ini]
```

Variant order matters: the first key that matched wins. Choose the priority by
what should answer when a request fires several rules: specific product replies
sit before generic ones (the bundled values are listed under
[Bundled response types](#bundled-response-types)).

Keep `methods` to `GET, HEAD` unless the attack really arrives in a POST. Every
POST and PUT first goes through credential capture; when a reply type allows
POST, a login POST that also fires that rule gets the fake reply instead of the
login page. That is why `sql_error` and `nosql_result` are GET-only.

If the replies must differ on something no detection string distinguishes, add
a selector string to the rule (see [Selector strings](#selector-strings)).

### 4. Add a fake attack and near misses

In `scripts/fake_attacks.py`, add one `FakeRequest` per indicator to `ATTACKS`:

```python
    FakeRequest(
        "examplecam config export",
        "cve_2099_00001",                      # expected attack_type
        rule="krawl_cve_2099_00001_examplecam_config_export",
        path="/cgi-bin/export_config.cgi",
    ),
```

It only needs the indicator the rule matches, never a working exploit; any host
in it must be `203.0.113.5` (`CALLBACK`) or another documentation address.
For a new family, add normal requests that share a word, path or parameter with
the indicator to `BENIGN`; they must produce no finding at all:

```python
    FakeRequest("camera settings page", path="/cgi-bin/settings.cgi"),
```

### 5. Pin the reply

Add one line per variant to `CASES` in `tests/test_response_content.py`: the
request and a string the reply must contain. If a variant holds secrets, add it
to the `test_secret_variants_ship_five_files` list in the same file.

```python
    ("GET", "/api/v1/config/export", "", "", '"admin_password"'),
    ("GET", "/cgi-bin/export_config.cgi", "", "", "admin_password="),
```

### 6. Run the tests

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q tests/test_rule_coverage.py -s   # per-string coverage report
```

The suite fails when the rule misses its fake attack, a benign request fires, metadata is missing or malformed, a variant key
is not a string of any rule, a file is missing or too large, a reply does not
contain its marker, or a selector changes whether the rule fires.

### 7. Try it on a running Krawl

```bash
python scripts/fake_attacks.py --url http://localhost:5000 --only krawl_cve_2099_00001_examplecam_config_export
curl -s http://localhost:5000/api/v1/config/export -H 'X-Forwarded-For: 198.51.100.66'
```

Krawl ignores loopback and private clients (`ignored_ips`), so local requests
need `X-Forwarded-For` with a public-looking documentation address; the replay
script sends one. The request then appears on the dashboard: the raw request
shows the rule card, and the Rules tab counts the match.

### 8. Ship it

Bundled rules and responses are part of the image. To run your own set without
rebuilding, mount the directories: Docker Compose already mounts `./rules` and
`./responses` read-only at `/app/rules` and `/app/responses`; on Kubernetes,
mount a volume at the same paths. A mounted directory replaces the bundled one,
so start from a copy of it.

## Bundled rules

### At a glance

Krawl ships **3,175 rules** covering **2,569 CVEs**, 336 of them on the CISA
Known Exploited Vulnerabilities list.

| Set | Rules | What it covers |
|-----|------:|----------------|
| Hand-written | 160 | Generic attack syntax (SQL injection, XSS, traversal, command injection, SSRF, SSTI, XXE, deserialization, webshells, open redirect, JWT `alg: none`), exposure probes, scanner user agents, and about 110 widely exploited CVEs with tuned indicators and replies |
| Baseline CVEs | 2,443 | One rule per CVE from 1999 to 2026, from the exploit request of a public check; 736 are WordPress plugins and themes |
| Baseline vulnerabilities | 568 | Product bugs without a CVE id, mostly OA, ERP, router and camera software |
| Baseline exposures | 4 | 558 paths of config, log, backup and sensitive files that scanners request |

Of the 3,015 baseline rules, 2,145 answer with a fake reply chosen by the kind
of bug (662 `xss`, 569 `path_traversal`, 492 `command_injection`, 295
`sql_error`, 113 `cloud_metadata`, 12 `template_eval`, 2 `sensitive_file`);
the other 870 record the attack and let the normal page answer. Their severity
is 9-10 for 952 rules, 7-8 for 952, and 6 or lower for the rest.

Analysts can add their own rules from the dashboard without a restart; see
[Uploading rules from the dashboard](#uploading-rules-from-the-dashboard).

### Files

| File | Contents |
|------|----------|
| `web_attacks.yar` | Classic web attacks: `path_traversal`, `lfi_rfi`, `sql_injection`, `xss_attempt`, `xxe_injection`, `ldap_injection`, `command_injection`, `open_redirect`, `common_probes`, `login_attempt` |
| `exploits.yar` | Generic exploit families: `log4shell`, `ssti`, `ssrf`, `shellshock`, `nosql_injection`, `crlf_injection`, `ognl_injection`, `el_injection`, `php_code_injection`, `prototype_pollution`, `download_execute`, `reverse_shell`, `ssi_injection`, `jwt_none_alg`, plus filter-evasion traversal |
| `deserialization.yar` | Java, JSON (`@type`), PHP, .NET and Python pickle markers |
| `webshells.yar` | Webshell filenames and scripts in upload directories, and PUT/MOVE/COPY uploads of scripts |
| `cve_enterprise.yar` | Frameworks, middleware and enterprise or edge products (Spring, Struts, Tomcat, WebLogic, Confluence, Exchange, vCenter, Citrix, F5, Ivanti, Fortinet, PAN-OS, Check Point, Cisco, MOVEit, ScreenConnect, CrushFTP, Serv-U, Splunk, CyberPanel, Langflow, TeamCity, Jenkins, GitLab and others) |
| `cve_php_cms.yar` | PHPUnit, PHP-CGI, ThinkPHP, Laravel Ignition, Drupal, Joomla, WordPress plugins (including Bricks Builder and Kaswara), vBulletin, Craft CMS |
| `cve_iot.yar` | Router, NAS and camera exploits sent by Mirai-family botnets (GPON, Huawei, Realtek, Hikvision, Zyxel, TP-Link, Netgear, DrayTek, Dahua, Tenda, Linksys, D-Link, AVTECH) |
| `recon.yar` | Exposure probes (credential and config files, backups, VCS/IDE files, Spring actuator, phpinfo, server-status, admin consoles, debug and profiler endpoints, Swagger/OpenAPI documents, GraphQL introspection, WEB-INF, container APIs, Elasticsearch, Hadoop YARN) and scanner user agents |
| `user_agents.yar` | `scanner_user_agent` (suspicious, not an attack) |
| `cve_2017_and_older.yar`, `cve_2018.yar` ... `cve_2026.yar` | Baseline: one rule per CVE, from public exploit checks (see below) |
| `vulnerabilities.yar` | Baseline: product vulnerabilities without a CVE id (many CNVD-tracked OA, ERP and router products) |
| `exposures.yar` | Baseline: four rules listing 558 paths of config, log, backup and sensitive files that scanners request |

CVE indicators in the hand-written files come from the vendor advisories and
NVD entries cited in each rule's `reference`.

### Baseline rules

The `cve_<year>.yar`, `vulnerabilities.yar` and `exposures.yar` files (3,015
rules) were mined from the HTTP checks in
[ProjectDiscovery nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
(MIT License). Each rule keys on the most specific part of one check's request:

- a path no other check uses (`/dataBases/upgrademysqlstatus`), ending at a
  path segment when the check's path ended there, so `/api/system/fileView`
  does not match `/api/system/fileViewer`; or
- a static parameter that names the product or plugin
  (`action=wcsales_purchased_products`, `option=com_baforms`), matched as a
  whole parameter: `submit=Log In` does not match inside `wp-submit=Log In`.

Indicators were left out when they would mislabel traffic: paths or parameters
shared by several checks (they name a product, not a bug), generic payloads
(`../../etc/passwd`, `;id`, `alert(document.domain)`, which the generic rules
already catch), values a scanner invents (nonces, `nuclei`, `dummy`), header
values, checks that only compare version numbers, and anything that matches a
`BENIGN` request or a link on Krawl's own pages. Also left out:

- every parameter of a request that carries a password field: many checks log
  in before the exploit, and that login step (`log=...&pwd=...&wp-submit=Log+In`)
  is ordinary WordPress or admin traffic;
- form plumbing and button labels (`submit`, `redirect_to`, `testcookie`,
  `nonce`, `Log In`, `Save`);
- paths of one plain word (`/monitoring`, `/workspace/`), and trailing
  placeholder segments such as the `x` in `/userfiles/x`. One-word paths with
  an extension, `_`, a digit or CamelCase stay (`/log_proxy`, `/NateMail.php`). CVEs that already have a
hand-written rule were skipped.

Baseline rules are `confidence = "medium"`: a request for the vulnerable
endpoint is a strong signal, but it cannot tell an exploit attempt from a
scanner checking whether the product is there. Severity follows the check's
severity (critical 9, high 7, medium 5, low 3), plus one for CVEs on the CISA
Known Exploited Vulnerabilities list. Checks tagged `lfi`, `sqli`, `ssrf`,
`ssti`, `xss` or `rce` get the matching fake reply. Each rule's `reference`
links the NVD entry and the source check.

They are ordinary rules: edit, tighten or delete them like any other. Each has
a sample request in `scripts/fake_attacks_baseline.json`, which
`fake_attacks.py` loads into `ATTACKS`, so the test suite proves every rule
still fires. A rule rewritten by hand should move to the matching
hand-written file (`cve_enterprise.yar`, `cve_iot.yar`, `cve_php_cms.yar`),
with its sample request moved into `fake_attacks.py`.

The authenticated dashboard's **Rules** tab lists every
loaded rule with its metadata, reply type and match count.

## Uploading rules from the dashboard

The **Rules** tab (authenticated) has an **Upload rule file** button for
analysts who need a detection now, without editing `rules/` or restarting:

1. Write the rule as in [step 1](#1-write-the-rule). Only `attack_type`,
   `classification` and `severity` are required for uploaded rules; the other
   fields are validated when present. Prefix the name with something of your
   own (`krawl_custom_...`, `acme_...`) so it never collides with a bundled rule.
2. Click **Upload rule file** and pick the `.yar` or `.yara` file (letters,
   digits, `_` and `-` in the name, at most 256 KB). One file may hold several
   rules.
3. Krawl compiles it together with the bundled rules and the other uploads.
   On success the rules are live at once and listed under **Uploaded rule
   files**; in the table their file shows as `uploaded/<name>.yar`. On error
   the message names the problem, with line numbers for syntax errors, and
   nothing changes.

Uploading a file with the same name replaces it. **Download** returns the
stored source, to edit and upload again; **Delete** removes the file and its
rules. Bundled rules cannot be deleted from the dashboard.

An upload is rejected when it:

- does not compile, or YARA warns about it (for example a slow regular expression);
- uses `import` or `include` (uploaded rules see only request fields);
- defines a rule name that is already loaded, bundled or uploaded;
- has the same name as another uploaded file with the other extension
  (`acme.yara` when `acme.yar` exists);
- misses required metadata, has an invalid value, or names a `response_type`
  the manifest does not define;
- makes a 64 KB request body take more than 250 ms to scan with every rule
  loaded;
- contains no rules.

Uploads are stored in the database (`custom_yara_rules`), so they survive
restarts and image upgrades, work with a read-only `rules/` mount, and reach
every replica in scalable mode: the replica that handles the upload swaps its
rules at once, the others within 30 seconds (the `reload-custom-rules` task).
If a stored upload stops compiling after an upgrade, for example because a
bundled rule now uses the same name, Krawl logs an error, skips that file and
starts normally; delete or fix it from the Rules tab.

Uploaded rules can use a fake reply (`response_type`) from the bundled
manifest, but cannot add new reply files: those live in `responses/` (see
[the walkthrough](#2-write-the-fake-files)). To make an uploaded rule
permanent, move it into a file under `rules/` with a fake attack, as in the
walkthrough, and delete the upload.

## Rule contract

Every list field is a comma-separated string.

| Field | Format | Bundled rules | Custom rules |
|-------|--------|---------------|--------------|
| `attack_type` | string, at most 50 characters | required | required |
| `classification` | `attack` or `suspicious` | required | required |
| `severity` | integer 1-10 | required | required |
| `confidence` | `high`, `medium` or `low` | required | optional, validated |
| `description` | what it detects and why an analyst cares | required | optional |
| `mitre_attack` | `T1234` or `T1234.567`, comma-separated | required | optional, validated |
| `version` | for example `1.0` | required | optional |
| `date`, `modified` | `YYYY-MM-DD` | required | optional, validated |
| `author` | string | required | optional |
| `false_positives` | known benign triggers, or `none known` | required | optional |
| `cve` | `CVE-YYYY-NNNN`, comma-separated | required for `krawl_cve_*` | optional, validated |
| `reference` | URL or URLs | required for CVE rules | optional |
| `response_type` | a type defined in the manifest | optional | optional, validated |

Startup fails on a missing required field, an invalid format, an unknown
`response_type`, or a rule name used twice across files (each file compiles into
its own namespace, so YARA itself would not catch the duplicate). The test suite
additionally requires the full "bundled rules" column for every file under
`rules/`. Bump `version` and `modified` when you change a rule.

`classification = "suspicious"` marks traffic worth seeing but not an attack on
its own (scanner user agents); it does not count toward the attack signal.

### What a rule sees

| Variable | Values |
|----------|--------|
| `scan_target` | `path`, `query`, `body`, `user_agent` or `header` |
| `http_method` | the request method, uppercase |
| `header_name` | the lowercase header name when `scan_target == "header"`, empty otherwise |

Path and query are scanned raw and up to twice URL-decoded; the body raw and
once decoded; each header value raw and once decoded. Query and body decoding
turns `+` into a space, so rules can match `' OR '1'='1` as written.

Each field is scanned separately, so a rule never sees two fields at once and
cannot require "this path AND that header". For exploits that need both, match
the strongest single indicator, combine alternatives with `or`, and set
`confidence = "medium"`:

```yara
    condition:
        (scan_target == "header" and header_name == "x-pan-authcheck" and $off)
        or (scan_target == "path" and $ztp)
```

### Headers and cookies

Every header except `User-Agent` (which keeps its own target) is scanned, and a
cookie arrives as the `cookie` header. At most 64 headers are scanned and a value
over 8 KB is skipped, with a debug log line.

The generic rules (`sql_injection`, `command_injection`, and so on) are gated to
path, query and body and must stay that way: a cookie such as `a=1; id=5` would
otherwise trip the command-chain pattern. Only header-specific rules (gated on
`header_name`) and rules whose syntax is safe on any field (`log4shell`,
`shellshock`, `jwt_none_alg`, serialized-object markers) may match `header`.

### Writing good rules

- **Match exploit syntax, not keywords.** A parameter such as `host=` or a word
  such as `curl` appears in ordinary traffic; the bundled command-injection rule
  only fires when a command follows a shell separator (`;id`, `|cat`, `&&uname`,
  `` `id` ``, `$(whoami)`). Add near misses to `BENIGN` to prove it.
- **Start every regular expression with a literal of two or more bytes.** Krawl
  compiles with warnings as errors, and YARA rejects patterns like `/['"]\s*--/`
  as slow. `tests/test_detection_speed.py` fails a rule that makes a 64 KB body
  take more than 250 ms.
- **Anchor paths** with `$` or a following `/` when a prefix would also match
  legitimate pages (`/server-status(\/|$)` does not match `/server-status-page`).
- **List strings explicitly** in the condition when the rule has selectors, so
  the selectors never decide whether it fires.

## Response catalogue

### Manifest format

```yaml
version: 1
responses:
  <type>:
    priority: 80                    # unique integer, lower wins
    methods: [GET, HEAD, POST, PUT] # from GET HEAD POST PUT DELETE PATCH OPTIONS
    variants:                       # order matters: first matching key wins
      $passwd:                      # a string id from a rule with this response_type
        content_type: text/plain
        status: [200]               # non-empty list of 100-599; one is picked at random
        files: [path_traversal/passwd/*.txt]   # globs, relative to responses/
        echo: false                 # optional, see Echo
      default:                      # required
        content_type: text/html
        status: [200]
        files: [path_traversal/listing/*.html]
```

List a status more than once to weight it: `sql_error` uses `[500, 500, 200]`,
so most fake database errors come back as server errors.

A type that does not allow the request method is skipped and the next matching
type is tried; with none left, the normal route answers. Variant keys match the
string ids of *every* finding of the request, not only the rule that owns the
type: the `webshell` variants use the `$sel_id` and `$sel_whoami` strings of
`krawl_command_injection`, which fires on `/shell.php?cmd=id`.

### Selector strings

A variant key is a YARA string id. When replies must differ on something no
detection string distinguishes, add a string named `$sel_<name>` and reference
it so it never changes whether the rule fires:

```yara
    strings:
        $entity = "<!ENTITY" ascii nocase
        $subset = /<!DOCTYPE[^>]{0,200}\[/ ascii nocase
        $sel_passwd = "/etc/passwd" ascii nocase
    condition:
        scan_target == "body" and any of ($entity, $subset) and (any of ($sel_*) or true)
```

- Write `(any of ($sel_*) or true)` exactly; a test checks every rule with
  selectors for it, and another strips all selectors and verifies that the same
  rules fire on the whole corpus.
- Never use `any of them` in a rule with selectors: the selectors alone would
  make it fire.
- A selector only counts in the field where the rule fires. A rule gated on
  `scan_target == "path"` never sees a selector that would match the query.

### Echo

With `echo: true`, `{{path}}`, `{{query}}` and `{{match}}` in the body are
replaced by the request path, the URL-decoded query and the matched evidence,
each cut to 2048 characters. It is plain string replacement in one pass, with no
escaping: the attacker's input is sent back as is, which is the point for `xss`,
`sql_error` and the `template_eval` default. Echo replies carry
`Content-Security-Policy: script-src 'none'`, so a reflected script does not run
in the browser of an operator who opens the URL on the honeypot origin, which
also serves the dashboard.

### Bundled response types

| Priority | Type | Methods | Rules | Variants |
|---------:|------|---------|-------|----------|
| 10 | `xxe_injection` | GET HEAD POST PUT | `xxe_injection` | `/etc/passwd`, `/etc/hosts`, generic XML |
| 20 | `cloud_metadata` | GET HEAD | `ssrf` | AWS credentials, AWS role list, GCP token, Azure instance, AWS index |
| 30 | `webshell` | GET HEAD POST PUT | `webshell_path` | command output (`passwd`, `id`, `whoami`, `uname`, `ls`), shell page |
| 40 | `spring_actuator` | GET HEAD | `probe_spring_actuator`, `cve_2022_22947_spring_cloud_gateway` | `/env`, index |
| 42 | `container_api` | GET HEAD POST | `probe_container_api` | container create (201), container list, pod list, namespace list, registry catalog, Docker version |
| 44 | `elasticsearch` | GET HEAD POST | `probe_elasticsearch` | search hits with fake users, `_cat/indices`, cluster health, banner |
| 46 | `graphql_schema` | GET HEAD POST | `graphql_introspection` | introspection result |
| 48 | `joomla_config` | GET HEAD | `cve_2023_23752_joomla_config_disclosure` | application config with database password |
| 50 | `phpinfo` | GET HEAD | `probe_phpinfo` | phpinfo page |
| 60 | `server_status` | GET HEAD | `probe_server_status` | Apache server-status |
| 62 | `vcs_metadata` | GET HEAD | `probe_vcs_ide` | `.git/config` with a token in the remote, `.git/HEAD`, `.svn/entries`, `.vscode` SFTP config, `.idea/workspace.xml`, 404 |
| 64 | `java_descriptor` | GET HEAD | `probe_web_inf` | `MANIFEST.MF`, `web.xml` with JDBC password |
| 66 | `api_docs` | GET HEAD | `probe_api_docs` | Swagger UI page, OpenAPI document |
| 70 | `sensitive_file` | GET HEAD | `probe_credential_files`, `probe_config_files`, `probe_backup_archives` | AWS, SSH keys, kubeconfig, Docker, npm, PyPI, git credentials, netrc, SQL dump, `wp-config.php`, `.env`, PHP config |
| 80 | `path_traversal` | GET HEAD POST PUT | `path_traversal`, `lfi_rfi`, `path_traversal_evasion` | `passwd`, `shadow`, `win.ini`, `/proc/self/environ`, directory listing |
| 90 | `template_eval` | GET HEAD | `ssti` | `49`, `1337`, `169`, echo of the probe |
| 100 | `command_injection` | GET HEAD POST PUT | `command_injection`, `shellshock` | `passwd`, `id`, `whoami`, `uname`, `ls`, generic output |
| 105 | `nosql_result` | GET HEAD | `nosql_injection` | user documents |
| 110 | `sql_error` | GET HEAD | `sql_injection` | PostgreSQL, SQL Server, MySQL, echoed MySQL syntax error |
| 120 | `xss` | GET HEAD | `xss_attempt` | echo page |

Rule names in the table omit the `krawl_` prefix. Baseline rules (see
[Baseline rules](#baseline-rules)) also feed `path_traversal`, `sql_error`,
`cloud_metadata`, `template_eval`, `xss` and `command_injection`, chosen by the
source check's tags, and the exposure rules feed `sensitive_file`.

### Startup validation

Krawl does not start, and logs the reason, when:

- the rules directory is missing or a rule does not compile (warnings count as errors);
- a rule misses required metadata, has an invalid value, or reuses a name;
- the manifest has an unknown or malformed key, or `version` is not `1`;
- a rule's `response_type` is not defined in the manifest;
- a variant key is a string id that no rule declares;
- two types share a priority, a type has no `default`, or a status is outside 100-599;
- a glob matches no file, a file is empty or over 256 KB, or a path leaves `responses/`.

Files are read once at startup and served from memory.

### Fingerprinting

The bundled bodies are the same in every Krawl deployment, so an attacker who
has seen one can recognize another. Replace or extend the files and mount your
own directory at `/app/responses`.

Known limit: a scanner probing `{{a*b}}` with numbers other than `7*7`,
`7*191` and `13*13` gets the `template_eval` default, which shows the probe
unevaluated, so it will not mark the target vulnerable.

## On the dashboard

The raw-request viewer lists the YARA matches stored for the request, one chip
per attack type, coloured by severity (suspicious rules have a dashed border).
Hovering or focusing a chip shows the rule card: the matched evidence, rule name
and file, description, classification, confidence, severity, MITRE ATT&CK
techniques and CVEs (linked to MITRE and NVD), known false positives and
references. Click a chip to pin the card so its links stay usable.

The card shows the metadata of the stored `rule_name` from the rules loaded now
(`/api/raw-request/{id}` returns it under `detections`). Detections stored
before Krawl recorded the rule name have none; for those, and for a rule renamed
or removed since, the card shows every loaded rule reporting the same attack
type. A type no loaded rule reports (for example `scanner_probe` from the
removed `wordlists.json` engine) appears without rule details.

The **Rules** tab (authenticated) lists every loaded rule and takes uploads;
see [Dashboard](dashboard.md#rules) and
[Uploading rules from the dashboard](#uploading-rules-from-the-dashboard).

## Upgrading from wordlists.json

Krawl no longer reads `wordlists.json`; see
[Honeypot](honeypot.md#moving-from-wordlistsjson) for where each key went. YARA
is the only detection engine; a leftover `detection.engine` key is ignored. The
`attack_detections.rule_name` column and its index are added automatically at
startup on existing SQLite and PostgreSQL databases.

## Tests

- `tests/test_fake_attacks.py` replays every fake attack through the deception
  middleware and honeypot dependency: the named rule fires, the attack type is
  recorded exactly once, every bundled rule has a fake attack, and no benign
  request produces a finding.
- `tests/test_rule_metadata.py` enforces the schema on bundled rules and the
  startup validation on custom ones.
- `tests/test_rule_coverage.py` fails when a rule is never triggered by the
  corpus, and with `-s` prints which `rule.$string` entries have no sample yet.
- `tests/test_response_content.py` sends requests through the bundled rules and
  catalogue and checks each reply's content, the five-file rule, fake-key
  validity, documentation-only addresses and the selector contract.
- `tests/test_responses.py` covers the manifest loader and reply selection.
- `tests/test_detection_speed.py` scans 64 KB bodies and 64 large headers with
  every rule and fails above 250 ms.

`DetectionCoordinator.iter_findings()` yields every raw finding;
`scan_request()` keeps one per attack type (the highest severity), which can
hide a lower-severity rule, so tests use `iter_findings()`.

## Replaying fake attacks against a running instance

```bash
python scripts/fake_attacks.py --url http://localhost:5000
python scripts/fake_attacks.py --url http://localhost:5000 --only ssti --benign
python scripts/fake_attacks.py --url http://localhost:5000 --only krawl_cve_2022_22965_spring4shell
```

`--only` accepts an attack type or a rule name. The script sends
`X-Forwarded-For` (`--source-ip`, default `198.51.100.66`) so local requests are
not ignored.

Only run it against a Krawl you control: the requests are real attack payloads,
and the source IP will be categorised as an attacker. Dashboard numbers are
computed every 5 minutes, so new traffic shows up after the next refresh.
