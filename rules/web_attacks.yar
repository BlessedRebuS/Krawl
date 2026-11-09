// Strings are tuned to exploit syntax, not keywords: a parameter name like
// host= or a word like curl is not evidence until it is chained to a shell
// separator, quote, or encoded traversal.

rule krawl_path_traversal {
    meta:
        attack_type = "path_traversal"
        classification = "attack"
        severity = 8
        confidence = "high"
        description = "Directory traversal or direct reads of well-known system files. Indicates an attacker trying to read files outside the web root."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Documentation or tutorials that quote ../ or /etc/passwd in a query string; some file-manager apps use relative paths."
        reference = "https://owasp.org/www-community/attacks/Path_Traversal"
        response_type = "path_traversal"
    strings:
        $parent = /\.\.[\/\\]/
        $passwd = "/etc/passwd" ascii nocase
        $shadow = "/etc/shadow" ascii nocase
        $windows = "c:\\windows" ascii nocase
        $ini = /(boot|win)\.ini/ ascii nocase
        $proc = "/proc/self" ascii nocase
        // {"file_path":".env"} sent to agent and dev-tool file readers
        $json_secret = /"(file_?path|path|file|filename|template_?file)"\s*:\s*"[^"]{0,64}(\.env|\.aws\/credentials|id_rsa)"/ ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_sql_injection {
    meta:
        attack_type = "sql_injection"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "SQL injection syntax: UNION SELECT, tautologies, quote-comment breaks, stacked queries, time-based functions or schema enumeration."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Search boxes where users type SQL, and forum posts about databases; the quote-comment pattern can match prose with an apostrophe followed by --."
        reference = "https://owasp.org/www-community/attacks/SQL_Injection"
        response_type = "sql_error"
    strings:
        $union = /union\s+(all\s+)?select/ ascii nocase
        $tautology = /['"]\s*(or|and)\s+['"]?\w+['"]?\s*(=|like)/ ascii nocase
        $numeric = /\b(or|and)\s+\d+\s*=\s*\d+/ ascii nocase
        $comment = /('--|"--|' --|" --|'#|"#|'\/\*|"\/\*)/ ascii
        $stacked = /;\s*(select|drop|insert|update|delete|truncate|exec)\s/ ascii nocase
        $timing = /(sleep|benchmark|pg_sleep)\s*\(\s*\d|waitfor\s+delay\s+'/ ascii nocase
        $schema = "information_schema" ascii nocase
        $xp = "xp_cmdshell" ascii nocase
        $sel_postgres = "pg_sleep" ascii nocase
        $sel_mssql = /waitfor\s+delay|xp_cmdshell/ ascii nocase
        $sel_mysql = /(sleep|benchmark)\s*\(/ ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of ($union, $tautology, $numeric, $comment, $stacked, $timing, $schema, $xp) and (any of ($sel_*) or true)
}

rule krawl_xss_attempt {
    meta:
        attack_type = "xss_attempt"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cross-site scripting payloads: script tags, javascript: URIs, inline event handlers, embedding tags and dialog calls."
        mitre_attack = "T1189, T1059.007"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Rich-text editors and CMS forms that legitimately submit HTML; the dialog-call pattern matches phrases like 'alert (' in prose."
        reference = "https://owasp.org/www-community/attacks/xss/"
        response_type = "xss"
    strings:
        $script = "<script" ascii nocase
        $javascript = "javascript:" ascii nocase
        $event = /\bon(error|load|click|focus|blur|mouseover)\s*=/ ascii nocase
        $tag = /<(iframe|svg|embed|object)\b/ ascii nocase
        $dialog = /(alert|prompt|confirm)\s*\(/ ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_lfi_rfi {
    meta:
        attack_type = "lfi_rfi"
        classification = "attack"
        severity = 8
        confidence = "high"
        description = "Local or remote file inclusion using PHP and URL wrappers (php://, data://, phar://, expect://) or direct reads of system files."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Applications that legitimately accept file:// or data: URLs in a parameter."
        reference = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"
        response_type = "path_traversal"
    strings:
        $wrapper = /(file|php|expect|data|zip|phar):\/\// ascii nocase
        $passwd = "/etc/passwd" ascii nocase
        $shadow = "/etc/shadow" ascii nocase
        $proc = "/proc/self" ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_xxe_injection {
    meta:
        attack_type = "xxe_injection"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "XML external entity injection: DOCTYPE with an internal subset or external SYSTEM/PUBLIC identifier, or ENTITY declarations in a request body."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "SOAP or XML clients that send a DOCTYPE with a public identifier (for example XHTML) are rare but exist."
        reference = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
        response_type = "xxe_injection"
    strings:
        $entity = "<!ENTITY" ascii nocase
        $subset = /<!DOCTYPE[^>]{0,200}\[/ ascii nocase
        $external = /<!DOCTYPE[^>]{0,200}(SYSTEM|PUBLIC)\s+["']/ ascii nocase
        $sel_passwd = "/etc/passwd" ascii nocase
        $sel_hosts = "/etc/hosts" ascii nocase
    condition:
        scan_target == "body" and any of ($entity, $subset, $external) and (any of ($sel_*) or true)
}

rule krawl_ldap_injection {
    meta:
        attack_type = "ldap_injection"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LDAP filter injection: filter operators followed by attribute comparisons, or a wildcard-close break-out."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Directory-search forms where users legitimately type LDAP filters."
        reference = "https://owasp.org/www-community/attacks/LDAP_Injection"
    strings:
        $filter = /(\(\||\(&|\(!)\s*\(\s*\w+\s*=/ ascii
        $break = /\*\)\s*\(\s*\w+\s*=/ ascii
    condition:
        (scan_target == "query" or scan_target == "body") and any of them
}

rule krawl_command_injection {
    meta:
        attack_type = "command_injection"
        classification = "attack"
        severity = 9
        confidence = "high"
        description = "OS command injection: command parameters, shell separators followed by common commands, shell paths and reverse-shell syntax."
        mitre_attack = "T1190, T1059.004"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Parameters named cmd or command used by legitimate admin consoles, and prose containing '; ls' style text."
        reference = "https://owasp.org/www-community/attacks/Command_Injection"
        response_type = "command_injection"
    strings:
        $parameter = /(^|[?&;])(cmd|exec|command|execute|system)=/ ascii nocase
        $chain = /(;|\||&&|`|\$\(|\$\{)\s*(id|whoami|uname|cat|ls|pwd|ps|wget|curl|nc|ncat|netcat|bash|sh|chmod|chown|rm|echo|ping|nslookup|sleep|ifconfig|ipconfig|dir|type)\b/ ascii nocase
        $shell = /\/bin\/(ba|z|da)?sh|cmd\.exe|powershell(\.exe)?\s+-/ ascii nocase
        $revshell = "/dev/tcp/" ascii
        // {"command":"env"} sent to agent and dev-tool exec endpoints
        $json_cmd = /"(command|cmd)"\s*:\s*"(env|printenv|id|whoami|uname|set)(\s[^"]{0,40})?"/ ascii nocase
        // base64 Python: "import os", "import subprocess", "__import__"
        $b64_py = /aW1wb3J0IG9z|aW1wb3J0IHN1YnByb2Nlc3|X19pbXBvcnRfX/ ascii
        $sel_passwd = "/etc/passwd" ascii nocase
        $sel_id = /(;|\||&&|`|\$\(|=)\s*id\b/ ascii nocase
        $sel_whoami = "whoami" ascii nocase
        $sel_uname = "uname" ascii nocase
        $sel_ls = /(;|\||&&|`|\$\(|=)\s*ls\b/ ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query" or scan_target == "body") and any of ($parameter, $chain, $shell, $revshell, $json_cmd, $b64_py) and (any of ($sel_*) or true)
}

rule krawl_common_probes {
    meta:
        attack_type = "common_probes"
        classification = "attack"
        severity = 3
        confidence = "low"
        description = "Requests for admin consoles, phpMyAdmin, VCS and dotfiles, or database backups. Typical of automated discovery that precedes exploitation."
        mitre_attack = "T1595.002, T1083"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Legitimate administrators and uptime monitors requesting /admin or /wp-admin."
        reference = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
    strings:
        $admin = "/admin" ascii nocase
        $wp = "/wp-admin" ascii nocase
        $pma = "/phpmyadmin" ascii nocase
        $dotfile = /\/\.(git|env|svn|hg|aws|ssh|htpasswd|htaccess|DS_Store)(\/|\.|$)/ ascii nocase
        $backup = /\/(db_)?backup\.sql/ ascii nocase
    condition:
        (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_login_attempt {
    meta:
        attack_type = "login_attempt"
        classification = "attack"
        severity = 4
        confidence = "medium"
        description = "POST to a login, sign-in, token or xmlrpc endpoint. Counts as credential guessing or brute force when repeated."
        mitre_attack = "T1110"
        version = "1.0"
        date = "2026-10-26"
        modified = "2026-10-26"
        author = "Krawl"
        false_positives = "Real users signing in; meaningful only in volume or from addresses that never browsed the site."
        reference = "https://attack.mitre.org/techniques/T1110/"
    strings:
        $login = /\/(wp-|admin\/|users?\/|account\/|portal\/|secure\/|auth\/|oauth\/|sso\/)?(login|signin)/ ascii nocase
        $signin = /\/(sign[-_]in|session\/new)/ ascii nocase
        $auth = /\/api\/(auth|login|signin|token)/ ascii nocase
        $xmlrpc = "/xmlrpc.php" ascii nocase
        $action = "action=login" ascii nocase
    condition:
        http_method == "POST" and (scan_target == "path" or scan_target == "query") and any of them
}

rule krawl_open_redirect {
    meta:
        attack_type = "open_redirect"
        classification = "attack"
        severity = 4
        confidence = "medium"
        description = "Redirect parameter pointing to a protocol-relative or backslash-mangled URL (//host, /\\host, https:/\\host), the forms that slip past same-site checks."
        mitre_attack = "T1566.002, T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl"
        false_positives = "Apps that pass protocol-relative URLs in a next or url parameter; full https:// URLs do not match."
        reference = "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
    strings:
        $a = /(^|[?&])(redirect(_?ur[il])?|redir|return(_?to|_?url)?|next|goto|dest(ination)?|continue|forward|rurl|target)=(\/\/|\/\\|\\\\|https?:\/?\\)/ ascii nocase
    condition:
        scan_target == "query" and $a
}
