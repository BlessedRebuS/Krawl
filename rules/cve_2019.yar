// Baseline rules generated from public exploit and exposure checks in
// ProjectDiscovery nuclei-templates (MIT License,
// https://github.com/projectdiscovery/nuclei-templates). Each rule keys on the
// most specific request indicator of one check: a path, a static parameter or
// a vendor header that no other check and no benign request uses. Rules are
// confidence = "medium": a probe for the endpoint is a strong signal, but a
// rule cannot tell an exploit attempt from a scanner fingerprinting it.
// The `reference` field links the source check.

rule krawl_cve_2019_0193_solr {
    meta:
        attack_type = "cve_2019_0193"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Apache Solr DataImportHandler <8.2.0 - Remote Code Execution: Apache Solr is vulnerable to remote code execution vulnerabilities via the DataImportHandler, an optional but popular module to pull in data from databases and other sources. The module has a feature in which the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-0193"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0193, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-0193.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])name=dataimport(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_0221_tomcat {
    meta:
        attack_type = "cve_2019_0221"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apache Tomcat - Cross-Site Scripting: Apache Tomcat 9.0.0.M1 to 9.0.0.17, 8.5.0 to 8.5.39, and 7.0.0 to 7.0.93 are vulnerable to cross-site scripting because the SSI printenv command echoes user provided data without escaping. Note: SSI is disabled by default. The printenv."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-0221"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-0221, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-0221.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/printenv\.shtml(\/|;|$)/ nocase
        $path1 = /\/ssi\/printenv\.shtml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_1003000_script_security {
    meta:
        attack_type = "cve_2019_1003000"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jenkins Script Security Plugin <=1.49 - Sandbox Bypass: A sandbox bypass vulnerability exists in the Jenkins Script Security Plugin (versions 1.49 and earlier) within src/main/java/org/jenkinsci/plugins/scriptsecurity/sandbox/groovy/GroovySandbox.java. This flaw allows."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-1003000"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-1003000, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-1003000.yaml"
    strings:
        $path0 = /\/j_acegi_security_check(\/|;|$)/ nocase
        $path1 = /\/descriptorByName\/org\.jenkinsci\.plugins\.scriptsecurity\.sandbox\.groovy\.SecureGroovyScript\/checkScript(\/|;|$)/ nocase
        $path2 = /\/descriptorByName\/org\.jenkinsci\.plugins\.workflow\.cps\.CpsFlowDefinition\/checkScriptCompile(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_10068_kentico {
    meta:
        attack_type = "cve_2019_10068"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Kentico CMS Insecure Deserialization Remote Code Execution: Kentico CMS is susceptible to remote code execution via a .NET deserialization vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-10068"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-10068, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-10068.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/CMSPages\/Staging\/SyncServer\.asmx\/ProcessSynchronizationTaskData(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_1010287_timesheet_next_gen {
    meta:
        attack_type = "cve_2019_1010287"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Timesheet Next Gen <=1.5.3 - Cross-Site Scripting: Timesheet Next Gen 1.5.3 and earlier is vulnerable to cross-site scripting that allows an attacker to execute arbitrary HTML and JavaScript code via a 'redirect' parameter. The component is: Web login form: login.php, lines 40."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-1010287"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-1010287, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-1010287.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/timesheet\/login\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_1010290_bable {
    meta:
        attack_type = "cve_2019_1010290"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Babel - Open Redirect: Babel contains an open redirect vulnerability via redirect.php in the newurl parameter. An attacker can use any legitimate site using Babel to redirect user to a malicious site, thus possibly obtaining sensitive information, modifying data, and/or."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-1010290"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-1010290, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-1010290.yaml"
    strings:
        $path0 = /\/modules\/babel\/redirect\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_10232_gestionnaire_libre_de_parc_inf {
    meta:
        attack_type = "cve_2019_10232"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Teclib GLPI <= 9.3.3 - Unauthenticated SQL Injection: Teclib GLPI <= 9.3.3 exposes a script (/scripts/unlock_tasks.php) that incorrectly sanitizes user controlled data before using it in SQL queries. Thus, an attacker could abuse the affected feature to alter the semantic."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-10232"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-10232, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-10232.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/glpi\/scripts\/unlock_tasks\.php(\/|;|$)/ nocase
        $path1 = /\/scripts\/unlock_tasks\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_10475_build_metrics {
    meta:
        attack_type = "cve_2019_10475"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jenkins build-metrics 1.3 - Cross-Site Scripting: Jenkins build-metrics 1.3 is vulnerable to a reflected cross-site scripting vulnerability that allows attackers to inject arbitrary HTML and JavaScript into the web pages the plugin provides."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-10475"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-10475, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-10475.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/plugin\/build-metrics\/getBuildStats(\/|;|$)/ nocase
        $param0 = /(^|[?&;])rangeUnits=Weeks(&|$)/ nocase
        $param1 = /(^|[?&;])Jenkins-Crumb=4412200a345e2a8cad31f07e8a09e18be6b7ee12b1b6b917bc01a334e0f20a96(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_10692_wp_go_maps {
    meta:
        attack_type = "cve_2019_10692"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Google Maps <7.11.18 - SQL Injection: WordPress Google Maps plugin before 7.11.18 contains a SQL injection vulnerability. The plugin includes /class.rest-api.php in the REST API and does not sanitize field names before a SELECT statement. An attacker can possibly."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-10692"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-10692, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-10692.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])rest_route=\/wpgmza\/v1\/markers(&|$)/ nocase
        $param1 = /(^|[?&;])fields=\* from wp_users-- -(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_10717_blogengine_net {
    meta:
        attack_type = "cve_2019_10717"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "BlogEngine.NET 3.3.7.0 - Local File Inclusion: BlogEngine.NET 3.3.7.0 allows /api/filemanager local file inclusion via the path parameter"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-10717"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-10717, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-10717.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/api\/filemanager(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_11248_kubernetes {
    meta:
        attack_type = "cve_2019_11248"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Debug Endpoint pprof - Exposure Detection: The debugging endpoint /debug/pprof is exposed over the unauthenticated Kubelet healthz port. This debugging endpoint can potentially leak sensitive information such as internal Kubelet memory addresses and configuration, or for."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-11248"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11248, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-11248.yaml"
    strings:
        $path0 = "/debug/pprof/" ascii nocase
        $path1 = /\/debug\/pprof\/goroutine(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_11253_kubernetes {
    meta:
        attack_type = "cve_2019_11253"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kubernetes API Server - YAML Parsing DoS (Billion Laughs): The Kubernetes API server is vulnerable to a denial of service attack via YAML/JSON parsing. An attacker can send a specially crafted YAML/JSON payload that causes exponential memory consumption (Billion Laughs attack)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-11253"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11253, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-11253.yaml"
    strings:
        $path0 = /\/apis\/authorization\.k8s\.io\/v1\/selfsubjectaccessreviews(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_11580_crowd {
    meta:
        attack_type = "cve_2019_11580"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Atlassian Crowd and Crowd Data Center - Unauthenticated Remote Code Execution: Atlassian Crowd and Crowd Data Center is susceptible to a remote code execution vulnerability because the pdkinstall development plugin is incorrectly enabled in release builds. Attackers who can."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-11580"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11580, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-11580.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/crowd\/admin\/uploadplugin\.action(\/|;|$)/ nocase
        $path1 = /\/crowd\/plugins\/servlet\/exp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_11869_yuzo {
    meta:
        attack_type = "cve_2019_11869"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Yuzo <5.12.94 - Cross-Site Scripting: WordPress Yuzo Related Posts plugin before 5.12.94 is vulnerable to cross-site scripting because it mistakenly expects that is_admin() verifies that the request comes from an admin user (it actually only verifies that the request."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-11869"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-11869, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-11869.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=yuzo-related-post(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_12276_grandnode {
    meta:
        attack_type = "cve_2019_12276"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GrandNode 4.40 - Local File Inclusion: GrandNode 4.40 is susceptible to local file inclusion in Controllers/LetsEncryptController.cs, which allows remote unauthenticated attackers to retrieve arbitrary files on the web server via specially crafted LetsEncrypt/Index?fileName=."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12276"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12276, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12276.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/LetsEncrypt\/Index(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_12314_maconomy {
    meta:
        attack_type = "cve_2019_12314"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Deltek Maconomy 2.2.5 - Local File Inclusion: Deltek Maconomy 2.2.5 is prone to local file inclusion via absolute path traversal in the WS.macx1.W_MCS/ PATH_INFO, as demonstrated by a cgi-bin/Maconomy/MaconomyWS.macx1.W_MCS/etc/passwd URI."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12314"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12314, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12314.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/cgi-bin/Maconomy/MaconomyWS.macx1.W_MCS/etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_12581_uag2100 {
    meta:
        attack_type = "cve_2019_12581"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Zyxel ZyWal/USG/UAG Devices - Cross-Site Scripting: Zyxel ZyWall, USG, and UAG devices allow remote attackers to inject arbitrary web script or HTML via the err_msg parameter free_time_failed.cgi CGI program, aka reflective cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12581"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12581, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12581.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/free_time_failed\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_12593_mail_server {
    meta:
        attack_type = "cve_2019_12593"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "IceWarp Mail Server <=10.4.4 - Local File Inclusion: IceWarp Mail Server through 10.4.4 is prone to a local file inclusion vulnerability via webmail/calendar/minimizer/index.php?style=..%5c directory traversal."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12593"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12593, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12593.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/webmail\/calendar\/minimizer\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_12935_shopware_5_5_8 {
    meta:
        attack_type = "cve_2019_12935"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Shopware < 5.5.8 - Cross-Site Scripting: Shopware before 5.5.8 contains a reflected cross-site scripting (XSS) caused by unsanitized query string parameters in the backend/Login or backend/Login/load/ URI, letting attackers execute arbitrary scripts in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12935"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12935, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12935.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/backend\/Login(\/|;|$)/ nocase
        $path1 = "/backend/Login/load/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_12962_livezilla {
    meta:
        attack_type = "cve_2019_12962"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LiveZilla Server 8.0.1.0 - Cross-Site Scripting: LiveZilla Server 8.0.1.0 is vulnerable to reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12962"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12962, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12962.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/mobile\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_12985_netscaler_sd_wan {
    meta:
        attack_type = "cve_2019_12985"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Citrix SD-WAN Center - Remote Command Injection: Citrix SD-WAN Center is susceptible to remote command injection via the ping function in DiagnosticsController, which does not sufficiently validate or sanitize HTTP request parameter values used to construct a shell command. An."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12985"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12985, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12985.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/Collector\/diagnostics\/ping(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_12986_netscaler_sd_wan {
    meta:
        attack_type = "cve_2019_12986"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Citrix SD-WAN Center - Remote Command Injection: Citrix SD-WAN Center is susceptible to remote command injection via the trace_route function in DiagnosticsController, which does not sufficiently validate or sanitize HTTP request parameter values used to construct a shell."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12986"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12986, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12986.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/Collector\/diagnostics\/trace_route(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_12987_netscaler_sd_wan {
    meta:
        attack_type = "cve_2019_12987"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Citrix SD-WAN Center - Remote Command Injection: Citrix SD-WAN Center is susceptible to remote command injection via the apply action in StorageMgmtController. The callStoragePerl function does not sufficiently validate or sanitize HTTP request parameter values that are used to."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12987"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12987, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12987.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/Collector\/storagemgmt\/apply(\/|;|$)/ nocase
        $param0 = /(^|[?&;])data\[0\]\[path\]=mypath(&|$)/ nocase
        $param1 = /(^|[?&;])data\[0\]\[type\]=mytype(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_12988_netscaler_sd_wan {
    meta:
        attack_type = "cve_2019_12988"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Citrix SD-WAN Center - Remote Command Injection: Citrix SD-WAN Center is susceptible to remote command injection via the addModifyZTDProxy function in NmsController. The function does not sufficiently validate or sanitize HTTP request parameter values that are used to construct."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12988"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12988, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12988.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/Collector\/nms\/addModifyZTDProxy(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_12989_netscaler_sd_wan {
    meta:
        attack_type = "cve_2019_12989"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Citrix SD-WAN and NetScaler SD-WAN - SQL Injection: Citrix SD-WAN 10.2.x before 10.2.3 and NetScaler SD-WAN 10.0.x before 10.0.8 contain an SQL injection vulnerability. An unauthenticated attacker can exploit improper validation of input in specific components, which could."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12989"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12989, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12989.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/sdwan\/nitro\/v1\/config\/get_package_file(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_12990_netscaler_sd_wan {
    meta:
        attack_type = "cve_2019_12990"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Citrix SD-WAN Center - Local File Inclusion: Citrix SD-WAN Center is susceptible to local file inclusion via the applianceSettingsFileTransfer function in ApplianceSettingsController. The function does not sufficiently validate or sanitize HTTP request parameter values used to."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-12990"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-12990, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-12990.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/Collector\/appliancesettings\/applianceSettingsFileTransfer(\/|;|$)/ nocase
        $path1 = "/talari/app/files/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_13392_natemail {
    meta:
        attack_type = "cve_2019_13392"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MindPalette NateMail 3.0.15 - Cross-Site Scripting: MindPalette NateMail 3.0.15 is susceptible to reflected cross-site scripting which could allows an attacker to execute remote JavaScript in a victim's browser via a specially crafted POST request. The application will reflect."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-13392"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-13392, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-13392.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/NateMail\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_13396_flightpath {
    meta:
        attack_type = "cve_2019_13396"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "FlightPath - Local File Inclusion: FlightPath versions prior to 4.8.2 and 5.0-rc2 are vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-13396"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-13396, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-13396.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/flightpath\/index\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])form_include=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_13462_lansweeper {
    meta:
        attack_type = "cve_2019_13462"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Lansweeper Unauthenticated SQL Injection: Lansweeper before 7.1.117.4 allows unauthenticated SQL injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-13462"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-13462, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-13462.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/WidgetHandler\.ashx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])MethodName=Sort(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_13608_storefront_server {
    meta:
        attack_type = "cve_2019_13608"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Citrix StoreFront Server - XML External Entity: Citrix StoreFront Server before 1903, 7.15 LTSR before CU4 (3.12.4000), and 7.6 LTSR before CU8 (3.0.8000) allows XXE attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-13608"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-13608, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-13608.yaml"
    strings:
        $path0 = /\/Citrix\/StoreAuth\/ExplicitForms\/Start(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_14205_adaptive_images {
    meta:
        attack_type = "cve_2019_14205"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Nevma Adaptive Images <0.6.67 - Local File Inclusion: WordPress Nevma Adaptive Images plugin before 0.6.67 allows remote attackers to retrieve arbitrary files via the $REQUEST['adaptive-images-settings']['source_file'] parameter in adaptive-images-script.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-14205"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-14205, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-14205.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])adaptive-images-settings\[source_file\]=\.\.\/\.\.\/\.\.\/wp-config\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_14206_adaptive_images {
    meta:
        attack_type = "cve_2019_14206"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Nevma Adaptive Images - Arbitrary File Deletion: Nevma Adaptive Images plugin before 0.6.67 for WordPress contains an arbitrary file deletion caused by unsanitized input in adaptive-images-script.php, letting remote attackers delete arbitrary files, exploit requires sending."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-14206"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-14206, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-14206.yaml"
    strings:
        $param0 = /(^|[?&;])adaptive-images-settings\[cache_dir\]=\.\.\/\.\.\/\.\.(&|$)/ nocase
        $param1 = /(^|[?&;])adaptive-images-settings\[request_uri\]=license\.txt(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_14223_alfresco {
    meta:
        attack_type = "cve_2019_14223"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Alfresco Share - Open Redirect: Alfresco Share before 5.2.6, 6.0.N and 6.1.N contains an open redirect vulnerability via a crafted POST request. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-14223"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-14223, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-14223.yaml"
    strings:
        $path0 = /\/share\/page\/dologin(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_14251_t24 {
    meta:
        attack_type = "cve_2019_14251"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "T24 Web Server - Local File Inclusion: T24 web server is vulnerable to unauthenticated local file inclusion that permits an attacker to exfiltrate data directly from server."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-14251"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-14251, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-14251.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/WealthT24\/GetImage(\/|;|$)/ nocase
        $param0 = /(^|[?&;])docDownloadPath=\/etc\/passwd(&|$)/ nocase
        $param1 = /(^|[?&;])docDownloadPath=c:\/windows\/win\.ini(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_14312_jaxer {
    meta:
        attack_type = "cve_2019_14312"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Aptana Jaxer 1.0.3.4547 - Local File inclusion: Aptana Jaxer 1.0.3.4547 is vulnerable to local file inclusion in the wikilite source code viewer. An attacker can read internal files on the server via a tools/sourceViewer/index.html?filename=../ URI."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-14312"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-14312, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-14312.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/tools\/sourceViewer\/index\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_14470_instagram_php_api {
    meta:
        attack_type = "cve_2019_14470"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress UserPro 4.9.32 - Cross-Site Scripting: WordPress UserPro 4.9.32 is vulnerable to reflected cross-site scripting because the Instagram PHP API (v2) it relies on allows it via the example/success.php error_description parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-14470"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-14470, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-14470.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/userpro\/lib\/instagram\/vendor\/cosenary\/instagram\/example\/success\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_14530_openemr {
    meta:
        attack_type = "cve_2019_14530"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OpenEMR <5.0.2 - Local File Inclusion: OpenEMR before 5.0.2 is vulnerable to local file inclusion via the fileName parameter in custom/ajax_download.php. An attacker can download any file (that is readable by the web server user) from server storage. If the requested file is."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-14530"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-14530, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-14530.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/custom\/ajax_download\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_14696_open_school {
    meta:
        attack_type = "cve_2019_14696"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Open-School 3.0/Community Edition 2.3 - Cross-Site Scripting: Open-School 3.0, and Community Edition 2.3, allows cross-site scripting via the osv/index.php?r=students/guardians/create id parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-14696"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-14696, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-14696.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])r=students\/guardians\/create(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_14974_sugarcrm {
    meta:
        attack_type = "cve_2019_14974"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SugarCRM Enterprise 9.0.0 - Cross-Site Scripting: SugarCRM Enterprise 9.0.0 contains a cross-site scripting vulnerability via mobile/error-not-supported-platform.html?desktop_url."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-14974"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-14974, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-14974.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/mobile\/error-not-supported-platform\.html(\/|;|$)/ nocase
        $param0 = /(^|[?&;])desktop_url=javascript:alert\(1337\);\/\/itms:\/\/(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_15811_domainmod {
    meta:
        attack_type = "cve_2019_15811"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD <=4.13.0 - Cross-Site Scripting: DomainMOD through 4.13.0 contains a cross-site scripting vulnerability via /reporting/domains/cost-by-month.php in Daterange parameters."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-15811"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-15811, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-15811.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/reporting\/domains\/cost-by-month\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_15823_wps_hide_login {
    meta:
        attack_type = "cve_2019_15823"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WPS Hide Login <= 1.5.2.2 - Login Page Bypass: WPS-Hide-Login plugin before 1.5.3 for WordPress contains an action=confirmaction protection bypass, letting attackers bypass security checks, exploit requires sending crafted requests."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-15823"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-15823, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-15823.yaml"
    strings:
        $param0 = /(^|[?&;])SECUPRESSaction=confirmaction(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_15829_gallery_photoblocks {
    meta:
        attack_type = "cve_2019_15829"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Gallery Photoblocks < 1.1.43 - Cross-Site Scripting: The Gallery PhotoBlocks WordPress plugin was affected by an Authenticated Reflected XSS security vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-15829"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-15829, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-15829.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=photoblocks-edit(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_15859_diris_a_40_firmware {
    meta:
        attack_type = "cve_2019_15859"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Socomec DIRIS A-40 Devices Password Disclosure: Socomec DIRIS A-40 devices before 48250501 are susceptible to a password disclosure vulnerability in the web interface that could allow remote attackers to get full access to a device via the /password.jsn URI."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-15859"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-15859, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-15859.yaml"
    strings:
        $path0 = /\/password\.jsn(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_15889_wordpress_download_manager {
    meta:
        attack_type = "cve_2019_15889"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Download Manager <2.9.94 - Cross-Site Scripting: WordPress Download Manager plugin before 2.9.94 contains a cross-site scripting vulnerability via the category shortcode feature, as demonstrated by the orderby or search[publish_date] parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-15889"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-15889, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-15889.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wpdmpro/list-packages/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_16072_enigma_network_management_solu {
    meta:
        attack_type = "cve_2019_16072"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Enigma NMS < 65.0.0 - Authenticated OS Command Injection: An OS command injection vulnerability in the discover_and_manage CGI script in NETSAS Enigma NMS 65.0.0 and prior allows an authenticated attacker to execute arbitrary code because of improper neutralization of shell."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16072"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16072, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16072.yaml"
    strings:
        $path0 = /\/cgi-bin\/protected\/main\.cgi(\/|;|$)/ nocase
        $path1 = /\/cgi-bin\/protected\/discover_and_manage\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])action=snmp_browser(&|$)/ nocase
        $param1 = /(^|[?&;])snmp_ro_string=public(&|$)/ nocase
        $param2 = /(^|[?&;])mib_oid=system(&|$)/ nocase
        $param3 = /(^|[?&;])mib_oid_manual=\.1\.3\.6\.1\.2\.1\.1(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_16123_piluscart {
    meta:
        attack_type = "cve_2019_16123"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PilusCart <=1.4.1 - Local File Inclusion: PilusCart versions 1.4.1 and prior suffer from a file disclosure vulnerability via local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16123"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16123, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16123.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/catalog\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_16313_fr6_firmware {
    meta:
        attack_type = "cve_2019_16313"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ifw8 Router ROM v4.31 - Credential Discovery: ifw8 Router ROM v4.31 is vulnerable to credential disclosure via action/usermanager.htm HTML source code."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16313"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16313, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16313.yaml"
    strings:
        $path0 = /\/action\/usermanager\.htm(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_16332_api_bearer_auth {
    meta:
        attack_type = "cve_2019_16332"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress API Bearer Auth <20190907 - Cross-Site Scripting: WordPress API Bearer Auth plugin before 20190907 contains a cross-site scripting vulnerability. The server parameter is not correctly filtered in swagger-config.yaml.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16332"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16332, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16332.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/api-bearer-auth\/swagger\/swagger-config\.yaml\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_16469_experience_manager {
    meta:
        attack_type = "cve_2019_16469"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Adobe Experience Manager - Expression Language Injection: Adobe Experience Manager versions 6.5, 6.4, 6.3, 6.2, 6.1, and 6.0 has an expression language injection vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16469"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16469, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16469.yaml"
    strings:
        $path0 = /\/mnt\/overlay\/dam\/gui\/content\/assets\/metadataeditor\.external\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_16525_checklist {
    meta:
        attack_type = "cve_2019_16525"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Checklist <1.1.9 - Cross-Site Scripting: WordPress Checklist plugin before 1.1.9 contains a cross-site scripting vulnerability. The fill parameter is not correctly filtered in the checklist-icon.php file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16525"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16525, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16525.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/checklist\/images\/checklist-icon\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_16662_rconfig {
    meta:
        attack_type = "cve_2019_16662"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "rConfig 3.9.2 - Remote Code Execution: rConfig 3.9.2 is susceptible to a remote code execution vulnerability. An attacker can directly execute system commands by sending a GET request to ajaxServerSettingsChk.php because the rootUname parameter is passed to the exec function."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16662"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16662, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16662.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/install\/lib\/ajaxHandlers\/ajaxServerSettingsChk\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_16920_dir_655_firmware {
    meta:
        attack_type = "cve_2019_16920"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "D-Link Routers - Remote Code Execution: D-Link products such as DIR-655C, DIR-866L, DIR-652, and DHP-1565 contain an unauthenticated remote code execution vulnerability. The issue occurs when the attacker sends an arbitrary input to a 'PingTest' device common gateway interface."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16920"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16920, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16920.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])html_response_page=login_pic\.asp(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_16931_visualizer {
    meta:
        attack_type = "cve_2019_16931"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Visualizer <3.3.1 - Cross-Site Scripting: WordPress Visualizer plugin before 3.3.1 contains a stored cross-site scripting vulnerability via /wp-json/visualizer/v1/update-chart WP-JSON API endpoint. An unauthenticated attacker can execute arbitrary JavaScript when an."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16931"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16931, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16931.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-json\/visualizer\/v1\/update-chart(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_16932_visualizer {
    meta:
        attack_type = "cve_2019_16932"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Visualizer <3.3.1 - Blind Server-Side Request Forgery: Visualizer prior to 3.3.1 suffers from a blind server-side request forgery vulnerability via the /wp-json/visualizer/v1/upload-data endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16932"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16932, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16932.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/wp-json\/visualizer\/v1\/upload-data(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_16996_metinfo {
    meta:
        attack_type = "cve_2019_16996"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Metinfo 7.0.0 beta - SQL Injection: Metinfo 7.0.0 beta is susceptible to SQL Injection in app/system/product/admin/product_admin.class.php via the admin/?n=product&c=product_admin&a=dopara&app_type=shop id parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16996"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16996, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16996.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])c=product_admin(&|$)/ nocase
        $param1 = /(^|[?&;])app_type=shop(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_16997_metinfo {
    meta:
        attack_type = "cve_2019_16997"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Metinfo 7.0.0 beta - SQL Injection: Metinfo 7.0.0 beta is susceptible to SQL Injection in app/system/language/admin/language_general.class.php via the admin/?n=language&c=language_general&a=doExportPack appno parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-16997"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-16997, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-16997.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])a=doExportPack(&|$)/ nocase
        $param1 = /(^|[?&;])appno=1 union SELECT 98989\*443131,1(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_17232_ultimate_faq {
    meta:
        attack_type = "cve_2019_17232"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Ultimate FAQs <= 1.8.24 Unauthenticated Options Import and Export: Functions/EWD_UFAQ_Import.php in the ultimate-faqs plugin through 1.8.24 for WordPress allows unauthenticated options import."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-17232"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-17232, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-17232.yaml"
    strings:
        $param0 = /(^|[?&;])Action=EWD_UFAQ_ExportToSpreadsheet(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_17270_yachtcontrol {
    meta:
        attack_type = "cve_2019_17270"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Yachtcontrol Webapplication 1.0 - Remote Command Injection: Yachtcontrol Webapplication 1.0 makes it possible to perform direct operating system commands as an unauthenticated user via the '/pages/systemcall.php?command={COMMAND}' page and parameter, where {COMMAND} will be."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-17270"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-17270, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-17270.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/pages\/systemcall\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_17418_metinfo {
    meta:
        attack_type = "cve_2019_17418"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MetInfo 7.0.0 beta - SQL Injection: MetInfo 7.0.0 beta is susceptible to SQL injection via the admin/?n=language&c=language_general&a=doSearchParameter appno parameter (a different issue than CVE-2019-16997)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-17418"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-17418, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-17418.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])a=doSearchParameter(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_17503_dynamic_resource_scheduling {
    meta:
        attack_type = "cve_2019_17503"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Kirona Dynamic Resource Scheduler - Information Disclosure: Kirona Dynamic Resource Scheduler is susceptible to information disclosure. An unauthenticated user can directly access /osm/REGISTER.cmd (aka /osm_tiles/REGISTER.cmd), which contains sensitive information with exposed."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-17503"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-17503, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-17503.yaml"
    strings:
        $path0 = /\/osm_tiles\/REGISTER\.cmd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_17538_jiangnan_online_judge {
    meta:
        attack_type = "cve_2019_17538"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jiangnan Online Judge 0.8.0 - Local File Inclusion: Jiangnan Online Judge (aka jnoj) 0.8.0 is susceptible to local file inclusion via web/polygon/problem/viewfile?id=1&name=../."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-17538"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-17538, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-17538.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/jnoj\/web\/polygon\/problem\/viewfile(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_17558_solr {
    meta:
        attack_type = "cve_2019_17558"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Apache Solr <=8.3.1 - Remote Code Execution: Apache Solr versions 5.0.0 to 8.3.1 are vulnerable to remote code execution vulnerabilities through the VelocityResponseWriter. A Velocity template can be provided through Velocity templates in a configset `velocity/ directory or as."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-17558"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-17558, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-17558.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])v\.template=custom(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_17574_popup_maker {
    meta:
        attack_type = "cve_2019_17574"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Popup-Maker < 1.8.12 - Broken Authentication: An issue was discovered in the Popup Maker plugin before 1.8.13 for WordPress. An unauthenticated attacker can partially control the arguments of the do_action function to invoke certain popmake_ or pum_ methods, as demonstrated by."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-17574"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-17574, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-17574.yaml"
    strings:
        $param0 = /(^|[?&;])pum_action=tools_page_tab_system_info(&|$)/ nocase
        $param1 = /(^|[?&;])popmake_action=popup_sysinfo(&|$)/ nocase
        $param2 = /(^|[?&;])popmake-sysinfo=CVE-2019-17574(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_17662_thinvnc {
    meta:
        attack_type = "cve_2019_17662"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ThinVNC 1.0b1 - Authentication Bypass: ThinVNC 1.0b1 is vulnerable to arbitrary file read, which leads to a compromise of the VNC server. The vulnerability exists even when authentication is turned on during the deployment of the VNC server. The password for authentication is."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-17662"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-17662, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-17662.yaml"
    strings:
        $path0 = /\/\.\.\/\.\.\/ThinVnc\.ini(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_1821_evolved_programmable_network_m {
    meta:
        attack_type = "cve_2019_1821"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cisco Prime Infrastructure and Cisco Evolved Programmable Network Manager - Remote Code Execution: Cisco Prime Infrastructure (PI) and Cisco Evolved Programmable Network (EPN) Manager could allow an authenticated, remote attacker to execute code with root-level privileges on."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-1821"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-1821, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-1821.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/servlet\/UploadServlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_18371_millet_router_3g_firmware {
    meta:
        attack_type = "cve_2019_18371"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Xiaomi Mi WiFi R3G Routers - Local file Inclusion: Xiaomi Mi WiFi R3G devices before 2.28.23-stable are susceptible to local file inclusion vulnerabilities via a misconfigured NGINX alias, as demonstrated by api-third-party/download/extdisks../etc/config/account. With this."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-18371"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-18371, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-18371.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/api-third-party\/download\/extdisks\.\.\/etc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_18394_openfire {
    meta:
        attack_type = "cve_2019_18394"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ignite Realtime Openfire <=4.4.2 - Server-Side Request Forgery: Ignite Realtime Openfire through version 4.4.2 allows attackers to send arbitrary HTTP GET requests in FaviconServlet.java, resulting in server-side request forgery."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-18394"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-18394, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-18394.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/getFavicon(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_18665_domos {
    meta:
        attack_type = "cve_2019_18665"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "DOMOS 5.5 - Local File Inclusion: SECUDOS DOMOS before 5.6 allows local file inclusion via the log module."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-18665"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-18665, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-18665.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/page\/sl_logdl(\/|;|$)/ nocase
        $param0 = /(^|[?&;])dcfct=DCMlog\.download_log(&|$)/ nocase
        $param1 = /(^|[?&;])dbkey:syslog\.rlog=\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_18818_strapi {
    meta:
        attack_type = "cve_2019_18818"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "strapi CMS <3.0.0-beta.17.5 - Admin Password Reset: strapi CMS before 3.0.0-beta.17.5 allows admin password resets because it mishandles password resets within packages/strapi-admin/controllers/Auth.js and packages/strapi-plugin-users-permissions/controllers/Auth.js."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-18818"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-18818, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-18818.yaml"
    strings:
        $path0 = /\/admin\/auth\/reset-password(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_18957_microstrategy_library {
    meta:
        attack_type = "cve_2019_18957"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MicroStrategy Library <11.1.3 - Cross-Site Scripting: MicroStrategy Library before 11.1.3 contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-18957"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-18957, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-18957.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/MicroStrategyLibrary\/auth\/ui\/loginPage(\/|;|$)/ nocase
        $param0 = /(^|[?&;])loginMode=alert\(document\.domain\)(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_1898_rv110w_firmware {
    meta:
        attack_type = "cve_2019_1898"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Cisco RV110W RV130W RV215W Router - Information leakage: A vulnerability in the web-based management interface of Cisco RV110W, RV130W, and RV215W Routers could allow an unauthenticated, remote attacker to access the syslog file on an affected device. The vulnerability is due."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-1898"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-1898, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-1898.yaml"
    strings:
        $path0 = /\/_syslog\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_19134_hero_maps_premium {
    meta:
        attack_type = "cve_2019_19134"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Hero Maps Premium <=2.2.1 - Cross-Site Scripting: WordPress Hero Maps Premium plugin 2.2.1 and prior contains an unauthenticated reflected cross-site scripting vulnerability via the views/dashboard/index.php p parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-19134"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-19134, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-19134.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/hmapsprem\/views\/dashboard\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_19411_usg9500 {
    meta:
        attack_type = "cve_2019_19411"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Huawei Firewall - Local File Inclusion: USG9500 with versions of V500R001C30SPC100, V500R001C30SPC200, V500R001C30SPC600, V500R001C60SPC500, V500R005C00SPC100, V500R005C00SPC200 have an information leakage vulnerability. Due to improper processing of the initialization vector."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-19411"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-19411, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-19411.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/umweb\/\.\.\/etc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_19824_a3002ru_firmware {
    meta:
        attack_type = "cve_2019_19824"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "TOTOLINK Realtek SD Routers - Remote Command Injection: TOTOLINK Realtek SDK based routers may allow an authenticated attacker to execute arbitrary OS commands via the sysCmd parameter to the boafrm/formSysCmd URI, even if the GUI (syscmd.htm) is not available. This allows for."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-19824"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-19824, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-19824.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])submit-url=\/syscmd\.htm(&|$)/ nocase
        $param1 = /(^|[?&;])save_apply=Run Command(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_19825_totolink_router {
    meta:
        attack_type = "cve_2019_19825"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TOTOLINK/Realtek Routers - CAPTCHA Bypass: On certain TOTOLINK Realtek SDK based routers, the CAPTCHA text can be retrieved via a POST request to the boafrm/formLogin URI with the JSON payload {'topicurl':'setting/getSanvas'}. This allows an unauthenticated attacker to bypass."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-19825"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-19825, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-19825.yaml"
    strings:
        $path0 = /\/boafrm\/formLogin(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_19908_phpmychat_plus {
    meta:
        attack_type = "cve_2019_19908"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "phpMyChat-Plus 1.98 - Cross-Site Scripting: phpMyChat-Plus 1.98 contains a cross-site scripting vulnerability via pmc_username parameter of pass_reset.php in password reset URL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-19908"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-19908, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-19908.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/plus\/pass_reset\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_20141_neon {
    meta:
        attack_type = "cve_2019_20141"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Laborator Neon Theme 2.0 - Cross-Site Scripting: WordPress Laborator Neon theme 2.0 contains a cross-site scripting vulnerability via the data/autosuggest-remote.php q parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-20141"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-20141, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-20141.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/data\/autosuggest-remote\.php(\/|;|$)/ nocase
        $path1 = /\/admin\/data\/autosuggest-remote\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_20224_pandora_fms {
    meta:
        attack_type = "cve_2019_20224"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Pandora FMS 7.0NG - Remote Command Injection: Pandora FMS 7.0NG allows remote authenticated users to execute arbitrary OS commands via shell metacharacters in the ip_src parameter in an index.php?operation/netflow/nf_live_view request."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-20224"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-20224, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-20224.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/pandora_console\/index\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])sec2=operation\/netflow\/nf_live_view(&|$)/ nocase
        $param1 = /(^|[?&;])chart_type=netflow_area(&|$)/ nocase
        $param2 = /(^|[?&;])draw_button=Draw(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_20504_kace_systems_management {
    meta:
        attack_type = "cve_2019_20504"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dell KACE Systems Management Appliance (K1000) 6.4.120756 - Remote Code Execution: service/krashrpt.php in Quest KACE K1000 Systems Management Appliance before 6.4 SP3 (6.4.120822) allows a remote attacker to execute code via shell metacharacters in the kuid parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-20504"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-20504, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-20504.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/service\/krashrpt\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_20933_influxdb {
    meta:
        attack_type = "cve_2019_20933"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "InfluxDB <1.7.6 - Authentication Bypass: InfluxDB before 1.7.6 contains an authentication bypass vulnerability via the authenticate function in services/httpd/handler.go. A JWT token may have an empty SharedSecret (aka shared secret). An attacker can possibly obtain sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-20933"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-20933, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-20933.yaml"
    strings:
        $param0 = /(^|[?&;])q=SHOW DATABASES(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_25213_wordpress_advanced_access_mana {
    meta:
        attack_type = "cve_2019_25213"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Advanced Access Manager - Path Traversal: The Advanced Access Manager plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Read in versions up to, and including, 5.9.8.1 due to insufficient validation on the aam-media parameter. This allows."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-25213"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-25213, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-25213.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])aam-media=\/wp-config\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_25246_n100_h_264_vga_ip_camera {
    meta:
        attack_type = "cve_2019_25246"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "BEWARD N100 H.264 VGA IP Camera M2.1.6 - Arbitrary File Disclosure: Beward N100 H.264 VGA IP Camera M2.1.6 contains an authenticated file disclosure vulnerability caused by improper validation of the 'READ.filePath' parameter in fileread script and SendCGICMD API, letting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-25246"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-25246, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-25246.yaml"
    strings:
        $path0 = /\/cgi-bin\/operator\/fileread(\/|;|$)/ nocase
        $param0 = /(^|[?&;])READ\.filePath=\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_2578_webcenter_sites {
    meta:
        attack_type = "cve_2019_2578"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Oracle Fusion Middleware WebCenter Sites 12.2.1.3.0 - Broken Access Control: Oracle Fusion Middleware WebCenter Sites 12.2.1.3.0 suffers from broken access control. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-2578"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2578, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-2578.yaml"
    strings:
        $param0 = /(^|[?&;])pagename=OpenMarket\/Xcelerate\/Admin\/Slots(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_2579_webcenter_sites {
    meta:
        attack_type = "cve_2019_2579"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Oracle Fusion Middleware WebCenter Sites 12.2.1.3.0 - SQL Injection: The Oracle WebCenter Sites component of Oracle Fusion Middleware 12.2.1.3.0 is susceptible to SQL injection via an easily exploitable vulnerability that allows low privileged attackers with network access via."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-2579"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2579, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-2579.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/cs\/ContentServer(\/|;|$)/ nocase
        $param0 = /(^|[?&;])searchChoice=webroot(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_2588_business_intelligence_publishe {
    meta:
        attack_type = "cve_2019_2588"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Oracle Business Intelligence - Path Traversal: Oracle Business Intelligence versions 11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0 are vulnerable to path traversal in the BI Publisher (formerly XML Publisher) component of Oracle Fusion Middleware (subcomponent: BI Publisher Security)."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-2588"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2588, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-2588.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/xmlpserver\/servlet\/adfresource(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_2616_business_intelligence_publishe {
    meta:
        attack_type = "cve_2019_2616"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Oracle Business Intelligence/XML Publisher - XML External Entity Injection: Oracle Business Intelligence and XML Publisher 11.1.1.9.0 / 12.2.1.3.0 / 12.2.1.4.0 are vulnerable to an XML external entity injection attack."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-2616"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2616, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-2616.yaml"
    strings:
        $path0 = /\/xmlpserver\/ReportTemplateService\.xls(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_2729_communications_diameter_signal {
    meta:
        attack_type = "cve_2019_2729"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Oracle WebLogic Server Administration Console - Remote Code Execution: The Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services) versions 0.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0 contain an easily exploitable vulnerability that allows."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-2729"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2729, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-2729.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/wls-wsat\/CoordinatorPortType(\/|;|$)/ nocase
        $path1 = /\/_async\/AsyncResponseService(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_2767_bi_publisher {
    meta:
        attack_type = "cve_2019_2767"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Oracle Business Intelligence Publisher - XML External Entity Injection: Oracle Business Intelligence Publisher is vulnerable to an XML external entity injection attack. The supported versions affected are 11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0. This easily exploitable."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-2767"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-2767, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-2767.yaml"
    strings:
        $path0 = /\/xmlpserver\/convert(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_3398_confluence {
    meta:
        attack_type = "cve_2019_3398"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Atlassian Confluence Download Attachments - Remote Code Execution: Confluence Server and Data Center had a path traversal vulnerability in the downloadallattachments resource. A remote attacker who has permission to add attachments to pages and / or blogs or to create a new."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-3398"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3398, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-3398.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/pages\/createpage\.action(\/|;|$)/ nocase
        $path1 = /\/pages\/downloadallattachments\.action(\/|;|$)/ nocase
        $param0 = /(^|[?&;])mimeType=text\/plain(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_3401_jira {
    meta:
        attack_type = "cve_2019_3401"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Atlassian Jira <7.13.3/8.0.0-8.1.1 - Incorrect Authorization: Atlasssian Jira before version 7.13.3 and from version 8.0.0 before version 8.1.1 is susceptible to incorrect authorization. The ManageFilters.jspa resource allows a remote attacker to enumerate usernames via an."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-3401"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3401, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-3401.yaml"
    strings:
        $path0 = /\/secure\/ManageFilters\.jspa(\/|;|$)/ nocase
        $param0 = /(^|[?&;])filter=popular(&|$)/ nocase
        $param1 = /(^|[?&;])filterView=popular(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_3402_jira {
    meta:
        attack_type = "cve_2019_3402"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jira < 8.1.1 - Cross-Site Scripting: Jira before 8.1.1 contains a cross-site scripting vulnerability via ConfigurePortalPages.jspa resource in the searchOwnerUserName parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-3402"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3402, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-3402.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/secure\/ConfigurePortalPages!default\.jspa(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_3403_jira {
    meta:
        attack_type = "cve_2019_3403"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jira - Incorrect Authorization: Jira before version 7.13.3, from version 8.0.0 before version 8.0.4, and from version 8.1.0 before version 8.1.1 is susceptible to an incorrect authorization check in the /rest/api/2/user/picker rest resource, enabling an attacker to enumerate."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-3403"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3403, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-3403.yaml"
    strings:
        $path0 = /\/rest\/api\/2\/user\/picker(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_3799_spring_cloud_config {
    meta:
        attack_type = "cve_2019_3799"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Spring Cloud Config Server - Local File Inclusion: Spring Cloud Config Server versions 2.1.x prior to 2.1.2, 2.0.x prior to 2.0.4, 1.4.x prior to 1.4.6, and older unsupported versions are vulnerable to local file inclusion because they allow applications to serve arbitrary."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-3799"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3799, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-3799.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/test\/pathtraversal\/master\/\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.\/etc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_3911_labkey_server {
    meta:
        attack_type = "cve_2019_3911"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LabKey Server Community Edition <18.3.0 - Cross-Site Scripting: LabKey Server Community Edition before 18.3.0-61806.763 contains a reflected cross-site scripting vulnerability via the onerror parameter in the /__r2/query endpoints, which allows an unauthenticated remote."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-3911"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3911, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-3911.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/__r2\/query-printRows\.view(\/|;|$)/ nocase
        $param0 = /(^|[?&;])schemaName=ListManager(&|$)/ nocase
        $param1 = /(^|[?&;])query\.queryName=ListManager(&|$)/ nocase
        $param2 = /(^|[?&;])query\.containerFilterName=CurrentAndSubfolders(&|$)/ nocase
        $param3 = /(^|[?&;])query\.selectionKey=\$ListManager\$ListManager\$\$query(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_3912_labkey_server {
    meta:
        attack_type = "cve_2019_3912"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LabKey Server Community Edition <18.3.0 - Open Redirect: LabKey Server Community Edition before 18.3.0-61806.763 contains an open redirect vulnerability via the /__r1/ returnURL parameter, which allows an attacker to redirect a user to a malicious site and possibly obtain."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-3912"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3912, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-3912.yaml"
    strings:
        $path0 = /\/labkey\/__r1\/login-login\.view(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_3929_am_100_firmware {
    meta:
        attack_type = "cve_2019_3929"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Barco/AWIND OEM Presentation Platform - Remote Command Injection: The Crestron AM-100 firmware 1.6.0.2, Crestron AM-101 firmware 2.7.0.1, Barco wePresent WiPG-1000P firmware 2.3.0.10, Barco wePresent WiPG-1600W before firmware 2.4.1.19, Extron ShareLink 200/250 firmware."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-3929"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-3929, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-3929.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cgi-bin\/file_transfer\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_4061_bigfix_platform {
    meta:
        attack_type = "cve_2019_4061"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "IBM BigFix Platform - Information Disclosure: IBM BigFix Platform 9.2 and 9.5 contains an information disclosure vulnerability caused by not enabling authenticated access in relay, letting remote attackers query and gather update and fixlet information, exploit requires no."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-4061"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-4061, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-4061.yaml"
    strings:
        $path0 = /\/masthead\/masthead\.axfm(\/|;|$)/ nocase
        $path1 = /\/cgi-bin\/bfenterprise\/clientregister\.exe(\/|;|$)/ nocase
        $param0 = /(^|[?&;])RequestType=FetchCommands(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_5127_youphptube_encoder {
    meta:
        attack_type = "cve_2019_5127"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "YouPHPTube Encoder 2.3 - Remote Command Injection: YouPHPTube Encoder 2.3 is susceptible to a command injection vulnerability which could allow an attacker to compromise the server. These exploitable unauthenticated command injections exist via the parameter base64Url in."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-5127"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-5127, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-5127.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/objects\/getImage\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_5434_revive_adserver {
    meta:
        attack_type = "cve_2019_5434"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Revive Adserver 4.2 - Remote Code Execution: Revive Adserver 4.2 is susceptible to remote code execution. An attacker can send a crafted payload to the XML-RPC invocation script and trigger the unserialize() call on the 'what' parameter in the 'openads.spc' RPC method. This can."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-5434"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-5434, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-5434.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/adxmlrpc\.php(\/|;|$)/ nocase
        $path1 = /\/plugins\/3rdPartyServers\/ox3rdPartyServers\/max\.class\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_6340_drupal {
    meta:
        attack_type = "cve_2019_6340"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Drupal - Remote Code Execution: Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10 V contain certain field types that do not properly sanitize data from non-form sources, which can lead to arbitrary PHP code execution in some cases."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-6340"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-6340, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-6340.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])_format=hal_json(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_6715_w3_total_cache {
    meta:
        attack_type = "cve_2019_6715"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "W3 Total Cache 0.9.2.6-0.9.3 - Unauthenticated File Read / Directory Traversal: WordPress plugin W3 Total Cache before version 0.9.4 allows remote attackers to read arbitrary files via the SubscribeURL field in SubscriptionConfirmation JSON data via pub/sns.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-6715"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-6715, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-6715.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/wp-content\/plugins\/w3-total-cache\/pub\/sns\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_6793_gitlab {
    meta:
        attack_type = "cve_2019_6793"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GitLab Enterprise Edition - Server-Side Request Forgery: An issue was discovered in GitLab Enterprise Edition before 11.5.8, 11.6.x before 11.6.6, and 11.7.x before 11.7.1. The Jira integration feature is vulnerable to an unauthenticated blind SSRF issue."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-6793"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-6793, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-6793.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/-\/jira\/login\/oauth\/access_token(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_7139_magento {
    meta:
        attack_type = "cve_2019_7139"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Magento - SQL Injection: An unauthenticated user can execute SQL statements that allow arbitrary read access to the underlying database, which causes sensitive data leakage."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-7139"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7139, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-7139.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/catalog\/product_frontend_action\/synchronize(\/|;|$)/ nocase
        $param0 = /(^|[?&;])type_id=recently_products(&|$)/ nocase
        $param1 = /(^|[?&;])ids\[0\]\[product_id\]\[to\]=\)\)\) OR \(SELECT 1 UNION SELECT 2 FROM DUAL WHERE 1=0\) -- -(&|$)/ nocase
        $param2 = /(^|[?&;])ids\[0\]\[product_id\]\[to\]=\)\)\) OR \(SELECT 1 UNION SELECT 2 FROM DUAL WHERE 1=1\) -- -(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_7194_photo_station {
    meta:
        attack_type = "cve_2019_7194"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "QNAP Photo Station < 6.0.3 - Remote Code Execution: QNAP Photo Station versions prior to 6.0.3 contain multiple vulnerabilities that, when chained together, enable unauthenticated remote code execution (RCE)."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-7194"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7194, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-7194.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/cgi-bin\/authLogin\.cgi(\/|;|$)/ nocase
        $path1 = /\/cgi-bin\/userConfig\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])filename=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/share\/Multimedia\/\.@__thumb\/ps\.app\.token(&|$)/ nocase
        $param1 = /(^|[?&;])app=PHOTO_STATION(&|$)/ nocase
        $param2 = /(^|[?&;])album=qsamplealbum(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_7254_linear_emerge_essential_firmwa {
    meta:
        attack_type = "cve_2019_7254"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "eMerge E3 1.00-06 - Local File Inclusion: Linear eMerge E3-Series devices are vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-7254"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7254, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-7254.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/badging\/badge_print_v0\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_7275_enterprise {
    meta:
        attack_type = "cve_2019_7275"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Optergy Proton/Enterprise Building Management System - Open Redirect: Optergy Proton/Enterprise Building Management System contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-7275"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7275, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-7275.yaml"
    strings:
        $path0 = /\/updating\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_7276_enterprise_proton {
    meta:
        attack_type = "cve_2019_7276"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Optergy Proton/Enterprise - Unauthenticated RCE via Backdoor Console: Optergy Proton/Enterprise devices allow Remote Root Code Execution via a Backdoor Console."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-7276"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7276, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-7276.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/tools\/ajax\/ConsoleResult\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_7481_sma_100_firmware {
    meta:
        attack_type = "cve_2019_7481"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "SonicWall SRA 4600 VPN - SQL Injection: The SonicWall SRA 4600 VPN appliance is susceptible to a pre-authentication SQL injection vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-7481"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7481, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-7481.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/cgi-bin\/supportInstaller(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_7543_kindeditor {
    meta:
        attack_type = "cve_2019_7543"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "KindEditor 4.1.11 - Cross-Site Scripting: KindEditor 4.1.11 contains a cross-site scripting vulnerability via the php/demo.php content1 parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-7543"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7543, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-7543.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/kindeditor\/php\/demo\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_7609_kibana {
    meta:
        attack_type = "cve_2019_7609"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Kibana Timelion - Arbitrary Code Execution: Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-7609"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-7609, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-7609.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/timelion\/run(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_8086_experience_manager {
    meta:
        attack_type = "cve_2019_8086"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Adobe Experience Manager - XML External Entity Injection: Adobe Experience Manager 6.5, 6.4, 6.3 and 6.2 are susceptible to XML external entity injection. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-8086"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8086, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-8086.yaml"
    strings:
        $param0 = /(^|[?&;])sling:resourceType=fd\/af\/components\/guideContainer(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_8442_jira {
    meta:
        attack_type = "cve_2019_8442"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jira - Local File Inclusion: Jira before version 7.13.4, from version 8.0.0 before version 8.0.4, and from version 8.1.0 before version 8.1.1, allows remote attackers to access files in the Jira webroot under the META-INF directory via local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-8442"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8442, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-8442.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/_\/WEB-INF\/classes\/META-INF\/maven\/com\.atlassian\.jira\/jira-core\/pom\.xml(\/|;|$)/ nocase
        $path1 = /\/_\/META-INF\/maven\/com\.atlassian\.jira\/atlassian-jira-webapp\/pom\.xml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_8446_jira_server {
    meta:
        attack_type = "cve_2019_8446"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jira Improper Authorization: The /rest/issueNav/1/issueTable resource in Jira before version 8.3.2 allows remote attackers to enumerate usernames via an incorrect authorisation check."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-8446"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8446, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-8446.yaml"
    strings:
        $path0 = /\/rest\/issueNav\/1\/issueTable(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_8449_jira {
    meta:
        attack_type = "cve_2019_8449"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jira <8.4.0 - Information Disclosure: Jira before 8.4.0 is susceptible to information disclosure. The /rest/api/latest/groupuserpicker resource can allow an attacker to enumerate usernames, and thereby potentially obtain sensitive information, modify data, and/or execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-8449"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8449, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-8449.yaml"
    strings:
        $path0 = /\/rest\/api\/latest\/groupuserpicker(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_8451_jira_server {
    meta:
        attack_type = "cve_2019_8451"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jira <8.4.0 - Server-Side Request Forgery: Jira before 8.4.0 is susceptible to server-side request forgery. The /plugins/servlet/gadgets/makeRequest resource contains a logic bug in the JiraWhitelist class, which can allow an attacker to access the content of internal network."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-8451"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8451, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-8451.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/plugins\/servlet\/gadgets\/makeRequest(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_8937_hoteldruid {
    meta:
        attack_type = "cve_2019_8937"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "HotelDruid 2.3.0 - Cross-Site Scripting: HotelDruid 2.3.0 contains a cross-site scripting vulnerability affecting nsextt, cambia1, mese_fine, origine, and anno parameters in creaprezzi.php, tabella3.php, personalizza.php, and visualizza_tabelle.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-8937"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8937, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-8937.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/hoteldruid\/visualizza_tabelle\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_8943_wordpress {
    meta:
        attack_type = "cve_2019_8943"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Core 5.0.0 - Crop-image Shell Upload: WordPress through 5.0.3 allows Path Traversal in wp_crop_image(). An attacker (who has privileges to crop an image) can write the output image to an arbitrary directory via a filename containing two image extensions and ../."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-8943"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8943, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-8943.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])action=query-attachments(&|$)/ nocase
        $param1 = /(^|[?&;])query\[orderby\]=date(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_8982_wavemarker_studio {
    meta:
        attack_type = "cve_2019_8982"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Wavemaker Studio 6.6 - Local File Inclusion/Server-Side Request Forgery: WaveMaker Studio 6.6 mishandles the studioService.download?method=getContent&inUrl= value in com/wavemaker/studio/StudioService.java, leading to disclosure of local files and server-side request forgery."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-8982"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-8982, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-8982.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wavemaker\/studioService\.download(\/|;|$)/ nocase
        $param0 = /(^|[?&;])method=getContent(&|$)/ nocase
        $param1 = /(^|[?&;])inUrl=file\/\/\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_9618_gracemedia_media_player {
    meta:
        attack_type = "cve_2019_9618"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress GraceMedia Media Player 1.0 - Local File Inclusion: WordPress GraceMedia Media Player plugin 1.0 is susceptible to local file inclusion via the cfg parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-9618"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9618, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-9618.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/gracemedia-media-player\/templates\/files\/ajax_controller\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])ajaxAction=getIds(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_9632_electronic_document_security_m {
    meta:
        attack_type = "cve_2019_9632"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ESAFENET CDG - Arbitrary File Download: ESAFENET CDG V3 and V5 has an arbitrary file download vulnerability via the fileName parameter in download.jsp because the InstallationPack parameter is mishandled in a /CDGServer3/ClientAjax request."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-9632"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9632, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-9632.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/CDGServer3\/ClientAjax(\/|;|$)/ nocase
        $param0 = /(^|[?&;])command=downclientpak(&|$)/ nocase
        $param1 = /(^|[?&;])InstallationPack=\.\.\/WEB-INF\/web\.xml(&|$)/ nocase
        $param2 = /(^|[?&;])forward=index\.jsp(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2019_9733_artifactory {
    meta:
        attack_type = "cve_2019_9733"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JFrog Artifactory 6.7.3 - Admin Login Bypass: JFrog Artifactory 6.7.3 is vulnerable to an admin login bypass issue because by default the access-admin account is used to reset the password of the admin account. While this is only allowable from a connection directly from."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-9733"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9733, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-9733.yaml"
    strings:
        $path0 = /\/artifactory\/ui\/auth\/login(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_9757_labkey_server {
    meta:
        attack_type = "cve_2019_9757"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LabKey Server 19.1.0 - XML External Entity (XXE): An issue was discovered in LabKey Server 19.1.0. Sending an SVG containing an XXE payload to the endpoint visualization-exportImage.view or visualization-exportPDF.view allows local files to be read."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-9757"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9757, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-9757.yaml"
    strings:
        $path0 = /\/labkey\/home\/project-begin\.view(\/|;|$)/ nocase
        $path1 = /\/home\/login-loginApi\.api(\/|;|$)/ nocase
        $path2 = /\/labkey\/home\/visualization-exportPDF\.view(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_9762_phpshe {
    meta:
        attack_type = "cve_2019_9762"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PHPSHE 1.7 - SQL Injection: A SQL Injection was discovered in PHPSHE 1.7 in include/plugin/payment/alipay/pay.php with the parameter id. The vulnerability does not need any authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-9762"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9762, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-9762.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/include\/plugin\/payment\/alipay\/pay\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_9874_experience_platform {
    meta:
        attack_type = "cve_2019_9874"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Sitecore Experience Platform - Deserialization of Untrusted Data: Sitecore Experience Platform before 8.2 Update-7 and 9.0 before Update-2 is vulnerable to a remote code execution vulnerability (CVE-2019-9874). An attacker can exploit this issue to execute arbitrary code on the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-9874"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9874, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-9874.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/sitecore\/shell\/Applications\/Security\/CreateNewUser\/CreateNewUser\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2019_9922_je_messenger {
    meta:
        attack_type = "cve_2019_9922"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Harmis Messenger 1.2.2 - Local File Inclusion: Joomla! Harmis Messenger 1.2.2 is vulnerable to local file inclusion which could give an attacker read access to arbitrary files."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2019-9922"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2019-9922, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2019/CVE-2019-9922.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/index\.php\/component\/jemessenger\/box_details(\/|;|$)/ nocase
        $param0 = /(^|[?&;])dw_file=\.\.\/\.\.\/\.\.\/\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}
