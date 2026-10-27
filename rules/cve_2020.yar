// Baseline rules generated from public exploit and exposure checks in
// ProjectDiscovery nuclei-templates (MIT License,
// https://github.com/projectdiscovery/nuclei-templates). Each rule keys on the
// most specific request indicator of one check: a path, a static parameter or
// a vendor header that no other check and no benign request uses. Rules are
// confidence = "medium": a probe for the endpoint is a strong signal, but a
// rule cannot tell an exploit attempt from a scanner fingerprinting it.
// The `reference` field links the source check.

rule krawl_cve_2020_0618_sql_server {
    meta:
        attack_type = "cve_2020_0618"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Microsoft SQL Server Reporting Services - Remote Code Execution: Microsoft SQL Server Reporting Services is vulnerable to a remote code execution vulnerability because it incorrectly handles page requests."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-0618"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-0618, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-0618.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/ReportServer\/Pages\/ReportViewer\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_10148_orion_platform {
    meta:
        attack_type = "cve_2020_10148"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "SolarWinds Orion API - Auth Bypass: SolarWinds Orion API is vulnerable to an authentication bypass vulnerability that could allow a remote attacker to execute API commands. This vulnerability could allow a remote attacker to bypass authentication and execute API commands which."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-10148"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10148, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-10148.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/SWNetPerfMon\.db\.i18n\.ashx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_10199_nexus {
    meta:
        attack_type = "cve_2020_10199"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Sonatype Nexus Repository Manager 3 - Remote Code Execution: Sonatype Nexus Repository before 3.21.2 allows JavaEL Injection"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-10199"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10199, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-10199.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/service\/rest\/beta\/repositories\/bower\/group(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_10220_rconfig {
    meta:
        attack_type = "cve_2020_10220"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "rConfig 3.9 - SQL Injection: An issue was discovered in rConfig through 3.9.4. The web interface is prone to a SQL injection via the commands.inc.php searchColumn parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-10220"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10220, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-10220.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/commands\.inc\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])searchField=vuln(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_10257_themerex {
    meta:
        attack_type = "cve_2020_10257"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ThemeREX Addons - Remote Code Execution: ThemeREX Addons plugin before 2020-03-09 for WordPress contains an access control vulnerability in the /trx_addons/v2/get/sc_layout REST API endpoint, allowing any users to execute PHP functions because includes/plugin.rest-api.php calls."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-10257"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10257, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-10257.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/wp-json\/trx_addons\/v2\/get\/sc_layout(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_10532_watchguard_fireware_ad_helper {
    meta:
        attack_type = "cve_2020_10532"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WatchGuard Fireware AD Helper Component - Credentials Disclosure: WatchGuard Fireware Threat Detection and Response (TDR) service contains a credential-disclosure vulnerability in the AD Helper component that allows unauthenticated attackers to gain Active Directory credentials."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-10532"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10532, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-10532.yaml"
    strings:
        $path0 = /\/rest\/domains\/list(\/|;|$)/ nocase
        $param0 = /(^|[?&;])sortCol=fullyQualifiedName(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_10546_rconfig {
    meta:
        attack_type = "cve_2020_10546"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "rConfig 3.9.4 - SQL Injection: rConfig 3.9.4 and previous versions have unauthenticated compliancepolicies.inc.php SQL injection. Because nodes' passwords are stored in cleartext by default, this vulnerability leads to lateral movement, granting an attacker access to monitored."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-10546"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10546, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-10546.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/compliancepolicies\.inc\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])searchColumn=policyName(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_10547_rconfig {
    meta:
        attack_type = "cve_2020_10547"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "rConfig 3.9.4 - SQL Injection: rConfig 3.9.4 and previous versions has unauthenticated compliancepolicyelements.inc.php SQL injection. Because nodes' passwords are stored by default in cleartext, this vulnerability leads to lateral movement, granting an attacker access to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-10547"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10547, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-10547.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/compliancepolicyelements\.inc\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])searchColumn=elementName(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_10548_rconfig {
    meta:
        attack_type = "cve_2020_10548"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "rConfig 3.9.4 - SQL Injection: rConfig 3.9.4 and previous versions have unauthenticated devices.inc.php SQL injection. Because nodes' passwords are stored in cleartext by default, this vulnerability leads to lateral movement, granting an attacker access to monitored network."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-10548"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10548, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-10548.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/devices\.inc\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])searchColumn=n\.id(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_10549_rconfig {
    meta:
        attack_type = "cve_2020_10549"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "rConfig <=3.9.4 - SQL Injection: rConfig 3.9.4 and prior has unauthenticated snippets.inc.php SQL injection. Because nodes' passwords are stored in cleartext by default, this vulnerability leads to lateral movement, granting an attacker access to monitored network devices."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-10549"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10549, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-10549.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/snippets\.inc\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])searchColumn=snippetName(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_10770_keycloak {
    meta:
        attack_type = "cve_2020_10770"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Keycloak <= 12.0.1 - request_uri Blind Server-Side Request Forgery (SSRF): Keycloak 12.0.1 and below allows an attacker to force the server to request an unverified URL using the OIDC parameter request_uri. This allows an attacker to execute a server-side request forgery (SSRF)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-10770"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-10770, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-10770.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/auth\/realms\/master\/protocol\/openid-connect\/auth(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_11450_microstrategy_web {
    meta:
        attack_type = "cve_2020_11450"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MicroStrategy Web 10.4 - Information Disclosure: MicroStrategy Web 10.4 is susceptible to information disclosure. The JVM configuration, CPU architecture, installation folder, and other information are exposed through /MicroStrategyWS/happyaxis.jsp. An attacker can use this."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-11450"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11450, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-11450.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/MicroStrategyWS\/happyaxis\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_11455_limesurvey {
    meta:
        attack_type = "cve_2020_11455"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LimeSurvey 4.1.11 - Local File Inclusion: LimeSurvey before 4.1.12+200324 is vulnerable to local file inclusion because it contains a path traversal vulnerability in application/controllers/admin/LimeSurveyFileManager.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-11455"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11455, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-11455.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/index\.php\/admin\/filemanager\/sa\/getZipFile(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_11515_seo {
    meta:
        attack_type = "cve_2020_11515"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Rank Math SEO <= 1.0.40.2 - Redirect Creation via Unprotected REST API Endpoint: The Rank Math plugin through 1.0.40.2 for WordPress allows unauthenticated remote attackers to create new URIs (that redirect to an external web site) via the unsecured."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-11515"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11515, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-11515.yaml"
    strings:
        $path0 = /\/wp-json\/rankmath\/v1\/updateRedirection(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_11546_superwebmailer {
    meta:
        attack_type = "cve_2020_11546"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SuperWebmailer 7.21.0.01526 - Remote Code Execution: SuperWebMailer 7.21.0.01526 is susceptible to a remote code execution vulnerability in the Language parameter of mailingupgrade.php. An unauthenticated remote attacker can exploit this behavior to execute arbitrary PHP code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-11546"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11546, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-11546.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/mailingupgrade\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_11547_prtg_network_monitor {
    meta:
        attack_type = "cve_2020_11547"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PRTG Network Monitor <20.1.57.1745 - Information Disclosure: PRTG Network Monitor before 20.1.57.1745 is susceptible to information disclosure. An attacker can obtain information about probes running or the server itself via an HTTP request, thus potentially being able to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-11547"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11547, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-11547.yaml"
    strings:
        $param0 = /(^|[?&;])type=requests(&|$)/ nocase
        $param1 = /(^|[?&;])type=treestat(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_11732_media_library_assistant {
    meta:
        attack_type = "cve_2020_11732"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Media Library Assistant < 2.82 - Unauthenticated Limited Local File Inclusion: Media Library Assistant plugin for WordPress before 2.82 contains a local file inclusion caused by unsanitized mla_gallery link parameter, letting attackers include arbitrary local files, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-11732"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11732, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-11732.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/media-library-assistant\/includes\/mla-file-downloader\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])mla_download_type=text\/html(&|$)/ nocase
        $param1 = /(^|[?&;])mla_download_file=\/var\/www\/html\/wordpress\/wp-content\/index\.php(&|$)/ nocase
        $param2 = /(^|[?&;])mla_download_file=\/var\/www\/html\/wp-content\/index\.php(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_11798_micollab_audio_web_video_confe {
    meta:
        attack_type = "cve_2020_11798"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Mitel MiCollab AWV 8.1.2.4 and 9.1.3 - Directory Traversal: A Directory Traversal vulnerability in the web conference component of Mitel MiCollab AWV before 8.1.2.4 and 9.x before 9.1.3 could allow an attacker to access arbitrary files from restricted directories of the server."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-11798"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11798, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-11798.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/awcuser\/cgi-bin\/vcs_access_file\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_11978_airflow {
    meta:
        attack_type = "cve_2020_11978"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Apache Airflow <=1.10.10 - Remote Code Execution: Apache Airflow versions 1.10.10 and below are vulnerable to remote code/command injection vulnerabilities in one of the example DAGs shipped with Airflow. This could allow any authenticated user to run arbitrary commands as the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-11978"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11978, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-11978.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/experimental\/test(\/|;|$)/ nocase
        $path1 = /\/api\/experimental\/dags\/example_trigger_target_dag\/paused\/false(\/|;|$)/ nocase
        $path2 = /\/api\/experimental\/dags\/example_trigger_target_dag\/dag_runs(\/|;|$)/ nocase
        $path3 = "/api/experimental/dags/example_trigger_target_dag/dag_runs/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_11991_cocoon {
    meta:
        attack_type = "cve_2020_11991"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache Cocoon 2.1.12 - XML Injection: Apache Cocoon 2.1.12 contains an XML injection caused by parsing user-provided XML with external system entities in StreamGenerator, letting attackers access arbitrary files on the server, exploit requires sending malicious XML."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-11991"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-11991, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-11991.yaml"
    strings:
        $path0 = /\/samples\/process-order(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_12256_rconfig {
    meta:
        attack_type = "cve_2020_12256"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "rConfig 3.9.4 - Cross-Site Scripting: The rConfig 3.9.4 is vulnerable to cross-site scripting. The devicemgmnt.php file improperly validates the request coming from the user input. Due to this flaw, An attacker can exploit this vulnerability by crafting arbitrary javascript in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-12256"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-12256, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-12256.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/devicemgmt\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_12259_rconfig {
    meta:
        attack_type = "cve_2020_12259"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "rConfig 3.9.4 - Cross-Site Scripting: rConfig 3.9.4 is vulnerable to reflected XSS. The configDevice.php file improperly validates user input. An attacker can exploit this vulnerability by crafting arbitrary JavaScript in the rid GET parameter of devicemgmnt.php"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-12259"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-12259, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-12259.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/configDevice\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_12478_teampass {
    meta:
        attack_type = "cve_2020_12478"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "TeamPass 2.1.27.36 - Improper Authentication: TeamPass 2.1.27.36 is susceptible to improper authentication. An attacker can retrieve files from the TeamPass web root, which may include backups or LDAP debug files, and therefore possibly obtain sensitive information, modify."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-12478"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-12478, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-12478.yaml"
    strings:
        $path0 = /\/files\/ldap\.debug\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_12641_webmail {
    meta:
        attack_type = "cve_2020_12641"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Roundcube Webmail - Command Injection: Roundcube Webmail before 1.4.4 contains a command injection caused by shell metacharacters in configuration settings for im_convert_path or im_identify_path, letting attackers execute arbitrary code, exploit requires attacker to control."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-12641"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-12641, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-12641.yaml"
    strings:
        $path0 = /\/roundcube\/installer\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_12720_vbulletin {
    meta:
        attack_type = "cve_2020_12720"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "vBulletin SQL Injection: vBulletin before 5.5.6pl1, 5.6.0 before 5.6.0pl1, and 5.6.1 before 5.6.1pl1 has incorrect access control that permits SQL injection attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-12720"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-12720, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-12720.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/ajax\/api\/content_infraction\/getIndexableContent(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_13121_submitty {
    meta:
        attack_type = "cve_2020_13121"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Submitty <= 20.04.01 - Open Redirect: Submitty through 20.04.01 contains an open redirect vulnerability via authentication/login?old= during an invalid login attempt. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-13121"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13121, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-13121.yaml"
    strings:
        $path0 = /\/authentication\/check_login(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_13158_artica_proxy {
    meta:
        attack_type = "cve_2020_13158"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Artica Proxy Community Edition <4.30.000000 - Local File Inclusion: Artica Proxy Community Edition before 4.30.000000 is vulnerable to local file inclusion via the fw.progrss.details.php popup parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-13158"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13158, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-13158.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/fw\.progrss\.details\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])popup=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_13167_netsweeper {
    meta:
        attack_type = "cve_2020_13167"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Netsweeper <=6.4.3 - Python Code Injection: Netsweeper through 6.4.3 allows unauthenticated remote code execution because webadmin/tools/unixlogin.php (with certain Referer headers) launches a command line with client-supplied parameters, and allows injection of shell."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-13167"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13167, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-13167.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/webadmin\/tools\/unixlogin\.php(\/|;|$)/ nocase
        $path1 = /\/webadmin\/out(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_13483_bitrix24 {
    meta:
        attack_type = "cve_2020_13483"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Bitrix24 <=20.0.0 - Cross-Site Scripting: The Web Application Firewall in Bitrix24 up to and including 20.0.0 allows XSS via the items[ITEMS][ID] parameter to the components/bitrix/mobileapp.list/ajax.php/ URI."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-13483"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13483, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-13483.yaml"
        response_type = "xss"
    strings:
        $path0 = "/bitrix/components/bitrix/mobileapp.list/ajax.php/" ascii nocase
        $param0 = /(^|[?&;])items\[ITEMS\]\[TOGGLABLE\]=test123(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_13640_wpdiscuz {
    meta:
        attack_type = "cve_2020_13640"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "wpDiscuz <= 5.3.5 - SQL Injection: A SQL injection issue in the gVectors wpDiscuz plugin 5.3.5 and earlier for WordPress allows remote attackers to execute arbitrary SQL commands via the order parameter of a wpdLoadMoreComments request."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-13640"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13640, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-13640.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/wp-json\/wp\/v2\/comments(\/|;|$)/ nocase
        $path1 = /\/wp-content\/plugins\/wpdiscuz\/utils\/ajax\/wpdiscuz-ajax\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])action=wpdLoadMoreComments(&|$)/ nocase
        $param1 = /(^|[?&;])orderBy=comment_date_gmt(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_13700_acf_to_rest_api {
    meta:
        attack_type = "cve_2020_13700"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress acf-to-rest-api <=3.1.0 - Insecure Direct Object Reference: WordPress acf-to-rest-ap through 3.1.0 allows an insecure direct object reference via permalinks manipulation, as demonstrated by a wp-json/acf/v3/options/ request that can read sensitive information in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-13700"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13700, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-13700.yaml"
    strings:
        $path0 = "/wp-json/acf/v3/options/" ascii nocase
        $param0 = /(^|[?&;])field=plugins(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_13820_extreme_management_center {
    meta:
        attack_type = "cve_2020_13820"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Extreme Management Center 8.4.1.24 - Cross-Site Scripting: Extreme Management Center 8.4.1.24 contains a cross-site scripting vulnerability via a parameter in a GET request. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-13820"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13820, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-13820.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/OneView\/view\/center(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_13927_airflow {
    meta:
        attack_type = "cve_2020_13927"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Airflow Experimental <1.10.11 - REST API Auth Bypass: Airflow's Experimental API prior 1.10.11 allows all API requests without authentication."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-13927"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13927, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-13927.yaml"
    strings:
        $path0 = /\/api\/experimental\/latest_runs(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_13937_kylin {
    meta:
        attack_type = "cve_2020_13937"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apache Kylin - Exposed Configuration File: Apache Kylin 2.0.0, 2.1.0, 2.2.0, 2.3.0, 2.3.1, 2.3.2, 2.4.0, 2.4.1, 2.5.0, 2.5.1, 2.5.2, 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 3.0.0-alpha, 3.0.0-alpha2, 3.0.0-beta, 3.0.0, 3.0.1, 3.0.2, 3.1.0, 4.0.0-alpha have one REST API."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-13937"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13937, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-13937.yaml"
    strings:
        $path0 = /\/kylin\/api\/admin\/config(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_13945_apisix {
    meta:
        attack_type = "cve_2020_13945"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apache APISIX - Insufficiently Protected Credentials: Apache APISIX 1.2, 1.3, 1.4, and 1.5 is susceptible to insufficiently protected credentials. An attacker can enable the Admin API and delete the Admin API access IP restriction rules. Eventually, the default token is allowed."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-13945"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-13945, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-13945.yaml"
    strings:
        $path0 = /\/apisix\/admin\/routes(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_14092_paypal_pro {
    meta:
        attack_type = "cve_2020_14092"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress PayPal Pro <1.1.65 - SQL Injection: WordPress PayPal Pro plugin before 1.1.65 is susceptible to SQL injection via the 'query' parameter which allows for any unauthenticated user to perform SQL queries with the results output to a web page in JSON format."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-14092"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14092, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-14092.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])cffaction=get_data_from_database(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_14144_gitea {
    meta:
        attack_type = "cve_2020_14144"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Gitea 1.1.0 - 1.12.5 - Remote Code Execution: Gitea 1.1.0 through 1.12.5 is susceptible to authenticated remote code execution, via the git hook functionality, in customer environments where the documentation is not understood (e.g., one viewpoint is that the dangerousness of."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-14144"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14144, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-14144.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])default_branch=master(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_14179_jira_data_center {
    meta:
        attack_type = "cve_2020_14179"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Atlassian Jira Server/Data Center <8.5.8/8.6.0 - 8.11.1 - Information Disclosure: Atlassian Jira Server and Data Center before 8.5.8 and 8.6.0 through 8.11.1 are susceptible to information disclosure via the /secure/QueryComponent!Default.jspa endpoint. An attacker can view."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-14179"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14179, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-14179.yaml"
    strings:
        $path0 = /\/secure\/QueryComponent!Default\.jspa(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_14181_data_center {
    meta:
        attack_type = "cve_2020_14181"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jira Server and Data Center - Information Disclosure: Jira Server and Data Center is susceptible to information disclosure. An attacker can enumerate users via the /ViewUserHover.jspa endpoint and thus potentially access sensitive information, modify data, and/or execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-14181"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14181, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-14181.yaml"
    strings:
        $path0 = /\/secure\/ViewUserHover\.jspa(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_14413_nedi {
    meta:
        attack_type = "cve_2020_14413"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "NeDi 1.9C - Cross-Site Scripting: NeDi 1.9C is vulnerable to cross-site scripting because of an incorrect implementation of sanitize() in inc/libmisc.php. This function attempts to escape the SCRIPT tag from user-controllable values, but can be easily bypassed, as demonstrated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-14413"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14413, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-14413.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/Devices-Config\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_14750_fusion_middleware {
    meta:
        attack_type = "cve_2020_14750"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Oracle WebLogic Server - Remote Command Execution: Oracle WebLogic Server 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0 is susceptible to remote code execution. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-14750"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14750, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-14750.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])weblogic\.work\.WorkAdapter adapter=executeThread\.getCurrentWork\(\);(&|$)/ nocase
        $param1 = /(^|[?&;])Object obj=field\.get\(adapter\);(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_14864_business_intelligence {
    meta:
        attack_type = "cve_2020_14864"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Oracle Fusion - Directory Traversal/Local File Inclusion: Oracle Business Intelligence Enterprise Edition 5.5.0.0.0, 12.2.1.3.0, and 12.2.1.4.0 are vulnerable to local file inclusion vulnerabilities via 'getPreviewImage.'"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-14864"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-14864, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-14864.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/analytics\/saw\.dll(\/|;|$)/ nocase
        $param0 = /(^|[?&;])previewFilePath=\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_15227_application {
    meta:
        attack_type = "cve_2020_15227"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Nette Framework - Remote Code Execution: Nette Framework versions before 2.0.19, 2.1.13, 2.2.10, 2.3.14, 2.4.16, and 3.0.6 are vulnerable to a code injection attack via specially formed parameters being passed to a URL. Nette is a PHP/Composer MVC Framework."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-15227"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-15227, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-15227.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/nette.micro/" ascii nocase
        $param0 = /(^|[?&;])callback=phpcredits(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_15505_core {
    meta:
        attack_type = "cve_2020_15505"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "MobileIron Core & Connector <= v10.6 & Sentry <= v9.8 - Remote Code Execution: A remote code execution vulnerability in MobileIron Core & Connector versions 10.3.0.3 and earlier, 10.4.0.0, 10.4.0.1, 10.4.0.2, 10.4.0.3, 10.5.1.0, 10.5.2.0 and 10.6.0.0; and Sentry versions 9.7.2."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-15505"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-15505, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-15505.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/mifs\/\.;\/services\/LogService(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_15568_tos {
    meta:
        attack_type = "cve_2020_15568"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TerraMaster TOS <.1.29 - Remote Code Execution: TerraMaster TOS before 4.1.29 has invalid parameter checking that leads to code injection as root. This is a dynamic class method invocation vulnerability in include/exportUser.php, in which an attacker can trigger a call to the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-15568"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-15568, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-15568.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/include\/exportUser\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_15718_rosariosis {
    meta:
        attack_type = "cve_2020_15718"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "RosarioSIS 6.7.2 - Cross-Site Scripting: RosarioSIS version 6.7.2 and earlier contains a reflected cross-site scripting (XSS) vulnerability in the Preferences module. The 'tab' parameter in Modules.php is not properly sanitized, allowing an attacker to inject arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-15718"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-15718, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-15718.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])modname=Users\/Preferences\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_15920_eframework {
    meta:
        attack_type = "cve_2020_15920"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Mida eFramework <=2.9.0 - Remote Command Execution: Mida eFramework through 2.9.0 allows an attacker to achieve remote code execution with administrative (root) privileges. No authentication is required."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-15920"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-15920, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-15920.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/PDC\/ajaxreq\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])PARAM=127\.0\.0\.1 -c 0; cat \/etc\/passwd(&|$)/ nocase
        $param1 = /(^|[?&;])DIAGNOSIS=PING(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_16139_unified_ip_conference_station {
    meta:
        attack_type = "cve_2020_16139"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cisco Unified IP Conference Station 7937G - Denial-of-Service: Cisco Unified IP Conference Station 7937G 1-4-4-0 through 1-4-5-7 allows attackers to restart the device remotely via specially crafted packets that can cause a denial-of-service condition. Note: We cannot prove."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-16139"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-16139, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-16139.yaml"
    strings:
        $path0 = /\/localmenus\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_17453_api_manager {
    meta:
        attack_type = "cve_2020_17453"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WSO2 Carbon Management Console <=5.10 - Cross-Site Scripting: WSO2 Management Console through 5.10 is susceptible to reflected cross-site scripting which can be exploited by tampering a request parameter in Management Console. This can be performed in both authenticated and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-17453"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17453, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-17453.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])msgId=';alert\('document\.domain'\)\/\/(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_17456_slc_130 {
    meta:
        attack_type = "cve_2020_17456"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SEOWON INTECH SLC-130 & SLR-120S - Unauthenticated Remote Code Execution: SEOWON INTECH SLC-130 and SLR-120S devices allow remote code execution via the ipAddr parameter to the system_log.cgi page."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-17456"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17456, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-17456.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])traceMode=ping(&|$)/ nocase
        $param1 = /(^|[?&;])logarea=com\.cgi(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_17496_vbulletin {
    meta:
        attack_type = "cve_2020_17496"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "vBulletin 5.5.4 - 5.6.2- Remote Command Execution: vBulletin versions 5.5.4 through 5.6.2 allow remote command execution via crafted subWidgets data in an ajax/render/widget_tabbedcontainer_tab_panel request. NOTE: this issue exists because of an incomplete fix for."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-17496"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17496, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-17496.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/ajax\/render\/widget_tabbedcontainer_tab_panel(\/|;|$)/ nocase
        $param0 = /(^|[?&;])subWidgets\[0\]\[template\]=widget_php(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_17505_web_proxy {
    meta:
        attack_type = "cve_2020_17505"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Artica Web Proxy 4.30 - OS Command Injection: Artica Web Proxy 4.30 allows an authenticated remote attacker to inject commands via the service-cmds parameter in cyrus.php. These commands are executed with root privileges via service_cmds_peform."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-17505"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17505, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-17505.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cyrus\.index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_17518_flink {
    meta:
        attack_type = "cve_2020_17518"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache Flink 1.5.1 - Local File Inclusion: Apache Flink 1.5.1 is vulnerable to local file inclusion because of a REST handler that allows file uploads to an arbitrary location on the local file system through a maliciously modified HTTP HEADER."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-17518"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17518, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-17518.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/jobmanager\/logs\/\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2ftmp%2fpoc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_17519_flink {
    meta:
        attack_type = "cve_2020_17519"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Apache Flink - Local File Inclusion: Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager through the REST interface of the JobManager process (aka local file inclusion)."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-17519"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-17519, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-17519.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/jobmanager\/logs\/\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2fetc%2fpasswd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_19283_jeesns {
    meta:
        attack_type = "cve_2020_19283"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jeesns 1.4.2 - Cross-Site Scripting: Jeesns 1.4.2 is vulnerable to reflected cross-site scripting in the /newVersion component and allows attackers to execute arbitrary web scripts or HTML."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-19283"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-19283, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-19283.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/newVersion(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_19360_fhem {
    meta:
        attack_type = "cve_2020_19360"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "FHEM 6.0 - Local File Inclusion: FHEM version 6.0 suffers from a local file inclusion vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-19360"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-19360, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-19360.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/fhem\/FileLog_logWrapper(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_19363_vtiger_crm_v7_2_0 {
    meta:
        attack_type = "cve_2020_19363"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Vtiger CRM v7.2.0 - Directory Listing: Vtiger CRM v7.2.0 contains a directory traversal vulnerability caused by improper access controls in /libraries and /layout directories, letting attackers display hidden files and list directories, exploit requires no authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-19363"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-19363, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-19363.yaml"
    strings:
        $path0 = "/vtigercrm/libraries/" ascii nocase
        $path1 = "/vtigercrm/layouts/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_1943_ofbiz {
    meta:
        attack_type = "cve_2020_1943"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apache OFBiz <=16.11.07 - Cross-Site Scripting: Apache OFBiz 16.11.01 to 16.11.07 is vulnerable to cross-site scripting because data sent with contentId to /control/stream is not sanitized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-1943"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1943, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-1943.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/control\/stream(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_1956_kylin {
    meta:
        attack_type = "cve_2020_1956"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Apache Kylin 3.0.1 - Command Injection Vulnerability: Apache Kylin 2.3.0, and releases up to 2.6.5 and 3.0.1 has some restful apis which will concatenate os command with the user input string, a user is likely to be able to execute any os command without any protection or."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-1956"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-1956, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-1956.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/kylin\/api\/user\/authentication(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_19625_gridx {
    meta:
        attack_type = "cve_2020_19625"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Gridx 1.3 - Remote Code Execution: Gridx 1.3 is susceptible to remote code execution via tests/support/stores/test_grid_filter.php, which allows remote attackers to execute arbitrary code via crafted values submitted to the $query parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-19625"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-19625, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-19625.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/tests\/support\/stores\/test_grid_filter\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_20300_weiphp {
    meta:
        attack_type = "cve_2020_20300"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WeiPHP 5.0 - SQL Injection: WeiPHP 5.0 contains a SQL injection vulnerability via the wp_where function. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-20300"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-20300, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-20300.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/public/index.php/home/index/bind_follow/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_20982_wdja_cms {
    meta:
        attack_type = "cve_2020_20982"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "shadoweb wdja v1.5.1 - Cross-Site Scripting: shadoweb wdja v1.5.1 is susceptible to cross-site scripting because it allows attackers to execute arbitrary code and gain escalated privileges via the backurl parameter to /php/passport/index.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-20982"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-20982, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-20982.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/passport\/index\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])mtype=userset(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_20988_domainmod {
    meta:
        attack_type = "cve_2020_20988"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DomainMOD 4.13.0 - Cross-Site Scripting: DomainMOD 4.13.0 is vulnerable to cross-site scripting via reporting/domains/cost-by-owner.php in the 'or Expiring Between' parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-20988"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-20988, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-20988.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/reporting\/domains\/cost-by-owner\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_2140_audit_trail {
    meta:
        attack_type = "cve_2020_2140"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jenkin Audit Trail <=3.2 - Cross-Site Scripting: Jenkins Audit Trail 3.2 and earlier does not escape the error message for the URL Patterns field form validation, resulting in a reflected cross-site scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-2140"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2140, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-2140.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/descriptorByName\/AuditTrailPlugin\/regexCheck(\/|;|$)/ nocase
        $path1 = /\/jenkins\/descriptorByName\/AuditTrailPlugin\/regexCheck(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_21998_homeautomation {
    meta:
        attack_type = "cve_2020_21998"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "HomeAutomation 3.3.2 - Open Redirect: HomeAutomation 3.3.2 contains a redirect vulnerability caused by improper verification of the 'redirect' GET parameter in 'api.php', letting attackers redirect users to arbitrary websites, exploit requires user interaction with a crafted."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-21998"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-21998, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-21998.yaml"
    strings:
        $path0 = /\/homeautomation_v3_3_2\/api\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_22208_74cms {
    meta:
        attack_type = "cve_2020_22208"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "74cms - ajax_street.php 'x' SQL Injection: SQL Injection in 74cms 3.2.0 via the x parameter to plus/ajax_street.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-22208"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-22208, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-22208.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])act=alphabet(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_22210_74cms {
    meta:
        attack_type = "cve_2020_22210"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "74cms - ajax_officebuilding.php SQL Injection: A SQL injection vulnerability exists in 74cms 3.2.0 via the x parameter to ajax_officebuilding.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-22210"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-22210, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-22210.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/plus\/ajax_officebuilding\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_22840_b2evolution {
    meta:
        attack_type = "cve_2020_22840"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "b2evolution CMS <6.11.6 - Open Redirect: b2evolution CMS before 6.11.6 contains an open redirect vulnerability via the redirect_to parameter in email_passthrough.php. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-22840"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-22840, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-22840.yaml"
    strings:
        $path0 = /\/email_passthrough\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])email_key=5QImTaEHxmAzNYyYvENAtYHsFu7fyotR(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_23697_monstra_cms {
    meta:
        attack_type = "cve_2020_23697"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Monstra CMS 3.0.4 - Cross-Site Scripting: Monstra CMS 3.0.4 contains a cross-site scripting vulnerability via the page feature in admin/index.php. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-23697"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-23697, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-23697.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])status=published(&|$)/ nocase
        $param1 = /(^|[?&;])access=public(&|$)/ nocase
        $param2 = /(^|[?&;])add_page_and_exit=Save and Exit(&|$)/ nocase
        $param3 = /(^|[?&;])page_date=2023-01-09 18:22:15(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_23814_xxl_job {
    meta:
        attack_type = "cve_2020_23814"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XXL-JOB v2.2.0 Stored Cross Site Scripting: Multiple cross-site scripting (XSS) vulnerabilities in xxl-job v2.2.0 allow remote attackers to inject arbitrary web script or HTML via (1) AppName and (2)AddressList parameter in JobGroupController.java file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-23814"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-23814, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-23814.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/xxl-job-admin\/jobgroup\/save(\/|;|$)/ nocase
        $path1 = /\/xxl-job-admin\/jobgroup\/pageList(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_23972_gmapfp {
    meta:
        attack_type = "cve_2020_23972"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Joomla! Component GMapFP 3.5 - Arbitrary File Upload: Joomla! Component GMapFP 3.5 is vulnerable to arbitrary file upload vulnerabilities. An attacker can access the upload function of the application without authentication and can upload files because of unrestricted file."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-23972"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-23972, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-23972.yaml"
    strings:
        $param0 = /(^|[?&;])controller=editlieux(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_24148_import_xml_and_rss_feeds {
    meta:
        attack_type = "cve_2020_24148"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Import XML & RSS Feeds WordPress Plugin <= 2.0.1 Server-Side Request Forgery: WordPress plugin Import XML and RSS Feeds (import-xml-feed) plugin 2.0.1 contains a server-side request forgery (SSRF) vulnerability via the data parameter in a moove_read_xml action."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-24148"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-24148, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-24148.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = /(^|[?&;])xmlaction=preview(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_24550_find {
    meta:
        attack_type = "cve_2020_24550"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "EpiServer Find <13.2.7 - Open Redirect: EpiServer Find before 13.2.7 contains an open redirect vulnerability via the _t_redirect parameter in a crafted URL, such as a /find_v2/_click URL. An attacker can redirect a user to a malicious site and possibly obtain sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-24550"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-24550, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-24550.yaml"
    strings:
        $path0 = /\/find_v2\/_click(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_24579_dsl2888a_firmware {
    meta:
        attack_type = "cve_2020_24579"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "D-Link DSL 2888a - Authentication Bypass/Remote Command Execution: D-Link DSL-2888A devices with firmware prior to AU_2.31_V1.1.47ae55 are vulnerable to authentication bypass issues which can lead to remote command execution. An unauthenticated attacker could bypass."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-24579"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-24579, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-24579.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cgi-bin\/execute_cmd\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_24589_api_manager {
    meta:
        attack_type = "cve_2020_24589"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WSO2 API Manager <=3.1.0 - Blind XML External Entity Injection: WSO2 API Manager 3.1.0 and earlier is vulnerable to blind XML external entity injection (XXE). XXE often allows an attacker to view files on the server file system, and to interact with any backend or external."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-24589"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-24589, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-24589.yaml"
    strings:
        $path0 = /\/carbon\/generic\/save_artifact_ajaxprocessor\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_24701_open_xchange_appsuite {
    meta:
        attack_type = "cve_2020_24701"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "OX Appsuite - Cross-Site Scripting: OX App Suite through 7.10.4 allows XSS via the app loading mechanism (the PATH_INFO to the /appsuite URI)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-24701"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-24701, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-24701.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/ajax\/apps\/manifests(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_24903_cute_editor {
    meta:
        attack_type = "cve_2020_24903"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Cute Editor for ASP.NET 6.4 - Cross-Site Scripting: Cute Editor for ASP.NET 6.4 contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-24903"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-24903, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-24903.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/CuteSoft_Client\/CuteEditor\/Template\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_24912_qcubed {
    meta:
        attack_type = "cve_2020_24912"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "QCube Cross-Site-Scripting: A reflected cross-site scripting vulnerability in qcubed (all versions including 3.1.1) in profile.php via the stQuery-parameter allows unauthenticated attackers to steal sessions of authenticated users."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-24912"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-24912, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-24912.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/assets\/_core\/php\/profile\.php(\/|;|$)/ nocase
        $path1 = /\/assets\/php\/profile\.php(\/|;|$)/ nocase
        $path2 = /\/vendor\/qcubed\/qcubed\/assets\/php\/profile\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])StrReferrer=somethinxg(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_24949_php_fusion {
    meta:
        attack_type = "cve_2020_24949"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PHP-Fusion 9.03.50 - Remote Code Execution: PHP-Fusion 9.03.50 downloads/downloads.php allows an authenticated user (not admin) to send a crafted request to the server and perform remote command execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-24949"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-24949, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-24949.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/infusions\/downloads\/downloads\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_25078_dcs_2530l_firmware {
    meta:
        attack_type = "cve_2020_25078"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "D-Link DCS-2530L/DCS-2670L - Administrator Password Disclosure: D-Link DCS-2530L before 1.06.01 Hotfix and DCS-2670L through 2.02 devices are vulnerable to password disclosures vulnerabilities because the /config/getuser endpoint allows for remote administrator password."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-25078"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-25078, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-25078.yaml"
    strings:
        $path0 = /\/config\/getuser(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_25495_openserver {
    meta:
        attack_type = "cve_2020_25495"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Xinuo Openserver 5/6 - Cross-Site scripting: Xinuo (formerly SCO) Openserver versions 5 and 6 allows remote attackers to inject arbitrary web script or HTML tag via the parameter 'section' and is vulnerable to reflected cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-25495"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-25495, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-25495.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/cgi-bin\/manlist(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_25780_commcell {
    meta:
        attack_type = "cve_2020_25780"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Commvault CommCell - Local File Inclusion: CommCell in Commvault before 14.68, 15.x before 15.58, 16.x before 16.44, 17.x before 17.29, and 18.x before 18.13 are vulnerable to local file inclusion because an attacker can view a log file can instead view a file outside of the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-25780"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-25780, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-25780.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/SearchSvc\/CVSearchService\.svc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_26073_cisco_sd_wan_vmanage_software {
    meta:
        attack_type = "cve_2020_26073"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cisco SD-WAN vManage Software - Local File Inclusion: Cisco SD-WAN vManage Software in the application data endpoints is vulnerable to local file inclusion which could allow an unauthenticated, remote attacker to gain access to sensitive information."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-26073"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-26073, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-26073.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/dataservice/disasterrecovery/download/token/../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_26153_event_espresso {
    meta:
        attack_type = "cve_2020_26153"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Event Espresso Core-Reg 4.10.7.p - Cross-Site Scripting: Event Espresso Core-Reg 4.10.7.p is vulnerable to cross-site scripting in wp-content/plugins/event-espresso-core-reg/admin_pages/messages/templates/ee_msg_admin_overview.template.php and allows remote attackers to inject."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-26153"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-26153, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-26153.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/event-espresso-core-reg\/admin_pages\/messages\/templates\/ee_msg_admin_overview\.template\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_26836_solution_manager {
    meta:
        attack_type = "cve_2020_26836"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SAP Solution Manager - Open Redirect: SAP Solution Manager contains an open redirect vulnerability via the logoff endpoint. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-26836"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-26836, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-26836.yaml"
    strings:
        $path0 = /\/sap\/public\/bc\/icf\/logoff(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_26876_wp_courses {
    meta:
        attack_type = "cve_2020_26876"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress WP Courses Plugin Information Disclosure: WordPress WP Courses Plugin < 2.0.29 contains a critical information disclosure which exposes private course videos and materials."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-26876"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-26876, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-26876.yaml"
    strings:
        $path0 = "/wp-json/wp/v2/lesson/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_26879_ruckus_vriot {
    meta:
        attack_type = "cve_2020_26879"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ruckus vRioT IoT Controller - Authentication Bypass: Ruckus vRioT through 1.5.1.0.21 contains an API backdoor caused by a hardcoded token in validate_token.py,letting unauthenticated attackers interact with the API without authentication."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-26879"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-26879, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-26879.yaml"
    strings:
        $path0 = /\/service\/v1\/createUser(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_26919_jgs516pe_firmware {
    meta:
        attack_type = "cve_2020_26919"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "NETGEAR ProSAFE Plus - Unauthenticated Remote Code Execution: NETGEAR ProSAFE Plus before 2.6.0.43 is susceptible to unauthenticated remote code execution. Any HTML page is allowed as a valid endpoint to submit POST requests, allowing debug action via the submitId and debugCmd."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-26919"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-26919, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-26919.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])submitId=debug(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_2733_jd_edwards_enterpriseone_tools {
    meta:
        attack_type = "cve_2020_2733"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JD Edwards EnterpriseOne Tools 9.2 - Information Disclosure: JD Edwards EnterpriseOne Tools 9.2 is susceptible to information disclosure via the Monitoring and Diagnostics component. An attacker with network access via HTTP can possibly obtain sensitive information, modify."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-2733"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-2733, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-2733.yaml"
    strings:
        $path0 = /\/manage\/fileDownloader(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_27481_good_learning_management_syste {
    meta:
        attack_type = "cve_2020_27481"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Good Layers LMS Plugin <= 2.1.4 - SQL Injection: An unauthenticated SQL Injection vulnerability in Good Layers LMS Plugin <= 2.1.4 exists due to the usage of 'wp_ajax_nopriv' call in WordPress, which allows any unauthenticated user to get access to the function."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-27481"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-27481, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-27481.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=gdlr_lms_cancel_booking(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_27735_wing_ftp_server {
    meta:
        attack_type = "cve_2020_27735"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Wing FTP 6.4.4 - Cross-Site Scripting: Wing FTP 6.4.4 is vulnerable to cross-site scripting via its web interface because an arbitrary IFRAME element can be included in the help pages via a crafted link, leading to the execution of (sandboxed) arbitrary HTML and JavaScript in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-27735"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-27735, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-27735.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/help\/english\/index\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_27838_keycloak {
    meta:
        attack_type = "cve_2020_27838"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "KeyCloak - Information Exposure: A flaw was found in keycloak in versions prior to 13.0.0. The client registration endpoint allows fetching information about PUBLIC clients (like client secret) without authentication which could be an issue if the same PUBLIC client changed to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-27838"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-27838, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-27838.yaml"
    strings:
        $path0 = /\/auth\/realms\/master\/clients-registrations\/default\/security-admin-console(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_27986_sonarqube {
    meta:
        attack_type = "cve_2020_27986"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SonarQube - Authentication Bypass: SonarQube 8.4.2.36762 allows remote attackers to discover cleartext SMTP, SVN, and GitLab credentials via the api/settings/values URI."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-27986"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-27986, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-27986.yaml"
    strings:
        $path0 = /\/api\/settings\/values(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_28185_tos {
    meta:
        attack_type = "cve_2020_28185"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "TerraMaster TOS < 4.2.06 - User Enumeration: User Enumeration vulnerability in TerraMaster TOS <= 4.2.06 allows remote unauthenticated attackers to identify valid users within the system via the username parameter to wizard/initialise.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-28185"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-28185, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-28185.yaml"
    strings:
        $path0 = /\/wizard\/initialise\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])tab=checkuser(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_28188_tos {
    meta:
        attack_type = "cve_2020_28188"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TerraMaster TOS - Unauthenticated Remote Command Execution: TerraMaster TOS <= 4.2.06 is susceptible to a remote code execution vulnerability which could allow remote unauthenticated attackers to inject OS commands via /include/makecvs.php via the Event parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-28188"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-28188, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-28188.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/include\/makecvs\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_28208_rocket_chat {
    meta:
        attack_type = "cve_2020_28208"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Rocket.Chat <3.9.1 - Information Disclosure: Rocket.Chat through 3.9.1 is susceptible to information disclosure. An attacker can enumerate email addresses via the password reset function and thus potentially access sensitive information, modify data, and/or execute unauthorized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-28208"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-28208, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-28208.yaml"
    strings:
        $path0 = /\/api\/v1\/method\.callAnon\/sendForgotPasswordEmail(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_28653_manageengine_opmanager {
    meta:
        attack_type = "cve_2020_28653"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ManageEngine OpManager SumPDU 12.1 - 12.5.232 - Java Deserialization: Zoho ManageEngine OpManager Stable build before 125203 (and Released build before 125233) allows Remote Code Execution via the Smart Update Manager (SUM) servlet."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-28653"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-28653, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-28653.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/servlets\/com\.adventnet\.tools\.sum\.transport\.SUMCommunicationServlet(\/|;|$)/ nocase
        $path1 = /\/servlets\/com\.adventnet\.tools\.sum\.transport\.SUMHandShakeServlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_28976_canto {
    meta:
        attack_type = "cve_2020_28976"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Canto 1.3.0 - Blind Server-Side Request Forgery: WordPress Canto plugin 1.3.0 is susceptible to blind server-side request forgery. An attacker can make a request to any internal and external server via /includes/lib/detail.php?subdomain and thereby possibly obtain."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-28976"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-28976, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-28976.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/wp-content\/plugins\/canto\/includes\/lib\/detail\.php(\/|;|$)/ nocase
        $path1 = /\/wp-content\/plugins\/canto\/includes\/lib\/get\.php(\/|;|$)/ nocase
        $path2 = /\/wp-content\/plugins\/canto\/includes\/lib\/tree\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_29453_data_center {
    meta:
        attack_type = "cve_2020_29453"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jira Server Pre-Auth - Arbitrary File Retrieval (WEB-INF, META-INF): The CachingResourceDownloadRewriteRule class in Jira Server and Jira Data Center allowed unauthenticated remote attackers to read arbitrary files within WEB-INF and META-INF directories via an incorrect path."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-29453"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-29453, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-29453.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/_\/\.\/WEB-INF\/classes\/META-INF\/maven\/com\.atlassian\.jira\/jira-core\/pom\.xml(\/|;|$)/ nocase
        $path1 = /\/_\/\.\/META-INF\/maven\/com\.atlassian\.jira\/atlassian-jira-webapp\/pom\.xml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_29597_incomcms {
    meta:
        attack_type = "cve_2020_29597"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "IncomCMS 2.0 - Arbitrary File Upload: IncomCMS 2.0 has a an insecure file upload vulnerability in modules/uploader/showcase/script.php. This allows unauthenticated attackers to upload files into the server."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-29597"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-29597, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-29597.yaml"
    strings:
        $path0 = /\/incom\/modules\/uploader\/showcase\/script\.php(\/|;|$)/ nocase
        $path1 = "/upload/userfiles/image/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_3187_firepower_threat_defense {
    meta:
        attack_type = "cve_2020_3187"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cisco Adaptive Security Appliance Software/Cisco Firepower Threat Defense - Directory Traversal: Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software are susceptible to directory traversal vulnerabilities that could allow an."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-3187"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3187, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-3187.yaml"
    strings:
        $path0 = /\/\+CSCOE\+\/session_password\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_35476_opentsdb {
    meta:
        attack_type = "cve_2020_35476"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OpenTSDB <=2.4.0 - Remote Code Execution: OpenTSDB 2.4.0 and earlier is susceptible to remote code execution via the yrange parameter written to a gnuplot file in the /tmp directory. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-35476"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-35476, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-35476.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])start=2000\/10\/21-00:00:00(&|$)/ nocase
        $param1 = /(^|[?&;])xrange=10:10(&|$)/ nocase
        $param2 = /(^|[?&;])wxh=1516x644(&|$)/ nocase
        $param3 = /(^|[?&;])style=linespoint(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_35580_searchblox {
    meta:
        attack_type = "cve_2020_35580"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SearchBlox <9.2.2 - Local File Inclusion: SearchBlox prior to version 9.2.2 is susceptible to local file inclusion in FileServlet that allows remote, unauthenticated users to read arbitrary files from the operating system via a /searchblox/servlet/FileServlet?col=url= request.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-35580"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-35580, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-35580.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/searchblox\/servlet\/FileServlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_35598_advanced_comment_system {
    meta:
        attack_type = "cve_2020_35598"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Advanced Comment System 1.0 - Local File Inclusion: ACS Advanced Comment System 1.0 is affected by local file inclusion via an advanced_component_system/index.php?ACS_path=..%2f URI."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-35598"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-35598, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-35598.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/advanced_component_system\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_35713_re6500_firmware {
    meta:
        attack_type = "cve_2020_35713"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Belkin Linksys RE6500 <1.0.012.001 - Remote Command Execution: Belkin LINKSYS RE6500 devices before 1.0.012.001 allow remote attackers to execute arbitrary commands or set a new password via shell metacharacters to the goform/setSysAdm page."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-35713"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-35713, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-35713.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/goform\/setSysAdm(\/|;|$)/ nocase
        $param0 = /(^|[?&;])admpasshint=61646D696E=(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_35729_klog_server {
    meta:
        attack_type = "cve_2020_35729"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Klog Server <=2.41 - Unauthenticated Command Injection: Klog Server 2.4.1 and prior is susceptible to an unauthenticated command injection vulnerability. The `authenticate.php` file uses the `user` HTTP POST parameter in a call to the `shell_exec()` PHP function without."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-35729"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-35729, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-35729.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/actions\/authenticate\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_35749_simple_board_job {
    meta:
        attack_type = "cve_2020_35749"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Simple Job Board <2.9.4 - Local File Inclusion: WordPress Simple Job Board prior to version 2.9.4 is vulnerable to arbitrary file retrieval vulnerabilities because it does not validate the sjb_file parameter when viewing a resume, allowing an authenticated user with."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-35749"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-35749, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-35749.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])sjb_file=\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_35774_twitter_server {
    meta:
        attack_type = "cve_2020_35774"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "twitter-server Cross-Site Scripting: twitter-server before 20.12.0 is vulnerable to cross-site scripting in some configurations. The vulnerability exists in the administration panel of twitter-server in the histograms component via server/handler/HistogramQueryHandler.scala."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-35774"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-35774, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-35774.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/admin\/histograms(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_3580_firepower_threat_defense {
    meta:
        attack_type = "cve_2020_3580"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Cisco ASA/FTD Software - Cross-Site Scripting: Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software are vulnerable to cross-site scripting and could allow an unauthenticated, remote attacker to conduct attacks against a user of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-3580"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-3580, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-3580.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/\+CSCOE\+\/saml\/sp\/acs(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_35848_cockpit {
    meta:
        attack_type = "cve_2020_35848"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Agentejo Cockpit <0.12.0 - NoSQL Injection: Agentejo Cockpit prior to 0.12.0 is vulnerable to NoSQL Injection via the newpassword method of the Auth controller, which is responsible for displaying the user password reset form."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-35848"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-35848, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-35848.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/auth\/newpassword(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_35951_quiz_and_survey_master {
    meta:
        attack_type = "cve_2020_35951"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Wordpress Quiz and Survey Master <7.0.1 - Arbitrary File Deletion: Wordpress Quiz and Survey Master <7.0.1 allows users to delete arbitrary files such as wp-config.php file, which could effectively take a site offline and allow an attacker to reinstall with a WordPress instance."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-35951"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-35951, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-35951.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/quiz-master-next\/README\.md(\/|;|$)/ nocase
        $path1 = /\/wp-content\/plugins\/quiz-master-next\/tests\/_support\/AcceptanceTester\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_36112_cse_bookstore {
    meta:
        attack_type = "cve_2020_36112"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CSE Bookstore 1.0 - SQL Injection: CSE Bookstore version 1.0 is vulnerable to time-based blind, boolean-based blind and OR error-based SQL injection in pubid parameter in bookPerPub.php. A successful exploitation of this vulnerability will lead to an attacker dumping the entire."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-36112"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-36112, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-36112.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/ebook\/bookPerPub\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_36289_data_center {
    meta:
        attack_type = "cve_2020_36289"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jira Server and Data Center - Information Disclosure: Jira Server and Data Center is susceptible to information disclosure. An attacker can enumerate users via the QueryComponentRendererValue!Default.jspa endpoint and thus potentially access sensitive information, modify data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-36289"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-36289, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-36289.yaml"
    strings:
        $path0 = /\/secure\/QueryComponentRendererValue!Default\.jspa(\/|;|$)/ nocase
        $path1 = /\/jira\/secure\/QueryComponentRendererValue!Default\.jspa(\/|;|$)/ nocase
        $param0 = /(^|[?&;])assignee=user:admin(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_36365_smartstorenet {
    meta:
        attack_type = "cve_2020_36365"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Smartstore <4.1.0 - Open Redirect: Smartstore (aka 'SmartStoreNET') before 4.1.0 contains an open redirect vulnerability via CommonController.ClearCache, ClearDatabaseCache, RestartApplication, and ScheduleTaskController.Edit. An attacker can redirect a user to a malicious site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-36365"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-36365, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-36365.yaml"
    strings:
        $path0 = /\/backend\/admin\/common\/clearcache(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_36708_activello {
    meta:
        attack_type = "cve_2020_36708"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Epsilon Framework Themes <=2.4.8 - Remote Code Execution: WordPress themes including Shapely <= 1.2.7, NewsMag <= 2.4.1, Activello <= 1.4.0, Illdy <= 2.1.4, Allegiant <= 1.2.2, Newspaper X <= 1.3.1, Pixova Lite <= 2.0.5, Brilliance <= 1.2.7, MedZone Lite <= 1.2.4."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-36708"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-36708, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-36708.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])action=epsilon_framework_ajax_action(&|$)/ nocase
        $param1 = /(^|[?&;])args\[action\]\[\]=Requests(&|$)/ nocase
        $param2 = /(^|[?&;])args\[action\]\[\]=request_multiple(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_36731_flexible_checkout_fields_for_w {
    meta:
        attack_type = "cve_2020_36731"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Flexible Checkout Fields for WooCommerce <= 2.3.1 - Unauthenticated Arbitrary Plugin Settings Update: The Flexible Checkout Fields for WooCommerce plugin for WordPress is vulnerable to Unauthenticated Arbitrary Plugin Settings update, in addition to Stored Cross-Site Scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-36731"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-36731, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-36731.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=inspire_checkout_fields_settings(&|$)/ nocase
        $param1 = /(^|[?&;])option_page=inspire_checkout_fields_settings(&|$)/ nocase
        $param2 = /(^|[?&;])inspire_checkout_fields\[settings\]\[order\]\[order_comments\]\[name\]=order_comments(&|$)/ nocase
        $param3 = /(^|[?&;])inspire_checkout_fields\[settings\]\[order\]\[order_comments\]\[label\]=Order Notes(&|$)/ nocase
        $param4 = /(^|[?&;])reset_settings=Reset Section Settings(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_36836_wp_fastest_cache {
    meta:
        attack_type = "cve_2020_36836"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress WP Fastest Cache <= 0.9.0.2 - Authenticated Arbitrary File Deletion: The WP Fastest Cache plugin for WordPress is vulnerable to unauthorized arbitrary file deletion in versions up to, and including, 0.9.0.2 due to a lack of capability checking and insufficient path."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-36836"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-36836, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-36836.yaml"
    strings:
        $path0 = "/wp-content/plugins/wp-fastest-cache/" ascii nocase
        $param0 = /(^|[?&;])action=wpfc_delete_current_page_cache(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_4427_data_risk_manager {
    meta:
        attack_type = "cve_2020_4427"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "IBM Data Risk Manager - Authentication Bypass via SAML: IBM Data Risk Manager versions 2.0.1 through 2.0.6 are vulnerable to authentication bypass when configured with SAML authentication. A remote attacker can bypass security restrictions by sending a specially crafted HTTP."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-4427"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-4427, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-4427.yaml"
    strings:
        $path0 = /\/albatross\/saml\/idpSelection(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_4463_maximo_asset_management {
    meta:
        attack_type = "cve_2020_4463"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "IBM Maximo Asset Management Information Disclosure - XML External Entity Injection: IBM Maximo Asset Management is vulnerable to an XML external entity injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-4463"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-4463, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-4463.yaml"
    strings:
        $path0 = /\/os\/mxperson(\/|;|$)/ nocase
        $path1 = /\/meaweb\/os\/mxperson(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_5191_hospital_management_system {
    meta:
        attack_type = "cve_2020_5191"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PHPGurukul Hospital Management System - Cross-Site Scripting: PHPGurukul Hospital Management System in PHP 4.0 contains multiple cross-site scripting vulnerabilities. An attacker can execute arbitrary script code in the browser of an unsuspecting user in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-5191"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5191, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-5191.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/hospital\/hms\/admin\/index\.php(\/|;|$)/ nocase
        $path1 = /\/hospital\/hms\/admin\/doctor-specilization\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_5192_hospital_management_system {
    meta:
        attack_type = "cve_2020_5192"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hospital Management System 4.0 - SQL Injection: Hospital Management System 4.0 contains multiple SQL injection vulnerabilities because multiple pages and parameters do not validate user input. An attacker can possibly obtain sensitive information from a database, modify data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-5192"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5192, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-5192.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/hospital\/hms\/doctor\/index\.php(\/|;|$)/ nocase
        $path1 = /\/hospital\/hms\/doctor\/search\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_5284_next_js {
    meta:
        attack_type = "cve_2020_5284"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Next.js <9.3.2 - Local File Inclusion: Next.js versions before 9.3.2 are vulnerable to local file inclusion. An attacker can craft special requests to access files in the dist directory (.next). This does not affect files outside of the dist directory (.next). In general, the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-5284"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5284, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-5284.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/_next\/static\/\.\.\/server\/pages-manifest\.json(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_5405_spring_cloud_config {
    meta:
        attack_type = "cve_2020_5405"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Spring Cloud Config - Local File Inclusion: Spring Cloud Config versions 2.2.x prior to 2.2.2, 2.1.x prior to 2.1.7, and older unsupported versions are vulnerable to local file inclusion because they allow applications to serve arbitrary configuration files through the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-5405"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5405, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-5405.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/a\/b\/%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2fetc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_5412_spring_cloud_netflix {
    meta:
        attack_type = "cve_2020_5412"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Spring Cloud Netflix - Server-Side Request Forgery: Spring Cloud Netflix 2.2.x prior to 2.2.4, 2.1.x prior to 2.1.6, and older unsupported versions are susceptible to server-side request forgery. Applications can use the Hystrix Dashboard proxy.stream endpoint to make requests."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-5412"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5412, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-5412.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/proxy\.stream(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_5722_grandstream_ucm6200 {
    meta:
        attack_type = "cve_2020_5722"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Grandstream UCM6200 - SQL Injection: Grandstream UCM6200 series contains an unauthenticated remote SQL injection caused by crafted HTTP requests, letting attackers execute shell commands as root on versions before 1.0.19.20 or inject HTML in emails before 1.0.20.17."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-5722"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5722, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-5722.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=sendPasswordEmail(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_5775_canvas_learning_management_ser {
    meta:
        attack_type = "cve_2020_5775"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Canvas LMS v2020-07-29 - Blind Server-Side Request Forgery: Canvas version 2020-07-29 is susceptible to blind server-side request forgery. An attacker can cause Canvas to perform HTTP GET requests to arbitrary domains and thus potentially access sensitive information, modify."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-5775"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5775, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-5775.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/external_content\/retrieve\/oembed(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_5776_magmi {
    meta:
        attack_type = "cve_2020_5776"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MAGMI - Cross-Site Request Forgery: MAGMI (Magento Mass Importer) is vulnerable to cross-site request forgery (CSRF) due to a lack of CSRF tokens. Remote code execution (via phpcli command) is also possible in the event that CSRF is leveraged against an existing admin session."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-5776"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5776, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-5776.yaml"
    strings:
        $path0 = /\/magmi\/web\/magmi_saveprofile\.php(\/|;|$)/ nocase
        $path1 = /\/magmi\/web\/magmi_run\.php(\/|;|$)/ nocase
        $path2 = /\/magmi\/web\/info\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])PLUGINS_DATASOURCES:class=Magmi_CSVDataSource(&|$)/ nocase
        $param1 = /(^|[?&;])CSV:importmode=remote(&|$)/ nocase
        $param2 = /(^|[?&;])CSV:basedir=var\/import(&|$)/ nocase
        $param3 = /(^|[?&;])PLUGINS_GENERAL:classes=Magmi_ReindexingPlugin(&|$)/ nocase
        $param4 = /(^|[?&;])REINDEX:indexes=cataloginventory_stock(&|$)/ nocase
        $param5 = /(^|[?&;])engine=magmi_productimportengine:Magmi_ProductImportEngine(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_5777_magmi {
    meta:
        attack_type = "cve_2020_5777"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Magento Mass Importer <0.7.24 - Remote Auth Bypass: Magento Mass Importer (aka MAGMI) versions prior to 0.7.24 are vulnerable to a remote authentication bypass due to allowing default credentials in the event there is a database connection failure."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-5777"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5777, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-5777.yaml"
    strings:
        $path0 = "/index.php/catalogsearch/advanced/result/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_5847_unraid {
    meta:
        attack_type = "cve_2020_5847"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "UnRaid <=6.80 - Remote Code Execution: UnRaid <=6.80 allows remote unauthenticated attackers to execute arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-5847"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-5847, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-5847.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/webGui/images/green-on.png/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_6207_solution_manager {
    meta:
        attack_type = "cve_2020_6207"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "SAP Solution Manager 7.2 - Remote Command Execution: SAP Solution Manager (SolMan) running version 7.2 has a remote command execution vulnerability within the SAP EEM servlet (tc~smd~agent~application~eem). The vulnerability occurs due to missing authentication checks when."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-6207"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6207, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-6207.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/EemAdminService\/EemAdmin(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_6308_businessobjects_business_intel {
    meta:
        attack_type = "cve_2020_6308"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SAP BusinessObjects Business Intelligence Platform - Blind Server-Side Request Forgery: SAP BusinessObjects Business Intelligence Platform (Web Services) 410, 420, and 430 is susceptible to blind server-side request forgery. An attacker can inject arbitrary values as CMS."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-6308"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6308, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-6308.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/AdminTools\/querybuilder\/logon(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_6637_opensis {
    meta:
        attack_type = "cve_2020_6637"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OpenSIS 7.3 - SQL Injection: OpenSIS Community Edition version 7.3 is vulnerable to SQL injection via the USERNAME parameter of index.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-6637"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6637, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-6637.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/opensis\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_6950_mojarra {
    meta:
        attack_type = "cve_2020_6950"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Eclipse Mojarra - Local File Read: Directory traversal in Eclipse Mojarra before 2.3.14 allows attackers to read arbitrary files via the loc parameter or con parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-6950"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-6950, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-6950.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/javax\.faces\.resources\/web\.xml\.jsf(\/|;|$)/ nocase
        $path1 = /\/javax\.faces\.resources\/faces-config\.xml\.jsf(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_7209_linuxki {
    meta:
        attack_type = "cve_2020_7209"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LinuxKI Toolset <= 6.01 - Remote Command Execution: LinuxKI v6.0-1 and earlier are vulnerable to remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-7209"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-7209, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-7209.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/linuxki\/experimental\/vis\/kivis\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])type=kitrace(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_7318_epolicy_orchestrator {
    meta:
        attack_type = "cve_2020_7318"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "McAfee ePolicy Orchestrator <5.10.9 Update 9 - Cross-Site Scripting: McAfee ePolicy Orchestrator before 5.10.9 Update 9 is vulnerable to a cross-site scripting vulnerability that allows administrators to inject arbitrary web script or HTML via multiple parameters where the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-7318"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-7318, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-7318.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/PolicyMgmt\/policyDetailsCard\.do(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_7796_zimbra_collaboration_suite {
    meta:
        attack_type = "cve_2020_7796"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Zimbra Collaboration Suite < 8.8.15 Patch 7 - Server-Side Request Forgery: Zimbra Collaboration Suite (ZCS) before 8.8.15 Patch 7 is susceptible to server-side request forgery when WebEx zimlet is installed and zimlet JSP is enabled."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-7796"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-7796, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-7796.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/zimlet\/com_zimbra_webex\/httpPost\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_7943_puppet_enterprise {
    meta:
        attack_type = "cve_2020_7943"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Puppet Server/PuppetDB - Sensitive Information Disclosure: Puppet Server and PuppetDB provide useful performance and debugging information via their metrics API endpoints, which may contain sensitive information when left exposed."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-7943"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-7943, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-7943.yaml"
    strings:
        $path0 = /\/metrics\/v1\/mbeans(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_7961_liferay_portal {
    meta:
        attack_type = "cve_2020_7961"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Liferay Portal Unauthenticated < 7.2.1 CE GA2 - Remote Code Execution: Liferay Portal prior to 7.2.1 CE GA2 allows remote attackers to execute arbitrary code via JSON web services (JSONWS)."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-7961"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-7961, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-7961.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/jsonws\/invoke(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_7980_aptus_web {
    meta:
        attack_type = "cve_2020_7980"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Satellian Intellian Aptus Web <= 1.24 - Remote Command Execution: Intellian Aptus Web 1.24 allows remote attackers to execute arbitrary OS commands via the Q field within JSON data to the cgi-bin/libagent.cgi URI. NOTE: a valid sid cookie for a login to the intellian default."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-7980"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-7980, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-7980.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cgi-bin\/libagent\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_8115_revive_adserver {
    meta:
        attack_type = "cve_2020_8115"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Revive Adserver <=5.0.3 - Cross-Site Scripting: Revive Adserver 5.0.3 and prior contains a reflected cross-site scripting vulnerability in the publicly accessible afr.php delivery script. In older versions, it is possible to steal the session identifier and gain access to the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-8115"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8115, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-8115.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/www\/delivery\/afr\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_8191_application_delivery_controlle {
    meta:
        attack_type = "cve_2020_8191"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Citrix ADC/Gateway - Cross-Site Scripting: Citrix ADC and Citrix Gateway versions before 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14 and 10.5-70.18 and Citrix SDWAN WAN-OP versions before 11.1.1a, 11.0.3d and 10.2.7 contain a cross-site scripting vulnerability due to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-8191"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8191, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-8191.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/menu\/stapp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_8193_application_delivery_controlle {
    meta:
        attack_type = "cve_2020_8193"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Citrix - Local File Inclusion: Citrix ADC and Citrix Gateway versions before 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14 and 10.5-70.18 and Citrix SDWAN WAN-OP versions before 11.1.1a, 11.0.3d and 10.2.7 are vulnerable to local file inclusion because they allow."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-8193"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8193, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-8193.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/pcidss\/report(\/|;|$)/ nocase
        $path1 = /\/rapi\/filedownload(\/|;|$)/ nocase
        $param0 = /(^|[?&;])type=allprofiles(&|$)/ nocase
        $param1 = /(^|[?&;])sid=loginchallengeresponse1requestbody(&|$)/ nocase
        $param2 = /(^|[?&;])filter=path:\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_8194_application_delivery_controlle {
    meta:
        attack_type = "cve_2020_8194"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Citrix ADC and Citrix NetScaler Gateway - Remote Code Injection: Citrix ADC and NetScaler Gateway are susceptible to remote code injection. An attacker can potentially execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-8194"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8194, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-8194.yaml"
    strings:
        $param0 = /(^|[?&;])nsvpx=phpinfo(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_8209_xenmobile_server {
    meta:
        attack_type = "cve_2020_8209"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Citrix XenMobile Server - Local File Inclusion: Citrix XenMobile Server 10.12 before RP2, Citrix XenMobile Server 10.11 before RP4, Citrix XenMobile Server 10.10 before RP6, and Citrix XenMobile Server before 10.9 RP5 are susceptible to local file inclusion vulnerabilities.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-8209"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8209, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-8209.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])sbFileName=\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2020_8497_pandora_fms {
    meta:
        attack_type = "cve_2020_8497"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Artica Pandora FMS <=7.42 - Arbitrary File Read: Artica Pandora FMS through 7.42 is susceptible to arbitrary file read. An attacker can read the chat history, which is in JSON format and contains user names, user IDs, private messages, and timestamps. This can potentially lead."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-8497"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8497, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-8497.yaml"
    strings:
        $path0 = /\/pandora_console\/attachment\/pandora_chat\.log\.json\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_8656_eyesofnetwork {
    meta:
        attack_type = "cve_2020_8656"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "EyesOfNetwork - Hardcoded API Key & SQL Injection: An issue was discovered in EyesOfNetwork 5.3. The EyesOfNetwork API 2.4.2 is prone to SQL injection, allowing an unauthenticated attacker to perform various tasks such as authentication bypass via the username field to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-8656"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8656, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-8656.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/eonapi\/getApiKey(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_8657_eyesofnetwork {
    meta:
        attack_type = "cve_2020_8657"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "EyesOfNetwork - Hardcoded API Key: An issue was discovered in EyesOfNetwork 5.3. The installation uses the same API key (hardcoded as EONAPI_KEY in include/api_functions.php for API version 2.4.2) by default for all installations, hence allowing an attacker to calculate/guess."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-8657"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8657, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-8657.yaml"
    strings:
        $path0 = /\/eonapi\/createEonUser(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_8813_cacti {
    meta:
        attack_type = "cve_2020_8813"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cacti v1.2.8 - Remote Code Execution: Cacti v1.2.8 is susceptible to remote code execution. This vulnerability could be exploited without authentication if 'Guest Realtime Graphs' privileges are enabled."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-8813"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8813, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-8813.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/graph_realtime\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_8982_sharefile_storagezones_control {
    meta:
        attack_type = "cve_2020_8982"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Citrix ShareFile StorageZones <=5.10.x - Arbitrary File Read: Citrix ShareFile StorageZones (aka storage zones) Controller versions through at least 5.10.x are susceptible to an unauthenticated arbitrary file read vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-8982"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-8982, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-8982.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/XmlPeek\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_9039_couchbase_server {
    meta:
        attack_type = "cve_2020_9039"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Couchbase Server - Broken Access Control: Couchbase Server versions 4.0.0, 4.1.0, 4.1.1, 4.5.0, 4.5.1, 4.6.0-4.6.5, 5.0.0, 5.1.1, 5.5.0, and 5.5.1 contain insecure permissions for the projector and indexer REST endpoints caused by unauthenticated access, letting attackers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-9039"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-9039, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-9039.yaml"
    strings:
        $path0 = /\/indexer\/settings(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_9054_nas326_firmware {
    meta:
        attack_type = "cve_2020_9054"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Zyxel NAS Firmware 5.21- Remote Code Execution: Multiple Zyxel network-attached storage (NAS) devices running firmware version 5.21 contain a pre-authentication command injection vulnerability, which may allow a remote, unauthenticated attacker to execute arbitrary code on a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-9054"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-9054, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-9054.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cgi-bin\/weblogin\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_9314_iplanet_web_server {
    meta:
        attack_type = "cve_2020_9314"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Oracle iPlanet Web Server 7.0.x - Image Injection: Oracle iPlanet Web Server 7.0.x allows image injection in the Administration console via the productNameSrc parameter to an admingui URI. This issue exists because of an incomplete fix for CVE-2012-0516."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-9314"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-9314, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-9314.yaml"
    strings:
        $path0 = /\/admingui\/version\/Version(\/|;|$)/ nocase
        $path1 = /\/admingui\/version\/Masthead\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_9315_iplanet_web_server {
    meta:
        attack_type = "cve_2020_9315"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Oracle iPlanet Web Server 7.0.x - Authentication Bypass: Oracle iPlanet Web Server 7.0.x has incorrect access control for admingui/version URIs in the Administration console, as demonstrated by unauthenticated read access to encryption keys. NOTE a related support policy can be."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-9315"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-9315, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-9315.yaml"
    strings:
        $path0 = /\/admingui\/version\/serverTasksGeneral(\/|;|$)/ nocase
        $path1 = /\/admingui\/version\/serverConfigurationsGeneral(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_9344_subversion_application_lifecyc {
    meta:
        attack_type = "cve_2020_9344"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jira Subversion ALM for Enterprise <8.8.2 - Cross-Site Scripting: Jira Subversion ALM for Enterprise before 8.8.2 contains a cross-site scripting vulnerability at multiple locations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-9344"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-9344, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-9344.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/plugins\/servlet\/svnwebclient\/changedResource\.jsp(\/|;|$)/ nocase
        $path1 = /\/plugins\/servlet\/svnwebclient\/commitGraph\.jsp(\/|;|$)/ nocase
        $path2 = /\/plugins\/servlet\/svnwebclient\/error\.jsp(\/|;|$)/ nocase
        $path3 = /\/plugins\/servlet\/svnwebclient\/statsItem\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_9480_spark {
    meta:
        attack_type = "cve_2020_9480"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Spark - Authentication Bypass: In Apache Spark 2.4.5 and earlier, a standalone resource manager's master may be configured to require authentication (spark.authenticate) via a shared secret. When enabled, however, a specially-crafted RPC to the master can succeed in."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-9480"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-9480, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-9480.yaml"
    strings:
        $path0 = /\/v1\/submissions\/create(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2020_9757_craft_cms {
    meta:
        attack_type = "cve_2020_9757"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Craft CMS < 3.3.0 - Server-Side Template Injection: Craft CMS before 3.3.0 is susceptible to server-side template injection via the SEOmatic component that could lead to remote code execution via malformed data submitted to the metacontainers controller."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2020-9757"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-9757, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-9757.yaml"
        response_type = "template_eval"
    strings:
        $path0 = "/actions/seomatic/meta-container/meta-link-container/" ascii nocase
        $path1 = /\/actions\/seomatic\/meta-container\/all-meta-containers(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}
