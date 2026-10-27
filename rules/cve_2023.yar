// Baseline rules generated from public exploit and exposure checks in
// ProjectDiscovery nuclei-templates (MIT License,
// https://github.com/projectdiscovery/nuclei-templates). Each rule keys on the
// most specific request indicator of one check: a path, a static parameter or
// a vendor header that no other check and no benign request uses. Rules are
// confidence = "medium": a probe for the endpoint is a strong signal, but a
// rule cannot tell an exploit attempt from a scanner fingerprinting it.
// The `reference` field links the source check.

rule krawl_cve_2023_0037_map_builder_for_google_maps {
    meta:
        attack_type = "cve_2023_0037"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress 10Web Map Builder < 1.0.73 - Unauthenticated SQL Injection: The 10Web Map Builder for Google Maps WordPress plugin before 1.0.73 does not properly sanitise and escape some parameters before using them in an SQL statement via an AJAX action available to unauthenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0037"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0037, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0037.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])radius=1 and \(SELECT 7741 FROM \(SELECT\(SLEEP\(7\)\)\)hlAf\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_0099_simple_urls {
    meta:
        attack_type = "cve_2023_0099"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Simple URLs < 115 - Cross Site Scripting: The plugin does not sanitise and escape some parameters before outputting them back in some pages, leading to Reflected Cross-Site Scripting which could be used against high privilege users such as admin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0099"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0099, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0099.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/simple-urls\/admin\/assets\/js\/import-js\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_0159_extensive_vc_addons_for_wpbake {
    meta:
        attack_type = "cve_2023_0159"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Extensive VC Addons for WPBakery page builder < 1.9.1 - Unauthenticated RCE: The plugin does not validate a parameter passed to the php extract function when loading templates, allowing an unauthenticated attacker to override the template path to read arbitrary files from the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0159"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0159, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0159.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])action=extensive_vc_init_shortcode_pagination(&|$)/ nocase
        $param1 = /(^|[?&;])options\[template\]=php:\/\/filter\/convert\.base64-encode\/resource=\.\.\/wp-config\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_0236_tutor_lms {
    meta:
        attack_type = "cve_2023_0236"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Tutor LMS <2.0.10 - Cross Site Scripting: WordPress Tutor LMS plugin before 2.0.10 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape the reset_key and user_id parameters before outputting then back in attributes. An attacker can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0236"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0236, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0236.yaml"
        response_type = "xss"
    strings:
        $path0 = "/dashboard/retrieve-password/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_0297_pyload {
    meta:
        attack_type = "cve_2023_0297"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PyLoad 0.5.0 - Pre-auth Remote Code Execution (RCE): Code Injection in GitHub repository pyload/pyload prior to 0.5.0b3.dev31."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0297"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0297, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0297.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])packages=YyVIbzmZ(&|$)/ nocase
        $param1 = /(^|[?&;])crypted=ZbIlxWYe(&|$)/ nocase
        $param2 = /(^|[?&;])passwords=oJFFUtTw(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_0448_wp_helper_premium {
    meta:
        attack_type = "cve_2023_0448"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP Helper Lite < 4.3 - Cross-Site Scripting: The WP Helper Lite WordPress plugin, in versions < 4.3, returns all GET parameters unsanitized in the response, resulting in a reflected cross-site scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0448"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0448, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0448.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=surveySubmit(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_0514_membership_database {
    meta:
        attack_type = "cve_2023_0514"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Membership Database <= 1.0 - Cross-Site Scripting: Membership Database before 1.0 is susceptible to cross-site scripting via the tab parameter due to insufficient input sanitization and output escaping. An attacker can inject arbitrary script in the browser of an unsuspecting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0514"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0514, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0514.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=member-database\/list_members\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_0527_online_security_guards_hiring {
    meta:
        attack_type = "cve_2023_0527"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Online Security Guards Hiring System - Cross-Site Scripting: A vulnerability was found in PHPGurukul Online Security Guards Hiring System 1.0 and classified as problematic. Affected by this issue is some unknown functionality of the file search-request.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0527"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0527, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0527.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/search-request\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_0562_bank_locker_management_system {
    meta:
        attack_type = "cve_2023_0562"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Bank Locker Management System v1.0 - SQL Injection: A vulnerability was found in PHPGurukul Bank Locker Management System 1.0. It has been rated as critical. Affected by this issue is some unknown functionality of the file index.php of the component Login. The manipulation of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0562"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0562, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0562.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/banker\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_0563_bank_locker_management_system {
    meta:
        attack_type = "cve_2023_0563"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Bank Locker Management System - Cross-Site Scripting: A vulnerability classified as problematic has been found in PHPGurukul Bank Locker Management System 1.0. This affects an unknown part of the file add-locker-form.php of the component Assign Locker. The manipulation of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0563"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0563, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0563.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/search-locker-details\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_0669_goanywhere_managed_file_transf {
    meta:
        attack_type = "cve_2023_0669"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Fortra GoAnywhere MFT - Remote Code Execution: Fortra GoAnywhere MFT is susceptible to remote code execution via unsafe deserialization of an arbitrary attacker-controlled object. This stems from a pre-authentication command injection vulnerability in the License Response."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0669"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0669, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0669.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/goanywhere\/lic\/accept(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_0676_phpipam {
    meta:
        attack_type = "cve_2023_0676"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "phpIPAM 1.5.1 - Cross-site Scripting: Cross-site Scripting (XSS) - Reflected in GitHub repository phpipam/phpipam prior to 1.5.1."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0676"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0676, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0676.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/app\/tools\/ip-calculator\/bw-calculator-result\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_0678_phpipam {
    meta:
        attack_type = "cve_2023_0678"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PHPIPAM <v1.5.1 - Missing Authorization: In phpIPAM 1.5.1, an unauthenticated user could download the list of high-usage IP subnets that contains sensitive information such as a subnet description, IP ranges, and usage rates via find_full_subnets.php endpoint. The bug lies in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0678"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0678, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0678.yaml"
    strings:
        $path0 = /\/functions\/scripts\/find_full_subnets\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_0900_pricing_table_builder {
    meta:
        attack_type = "cve_2023_0900"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AP Pricing Tables Lite <= 1.1.6 - SQL Injection: The plugin does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by high-privilege users such as admins."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0900"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0900, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0900.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])page=ap-pricing-tables-lite(&|$)/ nocase
        $param1 = /(^|[?&;])action=backend_ajax(&|$)/ nocase
        $param2 = /(^|[?&;])_action=copy_table(&|$)/ nocase
        $param3 = /(^|[?&;])table_id=1 AND \(SELECT 2035 FROM \(SELECT\(SLEEP\(10\)\)\)A\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_0942_japanized_for_woocommerce {
    meta:
        attack_type = "cve_2023_0942"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Japanized for WooCommerce <2.5.5 - Cross-Site Scripting: WordPress Japanized for WooCommerce plugin before 2.5.5 is susceptible to cross-site scripting via the tab parameter due to insufficient input sanitization and output escaping. An attacker can inject arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0942"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0942, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0942.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=wc4jp-options(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_0947_flatpress {
    meta:
        attack_type = "cve_2023_0947"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Flatpress < 1.3 - Path Traversal: Path Traversal in GitHub repository flatpressblog/flatpress prior to 1.3."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0947"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0947, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0947.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/flatpress/fp-content/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_0948_japanized_for_woocommerce {
    meta:
        attack_type = "cve_2023_0948"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Japanized for WooCommerce <2.5.8 - Cross-Site Scripting: WordPress Japanized for WooCommerce plugin before 2.5.8 is susceptible to cross-site scripting via the tab parameter due to insufficient input sanitization and output escaping. An attacker can inject arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0948"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0948, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0948.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=peachpay(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_0968_watu_quiz {
    meta:
        attack_type = "cve_2023_0968"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Watu Quiz <3.3.9.1 - Cross-Site Scripting: WordPress Watu Quiz plugin before 3.3.9.1 is susceptible to cross-site scripting. The plugin does not sanitize and escape some parameters, such as email, dn, date, and points, before outputting then back in a page. An."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-0968"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-0968, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-0968.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=watu_takings(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_1020_wp_live_chat_shoutbox {
    meta:
        attack_type = "cve_2023_1020"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Steveas WP Live Chat Shoutbox <= 1.4.2 - SQL Injection: The Steveas WP Live Chat Shoutbox WordPress plugin through 1.4.2 does not sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1020"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1020, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1020.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=shoutbox-ajax-update-messages(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_1080_gn_publisher {
    meta:
        attack_type = "cve_2023_1080"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress GN Publisher <1.5.6 - Cross-Site Scripting: WordPress GN Publisher plugin before 1.5.6 is susceptible to cross-site scripting via the tab parameter due to insufficient input sanitization and output escaping. An attacker can inject arbitrary script in the browser of an."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1080"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1080, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1080.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=gn-publisher-settings(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_1454_jeecg_boot {
    meta:
        attack_type = "cve_2023_1454"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Jeecg-boot 3.5.0 qurestSql - SQL Injection: A vulnerability classified as critical has been found in jeecg-boot 3.5.0. This affects an unknown part of the file jmreport/qurestSql. The manipulation of the argument apiSelectId leads to sql injection. It is possible to initiate."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1454"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1454, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1454.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/jeecg-boot\/jmreport\/qurestSql(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_1546_mycryptocheckout {
    meta:
        attack_type = "cve_2023_1546"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MyCryptoCheckout < 2.124 - Cross-Site Scripting: The MyCryptoCheckout WordPress plugin before 2.124 does not escape some URLs before outputting them in attributes, leading to Reflected Cross-Site Scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1546"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1546, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1546.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=mycryptocheckout(&|$)/ nocase
        $param1 = /(^|[?&;])tab=autosettlements(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_1671_web_appliance {
    meta:
        attack_type = "cve_2023_1671"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Sophos Web Appliance - Remote Code Execution: A pre-auth command injection vulnerability in the warn-proceed handler of Sophos Web Appliance older than version 4.3.10.4 allows execution of arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1671"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1671, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1671.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])args_reason=filetypewarn(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_1698_compact_controller_100_firmwar {
    meta:
        attack_type = "cve_2023_1698"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WAGO - Remote Command Execution: In multiple products of WAGO, a vulnerability allows an unauthenticated, remote attacker to create new users and change the device configuration which can result in unintended behavior, Denial of Service, and full system compromise."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1698"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1698, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1698.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/wbm\/plugins\/wbm-legal-information\/platform\/pfcXXX\/licenses\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_1719_bitrix24 {
    meta:
        attack_type = "cve_2023_1719"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Bitrix Component - Cross-Site Scripting: Global variable extraction in bitrix/modules/main/tools.php in Bitrix24 22.0.300 allows unauthenticated remote attackers to (1) enumerate attachments on the server and (2) execute arbitrary JavaScript code in the victims browser, and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1719"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1719, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1719.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/bitrix\/components\/bitrix\/socialnetwork\.events_dyn\/get_message_2\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_1780_companion_sitemap_generator {
    meta:
        attack_type = "cve_2023_1780"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Companion Sitemap Generator < 4.5.3 - Cross-Site Scripting: The plugin does not sanitise and escape some parameters before outputting them back in pages, leading to Reflected Cross-Site Scripting which could be used against high privilege users such as admin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1780"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1780, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1780.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=csg-sitemap(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_1835_ninja_forms {
    meta:
        attack_type = "cve_2023_1835"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ninja Forms < 3.6.22 - Cross-Site Scripting: Ninja Forms before 3.6.22 is susceptible to cross-site scripting via the page parameter due to insufficient input sanitization and output escaping. An attacker can inject arbitrary script in the browser of an unsuspecting user in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1835"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1835, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1835.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=nf-processing(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_1880_phpmyfaq {
    meta:
        attack_type = "cve_2023_1880"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Phpmyfaq v3.1.11 - Cross-Site Scripting: Phpmyfaq v3.1.11 is vulnerable to reflected XSS in send2friend because the 'artlang' parameter is not sanitized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1880"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1880, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1880.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=send2friend(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_1890_tablesome {
    meta:
        attack_type = "cve_2023_1890"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Tablesome < 1.0.9 - Cross-Site Scripting: Tablesome before 1.0.9 is susceptible to cross-site scripting via the tab parameter due to insufficient input sanitization and output escaping. An attacker can inject arbitrary script in the browser of an unsuspecting user in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1890"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1890, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1890.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=tablesome_cpt(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_1892_sidekiq {
    meta:
        attack_type = "cve_2023_1892"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Sidekiq < 7.0.8 - Cross-Site Scripting: An XSS vulnerability on a Sidekiq admin panel can pose serious risks to the security and functionality of the system."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1892"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1892, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1892.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/metrics\/SanityChecksJob(\/|;|$)/ nocase
        $path1 = /\/metrics\/ActiveStorage::PurgeJob(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_1893_login_configurator {
    meta:
        attack_type = "cve_2023_1893"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Login Configurator <=2.1 - Cross-Site Scripting: Login Configurator WordPress plugin <= 2.1 contains a reflected cross-site scripting caused by improper escaping of URL parameter before outputting it to the page, letting attackers execute scripts in the context of site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-1893"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-1893, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-1893.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=login-configurator-options(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_20073_rv340_firmware {
    meta:
        attack_type = "cve_2023_20073"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cisco VPN Routers - Unauthenticated Arbitrary File Upload: A vulnerability in the web-based management interface of Cisco RV340, RV340W, RV345, and RV345P Dual WAN Gigabit VPN Routers could allow an unauthenticated, remote attacker to upload arbitrary files to an affected."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-20073"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-20073, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-20073.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/api\/operations\/ciscosb-file:form-file-upload(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2009_pretty_url {
    meta:
        attack_type = "cve_2023_2009"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Pretty Url <= 1.5.4 - Cross-Site Scripting: Plugin does not sanitize and escape the URL field in the plugin settings, which could allow high-privilege users to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2009"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2009, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2009.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=prettyurls(&|$)/ nocase
        $param1 = /(^|[?&;])category=accordions~post_type(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_2059_dedecms {
    meta:
        attack_type = "cve_2023_2059"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DedeCMS 5.7.87 - Directory Traversal: Directory traversal vulnerability in DedeCMS 5.7.87 allows reading sensitive files via the $activepath parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2059"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2059, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2059.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/include\/dialog\/select_templets\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_20864_aria_operations_for_logs {
    meta:
        attack_type = "cve_2023_20864"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "VMware Aria Operations for Logs - Unauthenticated Remote Code Execution: VMware Aria Operations for Logs contains a deserialization vulnerability. An unauthenticated, malicious actor with network access to VMware Aria Operations for Logs may be able to execute arbitrary code as."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-20864"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-20864, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-20864.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/v2\/internal\/cluster\/applyMembership(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_20887_vrealize_network_insight {
    meta:
        attack_type = "cve_2023_20887"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "VMware VRealize Network Insight - Remote Code Execution: VMWare Aria Operations for Networks (vRealize Network Insight) is vulnerable to command injection when accepting user input through the Apache Thrift RPC interface. This vulnerability allows a remote unauthenticated."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-20887"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-20887, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-20887.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/saas\.\/resttosaasservlet(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_20888_vrealize_network_insight {
    meta:
        attack_type = "cve_2023_20888"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "VMware Aria Operations for Networks - Remote Code Execution: Aria Operations for Networks contains an authenticated deserialization vulnerability. A malicious actor with network access to VMware Aria Operations for Networks and valid 'member' role credentials may be able to."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-20888"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-20888, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-20888.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/events\/push-notifications(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_20889_vrealize_network_insight {
    meta:
        attack_type = "cve_2023_20889"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "VMware Aria Operations for Networks - Code Injection Information Disclosure Vulnerability: Aria Operations for Networks contains an information disclosure vulnerability. A malicious actor with network access to VMware Aria Operations for Networks may be able to perform a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-20889"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-20889, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-20889.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/pdfexport(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2130_purchase_order_management_syst {
    meta:
        attack_type = "cve_2023_2130"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Purchase Order Management v1.0 - SQL Injection: A vulnerability classified as critical has been found in SourceCodester Purchase Order Management System 1.0. Affected is an unknown function of the file /admin/suppliers/view_details.php of the component GET Parameter Handler.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2130"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2130, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2130.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/admin\/suppliers\/view_details\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2178_aajoda_testimonials {
    meta:
        attack_type = "cve_2023_2178"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Aajoda Testimonials < 2.2.2 - Cross-Site Scripting: The plugin does not sanitize and escape some of its settings, which could allow high-privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2178"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2178, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2178.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=aajoda-testimonials(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_22047_peoplesoft_enterprise {
    meta:
        attack_type = "cve_2023_22047"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Oracle Peoplesoft - Unauthenticated File Read: Vulnerability in the PeopleSoft Enterprise PeopleTools product of Oracle PeopleSoft (component- Portal). Supported versions that are affected are 8.59 and 8.60. Easily exploitable vulnerability allows unauthenticated attacker with."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-22047"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-22047, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-22047.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])wsrp-url=file:\/\/\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_22232_connect {
    meta:
        attack_type = "cve_2023_22232"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Adobe Connect < 12.1.5 - Local File Disclosure: Adobe Connect versions 11.4.5 (and earlier), 12.1.5 (and earlier) are affected by an Improper Access Control vulnerability that could result in a Security feature bypass. An attacker could leverage this vulnerability to impact the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-22232"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-22232, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-22232.yaml"
    strings:
        $param0 = /(^|[?&;])download-url=\/_a7\/p49dm7f4qjyt\/output\/(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_2224_seo {
    meta:
        attack_type = "cve_2023_2224"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Seo By 10Web < 1.2.7 - Cross-Site Scripting: The SEO by 10Web WordPress plugin before 1.2.7 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2224"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2224, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2224.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=wdseo_sitemap(&|$)/ nocase
        $param1 = /(^|[?&;])wd_settings\[additional_pages\]\[frequency\]\[\]=always(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_2227_modoboa {
    meta:
        attack_type = "cve_2023_2227"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Modoboa < 2.1.0 - Improper Authorization: Improper Authorization in GitHub repository modoboa/modoboa prior to 2.1.0."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2227"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2227, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2227.yaml"
    strings:
        $path0 = "/api/v2/parameters/core/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_22463_kubepi {
    meta:
        attack_type = "cve_2023_22463"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "KubePi JwtSigKey - Admin Authentication Bypass: KubePi is a k8s panel. The jwt authentication function of KubePi through version 1.6.2 uses hard-coded Jwtsigkeys, resulting in the same Jwtsigkeys for all online projects. This means that an attacker can forge any jwt token to."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-22463"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-22463, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-22463.yaml"
    strings:
        $path0 = /\/kubepi\/api\/v1\/users(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_22480_kubeoperator {
    meta:
        attack_type = "cve_2023_22480"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "KubeOperator Foreground `kubeconfig` - File Download: KubeOperator is an open source Kubernetes distribution focused on helping enterprises plan, deploy and operate production-level K8s clusters. In KubeOperator versions 3.16.3 and below, API interfaces with unauthorized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-22480"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-22480, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-22480.yaml"
    strings:
        $path0 = /\/api\/v1\/clusters\/kubeconfig\/k8s(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2252_directorist {
    meta:
        attack_type = "cve_2023_2252"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Directorist < 7.5.4 - Local File Inclusion: Directorist before 7.5.4 is susceptible to Local File Inclusion as it does not validate the file parameter when importing CSV files."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2252"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2252, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2252.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])post_type=at_biz_dir(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_22621_strapi {
    meta:
        attack_type = "cve_2023_22621"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Strapi Versions <=4.5.5 - SSTI to Remote Code Execution: Strapi through 4.5.5 allows authenticated Server-Side Template Injection (SSTI) that can be exploited to execute arbitrary code on the server. A remote attacker with access to the Strapi admin panel can inject a crafted."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-22621"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-22621, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-22621.yaml"
        response_type = "template_eval"
    strings:
        $path0 = /\/users-permissions\/advanced(\/|;|$)/ nocase
        $path1 = /\/users-permissions\/email-templates(\/|;|$)/ nocase
        $path2 = /\/api\/auth\/local\/register(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2272_tiempo {
    meta:
        attack_type = "cve_2023_2272"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Tiempo.com <= 0.1.2 - Cross-Site Scripting: Tiempo.com before 0.1.2 is susceptible to cross-site scripting via the page parameter due to insufficient input sanitization and output escaping. An attacker can inject arbitrary script in the browser of an unsuspecting user in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2272"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2272, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2272.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=tiempocom\/app\/admin\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_22893_strapi {
    meta:
        attack_type = "cve_2023_22893"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Strapi Versions <=4.5.6 - Authentication Bypass: Strapi through 4.5.5 does not verify the access or ID tokens issued during the OAuth flow when the AWS Cognito login provider is used for authentication. A remote attacker could forge an ID token that is signed using the 'None'."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-22893"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-22893, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-22893.yaml"
    strings:
        $path0 = /\/api\/auth\/cognito\/callback(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_22952_sugarcrm {
    meta:
        attack_type = "cve_2023_22952"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "SugarCRM Unauthenticated - Remote Code Execution: In SugarCRM before 12.0. Hotfix 91155, a crafted request can inject custom PHP code through the EmailTemplates because of missing input validation."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-22952"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-22952, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-22952.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/cache/images/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_23063_nvt_web_server {
    meta:
        attack_type = "cve_2023_23063"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cellinx NVT Web Server - Local File Disclosure: Cellinx NVT v1.0.6.002b was discovered to contain a local file disclosure vulnerability via the component /cgi-bin/GetFileContent.cgi."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-23063"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-23063, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-23063.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/cgi-bin\/GetFileContent\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2309_wpforo_forum {
    meta:
        attack_type = "cve_2023_2309"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "wpForo Forum <= 2.1.8 - Cross-Site Scripting: The wpForo Forum plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the wpforo_debug function in versions up to, and including, 2.1.8 due to insufficient input sanitization and output escaping. This makes it."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2309"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2309, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2309.yaml"
        response_type = "xss"
    strings:
        $path0 = "/community/main-forum/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_23161_art_gallery_management_system {
    meta:
        attack_type = "cve_2023_23161"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Art Gallery Management System Project v1.0 - Cross-Site Scripting: A reflected cross-site scripting (XSS) vulnerability in Art Gallery Management System Project v1.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the artname."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-23161"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-23161, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-23161.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/product\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_23491_quick_event_manager {
    meta:
        attack_type = "cve_2023_23491"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Quick Event Manager < 9.7.5 - Cross-Site Scripting: The Quick Event Manager WordPress Plugin, version < 9.7.5, is affected by a reflected cross-site scripting vulnerability in the 'category' parameter of its 'qem_ajax_calendar' action."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-23491"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-23491, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-23491.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=qem_ajax_calendar(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_23492_login_with_phone_number {
    meta:
        attack_type = "cve_2023_23492"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Login with Phone Number - Cross-Site Scripting: Login with Phone Number, versions < 1.4.2, is affected by an reflected XSS vulnerability in the login-with-phonenumber.php' file in the 'lwp_forgot_password()' function."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-23492"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-23492, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-23492.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=lwp_forgot_password(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_23897_simple_mobile_url_redirect {
    meta:
        attack_type = "cve_2023_23897"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ozette Plugins - Cross-Site Request Forgery: An attacker can update, create, and remove the site's mobile redirects via a forged request granted they can trick a site administrator into performing an action such as clicking on a link."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-23897"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-23897, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-23897.yaml"
    strings:
        $param0 = /(^|[?&;])page=simple-mobile-url-redirect-1\.7\/mobile-redirect\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_24278_squidex {
    meta:
        attack_type = "cve_2023_24278"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Squidex <7.4.0 - Cross-Site Scripting: Squidex before 7.4.0 contains a cross-site scripting vulnerability via the squid.svg endpoint. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-24278"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-24278, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-24278.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])title=Not Found(&|$)/ nocase
        $param1 = /(^|[?&;])text=This is not the page you are looking for!(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_24322_mojoportal {
    meta:
        attack_type = "cve_2023_24322"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "mojoPortal 2.7.0.0 - Cross-Site Scripting: mojoPortal 2.7.0.0 contains a cross-site scripting vulnerability in the FileDialog.aspx component, which can allow an attacker to execute arbitrary web scripts or HTML via a crafted payload injected into the ed and tbi parameters."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-24322"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-24322, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-24322.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/Dialog\/FileDialog\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2437_userpro {
    meta:
        attack_type = "cve_2023_2437"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "UserPro <= 5.1.1 - Authentication Bypass: The UserPro plugin for WordPress through 5.1.1 allows authentication bypass via the userpro_fbconnect AJAX action."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2437"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2437, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2437.yaml"
    strings:
        $param0 = /(^|[?&;])action=userpro_fbconnect(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_24489_sharefile_storage_zones_contro {
    meta:
        attack_type = "cve_2023_24489"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Citrix ShareFile StorageZones Controller - Unauthenticated Remote Code Execution: A vulnerability has been discovered in the customer-managed ShareFile storage zones controller which, if exploited, could allow an unauthenticated attacker to remotely compromise the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-24489"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-24489, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-24489.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/documentum\/upload\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_24657_phpipam {
    meta:
        attack_type = "cve_2023_24657"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "phpIPAM - 1.6 - Cross-Site Scripting: phpIPAM 1.6 contains a cross-site scripting vulnerability via the closeClass parameter at /subnet-masks/popup.php. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-24657"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-24657, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-24657.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/app\/tools\/subnet-masks\/popup\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_24733_pmb {
    meta:
        attack_type = "cve_2023_24733"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PMB 7.4.6 - Cross-Site Scripting: PMB 7.4.6 contains a cross-site scripting vulnerability via the query parameter at /admin/convert/export_z3950_new.php. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-24733"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-24733, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-24733.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/pmb\/admin\/convert\/export_z3950_new\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_24737_pmb {
    meta:
        attack_type = "cve_2023_24737"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PMB v7.4.6 - Cross-Site Scripting: PMB v7.4.6 allows an attacker to perform a reflected XSS on export_z3950.php via the 'query' parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-24737"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-24737, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-24737.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/pmb\/admin\/convert\/export_z3950\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2518_easy_forms_for_mailchimp {
    meta:
        attack_type = "cve_2023_2518"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Easy Forms for Mailchimp Plugin < 6.8.9 - Cross-Site Scripting: The Easy Forms for Mailchimp plugin before version 6.8.9 contains a reflected cross-site scripting vulnerability. The plugin does not properly sanitize and escape the sql_error parameter before outputting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2518"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2518, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2518.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=yikes-mailchimp-edit-form(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_25280_dir820la1_firmware {
    meta:
        attack_type = "cve_2023_25280"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "D-Link DIR820LA1_FW105B03 'ping_addr' - OS Command Injection: OS Command injection vulnerability in D-Link DIR820LA1_FW105B03 allows attackers to escalate privileges to root via a crafted payload with the ping_addr parameter to ping.ccp."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-25280"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-25280, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-25280.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])ccp_act=pingV4Msg(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_25346_churchcrm {
    meta:
        attack_type = "cve_2023_25346"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ChurchCRM 4.5.3 - Cross-Site Scripting: A reflected cross-site scripting (XSS) vulnerability in ChurchCRM 4.5.3 allows remote attackers to inject arbitrary web script or HTML via the id parameter of /churchcrm/v2/family/not-found."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-25346"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-25346, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-25346.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/v2\/person\/not-found(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_25573_metersphere {
    meta:
        attack_type = "cve_2023_25573"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Metersphere - Arbitrary File Read: Metersphere is an open source continuous testing platform. In affected versions an improper access control vulnerability exists in `/api/jmeter/download/files`, which allows any user to download any file without authentication. This issue may."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-25573"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-25573, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-25573.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/api\/jmeter\/download\/files(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_25717_ruckus_wireless_admin {
    meta:
        attack_type = "cve_2023_25717"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Ruckus Wireless Admin - Remote Code Execution: Ruckus Wireless Admin through 10.4 allows Remote Code Execution via an unauthenticated HTTP GET Request."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-25717"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-25717, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-25717.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/forms\/doLogin(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_25826_opentsdb {
    meta:
        attack_type = "cve_2023_25826"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OpenTSDB <= 2.4.1 - Unauthenticated RCE via Gnuplot Injection: OpenTSDB contains a command injection caused by insufficient validation of parameters passed to the legacy HTTP query API, letting attackers inject crafted OS commands and execute malicious code, exploit requires."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-25826"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-25826, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-25826.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/suggest(\/|;|$)/ nocase
        $param0 = /(^|[?&;])type=metrics(&|$)/ nocase
        $param1 = /(^|[?&;])start=1h-ago(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_26035_zoneminder {
    meta:
        attack_type = "cve_2023_26035"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ZoneMinder Snapshots - Command Injection: ZoneMinder is a free, open source Closed-circuit television software application for Linux which supports IP, USB and Analog cameras.Versions prior to 1.36.33 and 1.37.33 are vulnerable to Unauthenticated Remote Code Execution via."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-26035"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-26035, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-26035.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])view=snapshot(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_26067_cxtpc_firmware {
    meta:
        attack_type = "cve_2023_26067"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Lexmark Printers - Command Injection: Certain Lexmark devices through 2023-02-19 mishandle Input Validation (issue 1 of 4)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-26067"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-26067, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-26067.yaml"
    strings:
        $path0 = /\/cgi-bin\/fax_change_faxtrace_settings(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2624_kivicare {
    meta:
        attack_type = "cve_2023_2624"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "KiviCare WordPress Plugin - Cross-Site Scripting: The KiviCare WordPress plugin before 3.2.1 does not sanitise and escape the 'filterType' parameter, leading to Reflected Cross-Site Scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2624"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2624, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2624.yaml"
    strings:
        $param0 = /(^|[?&;])route_name=get_weekly_appointment(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_26255_stagil_navigation {
    meta:
        attack_type = "cve_2023_26255"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "STAGIL Navigation for Jira Menu & Themes <2.0.52 - Local File Inclusion: STAGIL Navigation for Jira Menu & Themes plugin before 2.0.52 is susceptible to local file inclusion via modifying the fileName parameter to the snjCustomDesignConfig endpoint. An attacker can inject."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-26255"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-26255, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-26255.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/plugins\/servlet\/snjCustomDesignConfig(\/|;|$)/ nocase
        $param0 = /(^|[?&;])fileName=\.\.\/dbconfig\.xmlpasswd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_26256_stagil_navigation {
    meta:
        attack_type = "cve_2023_26256"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "STAGIL Navigation for Jira Menu & Themes <2.0.52 - Local File Inclusion: STAGIL Navigation for Jira Menu & Themes plugin before 2.0.52 is susceptible to local file inclusion via modifying the fileName parameter to the snjFooterNavigationConfig endpoint. An attacker can inject."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-26256"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-26256, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-26256.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/plugins\/servlet\/snjFooterNavigationConfig(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_26258_udp {
    meta:
        attack_type = "cve_2023_26258"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Arcserve UDP <= 9.0.6034 - Authentication Bypass: Arcserve UDP through 9.0.6034 allows authentication bypass. The method getVersionInfo at WebServiceImpl/services/FlashServiceImpl leaks the AuthUUID token. This token can be used at."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-26258"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-26258, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-26258.yaml"
    strings:
        $path0 = /\/WebServiceImpl\/services\/FlashServiceImpl(\/|;|$)/ nocase
        $path1 = /\/WebServiceImpl\/services\/VirtualStandbyServiceImpl(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_26347_coldfusion {
    meta:
        attack_type = "cve_2023_26347"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Adobe Coldfusion - Authentication Bypass: Adobe ColdFusion versions 2023.5 (and earlier) and 2021.11 (and earlier) are affected by an Improper Access Control vulnerability that could result in a Security feature bypass. An unauthenticated attacker could leverage this."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-26347"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-26347, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-26347.yaml"
    strings:
        $path0 = /\/hax\/\.\.CFIDE\/adminapi\/administrator\.cfc(\/|;|$)/ nocase
        $param0 = /(^|[?&;])method=getBuildNumber(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_26360_coldfusion {
    meta:
        attack_type = "cve_2023_26360"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Adobe ColdFusion - Local File Read: Unauthenticated Arbitrary File Read vulnerability due to deserialization of untrusted data in Adobe ColdFusion. The vulnerability affects ColdFusion 2021 Update 5 and earlier as well as ColdFusion 2018 Update 15 and earlier"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-26360"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-26360, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-26360.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/cf_scripts\/scripts\/ajax\/ckeditor\/plugins\/filemanager\/iedit\.cfc(\/|;|$)/ nocase
        $path1 = /\/cfusion\/\.\.CFIDE\/wizards\/common\/utils\.cfc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_26802_dcbi_netlog_lab_firmware {
    meta:
        attack_type = "cve_2023_26802"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "DCBI-Netlog-LAB v1.0 - Command Injection: An issue in the component /network_config/nsg_masq.cgi of DCN (Digital China Networks) DCBI-Netlog-LAB v1.0 allows attackers to bypass authentication and execute arbitrary commands via a crafted request."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-26802"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-26802, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-26802.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cgi-bin\/network_config\/nsg_masq\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_26842_churchcrm {
    meta:
        attack_type = "cve_2023_26842"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ChurchCRM 4.5.3 - Cross-Site Scripting: A stored Cross-site scripting (XSS) vulnerability in ChurchCRM 4.5.3 allows remote attackers to inject arbitrary web script or HTML via the OptionManager.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-26842"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-26842, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-26842.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/OptionManager\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])mode=classes(&|$)/ nocase
        $param1 = /(^|[?&;])1name=Member(&|$)/ nocase
        $param2 = /(^|[?&;])2name=Regular Attender(&|$)/ nocase
        $param3 = /(^|[?&;])4name=Non-Attender(&|$)/ nocase
        $param4 = /(^|[?&;])5name=Non-Attender \(staff\)(&|$)/ nocase
        $param5 = /(^|[?&;])AddField=Add New Person Classification(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_26843_churchcrm {
    meta:
        attack_type = "cve_2023_26843"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ChurchCRM 4.5.3 - Cross-Site Scripting: A stored Cross-site scripting (XSS) vulnerability in ChurchCRM 4.5.3 allows remote attackers to inject arbitrary web script or HTML via the NoteEditor.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-26843"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-26843, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-26843.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/NoteEditor\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_27008_atutor {
    meta:
        attack_type = "cve_2023_27008"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ATutor < 2.2.1 - Cross Site Scripting: ATutor < 2.2.1 was discovered with a vulnerability, a reflected cross-site scripting (XSS), in ATtutor 2.2.1 via token body parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27008"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27008, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27008.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/atutor\/login\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_27032_popup_module_on_entering_exit {
    meta:
        attack_type = "cve_2023_27032"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PrestaShop AdvancedPopupCreator - SQL Injection: In the module Advanced Popup Creator (advancedpopupcreator) from Idnovate for PrestaShop, a guest can perform SQL injection in affected versions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27032"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27032, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27032.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/module\/advancedpopupcreator\/popup(\/|;|$)/ nocase
        $param0 = /(^|[?&;])availablePopups=if\(now\(\)=sysdate\(\),sleep\(6\),0\)(&|$)/ nocase
        $param1 = /(^|[?&;])fromController=product(&|$)/ nocase
        $param2 = /(^|[?&;])availablePopups=-8514\) OR 6158=6158-- eKWg(&|$)/ nocase
        $param3 = /(^|[?&;])availablePopups=-8514\) OR 6158=6157-- eKWg(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_27034_jms_blog {
    meta:
        attack_type = "cve_2023_27034"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Jms Blog - SQL Injection: The module Jms Blog (jmsblog) from Joommasters contains a Time Based SQL injection vulnerability. This module is for the PrestaShop e-commerce platform and mainly provided with joommasters PrestaShop themes"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27034"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27034, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27034.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])0'XOR\(if\(now\(\)=sysdate\(\),sleep\(6\),0\)\)XOR'Z(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_27159_appwrite {
    meta:
        attack_type = "cve_2023_27159"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Appwrite <=1.2.1 - Server-Side Request Forgery: Appwrite through 1.2.1 is susceptible to server-side request forgery via the component /v1/avatars/favicon. An attacker can potentially access network resources and sensitive information via a crafted GET request, thereby also."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27159"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27159, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27159.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/v1\/avatars\/favicon(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_27163_request_baskets {
    meta:
        attack_type = "cve_2023_27163"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Request-Baskets <= 1.2.1 - Server Side Request Forgery: Request-Baskets <= 1.2.1 allows unauthenticated SSRF via the forward_url parameter when creating a new basket."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27163"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27163, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27163.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/baskets/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_27179_gdidees_cms {
    meta:
        attack_type = "cve_2023_27179"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GDidees CMS v3.9.1 - Arbitrary File Download: GDidees CMS v3.9.1 and lower was discovered to contain an arbitrary file download vulenrability via the filename parameter at /_admin/imgdownload.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27179"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27179, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27179.yaml"
    strings:
        $path0 = /\/_admin\/imgdownload\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])filename=imgdownload\.php(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_27292_opencats {
    meta:
        attack_type = "cve_2023_27292"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "OpenCATS - Open Redirect: OpenCATS contains an open redirect vulnerability due to improper validation of user-supplied GET parameters. This, in turn, exposes OpenCATS to possible template injection and obtaining sensitive information, modifying data, and/or executing."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27292"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27292, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27292.yaml"
    strings:
        $param0 = /(^|[?&;])a=previewPage(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_2732_mstore_api {
    meta:
        attack_type = "cve_2023_2732"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MStore API <= 3.9.2 - Authentication Bypass: The MStore API plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 3.9.2. This is due to insufficient verification on the user being supplied during the add listing REST API request through."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2732"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2732, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2732.yaml"
    strings:
        $path0 = /\/wp-json\/wp\/v2\/add-listing(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2734_mstore_api {
    meta:
        attack_type = "cve_2023_2734"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MStore API <= 3.9.1 - Authentication Bypass: The MStore API plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 3.9.1. This is due to insufficient verification on the user being supplied during the cart sync from mobile REST API request."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2734"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2734, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2734.yaml"
    strings:
        $path0 = /\/wp-json\/api\/flutter_woo\/cart(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_27351_papercut_mf_papercut_ng {
    meta:
        attack_type = "cve_2023_27351"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "PaperCut NG - Authentication Bypass: This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27351"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27351, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27351.yaml"
    strings:
        $path0 = /\/rpc\/api\/rest\/master\/user\/createInternalUser;\/keepalive(\/|;|$)/ nocase
        $path1 = /\/rpc\/api\/rest\/master\/user\/getExportedUser;\/keepalive(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_27372_spip {
    meta:
        attack_type = "cve_2023_27372"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SPIP - Remote Command Execution: SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27372"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27372, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27372.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])formulaire_action=oubli(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_2745_wordpress_core_6_2 {
    meta:
        attack_type = "cve_2023_2745"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Core <=6.2 - Directory Traversal: WordPress Core is vulnerable to Directory Traversal in versions up to, and including, 6.2, via the wp_lang parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2745"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2745, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2745.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])wp_lang=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/wp-config\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_27482_home_assistant {
    meta:
        attack_type = "cve_2023_27482"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Home Assistant Supervisor - Authentication Bypass: Home Assistant Supervisor is an open source home automation tool. A remotely exploitable vulnerability bypassing authentication for accessing the Supervisor API through Home Assistant has been discovered.This impacts all Home."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27482"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27482, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27482.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/hassio\/app\/\.%2e\/supervisor\/info(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_27587_readtomyshoe {
    meta:
        attack_type = "cve_2023_27587"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ReadToMyShoe - Generation of Error Message Containing Sensitive Information: ReadToMyShoe generates an error message containing sensitive information prior to commit 8533b01. If an error occurs when adding an article, the website shows the user an error message. If the error."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27587"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27587, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27587.yaml"
    strings:
        $path0 = /\/api\/add-article-by-text(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_27624_redirect_after_login {
    meta:
        attack_type = "cve_2023_27624"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Redirect After Login <= 0.1.9 - Admin Stored XSS: Marcelotorres Redirect After Login plugin <= 0.1.9 contains a stored cross-site scripting caused by insufficient sanitization in the login redirect parameter, letting attackers execute scripts in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27624"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27624, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27624.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])option_page=mtral_settings(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_27639_custom_product_designer {
    meta:
        attack_type = "cve_2023_27639"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PrestaShop TshirteCommerce - Directory Traversal: The Custom Product Designer (tshirtecommerce) module for PrestaShop allows HTTP requests to be forged using POST and GET parameters, enabling a remote attacker to perform directory traversal on the system and view the contents."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27639"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27639, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27639.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/tshirtecommerce\/ajax\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])url=\.\/\.\.\/vendor\/jdorn\/sql-formatter\/examples(&|$)/ nocase
        $param1 = /(^|[?&;])file_name=examples\.php(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_27640_custom_product_designer {
    meta:
        attack_type = "cve_2023_27640"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PrestaShop tshirtecommerce - Directory Traversal: The Custom Product Designer (tshirtecommerce) module for PrestaShop allows HTTP requests to be forged using POST and GET parameters, enabling a remote attacker to perform directory traversal on the system and view the contents."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27640"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27640, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27640.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/tshirtecommerce\/fonts\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2766_weaver_office_automation {
    meta:
        attack_type = "cve_2023_2766"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Weaver OA 9.5 - Information Disclosure: A vulnerability was found in Weaver OA 9.5 and classified as problematic. This issue affects some unknown processing of the file /building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini. The manipulation leads to files or directories."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2766"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2766, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2766.yaml"
    strings:
        $path0 = /\/building\/backmgr\/urlpage\/mobileurl\/configfile\/jx2_config\.ini(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_27847_prestashop_xipblog {
    meta:
        attack_type = "cve_2023_27847"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PrestaShop xipblog - SQL Injection: In the blog module (xipblog), an anonymous user can perform SQL injection. Even though the module has been patched in version 2.0.1, the version number was not incremented at the time."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27847"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27847, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27847.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/module\/xipblog\/archive(\/|;|$)/ nocase
        $param0 = /(^|[?&;])page_type=category(&|$)/ nocase
        $param1 = /(^|[?&;])rewrite=news(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_27922_newsletter {
    meta:
        attack_type = "cve_2023_27922"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Newsletter < 7.6.9 - Cross-Site Scripting: The plugin does not escape generated URLs before outputting them in attributes, leading to Reflected Cross-Site Scripting which could be used against high privilege users such as administrators"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-27922"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-27922, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27922.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=newsletter_system_status(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_2825_gitlab {
    meta:
        attack_type = "cve_2023_2825"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GitLab 16.0.0 - Path Traversal: An issue has been discovered in GitLab CE/EE affecting only version 16.0.0. An unauthenticated malicious user can use a path traversal vulnerability to read arbitrary files on the server when an attachment exists in a public project nested within."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2825"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2825, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2825.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])project\[name\]=CVE-2023-2825(&|$)/ nocase
        $param1 = /(^|[?&;])project\[path\]=CVE-2023-2825(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_28432_minio {
    meta:
        attack_type = "cve_2023_28432"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "MinIO Cluster Deployment - Information Disclosure: MinIO is susceptible to information disclosure. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including MINIO_SECRET_KEY."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-28432"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-28432, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-28432.yaml"
    strings:
        $path0 = /\/minio\/bootstrap\/v1\/verify(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_28662_gift_vouchers {
    meta:
        attack_type = "cve_2023_28662"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Wordpress Gift Cards <= 4.3.1 - SQL Injection: The Gift Cards (Gift Vouchers and Packages) WordPress Plugin, version <= 4.3.1, is affected by an unauthenticated SQL injection vulnerability in the template parameter in the wpgv_doajax_voucher_pdf_save_func action."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-28662"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-28662, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-28662.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=wpgv_doajax_voucher_pdf_save_func(&|$)/ nocase
        $param1 = /(^|[?&;])template=LTEgT1IgU0xFRVAoNik=(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_28665_bulk_price_update_for_woocomme {
    meta:
        attack_type = "cve_2023_28665"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Woo Bulk Price Update <2.2.2 - Cross-Site Scripting: The Woo Bulk Price Update WordPress plugin, in versions < 2.2.2, is affected by a reflected cross-site scripting vulnerability in the 'page' parameter to the techno_get_products action, which can only be triggered by an."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-28665"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-28665, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-28665.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=techno_get_products(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_29084_manageengine_admanager_plus {
    meta:
        attack_type = "cve_2023_29084"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ManageEngine ADManager Plus - Command Injection: Zoho ManageEngine ADManager Plus through 7180 allows for authenticated users to exploit command injection via Proxy settings."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-29084"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-29084, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-29084.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/json\/admin\/saveServerSettings(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_29300_coldfusion {
    meta:
        attack_type = "cve_2023_29300"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Adobe ColdFusion - Pre-Auth Remote Code Execution: Adobe ColdFusion versions 2018u16 (and earlier), 2021u6 (and earlier) and 2023.0.0.330468 (and earlier) are affected by a Deserialization of Untrusted Data vulnerability that could result in Arbitrary code execution.."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-29300"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-29300, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-29300.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/CFIDE\/adminapi\/accessmanager\.cfc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_29357_sharepoint_server {
    meta:
        attack_type = "cve_2023_29357"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Microsoft SharePoint - Authentication Bypass: Microsoft SharePoint Server Elevation of Privilege Vulnerability"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-29357"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-29357, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-29357.yaml"
    strings:
        $path0 = /\/_api\/web\/siteusers(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_29439_foogallery {
    meta:
        attack_type = "cve_2023_29439"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "FooGallery plugin <= 2.2.35 - Cross-Site Scripting: Reflected Cross-Site Scripting (XSS) vulnerability in FooPlugins FooGallery plugin <= 2.2.35 versions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-29439"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-29439, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-29439.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=foogallery(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_2948_openemr {
    meta:
        attack_type = "cve_2023_2948"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "OpenEMR < 7.0.1 - Cross-Site Scripting: Cross-site Scripting (XSS) - Reflected in GitHub repository openemr/openemr prior to 7.0.1."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2948"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2948, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2948.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/library\/custom_template\/share_template\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2949_openemr {
    meta:
        attack_type = "cve_2023_2949"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "OpenEMR < 7.0.1 - Cross-site Scripting: Cross-site Scripting (XSS) - Reflected in GitHub repository openemr/openemr prior to 7.0.1."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2949"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2949, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2949.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/interface\/forms\/eye_mag\/js\/eye_base\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_2982_wordpress_social_login_and_reg {
    meta:
        attack_type = "cve_2023_2982"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Miniorange Social Login and Register <= 7.6.3 - Authentication Bypass: The WordPress Social Login and Register (Discord, Google, Twitter, LinkedIn) plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 7.6.4. This is due to insufficient."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-2982"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-2982, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-2982.yaml"
    strings:
        $param0 = /(^|[?&;])option=moopenid(&|$)/ nocase
        $param1 = /(^|[?&;])email=uzmpvjPBmwEO3tFXq0vlJg==(&|$)/ nocase
        $param2 = /(^|[?&;])appName=rlHeqZw2vrPzOiWWfCParA==(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_29887_spreadsheet_reader {
    meta:
        attack_type = "cve_2023_29887"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Nuovo Spreadsheet Reader 0.5.11 - Local File Inclusion: A Local File inclusion vulnerability in test.php in spreadsheet-reader 0.5.11 allows remote attackers to include arbitrary files via the File parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-29887"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-29887, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-29887.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/spreadsheet-reader\/test\.php(\/|;|$)/ nocase
        $path1 = /\/nuovo\/spreadsheet-reader\/test\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_29919_solarview_compact {
    meta:
        attack_type = "cve_2023_29919"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SolarView Compact <= 6.00 - Local File Inclusion: There is an arbitrary read file vulnerability in SolarView Compact 6.00 and below, attackers can bypass authentication to read files through texteditor.php"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-29919"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-29919, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-29919.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/texteditor\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])editfile=\/home\/contec\/data\/outputCtrl\/remote\/2016\/(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_30019_imgproxy {
    meta:
        attack_type = "cve_2023_30019"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Imgproxy <= 3.14.0 - Server-side request forgery (SSRF): imgproxy <=3.14.0 is vulnerable to Server-Side Request Forgery (SSRF) due to a lack of sanitization of the imageURL parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-30019"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-30019, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-30019.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/111/rs:fit:400:400:0:0/plain/http:/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_30150_leocustomajax {
    meta:
        attack_type = "cve_2023_30150"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PrestaShop leocustomajax 1.0 & 1.0.0 - SQL Injection: PrestaShop leocustomajax 1.0 and 1.0.0 are vulnerable to SQL Injection via modules/leocustomajax/leoajax.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-30150"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-30150, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-30150.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])pro_add=if\(now\(\)=sysdate\(\),sleep\(6\),0\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_30192_possearchproducts {
    meta:
        attack_type = "cve_2023_30192"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PrestaShop 'possearchproducts' <= 1.7 - SQL Injection: In the module Search Products (possearchproducts) from PosThemes for PrestaShop, a guest can perform SQL injection in affected versions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-30192"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-30192, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-30192.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])id_category=10\*if\(now\(\)=sysdate\(\),sleep\(6\),0\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_30210_ourphp {
    meta:
        attack_type = "cve_2023_30210"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "OURPHP <= 7.2.0 - Cross Site Scripting: OURPHP <= 7.2.0 is vulnerable to Cross Site Scripting (XSS) via /client/manage/ourphp_tz.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-30210"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-30210, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-30210.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/client\/manage\/ourphp_tz\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_30212_ourphp {
    meta:
        attack_type = "cve_2023_30212"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "OURPHP <= 7.2.0 - Cross Site Scripting: OURPHP <= 7.2.0 is vulnerale to Cross Site Scripting (XSS) via /client/manage/ourphp_out.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-30212"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-30212, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-30212.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/client\/manage\/ourphp_out\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])ourphp_admin=logout(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_30256_qloapps {
    meta:
        attack_type = "cve_2023_30256"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Webkul QloApps 1.5.2 - Cross-site Scripting: Cross Site Scripting vulnerability found in Webkil QloApps v.1.5.2 allows a remote attacker to obtain sensitive information via the back and email_create parameters in the AuthController.php file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-30256"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-30256, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-30256.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])back=xss onfocus=alert\(document\.domain\) autofocus= xss(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_30258_magnusbilling {
    meta:
        attack_type = "cve_2023_30258"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MagnusBilling - Remote Code Execution: Command Injection vulnerability in MagnusSolution magnusbilling 6.x and 7.x allows remote attackers to run arbitrary commands via unauthenticated HTTP request."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-30258"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-30258, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-30258.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/mbilling\/lib\/icepay\/icepay\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_30534_cacti {
    meta:
        attack_type = "cve_2023_30534"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Cacti < 1.2.25 Insecure Deserialization: Cacti is an open source operational monitoring and fault management framework. There are two instances of insecure deserialization in Cacti version 1.2.24."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-30534"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-30534, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-30534.yaml"
    strings:
        $path0 = /\/managers\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_30625_rudder_server {
    meta:
        attack_type = "cve_2023_30625"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Rudder Server < 1.3.0-rc.1 - SQL Injection: Rudder-server is part of RudderStack, an open source Customer Data Platform (CDP). Versions of rudder-server prior to 1.3.0-rc.1 are vulnerable to SQL injection. This issue may lead to Remote Code Execution (RCE) due to the `rudder`."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-30625"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-30625, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-30625.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/v1\/warehouse\/pending-events(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_30777_advanced_custom_fields {
    meta:
        attack_type = "cve_2023_30777"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Advanced Custom Fields < 6.1.6 - Cross-Site Scripting: Advanced Custom Fields beofre 6.1.6 is susceptible to cross-site scripting via the post_status parameter due to insufficient input sanitization and output escaping. An attacker can inject arbitrary script in the browser of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-30777"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-30777, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-30777.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=acf-post-type(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_30943_moodle {
    meta:
        attack_type = "cve_2023_30943"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Moodle - Cross-Site Scripting/Remote Code Execution: The vulnerability was found Moodle which exists because the application allows a user to control path of the older to create in TinyMCE loaders. A remote user can send a specially crafted HTTP request and create arbitrary."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-30943"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-30943, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-30943.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/lib\/editor\/tiny\/loader\.php(\/|;|$)/ nocase
        $path1 = /\/admin\/tool\/filetypes\/edit\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_31465_timekeeper {
    meta:
        attack_type = "cve_2023_31465"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TimeKeeper by FSMLabs - Remote Code Execution: An issue was discovered in FSMLabs TimeKeeper 8.0.17 through 8.0.28. By intercepting requests from various timekeeper streams, it is possible to find the getsamplebacklog call. Some query parameters are passed directly in the URL."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-31465"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-31465, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-31465.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])arg1=2d0ows2x9anpzaorxi9h4csmai08jjor(&|$)/ nocase
        $param1 = /(^|[?&;])arg3=undefined(&|$)/ nocase
        $param2 = /(^|[?&;])arg4=undefined(&|$)/ nocase
        $param3 = /(^|[?&;])arg5=undefined(&|$)/ nocase
        $param4 = /(^|[?&;])arg6=undefined(&|$)/ nocase
        $param5 = /(^|[?&;])arg7=undefined(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_31478_gl_s20_firmware {
    meta:
        attack_type = "cve_2023_31478"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GL.iNET SSID Key Disclosure: An issue was discovered on GL.iNet devices before 3.216. An API endpoint reveals information about the Wi-Fi configuration, including the SSID and key."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-31478"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-31478, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-31478.yaml"
    strings:
        $path0 = /\/api\/router\/mesh\/status(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_31548_churchcrm {
    meta:
        attack_type = "cve_2023_31548"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ChurchCRM v4.5.3 - Cross-Site Scripting: A stored Cross-site scripting (XSS) vulnerability in the FundRaiserEditor.php component of ChurchCRM v4.5.3 allows attackers to execute arbitrary web scripts or HTML via a crafted payload."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-31548"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-31548, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-31548.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/FundRaiserEditor\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_3188_owncast {
    meta:
        attack_type = "cve_2023_3188"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Owncast - Server Side Request Forgery: Server-Side Request Forgery (SSRF) in GitHub repository owncast/owncast prior to 0.1.0."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3188"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3188, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3188.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/api\/remotefollow(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_3197_wordpress_mstore_api_4_0_1 {
    meta:
        attack_type = "cve_2023_3197"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress MStore API <= 4.0.1 - Unauthenticated SQL Injection: MStore API plugin for WordPress up to version 4.0.1 contains an unauthenticated blind SQL injection caused by insufficient escaping of 'id' parameter in SQL queries, letting attackers execute arbitrary SQL commands."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3197"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3197, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3197.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/wp-json\/api\/flutter_multi_vendor\/product-categories(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_32235_ghost {
    meta:
        attack_type = "cve_2023_32235"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ghost CMS < 5.42.1 - Path Traversal: Ghost before 5.42.1 allows remote attackers to read arbitrary files within the active theme's folder via /assets/built%2F..%2F..%2F/ directory traversal. This occurs in frontend/web/middleware/static-theme.js."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-32235"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-32235, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-32235.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/assets/built/../../package.json" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_32243_essential_addons_for_elementor {
    meta:
        attack_type = "cve_2023_32243"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Elementor Lite 5.7.1 - Arbitrary Password Reset: Improper Authentication vulnerability in WPDeveloper Essential Addons for Elementor allows Privilege Escalation. This issue affects Essential Addons for Elementor: from 5.4.0 through 5.7.1."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-32243"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-32243, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-32243.yaml"
    strings:
        $path0 = /\/author-sitemap\.xml(\/|;|$)/ nocase
        $param0 = /(^|[?&;])rest_route=\/wp\/v2\/users(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_32563_avalanche {
    meta:
        attack_type = "cve_2023_32563"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ivanti Avalanche - Remote Code Execution: An unauthenticated attacker could achieve the code execution through a RemoteControl server."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-32563"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-32563, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-32563.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/Servlet\/Skins(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_3277_mstore_api {
    meta:
        attack_type = "cve_2023_3277"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MStore API <= 4.10.7 - Unauthorized Account Access and Privilege Escalation: The MStore API plugin for WordPress is vulnerable to Unauthorized Account Access and Privilege Escalation in versions up to, and including, 4.10.7 due to improper implementation of the Apple login."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3277"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3277, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3277.yaml"
    strings:
        $path0 = /\/wp-json\/api\/flutter_user\/apple_login(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_33439_faculty_evaluation_system {
    meta:
        attack_type = "cve_2023_33439"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Faculty Evaluation System v1.0 - SQL Injection: Sourcecodester Faculty Evaluation System v1.0 is vulnerable to SQL Injection via /eval/admin/manage_task.php?id="
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-33439"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-33439, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-33439.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/admin\/manage_task\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_3345_masteriyo {
    meta:
        attack_type = "cve_2023_3345"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LMS by Masteriyo < 1.6.8 - Information Exposure: The plugin does not properly safeguards sensitive user information, like other user's email addresses, making it possible for any students to leak them via some of the plugin's REST API endpoints."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3345"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3345, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3345.yaml"
    strings:
        $path0 = "/wp-json/masteriyo/v1/users/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_33510_jeecg_p3_biz_chat {
    meta:
        attack_type = "cve_2023_33510"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jeecg P3 Biz Chat - Local File Inclusion: Jeecg P3 Biz Chat 1.0.5 allows remote attackers to read arbitrary files through specific parameters."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-33510"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-33510, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-33510.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/chat\/imController\/showOrDownByurl\.do(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_33568_dolibarr_erp_crm {
    meta:
        attack_type = "cve_2023_33568"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dolibarr Unauthenticated Contacts Database Theft: An issue in Dolibarr 16 before 16.0.5 allows unauthenticated attackers to perform a database dump and access a company's entire customer file, prospects, suppliers, and employee information if a contact file exists."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-33568"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-33568, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-33568.yaml"
    strings:
        $path0 = /\/public\/ticket\/ajax\/ajax\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])action=getContacts(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_33629_magic_r300_2100m_firmware {
    meta:
        attack_type = "cve_2023_33629"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "H3C Magic R300-2100M - Remote Code Execution: H3C Magic R300 version R300-2100MV100R004 was discovered to contain a stack overflow via the DeltriggerList interface at /goform/aspForm."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-33629"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-33629, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-33629.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/goform\/aspForm(\/|;|$)/ nocase
        $param0 = /(^|[?&;])CMD=DelL2tpLNSList(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_33831_fuxa {
    meta:
        attack_type = "cve_2023_33831"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FUXA - Unauthenticated Remote Code Execution: A remote command execution (RCE) vulnerability in the /api/runscript endpoint of FUXA 1.1.13 allows attackers to execute arbitrary commands via a crafted POST request."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-33831"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-33831, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-33831.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/runscript(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_3388_beautiful_cookie_consent_banne {
    meta:
        attack_type = "cve_2023_3388"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Beautiful Cookie Consent Banner < 2.10.2 - Cross-Site Scripting: The Beautiful Cookie Consent Banner for WordPress is vulnerable to Stored Cross-Site Scripting via the 'nsc_bar_content_href' parameter in versions up to, and including, 2.10.1 due to insufficient input."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3388"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3388, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3388.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])nsc_bar_type=opt-in(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_34020_uncanny_toolkit_for_learndash {
    meta:
        attack_type = "cve_2023_34020"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Uncanny Toolkit for LearnDash - Open Redirection: A vulnerability in the WordPress Uncanny Toolkit for LearnDash Plugin allowed malicious actors to redirect users, posing a potential risk of phishing incidents. The issue has been resolved in version 3.6.4.4, and users are urged."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34020"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34020, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34020.yaml"
    strings:
        $param0 = /(^|[?&;])rest_route=\/ult\/v2\/review-banner-visibility(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_34105_simple_realtime_server {
    meta:
        attack_type = "cve_2023_34105"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SRS - Command Injection: SRS's v5.0.137~v5.0.156, v6.0.18~v6.0.47 api-server server is vulnerable to a drive-by command injection."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34105"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34105, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34105.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/v1\/snapshots(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_34124_analytics {
    meta:
        attack_type = "cve_2023_34124"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SonicWall GMS and Analytics Web Services - Shell Injection: The authentication mechanism in SonicWall GMS and Analytics Web Services had insufficient checks, allowing authentication bypass. This issue affects GMS: 9.3.2-SP1 and earlier versions; Analytics: 2.5.0.4-R7 and."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34124"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34124, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34124.yaml"
    strings:
        $path0 = /\/ws\/msw\/tenant\/' union select \(select ID from SGMSDB\.DOMAINS limit 1\), '', '', '', '', '', \(select concat\(id, ':', password\) from sgmsdb\.users where active = '1' order by issuperadmin desc limit 1 offset 0\),'', '', '(\/|;|$)/ nocase
        $path1 = /\/appliance\/login(\/|;|$)/ nocase
        $path2 = /\/appliance\/applianceMainPage(\/|;|$)/ nocase
        $param0 = /(^|[?&;])searchFolder=\/opt\/GMSVP\/etc\/(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_34133_analytics {
    meta:
        attack_type = "cve_2023_34133"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SonicWall GMS and Analytics - SQL Injection: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in SonicWall GMS and Analytics allows an unauthenticated attacker to extract sensitive information from the application database. This."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34133"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34133, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34133.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/ws/msw/tenant/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_34192_collaboration {
    meta:
        attack_type = "cve_2023_34192"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Zimbra Collaboration Suite (ZCS) v.8.8.15 - Cross-Site Scripting: Cross Site Scripting vulnerability in Zimbra ZCS v.8.8.15 allows a remote authenticated attacker to execute arbitrary code via a crafted script to the /h/autoSaveDraft function."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34192"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34192, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34192.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/h\/autoSaveDraft(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_34537_hoteldruid {
    meta:
        attack_type = "cve_2023_34537"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Hoteldruid 3.0.5 - Cross-Site Scripting: A Reflected XSS was discovered in HotelDruid version 3.0.5, an attacker can issue malicious code/command on affected webpage's parameter to trick user on browser and/or exfiltrate data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34537"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34537, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34537.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])inizioperiodosett1=2023-12-24(&|$)/ nocase
        $param1 = /(^|[?&;])fineperiodosett1=2023-12-31(&|$)/ nocase
        $param2 = /(^|[?&;])tipo_prezzo=sett(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_34599_gibbon {
    meta:
        attack_type = "cve_2023_34599"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Gibbon v25.0.0 - Cross-Site Scripting: Multiple Cross-Site Scripting (XSS) vulnerabilities have been identified in Gibbon v25.0.0, which enable attackers to execute arbitrary Javascript code."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34599"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34599, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34599.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])q=\/modules\/Staff\/staff_view_details\.php(&|$)/ nocase
        $param1 = /(^|[?&;])ttDate=05\/23\/2023(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_34659_jeecg_boot {
    meta:
        attack_type = "cve_2023_34659"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JeecgBoot 3.5.0 - SQL Injection: jeecg-boot 3.5.0 and 3.5.1 have a SQL injection vulnerability the id parameter of the /jeecg-boot/jmreport/show interface."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34659"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34659, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34659.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/jeecg-boot\/jmreport\/show(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_34752_bloofoxcms {
    meta:
        attack_type = "cve_2023_34752"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "bloofoxCMS v0.5.2.1 - SQL Injection: bloofox v0.5.2.1 was discovered to contain a SQL injection vulnerability via the lid parameter at admin/index.php?mode=settings&page=lang&action=edit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34752"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34752, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34752.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])name=English(&|$)/ nocase
        $param1 = /(^|[?&;])filename=english\.php(&|$)/ nocase
        $param2 = /(^|[?&;])datetime=m\/d\/Y - H:i(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_34753_bloofoxcms {
    meta:
        attack_type = "cve_2023_34753"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "bloofoxCMS v0.5.2.1 - SQL Injection: bloofox v0.5.2.1 was discovered to contain a SQL injection vulnerability via the tid parameter at admin/index.php?mode=settings&page=tmpl&action=edit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34753"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34753, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34753.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])template_print=print\.html(&|$)/ nocase
        $param1 = /(^|[?&;])template_print_css=print\.css(&|$)/ nocase
        $param2 = /(^|[?&;])template_login=login\.html(&|$)/ nocase
        $param3 = /(^|[?&;])template_text=text\.html(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_3479_control_panel {
    meta:
        attack_type = "cve_2023_3479"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Hestiacp <= 1.7.7 - Cross-Site Scripting: Cross-site Scripting (XSS) - Reflected in GitHub repository hestiacp/hestiacp prior to 1.7.8."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3479"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3479, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3479.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/templates\/pages\/debug_panel\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_34990_fortiwlm {
    meta:
        attack_type = "cve_2023_34990"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FortiWLM - Directory Traversal: A relative path traversal in Fortinet FortiWLM version 8.6.0 through 8.6.5 and 8.5.0 through 8.5.4 allows attacker to execute unauthorized code or commands via specially crafted web requests."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34990"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34990, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34990.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/ems\/cgi-bin\/ezrf_lighttpd\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])op_type=upgradelogs(&|$)/ nocase
        $param1 = /(^|[?&;])imagename=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/data\/apps\/nms\/logs\/httpd_error_log(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_34993_fortiwlm {
    meta:
        attack_type = "cve_2023_34993"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Fortinet FortiWLM Unauthenticated Command Injection Vulnerability: A improper neutralization of special elements used in an os command ('os command injection') in Fortinet FortiWLM version 8.6.0 through 8.6.5 and 8.5.0 through 8.5.4 allows attacker to execute unauthorized code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-34993"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-34993, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34993.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/ems\/cgi-bin\/ezrf_upgrade_images\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])op_type=deleteprogressfile(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_35155_xwiki {
    meta:
        attack_type = "cve_2023_35155"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki - Cross-Site Scripting: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-35155"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-35155, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-35155.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])viewer=share(&|$)/ nocase
        $param1 = /(^|[?&;])includeDocument=inline(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_35156_xwiki {
    meta:
        attack_type = "cve_2023_35156"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki >= 6.0-rc-1 - Cross-Site Scripting: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS). It's possible to exploit the delete."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-35156"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-35156, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-35156.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/bin\/get\/FlamingoThemes\/Cerulean(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_35158_xwiki {
    meta:
        attack_type = "cve_2023_35158"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki - Cross-Site Scripting: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS). It's possible to exploit the restore template to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-35158"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-35158, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-35158.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])xpage=restore(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_35159_xwiki {
    meta:
        attack_type = "cve_2023_35159"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki >= 3.4-milestone-1 - Cross-Site Scripting: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS). It's possible to exploit the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-35159"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-35159, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-35159.yaml"
        response_type = "xss"
    strings:
        $path0 = "/xwiki/bin/deletespace/Sandbox/" ascii nocase
        $path1 = "/bin/deletespace/Sandbox/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_35160_xwiki {
    meta:
        attack_type = "cve_2023_35160"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki >= 2.5-milestone-2 - Cross-Site Scripting: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS). It's possible to exploit the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-35160"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-35160, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-35160.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/bin\/view\/XWiki\/Main(\/|;|$)/ nocase
        $param0 = /(^|[?&;])xpage=resubmit(&|$)/ nocase
        $param1 = /(^|[?&;])resubmit=javascript:alert\(document\.domain\)(&|$)/ nocase
        $param2 = /(^|[?&;])xback=javascript:alert\(document\.domain\)(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_35161_xwiki {
    meta:
        attack_type = "cve_2023_35161"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki >= 6.2-milestone-1 - Cross-Site Scripting: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS). It's possible to exploit the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-35161"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-35161, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-35161.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])appName=Menu(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_35162_xwiki {
    meta:
        attack_type = "cve_2023_35162"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki < 14.10.5 - Cross-Site Scripting: XWiki Platform is vulnerable to reflected XSS via the previewactions template. An attacker can inject JavaScript through the xcontinue parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-35162"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-35162, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-35162.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])vm=previewactions\.vm(&|$)/ nocase
        $param1 = /(^|[?&;])xcontinue=javascript:alert\(document\.domain\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_35813_experience_commerce {
    meta:
        attack_type = "cve_2023_35813"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Sitecore - Remote Code Execution: Multiple Sitecore products allow remote code execution. This affects Experience Manager, Experience Platform, and Experience Commerce through 10.3."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-35813"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-35813, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-35813.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/sitecore_xaml\.ashx\/-\/xaml\/Sitecore\.Xaml\.Tutorials\.Styles\.Index(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_35844_lightdash {
    meta:
        attack_type = "cve_2023_35844"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Lightdash version <= 0.510.3 Arbitrary File Read: packages/backend/src/routers in Lightdash before 0.510.3 has insecure file endpoints, e.g., they allow .. directory traversal and do not ensure that an intended file extension (.csv or .png) is used."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-35844"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-35844, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-35844.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/v1/slack/image/slack-image" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_35885_cloudpanel {
    meta:
        attack_type = "cve_2023_35885"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cloudpanel 2 < 2.3.1 - Remote Code Execution: CloudPanel 2 before 2.3.1 has insecure file-manager cookie authentication."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-35885"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-35885, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-35885.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/file-manager\/backend\/makefile(\/|;|$)/ nocase
        $path1 = /\/file-manager\/backend\/text(\/|;|$)/ nocase
        $path2 = /\/file-manager\/backend\/permissions(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_36144_sg_2404_mr_firmware {
    meta:
        attack_type = "cve_2023_36144"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Intelbras Switch - Information Disclosure: An authentication bypass in Intelbras Switch SG 2404 MR in firmware 1.00.54 allows an unauthenticated attacker to download the backup file of the device, exposing critical information about the device configuration."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-36144"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-36144, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-36144.yaml"
    strings:
        $path0 = /\/cgi-bin\/exportCfgwithpasswd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_36287_qloapps {
    meta:
        attack_type = "cve_2023_36287"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Webkul QloApps 1.6.0 - Cross-site Scripting: An unauthenticated Cross-Site Scripting (XSS) vulnerability found in Webkul QloApps 1.6.0 allows an attacker to obtain a user's session cookie and then impersonate that user via POST controller parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-36287"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-36287, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-36287.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])controller=change-currency9405'-alert\(document\.domain\)-'(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_36306_loganalyzer {
    meta:
        attack_type = "cve_2023_36306"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Adiscon LogAnalyzer v.4.1.13 - Cross-Site Scripting: A Cross Site Scripting (XSS) vulnerability in Adiscon Aiscon LogAnalyzer through 4.1.13 allows a remote attacker to execute arbitrary code via the asktheoracle.php"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-36306"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-36306, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-36306.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/loganalyzer\/asktheoracle\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_36346_codekop {
    meta:
        attack_type = "cve_2023_36346"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "POS Codekop v2.0 - Cross Site Scripting: POS Codekop v2.0 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the nm_member parameter at print.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-36346"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-36346, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-36346.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/print\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_36347_codekop {
    meta:
        attack_type = "cve_2023_36347"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "POS Codekop v2.0 - Broken Authentication: A broken authentication mechanism in the endpoint excel.php of POS Codekop v2.0 allows unauthenticated attackers to download selling data."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-36347"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-36347, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-36347.yaml"
    strings:
        $path0 = /\/excel\.php(\/|;|$)/ nocase
        $path1 = /\/pos-kasir-php\/excel\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_3643_boss_mini {
    meta:
        attack_type = "cve_2023_3643"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CAREL Boss Mini <= 1.4.0 - Local File Inclusion: Boss Mini 1.4.0 Build 6221 contains a file inclusion caused by manipulation of the 'path' argument in boss/servlet/document, letting remote attackers include arbitrary files, exploit requires remote access."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3643"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3643, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3643.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/boss\/servlet\/document(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_36845_junos {
    meta:
        attack_type = "cve_2023_36845"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Juniper J-Web - Remote Code Execution: A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series and SRX Series allows an unauthenticated, network-based attacker to control certain environments variables to execute remote commands"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-36845"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-36845, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-36845.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])PHPRC=\/dev\/fd\/0(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_36934_moveit_transfer {
    meta:
        attack_type = "cve_2023_36934"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MOVEit Transfer - SQL Injection: In Progress MOVEit Transfer before 2020.1.11 (12.1.11), 2021.0.9 (13.0.9), 2021.1.7 (13.1.7), 2022.0.7 (14.0.7), 2022.1.8 (14.1.8), and 2023.0.4 (15.0.4), a SQL injection vulnerability has been identified in the MOVEit Transfer web application."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-36934"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-36934, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-36934.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/human\.aspx(\/|;|$)/ nocase
        $path1 = /\/machine\.aspx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])transaction=signon(&|$)/ nocase
        $param1 = /(^|[?&;])transaction=passchangerequest(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_3710_pm43_firmware {
    meta:
        attack_type = "cve_2023_3710"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Honeywell PM43 Printers - Command Injection: Improper Input Validation vulnerability in Honeywell PM43 on 32 bit, ARM (Printer web page modules) allows Command Injection.This issue affects PM43 versions prior to P10.19.050004. Update to the latest available firmware version of."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3710"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3710, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3710.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/loadfile\.lp(\/|;|$)/ nocase
        $param0 = /(^|[?&;])pageid=Configure(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_3722_aura_device_services {
    meta:
        attack_type = "cve_2023_3722"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Avaya Aura Device Services - OS Command Injection: An OS command injection vulnerability was found in the Avaya Aura Device Services Web application which could allow remote code execution as the Web server user via a malicious uploaded file. This issue affects Avaya Aura."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3722"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3722, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3722.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/PhoneBackup/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_37270_piwigo {
    meta:
        attack_type = "cve_2023_37270"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Piwigo 13.7.0 - SQL Injection: Piwigo is open source photo gallery software. Prior to version 13.8.0, there is a SQL Injection vulnerability in the login of the administrator screen. The SQL statement that acquires the HTTP Header `User-Agent` is vulnerable at the endpoint that."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-37270"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-37270, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-37270.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])page=user_activity(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_37462_xwiki {
    meta:
        attack_type = "cve_2023_37462"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "XWiki Platform - Remote Code Execution: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Improper escaping in the document `SkinsCode.XWikiSkinsSheet` leads to an injection vector from view right on that document to."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-37462"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-37462, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-37462.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])sheet=SkinsCode\.XWikiSkinsSheet(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_37580_zimbra {
    meta:
        attack_type = "cve_2023_37580"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Zimbra Collaboration Suite (ZCS) v.8.8.15 - Cross-Site Scripting: Zimbra Collaboration (ZCS) 8 before 8.8.15 Patch 41 allows XSS in the Zimbra Classic Web Client."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-37580"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-37580, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-37580.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/m\/momoveto(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_37645_eyoucms {
    meta:
        attack_type = "cve_2023_37645"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "EyouCms v1.6.3 - Information Disclosure: EyouCms v1.6.3 was discovered to contain an information disclosure vulnerability via the component /custom_model_path/recruit.filelist.txt."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-37645"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-37645, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-37645.yaml"
    strings:
        $path0 = /\/data\/model\/custom_model_path\/recruit\.filelist\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_3765_mlflow {
    meta:
        attack_type = "cve_2023_3765"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MLflow Absolute Path Traversal: Absolute Path Traversal in GitHub repository mlflow/mlflow prior to 2.5.0."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3765"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3765, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3765.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/ajax-api\/2\.0\/mlflow-artifacts\/artifacts(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_37979_ninja_forms {
    meta:
        attack_type = "cve_2023_37979"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ninja Forms < 3.6.26 - Cross-Site Scripting: The plugin does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against high privilege users such as admin"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-37979"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-37979, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-37979.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=nf_batch_process(&|$)/ nocase
        $param1 = /(^|[?&;])batch_type=import_form_template(&|$)/ nocase
        $param2 = /(^|[?&;])extraData\[template\]=formtemplate-contactformd(&|$)/ nocase
        $param3 = /(^|[?&;])method_override=_respond(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_37988_contact_form_generator {
    meta:
        attack_type = "cve_2023_37988"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Contact Form Generator <= 2.5.5 - Cross-Site Scripting: The Contact Form Generator plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the 'id' parameter in wp-admin/admin.php in versions up to, and including, 2.5.5 due to insufficient input sanitization."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-37988"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-37988, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-37988.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=contact_form_generator(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_38035_mobileiron_sentry {
    meta:
        attack_type = "cve_2023_38035"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Ivanti Sentry - Authentication Bypass: A security vulnerability in MICS Admin Portal in Ivanti MobileIron Sentry versions 9.18.0 and below, which may allow an attacker to bypass authentication controls on the administrative interface due to an insufficiently restrictive Apache."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-38035"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38035, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-38035.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/mics\/services\/MICSLogService(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_38040_revive_adserver {
    meta:
        attack_type = "cve_2023_38040"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Revive Adserver 5.4.1 - Cross-Site Scripting: A reflected XSS vulnerability exists in Revive Adserver 5.4.1 and earlier versions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-38040"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38040, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-38040.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/www\/delivery\/al\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])layerstyle=geocities(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_38192_superwebmailer {
    meta:
        attack_type = "cve_2023_38192"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SuperWebMailer 9.00.0.01710 - Cross-Site Scripting: An issue was discovered in SuperWebMailer 9.00.0.01710 allowing XSS via crafted incorrect passwords."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-38192"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38192, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-38192.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/superadmincreate\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_38194_superwebmailer {
    meta:
        attack_type = "cve_2023_38194"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SuperWebMailer - Cross-Site Scripting: An issue was discovered in SuperWebMailer 9.00.0.01710 that allows keepalive.php XSS via a GET parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-38194"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38194, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-38194.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/keepalive\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])uq_mt=1664137650\.085(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_38203_coldfusion {
    meta:
        attack_type = "cve_2023_38203"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Adobe ColdFusion - Deserialization of Untrusted Data: Adobe ColdFusion versions 2018u17 (and earlier), 2021u7 (and earlier) and 2023u1 (and earlier) are affected by a Deserialization of Untrusted Data vulnerability that could result in Arbitrary code execution. Exploitation of."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-38203"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38203, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-38203.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/CFIDE\/adminapi\/base\.cfc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_38205_coldfusion {
    meta:
        attack_type = "cve_2023_38205"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Adobe ColdFusion - Access Control Bypass: There is an access control bypass vulnerability in Adobe ColdFusion versions 2023 Update 2 and below, 2021 Update 8 and below and 2018 update 18 and below, which allows a remote attacker to bypass the ColdFusion mechanisms that restrict."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-38205"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38205, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-38205.yaml"
    strings:
        $path0 = /\/hax\/\.\.CFIDE\/wizards\/common\/utils\.cfc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_3836_smart_parking_management {
    meta:
        attack_type = "cve_2023_3836"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dahua Smart Park Management - Arbitrary File Upload: Dahua wisdom park integrated management platform is a comprehensive management platform, a park operations,resource allocation, and intelligence services,and other functions, including/emap/devicePoint_addImgIco?."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3836"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3836, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3836.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/emap\/devicePoint_addImgIco(\/|;|$)/ nocase
        $path1 = "/upload/emap/society_new/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_38879_opensis {
    meta:
        attack_type = "cve_2023_38879"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "openSIS v9.0 - Path Traversal: A path traversal vulnerability exists in openSIS Classic Community Edition v9.0 via the 'filename' parameter in DownloadWindow.php. An unauthenticated remote attacker can exploit this to read arbitrary files on the server by manipulating file paths."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-38879"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38879, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-38879.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/DownloadWindow\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_38950_biotime {
    meta:
        attack_type = "cve_2023_38950"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "ZKTeco BioTime v8.5.5 - Path Traversal: A path traversal vulnerability in the iclock API of ZKTeco BioTime v8.5.5 allows unauthenticated attackers to read arbitrary files via supplying a crafted payload."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-38950"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38950, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-38950.yaml"
    strings:
        $path0 = /\/iclock\/file(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_38952_biotime {
    meta:
        attack_type = "cve_2023_38952"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ZKTeco BioTime <= 9.0.1 - Privilege Escalation: BioTime default employee credentials (password 123456) allow login. Sessions are not role-validated, enabling privilege escalation to perform admin actions and enumerate backup files."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-38952"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38952, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-38952.yaml"
    strings:
        $path0 = "/base/dbbackuplog/table/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_38964_academy_lms {
    meta:
        attack_type = "cve_2023_38964"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Academy LMS 6.0 - Cross-Site Scripting: Creative Item Academy LMS 6.0 was discovered to contain a cross-site scripting (XSS) vulnerability through `query` parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-38964"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38964, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-38964.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/home\/courses(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_38992_jeecg_boot_v3_5_1 {
    meta:
        attack_type = "cve_2023_38992"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Jeecg-Boot v3.5.1 - SQL Injection: SQL injection vulnerability via the title parameter at /sys/dict/loadTreeData in jeecg-boot v3.5.1."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-38992"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-38992, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-38992.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "sys/dict/loadTreeData" ascii nocase
        $param0 = /(^|[?&;])tableName=sys_user(&|$)/ nocase
        $param1 = /(^|[?&;])text=password text,id(&|$)/ nocase
        $param2 = /(^|[?&;])code=password(&|$)/ nocase
        $param3 = /(^|[?&;])pidField=username(&|$)/ nocase
        $param4 = /(^|[?&;])tableName=sys_user t(&|$)/ nocase
        $param5 = /(^|[?&;])text=password,id(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_39002_opnsense {
    meta:
        attack_type = "cve_2023_39002"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "OPNsense - Cross-Site Scripting: A cross-site scripting (XSS) vulnerability in the act parameter of system_certmanager.php in OPNsense before 23.7 allows attackers to execute arbitrary web scripts or HTML via a crafted payload."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-39002"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-39002, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-39002.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/system_certmanager\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_39108_rconfig {
    meta:
        attack_type = "cve_2023_39108"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "rConfig 3.9.4 - Server-Side Request Forgery: rconfig v3.9.4 was discovered to contain a Server-Side Request Forgery (SSRF) via the path_b parameter in the doDiff Function of /classes/compareClass.php. This vulnerability allows authenticated attackers to make arbitrary requests."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-39108"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-39108, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-39108.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = /(^|[?&;])path_b=file:\/\/\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_39109_rconfig {
    meta:
        attack_type = "cve_2023_39109"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "rConfig 3.9.4 - Server-Side Request Forgery: rconfig v3.9.4 was discovered to contain a Server-Side Request Forgery (SSRF) via the path_a parameter in the doDiff Function of /classes/compareClass.php. This vulnerability allows authenticated attackers to make arbitrary requests."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-39109"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-39109, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-39109.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])path_a=file:\/\/\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_39110_rconfig {
    meta:
        attack_type = "cve_2023_39110"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "rConfig 3.9.4 - Server-Side Request Forgery: rconfig v3.9.4 was discovered to contain a Server-Side Request Forgery (SSRF) via the path parameter at /ajaxGetFileByPath.php. This vulnerability allows authenticated attackers to make arbitrary requests via injection of crafted URLs."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-39110"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-39110, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-39110.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = /(^|[?&;])path=file:\/\/localhost\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_39121_emlog {
    meta:
        attack_type = "cve_2023_39121"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Emlog 2.1.9 - SQL Injection: emlog v2.1.9 contains a SQL injection caused by unsanitized input in the data backup/restore functionality, allowing attackers to execute arbitrary SQL commands through crafted backup files."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-39121"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-39121, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-39121.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=dosignin(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_3936_blog2social {
    meta:
        attack_type = "cve_2023_3936"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Blog2Social < 7.2.1 - Cross-Site Scripting: The Blog2Social WordPress plugin before 7.2.1 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against high privilege users such as admin"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-3936"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-3936, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-3936.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])origin=publish_post(&|$)/ nocase
        $param1 = /(^|[?&;])deletePostStatus=success(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_39676_fieldpopupnewsletter {
    meta:
        attack_type = "cve_2023_39676"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PrestaShop fieldpopupnewsletter Module - Cross Site Scripting: Fieldpopupnewsletter Prestashop Module v1.0.0 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the callback parameter at ajax.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-39676"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-39676, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-39676.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/modules\/fieldpopupnewsletter\/ajax\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_39677_simpleimportproduct {
    meta:
        attack_type = "cve_2023_39677"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PrestaShop MyPrestaModules - PhpInfo Disclosure: PrestaShop modules by MyPrestaModules expose PHPInfo"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-39677"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-39677, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-39677.yaml"
    strings:
        $path0 = /\/modules\/simpleimportproduct\/send\.php(\/|;|$)/ nocase
        $path1 = /\/modules\/updateproducts\/send\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_39796_wbce_cms {
    meta:
        attack_type = "cve_2023_39796"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WBCE 1.6.0 - SQL Injection: There is an sql injection vulnerability in 'miniform module' which is a default module installed in the WBCE cms. It is an unauthenticated sqli so anyone could access it and takeover the whole database. In file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-39796"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-39796, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-39796.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])DB_COLUMN=message_id(&|$)/ nocase
        $param1 = /(^|[?&;])purpose=delete_record(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_40208_stock_ticker {
    meta:
        attack_type = "cve_2023_40208"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Stock Ticker <= 3.23.2 - Cross-Site Scripting: The Stock Ticker plugin for WordPress is vulnerable to Reflected Cross-Site Scripting in the ajax_stockticker_load function in versions up to, and including, 3.23.3 due to insufficient input sanitization and output escaping. This."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-40208"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-40208, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-40208.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=stockticker_load(&|$)/ nocase
        $param1 = /(^|[?&;])symbols=MSFT(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_40504_simple_editor {
    meta:
        attack_type = "cve_2023_40504"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LG Simple Editor <= v3.21.0 - Command Injection: LG Simple Editor readVideoInfo Command Injection Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of LG Simple Editor. Authentication is not."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-40504"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-40504, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-40504.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/simpleeditor\/common\/commonReleaseNotes\.do(\/|;|$)/ nocase
        $path1 = /\/simpleeditor\/imageManager\/uploadVideo\.do(\/|;|$)/ nocase
        $path2 = /\/simpleeditor\/fileSystem\/makeDetailContent\.do(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_40600_ewww_image_optimizer_7_2_0 {
    meta:
        attack_type = "cve_2023_40600"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "EWWW Image Optimizer <= 7.2.0 - Unauthenticated Information Disclosure: The EWWW Image Optimizer plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 7.2.0 via the debug_log function. This makes it possible for."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-40600"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-40600, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-40600.yaml"
    strings:
        $path0 = /\/wp-content\/ewww\/debug\.log(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_40931_nagios_xi {
    meta:
        attack_type = "cve_2023_40931"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Nagios XI v5.11.0 - SQL Injection: A SQL injection vulnerability in Nagios XI from version 5.11.0 up to and including 5.11.1 allows authenticated attackers to execute arbitrary SQL commands via the ID parameter in the POST request to /nagiosxi/admin/banner_message-ajaxhelper.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-40931"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-40931, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-40931.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/nagiosxi\/admin\/banner_message-ajaxhelper\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])action=acknowledge_banner_message(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_4110_availability_booking_calendar {
    meta:
        attack_type = "cve_2023_4110"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PHPJabbers Availability Booking Calendar 5.0 - Cross-Site Scripting: A vulnerability has been found in PHP Jabbers Availability Booking Calendar 5.0 and classified as problematic. Affected by this vulnerability is an unknown functionality of the file /index.php. The."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4110"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4110, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4110.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=pjActionGetBookingForm(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_4111_bus_reservation_system {
    meta:
        attack_type = "cve_2023_4111"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PHPJabbers Bus Reservation System 1.1 - Cross-Site Scripting: A vulnerability was found in PHP Jabbers Bus Reservation System 1.1 and classified as problematic. Affected by this issue is some unknown functionality of the file /index.php. The manipulation of the argument."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4111"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4111, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4111.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])controller=pjFrontEnd(&|$)/ nocase
        $param1 = /(^|[?&;])action=pjActionGetLocations(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_4112_shuttle_booking_software {
    meta:
        attack_type = "cve_2023_4112"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PHPJabbers Shuttle Booking Software 1.0 - Cross Site Scripting: The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4112"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4112, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4112.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=pjActionLogin(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_41266_qlik_sense {
    meta:
        attack_type = "cve_2023_41266"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Qlik Sense Enterprise - Path Traversal: A path traversal vulnerability found in Qlik Sense Enterprise for Windows for versions May 2023 Patch 3 and earlier, February 2023 Patch 7 and earlier, November 2022 Patch 10 and earlier, and August 2022 Patch 12 and earlier allows an."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-41266"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-41266, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-41266.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/resources\/qmc\/fonts\/\.\.\/\.\.\/\.\.\/qrs\/ReloadTask(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_4136_craftercms {
    meta:
        attack_type = "cve_2023_4136"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "CrafterCMS Engine - Cross-Site Scripting: CrafterCMS Engine is vulnerable to reflected cross-site scripting (XSS) via the transformerName parameter in the /api/1/site/url/transform endpoint, allowing attackers to execute arbitrary JavaScript in the context of the user."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4136"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4136, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4136.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/api\/1\/site\/url\/transform(\/|;|$)/ nocase
        $path1 = /\/api\/1\/site\/content_store\/children(\/|;|$)/ nocase
        $path2 = /\/api\/1\/site\/content_store\/item(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_41538_php_forum_script {
    meta:
        attack_type = "cve_2023_41538"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PHPJabbers PHP Forum Script 3.0 - Cross-Site Scripting: PhpJabbers PHP Forum Script 3.0 is vulnerable to Cross Site Scripting (XSS) via the keyword parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-41538"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-41538, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-41538.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=pjActionIndex(&|$)/ nocase
        $param1 = /(^|[?&;])column=created(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_41597_eyoucms {
    meta:
        attack_type = "cve_2023_41597"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "EyouCms v1.6.2 - Cross-Site Scripting: EyouCms v1.6.2 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the component /admin/twitter.php?active_t."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-41597"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-41597, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-41597.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/admin\/twitter\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_41599_jfinalcms {
    meta:
        attack_type = "cve_2023_41599"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "JFinalCMS v5.0.0 - Directory Traversal: An issue in the component /common/DownController.java of JFinalCMS v5.0.0 allows attackers to execute a directory traversal."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-41599"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-41599, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-41599.yaml"
    strings:
        $param0 = /(^|[?&;])filekey=\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_41621_emlog {
    meta:
        attack_type = "cve_2023_41621"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Emlog Pro v2.1.14 - Cross-Site Scripting: Cross Site Scripting (XSS) vulnerability in Emlog Pro v2.1.14 via /admin/store.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-41621"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-41621, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-41621.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/admin\/store\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_41642_realgimm {
    meta:
        attack_type = "cve_2023_41642"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "RealGimm by GruppoSCAI v1.1.37p38 - Cross-Site Scripting: Multiple reflected cross-site scripting (XSS) vulnerabilities in the ErroreNonGestito.aspx component of GruppoSCAI RealGimm 1.1.37p38 allow attackers to execute arbitrary Javascript in the context of a victim user's."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-41642"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-41642, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-41642.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/RealGimmWeb\/Pages\/Sistema\/LogObjectTrace\.aspx(\/|;|$)/ nocase
        $path1 = /\/RealGimmWeb\/Pages\/ErroreNonGestito\.aspx(\/|;|$)/ nocase
        $param0 = /(^|[?&;])__EVENTTARGET=T1bPulsantiera(&|$)/ nocase
        $param1 = /(^|[?&;])EVENTARGUMENT=TlbPulsantiera_Item_0:UP(&|$)/ nocase
        $param2 = /(^|[?&;])___VIEWSTATE='TESTING(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_4174_moostore {
    meta:
        attack_type = "cve_2023_4174"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "mooSocial 3.1.6 - Reflected Cross Site Scripting: A vulnerability has been found in mooSocial mooStore 3.1.6 and classified as problematic. Affected by this vulnerability is an unknown functionality. The manipulation leads to cross site scripting. The attack can be launched."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4174"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4174, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4174.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])sortby=most_recent(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_41763_skype_for_business_server {
    meta:
        attack_type = "cve_2023_41763"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Skype for Business 2019 (SfB) - Blind Server-side Request Forgery: Skype Pre-Auth Server-side Request Forgery (SSRF) vulnerability"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-41763"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-41763, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-41763.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/lwa\/Webpages\/LwaClient\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_4220_chamilo_lms {
    meta:
        attack_type = "cve_2023_4220"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Chamilo LMS <= 1.11.24 - Remote Code Execution: Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS <= v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4220"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4220, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4220.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/main\/inc\/lib\/javascript\/bigupload\/inc\/bigUpload\.php(\/|;|$)/ nocase
        $path1 = "/main/inc/lib/javascript/bigupload/files/" ascii nocase
        $param0 = /(^|[?&;])action=post-unsupported(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_42343_opencms {
    meta:
        attack_type = "cve_2023_42343"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "OpenCMS - Cross-Site Scripting: OpenCMS below 10.5.1 is vulnerable to Cross-Site Scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-42343"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-42343, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-42343.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/opencms\/cmisatom\/cmis-online\/type(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_42344_opencms {
    meta:
        attack_type = "cve_2023_42344"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OpenCMS - XML external entity (XXE): users can execute code without authentication. An attacker can execute malicious requests on the OpenCms server. When the requests are successful vulnerable OpenCms can be exploited resulting in an unauthenticated XXE vulnerability. Based on."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-42344"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-42344, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-42344.yaml"
    strings:
        $path0 = /\/opencms\/cmisatom\/cmis-online\/query(\/|;|$)/ nocase
        $path1 = /\/cmisatom\/cmis-online\/query(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_42442_jumpserver {
    meta:
        attack_type = "cve_2023_42442"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "JumpServer > 3.6.4 - Information Disclosure: JumpServer is an open source bastion host and a professional operation and maintenance security audit system. Starting in version 3.0.0 and prior to versions 3.5.5 and 3.6.4, session replays can download without authentication.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-42442"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-42442, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-42442.yaml"
    strings:
        $path0 = "/api/v1/terminal/sessions/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_4284_post_timeline {
    meta:
        attack_type = "cve_2023_4284"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Post Timeline Plugin < 2.2.6 - Cross-Site Scripting: The Post Timeline WordPress plugin before version 2.2.6 contains a reflected cross-site scripting vulnerability. The plugin does not properly sanitize and escape an invalid nonce before outputting it back in an AJAX."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4284"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4284, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4284.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=ptl_ajax_handler(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_43177_crushftp {
    meta:
        attack_type = "cve_2023_43177"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CrushFTP < 10.5.1 - Unauthenticated Remote Code Execution: CrushFTP prior to 10.5.1 is vulnerable to Improperly Controlled Modification of Dynamically-Determined Object Attributes."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-43177"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-43177, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-43177.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/WebInterface(\/|;|$)/ nocase
        $path1 = "/WebInterface/" ascii nocase
        $param0 = /(^|[?&;])command=getUsername(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_43261_ur51 {
    meta:
        attack_type = "cve_2023_43261"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Milesight Routers - Information Disclosure: A critical security vulnerability has been identified in Milesight Industrial Cellular Routers, compromising the security of sensitive credentials and permitting unauthorized access. This vulnerability stems from a misconfiguration."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-43261"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-43261, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-43261.yaml"
    strings:
        $path0 = /\/lang\/log\/httpd\.log(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_43323_moostore {
    meta:
        attack_type = "cve_2023_43323"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "mooSocial 3.1.8 - External Service Interaction: mooSocial 3.1.8 is vulnerable to external service interaction via multiple parameters in the post function."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-43323"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-43323, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-43323.yaml"
    strings:
        $path0 = /\/activities\/ajax_share(\/|;|$)/ nocase
        $param0 = /(^|[?&;])data\[action\]=wall_post(&|$)/ nocase
        $param1 = /(^|[?&;])messageText=asas(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_43373_hoteldruid {
    meta:
        attack_type = "cve_2023_43373"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hoteldruid v3.0.5 - SQL Injection: Hoteldruid v3.0.5 was discovered to contain a SQL injection vulnerability via the n_utente_agg parameter at /hoteldruid/interconnessioni.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-43373"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-43373, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-43373.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/interconnessioni\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_43374_hoteldruid {
    meta:
        attack_type = "cve_2023_43374"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hoteldruid v3.0.5 - SQL Injection: Hoteldruid v3.0.5 was discovered to contain a SQL injection vulnerability via the id_utente_log parameter at /hoteldruid/personalizza.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-43374"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-43374, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-43374.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])attiva_phpr_log=Enable(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_43472_mlflow {
    meta:
        attack_type = "cve_2023_43472"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MLFlow < 2.8.1 - Sensitive Information Disclosure: An issue in MLFlow versions 2.8.1 and before allows a remote attacker to obtain sensitive information via a crafted request to REST API."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-43472"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-43472, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-43472.yaml"
    strings:
        $path0 = /\/api\/2\.0\/preview\/mlflow\/experiments\/list(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_44353_coldfusion {
    meta:
        attack_type = "cve_2023_44353"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Adobe ColdFusion WDDX Deserialization Gadgets: Adobe ColdFusion versions 2023.5 (and earlier) and 2021.11 (and earlier) are affected by an Deserialization of Untrusted Data vulnerability that could result in Arbitrary code execution. Exploitation of this issue does not require."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-44353"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-44353, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-44353.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])method=wizardHash inPassword=bar _cfclient=true(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_4450_jeecg {
    meta:
        attack_type = "cve_2023_4450"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JeecgBoot JimuReport - Template injection: A vulnerability was found in jeecgboot JimuReport up to 1.6.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the component Template Handler. The manipulation leads to injection. The."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4450"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4450, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4450.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/jeecg-boot\/jmreport\/queryFieldBySql(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_44813_moosocial {
    meta:
        attack_type = "cve_2023_44813"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "mooSocial v.3.1.8 - Cross-Site Scripting: Cross-Site Scripting (XSS) vulnerability in mooSocial v.3.1.8 allows a remote attacker to execute arbitrary code via a crafted payload to the mode parameter of the invite friend login function."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-44813"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-44813, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-44813.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/friends\/ajax_invite(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_4490_wordpress_job_portal_2_0_6 {
    meta:
        attack_type = "cve_2023_4490"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Job Portal < 2.0.6 - SQL Injection: The WP Job Portal WordPress plugin before 2.0.6 does not sanitise and escape the city parameter before using it in a SQL statement,leading to a SQL injection vulnerability that is exploitable by unauthenticated users. This."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4490"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4490, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4490.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])city=\(select\*from\(select\(sleep\(7\)\)\)a\)(&|$)/ nocase
        $param1 = /(^|[?&;])default_longitude=71\.2577233(&|$)/ nocase
        $param2 = /(^|[?&;])default_latitude=29\.1411551(&|$)/ nocase
        $param3 = /(^|[?&;])WPJOBPORTAL_form_search=WPJOBPORTAL_SEARCH(&|$)/ nocase
        $param4 = /(^|[?&;])wpjobportallay=jobs(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_44982_perfect_images {
    meta:
        attack_type = "cve_2023_44982"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Perfect Images (WP Retina 2x) < 6.4.6 - Sensitive Information Exposure: Jordy Meow Perfect Images (Manage Image Sizes, Thumbnails, Replace, Retina) versions up to 6.4.5 contain a vulnerability that exposes sensitive information to unauthorized actors, letting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-44982"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-44982, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-44982.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/wp-retina-2x\/classes\/wp-retina-2x\.log(\/|;|$)/ nocase
        $path1 = /\/wp-content\/uploads\/wp-retina-2x\.log(\/|;|$)/ nocase
        $path2 = /\/wp-content\/uploads\/wp-retina-2x-logs\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_45038_music_station {
    meta:
        attack_type = "cve_2023_45038"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "QNAP Music Station < 5.4.0 - Authentication Bypass: An improper authentication vulnerability has been reported to affect Music Station. If exploited, the vulnerability could allow users to compromise the security of the system via a network. We have already fixed the."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-45038"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-45038, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-45038.yaml"
    strings:
        $path0 = /\/musicstation\/api\/as_get_file_api\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])f=L2V0Yy9wYXNzd2Q=(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_4521_import_xml_and_rss_feeds {
    meta:
        attack_type = "cve_2023_4521"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Import XML and RSS Feeds < 2.1.5 - Unauthenticated RCE: The Import XML and RSS Feeds WordPress plugin before 2.1.5 allows unauthenticated attackers to execute arbitrary commands via a web shell."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4521"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4521, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4521.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/wp-content\/plugins\/import-xml-feed\/uploads\/169227090864de013cac47b\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_4547_ecommerce_cms {
    meta:
        attack_type = "cve_2023_4547"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SPA-Cart eCommerce CMS 1.9.0.3 - Cross-Site Scripting: A vulnerability was found in SPA-Cart eCommerce CMS 1.9.0.3. It has been rated as problematic. Affected by this issue is some unknown functionality of the file /search. The manipulation of the argument."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4547"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4547, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4547.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])filter\[attr\]\[Memory\]\[\]=16 GB(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_4568_papercut_ng {
    meta:
        attack_type = "cve_2023_4568"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PaperCut NG Unauthenticated XMLRPC Functionality: PaperCut NG allows for unauthenticated XMLRPC commands to be run by default. Versions 22.0.12 and below are confirmed to be affected, but later versions may also be affected due to lack of a vendor supplied patch."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4568"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4568, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4568.yaml"
    strings:
        $path0 = /\/rpc\/clients\/xmlrpc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_45826_leantime {
    meta:
        attack_type = "cve_2023_45826"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Leantime < 2.4 - Authenticated SQL Injection: Leantime is an open source project management system. A 'userId' variable in `app/domain/files/repositories/class.files.php` is not parameterized. An authenticated attacker can send a carefully crafted POST request to `/api/jsonrpc`."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-45826"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-45826, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-45826.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/api\/jsonrpc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_45878_gibbon {
    meta:
        attack_type = "cve_2023_45878"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Gibbon LMS <= v25.0.01 - File Upload to RCE: Gibbon LMS versions 25.0.1 and earlier are vulnerable to an Arbitrary File Upload that can lead to Remote Code Execution (RCE). The issue stems from the rubrics_visualise_saveAjax.php endpoint, which, notably, does not require."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-45878"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-45878, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-45878.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/modules\/Rubrics\/rubrics_visualise_saveAjax\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_4634_media_library_assistant {
    meta:
        attack_type = "cve_2023_4634"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Media Library Assistant < 3.09 - Remote Code Execution/Local File Inclusion: A vulnerability in the Wordpress Media-Library-Assistant plugins in version < 3.09 is vulnerable to a local file inclusion which leading to RCE on default Imagegick installation/configuration."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4634"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4634, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4634.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/media-library-assistant\/includes\/mla-stream-image\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_46359_cph2_echarge {
    meta:
        attack_type = "cve_2023_46359"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "cPH2 Charging Station v1.87.0 - OS Command Injection: An OS command injection vulnerability in Hardy Barth cPH2 Ladestation v1.87.0 and earlier, may allow an unauthenticated remote attacker to execute arbitrary commands on the system via a specifically crafted arguments passed."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-46359"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-46359, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-46359.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/connectioncheck\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_46818_ispconfig {
    meta:
        attack_type = "cve_2023_46818"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ISPConfig - PHP Code Injection: An issue was discovered in ISPConfig before 3.2.11p1. PHP code injection can be achieved in the language file editor by an admin if admin_allow_langedit is enabled."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-46818"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-46818, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-46818.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/admin\/language_edit\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_47115_label_studio {
    meta:
        attack_type = "cve_2023_47115"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Label Studio - Cross-Site Scripting: Versions prior to 1.9.2 have a cross-site scripting (XSS) vulnerability that could be exploited when an authenticated user uploads a crafted image file for their avatar that gets rendered as a HTML file on the website."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-47115"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-47115, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-47115.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/api\/current-user\/whoami(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_47117_label_studio {
    meta:
        attack_type = "cve_2023_47117"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Label Studio - Sensitive Information Exposure: An attacker can construct a filter chain to filter tasks based on sensitive fields for all user accounts on the platform by exploiting Django's Object Relational Mapper (ORM). Since the results of query can be manipulated by the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-47117"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-47117, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-47117.yaml"
    strings:
        $path0 = "/api/dm/views/" ascii nocase
        $path1 = /\/api\/tasks(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_47211_manageengine_firewall_analyzer {
    meta:
        attack_type = "cve_2023_47211"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ManageEngine OpManager - Directory Traversal: A directory traversal vulnerability exists in the uploadMib functionality of ManageEngine OpManager 12.7.258. A specially crafted HTTP request can lead to arbitrary file creation. An attacker can send a malicious MiB file to trigger."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-47211"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-47211, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-47211.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/two_factor_auth(\/|;|$)/ nocase
        $path1 = /\/client\/api\/json\/mibbrowser\/uploadMib(\/|;|$)/ nocase
        $param0 = /(^|[?&;])\.\.\/images\/karas DEFINITIONS ::=BEGIN(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_47218_qts {
    meta:
        attack_type = "cve_2023_47218"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "QNAP QTS and QuTS Hero - OS Command Injection: An OS command injection vulnerability has been reported to affect several QNAP operating system versions. If exploited, the vulnerability could allow users to execute commands via a network. We have already fixed the vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-47218"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-47218, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-47218.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cgi-bin\/quick\/quick\.cgi(\/|;|$)/ nocase
        $path1 = "/cgi-bin/quick/" ascii nocase
        $param0 = /(^|[?&;])todo=uploaf_firmware_image(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_47246_sysaid_on_premises {
    meta:
        attack_type = "cve_2023_47246"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "SysAid Server - Remote Code Execution: In SysAid On-Premise before 23.3.36, a path traversal vulnerability leads to code execution after an attacker writes a file to the Tomcat webroot, as exploited in the wild in November 2023."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-47246"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-47246, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-47246.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])base64UserName=YWRtaW4=(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_47248_pyarrow {
    meta:
        attack_type = "cve_2023_47248"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PyArrow Flight RPC - Remote Code Execution: PyArrow Flight RPC from v0.14.0 through v14.0.0 allows remote attackers to execute arbitrary code via a maliciously crafted Python-defined extension type."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-47248"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-47248, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-47248.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/arrow\.flight\.protocol\.FlightService\/DoPut(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_47253_qualitor {
    meta:
        attack_type = "cve_2023_47253"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Qualitor <= 8.20 - Remote Code Execution: Qualitor through 8.20 allows remote attackers to execute arbitrary code via PHP code in the html/ad/adpesquisasql/request/processVariavel.php gridValoresPopHidden parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-47253"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-47253, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-47253.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/html\/ad\/adpesquisasql\/request\/processVariavel\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_47684_essential_grid {
    meta:
        attack_type = "cve_2023_47684"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Essential Grid <= 3.1.0 - Cross-Site Scripting: Unauthenticated Reflected Cross-Site Scripting (XSS) vulnerability in ThemePunch OHG Essential Grid plugin <= 3.1.0 versions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-47684"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-47684, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-47684.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=Essential_Grid_Front_request_ajax(&|$)/ nocase
        $param1 = /(^|[?&;])client_action=load_post_content(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_48023_ray {
    meta:
        attack_type = "cve_2023_48023"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Anyscale Ray 2.6.3 and 2.8.0 - Server-Side Request Forgery: The Ray Dashboard API is affected by a Server-Side Request Forgery (SSRF) vulnerability in the url parameter of the /log_proxy API endpoint. The API does not perform sufficient input validation within the affected."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-48023"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-48023, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-48023.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/log_proxy(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_48241_xwiki {
    meta:
        attack_type = "cve_2023_48241"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "XWiki < 4.10.15 - Information Disclosure: The Solr-based search suggestion provider that also duplicates as generic JavaScript API for search results in XWiki exposes the content of all documents of all wikis to anybody who has access to it, by default it is public. This."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-48241"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-48241, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-48241.yaml"
    strings:
        $path0 = /\/bin\/get\/XWiki\/SuggestSolrService(\/|;|$)/ nocase
        $path1 = /\/xwiki\/bin\/get\/XWiki\/SuggestSolrService(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_48728_avideo {
    meta:
        attack_type = "cve_2023_48728"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WWBN AVideo 11.6 - Cross-Site Scripting: A reflected XSS vulnerability exists in the functiongetOpenGraph videoName functionality of WWBN AVideo 11.6 and dev master commit 3c6bb3ff, allowing arbitrary Javascript execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-48728"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-48728, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-48728.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/objects\/functiongetOpenGraph\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_48777_website_builder {
    meta:
        attack_type = "cve_2023_48777"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Elementor 3.18.1 - File Upload/Remote Code Execution: The plugin is vulnerable to Remote Code Execution via file upload via the template import functionality, allowing authenticated attackers, with contributor-level access and above, to upload files and execute code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-48777"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-48777, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-48777.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])action=elementor(&|$)/ nocase
        $param1 = /(^|[?&;])action=elementor_ajax(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_49103_graph_api {
    meta:
        attack_type = "cve_2023_49103"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "OwnCloud - Phpinfo Configuration: An issue was discovered in ownCloud owncloud/graphapi 0.2.x before 0.2.1 and 0.3.x before 0.3.1. The graphapi app relies on a third-party GetPhpInfo.php library that provides a URL. When this URL is accessed, it reveals the configuration."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-49103"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-49103, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-49103.yaml"
    strings:
        $path0 = "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/" ascii nocase
        $path1 = "/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_49230_balance_two_firmware {
    meta:
        attack_type = "cve_2023_49230"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Peplink Balance Two before 8.4.0 - Unauthenticated Config Upload: A vulnerability in Peplink Balance Two prior to version 8.4.0 allows unauthenticated attackers to modify captive portal configurations due to a missing authorization check. Specifically, attackers can upload."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-49230"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-49230, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-49230.yaml"
    strings:
        $path0 = /\/cgi-bin\/MANGA\/index\.cgi(\/|;|$)/ nocase
        $path1 = /\/guest\/portal_admin_upload\.cgi(\/|;|$)/ nocase
        $path2 = /\/guest\/api\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])option=preview(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_49494_dedecms {
    meta:
        attack_type = "cve_2023_49494"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "DedeCMS v5.7.111 - Cross-Site Scripting: DedeCMS v5.7.111 was discovered to contain a reflective cross-site scripting (XSS) vulnerability via the component select_media_post_wangEditor.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-49494"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-49494, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-49494.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/uploads\/include\/dialog\/select_media_post_wangEditor\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_4966_netscaler_application_delivery {
    meta:
        attack_type = "cve_2023_4966"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Citrix Bleed - Leaking Session Tokens: Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA ?virtual?server."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4966"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4966, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4966.yaml"
    strings:
        $path0 = /\/oauth\/idp\/\.well-known\/openid-configuration(\/|;|$)/ nocase
        $path1 = /\/logon\/LogonPoint\/Authentication\/GetUserName(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_4973_academy_lms {
    meta:
        attack_type = "cve_2023_4973"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Academy LMS 6.2 - Cross-Site Scripting: A vulnerability was found in Academy LMS 6.2 on Windows. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file /academy/tutor/filter of the component GET Parameter Handler. The."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-4973"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4973, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-4973.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/academy\/tutor\/filter(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_49785_chatgpt_next_web {
    meta:
        attack_type = "cve_2023_49785"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ChatGPT-Next-Web - SSRF/XSS: Full-Read SSRF/XSS in NextChat, aka ChatGPT-Next-Web"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-49785"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-49785, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-49785.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/cors/http:/nextchat." ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_5003_active_directory_integration_l {
    meta:
        attack_type = "cve_2023_5003"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Active Directory Integration WP Plugin < 4.1.10 - Log Disclosure: The Active Directory Integration / LDAP Integration WordPress plugin before 4.1.10 stores sensitive LDAP logs in a buffer file when an administrator wants to export said logs. Unfortunately, this log file is."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-5003"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5003, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-5003.yaml"
    strings:
        $path0 = /\/wp-content\/ldap-authentication-report\.csv(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_50094_rengine {
    meta:
        attack_type = "cve_2023_50094"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "reNgine 2.2.0 - Command Injection: reNgine before 2.1.2 allows OS Command Injection if an adversary has a valid session ID. The attack places shell metacharacters in an api/tools/waf_detector/?url= string. The commands are executed as root via subprocess.check_output."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-50094"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-50094, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-50094.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/scan-engine\/update(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_50290_solr {
    meta:
        attack_type = "cve_2023_50290"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apache Solr - Host Environment Variables Leak via Metrics API: Exposure of Sensitive Information to an Unauthorized Actor Vulnerability in Apache Solr. The Solr Metrics API publishes all unprotected environment variables available to each Apache Solr instance. Users can specify."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-50290"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-50290, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-50290.yaml"
    strings:
        $path0 = /\/solr\/admin\/metrics(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_50720_xwiki {
    meta:
        attack_type = "cve_2023_50720"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki < 4.10.15 - Email Disclosure: The Solr-based search in XWiki discloses the email addresses of users even when obfuscation of email addresses is enabled. To demonstrate the vulnerability, search for objcontent:email* using XWiki's regular search interface."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-50720"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-50720, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-50720.yaml"
    strings:
        $param0 = /(^|[?&;])text=objcontent:email\*(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_5074_d_view_8 {
    meta:
        attack_type = "cve_2023_5074"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "D-Link D-View 8 v2.0.1.28 - Authentication Bypass: Use of a static key to protect a JWT token used in user authentication can allow an for an authentication bypass in D-Link D-View 8 v2.0.1.28"
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-5074"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5074, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-5074.yaml"
    strings:
        $path0 = /\/dview8\/api\/usersByLevel(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_50839_js_help_desk_2_8_1 {
    meta:
        attack_type = "cve_2023_50839"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JS Help Desk <= 2.8.1 - SQL Injection: The JS Help Desk Best Help Desk & Support Plugin plugin for WordPress is vulnerable to SQL Injection via the 'email' and 'trackingid' parameters in all versions up to 2.8.2 (exclusive) due to insufficient escaping on the user supplied."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-50839"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-50839, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-50839.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])form_request=jssupportticket(&|$)/ nocase
        $param1 = /(^|[?&;])jstmod=ticket(&|$)/ nocase
        $param2 = /(^|[?&;])task=showticketstatus(&|$)/ nocase
        $param3 = /(^|[?&;])ticketid=test123(&|$)/ nocase
        $param4 = /(^|[?&;])email=test@test\.com(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_50917_majordomo {
    meta:
        attack_type = "cve_2023_50917"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MajorDoMo thumb.php - OS Command Injection: MajorDoMo (aka Major Domestic Module) before 0662e5e allows command execution via thumb.php shell metacharacters. NOTE: this is unrelated to the Majordomo mailing-list manager."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-50917"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-50917, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-50917.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/modules\/thumb\/thumb\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])url=cnRzcDovL2EK(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_50968_ofbiz {
    meta:
        attack_type = "cve_2023_50968"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache OFBiz < 18.12.11 - Server Side Request Forgery: Arbitrary file properties reading vulnerability in Apache Software Foundation Apache OFBiz when user operates an uri call without authorizations. The same uri can be operated to realize a SSRF attack also without."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-50968"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-50968, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-50968.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/partymgr/control/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_5204_wordpress_ai_chatbot_wpbot_4_8 {
    meta:
        attack_type = "cve_2023_5204"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress AI ChatBot (WPBot) <= 4.8.9 - SQL Injection: ChatBot plugin for WordPress up to 4.8.9 contains a sql_injection caused by insufficient escaping and lack of preparation on the $strid parameter, letting unauthenticated attackers extract sensitive data, exploit requires."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-5204"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5204, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-5204.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=wpbo_search_response(&|$)/ nocase
        $param1 = /(^|[?&;])strid=1 AND \(SELECT 42 FROM \(SELECT\(SLEEP\(8\)\)\)sqltest\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_52085_winter {
    meta:
        attack_type = "cve_2023_52085"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Winter CMS Local File Inclusion - (LFI): Winter is a free, open-source content management system. Users with access to backend forms that include a ColorPicker FormWidget can provide a value that would then be included without further processing in the compilation of custom."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-52085"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-52085, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-52085.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/backend\/system\/mailbrandsettings(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_52163_digiever_ds_2105_pro {
    meta:
        attack_type = "cve_2023_52163"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Digiever DS-2105 Pro - Command Injection: Digiever DS-2105 Pro 3.1.0.71-11 contains a command injection caused by unsanitized input in time_tzsetup.cgi, letting attackers execute arbitrary commands remotely, exploit requires no authentication."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-52163"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-52163, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-52163.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])cgiName=time_tzsetup\.cgi(&|$)/ nocase
        $param1 = /(^|[?&;])ntp=\/etc\/digigiver-release(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_52251_ui {
    meta:
        attack_type = "cve_2023_52251"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kafka UI 0.7.1 Command Injection: An issue discovered in provectus kafka-ui 0.4.0 through 0.7.1 allows remote attackers to execute arbitrary code via the q parameter of /api/clusters/local/topics/{topic}/messages."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-52251"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-52251, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-52251.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/clusters(\/|;|$)/ nocase
        $path1 = "/api/clusters/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_5244_microweber {
    meta:
        attack_type = "cve_2023_5244"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microweber < V.2.0 - Cross-Site Scripting: Reflected Cross-Site Scripting Vulnerability in types GET parameter on the /editor_tools/rte_image_editor endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-5244"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5244, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-5244.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/editor_tools\/rte_image_editor(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_5360_royal_elementor_addons {
    meta:
        attack_type = "cve_2023_5360"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Royal Elementor Addons Plugin <= 1.3.78 - Arbitrary File Upload: Arbitrary File Upload vulnerability in WordPress Royal Elementor Addons Plugin. This could allow a malicious actor to upload any type of file to your website. This can include backdoors which are then."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-5360"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5360, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-5360.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/uploads/wpr-addons/forms/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_5375_mosparo {
    meta:
        attack_type = "cve_2023_5375"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Mosparo < 1.0.2 - Open Redirect: Open Redirect in GitHub repository mosparo/mosparo prior to 1.0.2."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-5375"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5375, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-5375.yaml"
    strings:
        $path0 = "/project/switch/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_54391_proxmox_ve {
    meta:
        attack_type = "cve_2023_54391"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Proxmox VE - Default Credentials with TFA Bypass: Detected Proxmox VE was accessible using default root@pam credentials combined with a TFA challenge bypass. An attacker could authenticate as root by submitting the default password 'root@pam' along with a crafted tfa-challenge."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-54391"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-54391, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-54391.yaml"
    strings:
        $path0 = /\/api2\/json\/access\/ticket(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_5556_on_premises_installation {
    meta:
        attack_type = "cve_2023_5556"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Structurizr on-premises - Cross Site Scripting: Cross-site Scripting (XSS) - Reflected in GitHub repository structurizr/onpremises prior to 3194."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-5556"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5556, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-5556.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/workspace\/create(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_5559_10web_booster {
    meta:
        attack_type = "cve_2023_5559"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "10Web Booster < 2.24.18 - Unauthenticated Arbitrary Option Deletion: The 10Web Booster WordPress plugin before 2.24.18 does not validate the option name given to some AJAX actions, allowing unauthenticated users to delete arbitrary options from the database, leading to denial."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-5559"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5559, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-5559.yaml"
    strings:
        $param0 = /(^|[?&;])action=two_activate_score_check(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_5815_news_blog_designer_pack {
    meta:
        attack_type = "cve_2023_5815"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "News & Blog Designer Pack WordPress Blog Plugin <= 3.4.1 - Unauthenticated Local File Inclusion: The News & Blog Designer Pack WordPress plugin up to version 3.4.1 contains a remote code execution caused by local file inclusion in the bdp_get_more_post function, letting."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-5815"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5815, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-5815.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])shrt_param\[design\]=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/wp-login(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_5914_citrix_storefront {
    meta:
        attack_type = "cve_2023_5914"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Citrix StoreFront - Cross-Site Scripting: Reflected Cross-Site Scripting issue which is exploitable without authentication. This vulnerability was exploitable through coercing an error message during an XML parsing procedure in the SSO flow."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-5914"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5914, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-5914.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/Citrix\/teststoreAuth\/SamlTest(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_5991_hotel_booking_lite {
    meta:
        attack_type = "cve_2023_5991"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hotel Booking Lite < 4.8.5 - Arbitrary File Download & Deletion: The Hotel Booking Lite WordPress plugin before 4.8.5 does not validate file paths provided via user input, as well as does not have proper CSRF and authorisation checks, allowing unauthenticated users to download."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-5991"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5991, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-5991.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])mphb_action=download(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_6000_popup_builder {
    meta:
        attack_type = "cve_2023_6000"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Popup Builder <= 4.2.3 - Unauthenticated Stored XSS: The Popup Builder WordPress plugin before 4.2.3 does not prevent simple visitors from updating existing popups, and injecting raw JavaScript in them, which could lead to Stored XSS attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6000"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6000, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6000.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])sgpb-WillOpen=alert\('document\.domain'\);(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_6021_ray {
    meta:
        attack_type = "cve_2023_6021"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ray API - Local File Inclusion: LFI in Ray's log API endpoint allows attackers to read any file on the server without authentication."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6021"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6021, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6021.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])view=summary(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_6023_modeldb {
    meta:
        attack_type = "cve_2023_6023"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "VertaAI ModelDB - Path Traversal: The endpoint '/api/v1/artifact/getArtifact?artifact_path=' is vulnerable to path traversal. The main cause of this vulnerability is due to the lack of validation and sanitization of the artifact_path parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6023"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6023, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6023.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/api\/v1\/artifact\/getArtifact(\/|;|$)/ nocase
        $param0 = /(^|[?&;])artifact_path=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_6038_h2o {
    meta:
        attack_type = "cve_2023_6038"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "H2O ImportFiles - Local File Inclusion: An attacker is able to read any file on the server hosting the H2O dashboard without any authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6038"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6038, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6038.yaml"
    strings:
        $path0 = /\/3\/ImportFiles(\/|;|$)/ nocase
        $path1 = /\/3\/ParseSetup(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6065_quttera_web_malware_scanner {
    meta:
        attack_type = "cve_2023_6065"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Quttera Web Malware Scanner <= 3.4.1.48 - Sensitive Data Exposure: The Quttera Web Malware Scanner WordPress plugin before 3.4.2.1 doesn't restrict access to detailed scan logs, which allows a malicious actor to discover local paths and portions of the site's code"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6065"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6065, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6065.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/quttera-web-malware-scanner\/quttera_wp_report\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6266_backup_migration {
    meta:
        attack_type = "cve_2023_6266"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Backup Migration <= 1.3.6 - Path Traversal: WordPress Backup Migration plugin versions up to 1.3.6 contain a path traversal and file validation issue in handle_downloading function, letting unauthenticated attackers download backup files containing sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6266"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6266, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6266.yaml"
    strings:
        $param0 = /(^|[?&;])backup-migration=BMI_BACKUP(&|$)/ nocase
        $param1 = /(^|[?&;])backup-id=\.\.\/complete_logs\.log(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_6275_fluig {
    meta:
        attack_type = "cve_2023_6275"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "TOTVS Fluig Platform - Cross-Site Scripting: A vulnerability was found in TOTVS Fluig Platform 1.6.x/1.7.x/1.8.0/1.8.1. It has been rated as problematic. Affected by this issue is some unknown functionality of the file /mobileredir/openApp.jsp of the component mobileredir. The."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6275"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6275, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6275.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/mobileredir\/openApp\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6329_idsecure {
    meta:
        attack_type = "cve_2023_6329"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Control iD iDSecure - Authentication Bypass: An authentication bypass vulnerability exists in Control iD iDSecure v4.7.32.0. The login routine used by iDS-Core.dll contains a 'passwordCustom' option that allows an unauthenticated attacker to compute valid credentials that can."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6329"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6329, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6329.yaml"
    strings:
        $path0 = /\/api\/login\/unlockGetData(\/|;|$)/ nocase
        $path1 = "/api/operator/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6380_opencms {
    meta:
        attack_type = "cve_2023_6380"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "OpenCms 14 & 15 - Open Redirect: Open redirect vulnerability has been found in the Open CMS product affecting versions 14 and 15 of the 'Mercury' template"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6380"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6380, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6380.yaml"
    strings:
        $path0 = /\/system\/modules\/alkacon\.mercury\.template\.jsondemo\/elements\/jsonapi\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6389_wordpress_toolbar {
    meta:
        attack_type = "cve_2023_6389"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Toolbar <= 2.2.6 - Open Redirect: The plugin redirects to any URL via the 'wptbto' parameter. This makes it possible for unauthenticated attackers to redirect users to potentially malicious sites if they can successfully trick them into performing an action."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6389"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6389, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6389.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/wordpress-toolbar\/toolbar\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])wptbhash=acme(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_6505_prime_mover {
    meta:
        attack_type = "cve_2023_6505"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Prime Mover < 1.9.3 - Sensitive Data Exposure: Prime Mover plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 1.9.2 via directory listing in the 'prime-mover-export-files/1/' folder. This makes it possible for."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6505"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6505, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6505.yaml"
    strings:
        $path0 = "/wp-content/uploads/prime-mover-export-files/1/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6549_netscaler_gateway {
    meta:
        attack_type = "cve_2023_6549"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Citrix Netscaler ADC & Gateway - Out-Of-Bounds Memory Read: The vulnerability would enable an attacker to remotely obtain sensitive information from a NetScaler appliance configured as a Gateway or AAA virtual server via a very commonly connected Web interface, and without."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6549"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6549, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6549.yaml"
    strings:
        $path0 = /\/nf\/auth\/startwebview\.do(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6568_mlflow {
    meta:
        attack_type = "cve_2023_6568"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Mlflow - Cross-Site Scripting: The vulnerability allows an attacker to inject malicious code into the Content-Type header of a POST request, which is then reflected back to the user without proper sanitization or escaping."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6568"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6568, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6568.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/api\/2\.0\/mlflow\/users\/create(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6592_wordpress_fastdup_2_1_9_sensit {
    meta:
        attack_type = "cve_2023_6592"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress FastDup <= 2.1.9 Sensitive Information Exposure - Directory Listing: FastDup WordPress plugin < 2.2 contains a directory listing vulnerability caused by lack of access restrictions in sensitive directories, letting attackers view export files, exploit requires no."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6592"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6592, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6592.yaml"
    strings:
        $path0 = "/wp-content/plugins/fastdup/logs/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6623_essential_blocks {
    meta:
        attack_type = "cve_2023_6623"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Essential Blocks < 4.4.3 - Local File Inclusion: Wordpress Essential Blocks plugin prior to 4.4.3 was discovered to be vulnerable to a significant Local File Inclusion vulnerability that may be exploited by any attacker, regardless of whether they have an account on the site."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6623"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6623, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6623.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])rest_route=\/essential-blocks\/v1\/products(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_6655_e_hr {
    meta:
        attack_type = "cve_2023_6655"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hongjing e-HR 2020 - SQL Injection: A vulnerability, which was classified as critical, has been found in Hongjing e-HR 2020. Affected by this issue is some unknown functionality of the file /w_selfservice/oauthservlet/%2e./.%2e/general/inform/org/loadhistroyorgtree of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6655"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6655, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6655.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/w_selfservice\/oauthservlet\/\.\.\/\.\.\/general\/inform\/org\/loadhistroyorgtree(\/|;|$)/ nocase
        $param0 = /(^|[?&;])isroot=child(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_6750_clone {
    meta:
        attack_type = "cve_2023_6750"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress WP Clone <= 2.4.2 - Database Backup Exposure: Clone WordPress plugin < 2.4.3 contains a buffer overflow caused by storing in-progress backup information in publicly accessible buffer files at a static file path, letting attackers access sensitive backup data, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6750"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6750, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6750.yaml"
    strings:
        $path0 = /\/wp-content\/uploads\/wp-clone\/wpclone_backup\/database\.sql(\/|;|$)/ nocase
        $path1 = /\/wp-content\/uploads\/wp-clone\/wpclone_backup\/prefix\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6786_payment_gateway_for_telcell_2 {
    meta:
        attack_type = "cve_2023_6786"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Payment Gateway for Telcell < 2.0.4 - Open Redirect: The plugin does not validate the api_url parameter before redirecting the user to its value, leading to an Open Redirect issue"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6786"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6786, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6786.yaml"
    strings:
        $param0 = /(^|[?&;])action=redirect_telcell_form(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_6831_mlflow {
    meta:
        attack_type = "cve_2023_6831"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "mlflow - Path Traversal: Path Traversal: '/../filename' in GitHub repository mlflow/mlflow prior to 2.9.2."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6831"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6831, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6831.yaml"
    strings:
        $path0 = "/api/2.0/mlflow-artifacts/artifacts/" ascii nocase
        $path1 = /\/api\/2\.0\/mlflow-artifacts\/artifacts\/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2fpasswd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6875_post_smtp_mailer {
    meta:
        attack_type = "cve_2023_6875"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress POST SMTP Mailer <= 2.8.7 - Authorization Bypass: The POST SMTP Mailer Email log, Delivery Failure Notifications and Best Mail SMTP for WordPress plugin for WordPress is vulnerable to unauthorized access of data and modification of data due to a type juggling issue on."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6875"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6875, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6875.yaml"
    strings:
        $path0 = /\/wp-json\/post-smtp\/v1\/connect-app(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6970_wp_recipe_maker_9_1_0 {
    meta:
        attack_type = "cve_2023_6970"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP Recipe Maker <= 9.1.0 - Reflected XSS via Referer Header: The WP Recipe Maker plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the 'Referer' header in all versions up to, and including, 9.1.0 due to insufficient input sanitization and output escaping.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6970"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6970, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6970.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-json\/wp\/v2\/wprm_recipe(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_6989_shield_security {
    meta:
        attack_type = "cve_2023_6989"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Shield Security WP Plugin <= 18.5.9 - Local File Inclusion: The Shield Security Smart Bot Blocking & Intrusion Prevention Security plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 18.5.9 via the render_action_template parameter.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-6989"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-6989, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-6989.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])ex=generic_render(&|$)/ nocase
        $param1 = /(^|[?&;])exnonce=5a988a925a(&|$)/ nocase
        $param2 = /(^|[?&;])render_action_template=\.\.\/\.\.\/icwp-wpsf\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2023_7116_datax_web {
    meta:
        attack_type = "cve_2023_7116"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WeiYe-Jing datax-web <= 2.1.2 - OS Command Injection: A vulnerability, which was classified as critical, has been found in WeiYe-Jing datax-web 2.1.2. Affected by this issue is some unknown functionality of the file /api/log/killJob of the component HTTP POST Request Handler.."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-7116"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-7116, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-7116.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/log\/killJob(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_7164_wordpress_backwpup_4_0_4 {
    meta:
        attack_type = "cve_2023_7164"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress BackWPup < 4.0.4 - Backup File Disclosure: BackWPup WordPress plugin < 4.0.4 contains a directory listing vulnerability caused by lack of access restrictions in its temporary backup folder, letting unauthenticated attackers download site backups, exploit requires no."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-7164"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-7164, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-7164.yaml"
    strings:
        $path0 = "/wordpress/wp-content/uploads/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_7165_jetbackup {
    meta:
        attack_type = "cve_2023_7165"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "JetBackup <= 2.0.9.7 - Sensitive Information Exposure via Directory Listing: JetBackup WordPress plugin <= 2.0.9.9 does not use index files to prevent directory listing in certain configurations, letting malicious actors leak backup files, exploit requires access to the web."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-7165"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-7165, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-7165.yaml"
    strings:
        $path0 = "/wp-content/uploads/jetbackup/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2023_7327_ozeki_10_sms_gateway_10_3_208 {
    meta:
        attack_type = "cve_2023_7327"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ozeki 10 SMS Gateway 10.3.208 - Arbitrary File Read: An arbitrary file read vulnerability, also known as a 'path traversal' or 'directory traversal' vulnerability, occurs when an attacker is able to access files on a system that they shouldn't have access to. This vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2023-7327"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-7327, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-7327.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2f\.\.%2fwindows\/win\.ini(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}
