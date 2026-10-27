// Baseline rules generated from public exploit and exposure checks in
// ProjectDiscovery nuclei-templates (MIT License,
// https://github.com/projectdiscovery/nuclei-templates). Each rule keys on the
// most specific request indicator of one check: a path, a static parameter or
// a vendor header that no other check and no benign request uses. Rules are
// confidence = "medium": a probe for the endpoint is a strong signal, but a
// rule cannot tell an exploit attempt from a scanner fingerprinting it.
// The `reference` field links the source check.

rule krawl_cve_2026_0558_lollms {
    meta:
        attack_type = "cve_2026_0558"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LolLMS <= 2.2.0 - Unauthenticated File Upload: A vulnerability in parisneo/lollms up to and including version 2.2.0 allows unauthenticated users to upload and process files through the /api/files/extract-text endpoint. The endpoint lacks the Depends(get_current_active_user)."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-0558"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-0558, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-0558.yaml"
    strings:
        $path0 = "/api/files/extract-text" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_0561_shield_security {
    meta:
        attack_type = "cve_2026_0561"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Shield Security <= 21.0.8 - Unauthenticated Reflected XSS: Shield Security WordPress plugin <= 21.0.8 contains a reflected cross-site scripting caused by insufficient input sanitization and output escaping in the 'message' parameter, letting unauthenticated attackers inject."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-0561"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-0561, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-0561.yaml"
        response_type = "xss"
    strings:
        $param0 = "ex=display_full_page_dynamic" ascii nocase
        $param1 = "render_slug=render_shield_wploginreplica_header" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_0650_flagr {
    meta:
        attack_type = "cve_2026_0650"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OpenFlagr <= 1.1.18 - Authentication Bypass: OpenFlagr <= 1.1.18 contains an authentication bypass caused by improper path normalization handling in HTTP middleware whitelist logic, letting attackers access protected API endpoints without valid credentials, exploit requires."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-0650"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-0650, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-0650.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/v1/health/../flags" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_0692_bluesnap_payment_gateway_for_w {
    meta:
        attack_type = "cve_2026_0692"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "BlueSnap Payment Gateway for WooCommerce <=3.4.0 - IPN Authorization Bypass: BlueSnap Payment Gateway for WooCommerce <= 3.4.0 validates its unauthenticated IPN webhook using WooCommerce's client-IP geolocation, which trusts spoofed forwarding headers instead of requiring a."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-0692"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-0692, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-0692.yaml"
    strings:
        $param0 = "wc-api=bluesnap" ascii nocase
        $param1 = "transactionType=CHARGEBACK" ascii nocase
        $param2 = "referenceNumber=CVE0692CODEX" ascii nocase
        $param3 = "reason=CVE0692" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_0702_vidshop_for_woocommerce_1_1_4 {
    meta:
        attack_type = "cve_2026_0702"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "VidShop for WooCommerce <= 1.1.4 - SQL Injection: VidShop Shoppable Videos for WooCommerce plugin for WordPress <= 1.1.4 contains a time-based SQL injection caused by insufficient escaping of the 'fields' parameter, letting unauthenticated attackers extract sensitive database."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-0702"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-0702, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-0702.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/wp-json/vsfw/v1/videos" ascii nocase
        $param0 = "fields=(SELECT 424242*2) as id" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_0926_prodigy_commerce_3_3_0 {
    meta:
        attack_type = "cve_2026_0926"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Prodigy Commerce <= 3.3.0 - Local File Inclusion: Prodigy Commerce WordPress plugin <= 3.2.9 contains a local file inclusion caused by improper sanitization of 'parameters[template_name]' parameter, letting unauthenticated attackers include and execute arbitrary files remotely."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-0926"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-0926, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-0926.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "action=prodigy-render-my-account-widget" ascii nocase
        $param1 = "parameters[template_name]=etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_102782_simple_membership {
    meta:
        attack_type = "cve_2026_102782"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OrdaSoft Simple Membership < 7.4.0 - SQL Injection: OrdaSoft Simple Membership (com_simplemembership) for Joomla before 7.4.0 is vulnerable to unauthenticated SQL injection via the 'login' parameter of the checkLoginPass task (site/simplemembership.php). The handler passes the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-102782"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-102782, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-102782.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "option=com_simplemembership" ascii nocase
        $param1 = "task=checkLoginPass" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_103956_loom_for_aws {
    meta:
        attack_type = "cve_2026_103956"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Loom for AWS < 1.6.1 - Unauthenticated Super-Admin Access: Loom for AWS < 1.6.1 contains a broken authentication caused by missing authentication for critical functions in the authentication dependency, letting remote actors obtain super-admin authority over the agent control."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-103956"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-103956, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-103956.yaml"
    strings:
        $path0 = "/api/mcp/servers" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_105134_ahsaycbs {
    meta:
        attack_type = "cve_2026_105134"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "AhsayCBS <= 10.3.4 - Unauthenticated RCE: Ahsay AhsayCBS <= 10.3.2 contains a command injection caused by manipulation of the /'random/' argument in /rps/api/json/UpdateReceivers.do of Replication Receiver, letting remote attackers execute OS commands, exploit requires crafted."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-105134"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-105134, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-105134.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/rps/api/json/ListReceiver.do" ascii nocase
        $path1 = "/rps/api/json/UpdateReceivers.do" ascii nocase
        $path2 = "/rps/obs7/rpsfile/upload" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_10520_ivanti_sentry {
    meta:
        attack_type = "cve_2026_10520"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Ivanti Sentry - OS Command Injection: An OS Command Injection vulnerability in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated user to achieve root-level remote code execution"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-10520"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-10520, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-10520.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/mics/api/v2/sentry/mics-config/handleMessage" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_10768_localgov_workflows {
    meta:
        attack_type = "cve_2026_10768"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Drupal LocalGov Workflows < 1.6.0 - Information Disclosure: Drupal LocalGov Workflows < 1.6.0 contains a broken access control vulnerability caused by missing authorization checks, letting attackers perform forceful browsing to access unauthorized resources, exploit requires no."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-10768"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-10768, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-10768.yaml"
    strings:
        $path0 = "/admin/content/localgov-service-contact/content-by-owner" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_10818_wpforms {
    meta:
        attack_type = "cve_2026_10818"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WPForms Pro <= 1.10.1.1 - Unauthenticated Arbitrary File Upload: WPForms Pro for WordPress up to and including 1.10.1.1 allows unauthenticated arbitrary file upload. The wpforms_upload_chunk_init, wpforms_upload_chunk and wpforms_file_chunks_uploaded AJAX actions are registered."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-10818"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-10818, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-10818.yaml"
    strings:
        $path0 = "/wp-content/uploads/wpforms/tmp/" ascii nocase
        $param0 = "action=wpforms_upload_chunk_init" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_10823_ymc_filter {
    meta:
        attack_type = "cve_2026_10823"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "YMC Filter WordPress - Unauthenticated Post Disclosure: YMC Filter WordPress plugin < 3.11.3 contains a broken access control vulnerability caused by improper authorization and lack of validation in a REST API endpoint, letting unauthenticated attackers retrieve private and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-10823"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-10823, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-10823.yaml"
    strings:
        $path0 = "/wp-json/ymc/v1/posts/filter" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_109618_php {
    meta:
        attack_type = "cve_2026_109618"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "PHP2Shell (CVE-2026-109618/CVE-2026-109619) - Active Crash Detection: PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-109618"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-109618, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-109618.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "Content-Disposition:name=a;filename=" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_1115_lollms {
    meta:
        attack_type = "cve_2026_1115"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "parisneo/lollms < 2.2.0 - Authenticated Stored XSS: parisneo/lollms < 2.2.0 contains a stored XSS caused by unsanitized user input in create_post function in backend/routers/social/__init__.py, letting attackers inject malicious scripts executed in user browsers, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-1115"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-1115, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1115.yaml"
        response_type = "xss"
    strings:
        $path0 = "/api/social/posts" ascii nocase
        $path1 = "/api/social/feed" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_11387_sms_alert {
    meta:
        attack_type = "cve_2026_11387"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SMS Alert SMS & OTP for WooCommerce - Privilege Escalation: The SMS Alert SMS & OTP for WooCommerce, Order Notifications & Abandoned Cart Recovery plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 3.9.5. This."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-11387"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-11387, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-11387.yaml"
    strings:
        $param0 = "option=smsalert-change-password-form" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_11565_file_manager_advanced {
    meta:
        attack_type = "cve_2026_11565"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Advanced File Manager < 5.4.13 - Arbitrary File Read: The Advanced File Manager WordPress plugin before 5.4.13 does not perform capability checks in several of its file management AJAX actions, allowing users with any role to which an administrator has granted."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-11565"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-11565, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-11565.yaml"
    strings:
        $param0 = "page=file_manager_advanced_ui" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_116067_paisa {
    meta:
        attack_type = "cve_2026_116067"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Paisa < 0.7.8 - Unauthenticated Path Traversal: Paisa < 0.7.8 contains a path traversal vulnerability caused by improper sanitization of file names in GetFile, GetSheet, DeleteBackups, and DeleteSheetBackups handlers, letting unauthenticated attackers read arbitrary files and."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-116067"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-116067, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-116067.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/editor/file" ascii nocase
        $path1 = "/api/sheets/file" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_116485_danmu_api {
    meta:
        attack_type = "cve_2026_116485"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "danmu_api - Unauthenticated Access to Admin API via Default Token: danmu_api before 1.21.7 contains an authentication bypass caused by default TOKEN usage and unset ADMIN_TOKEN, letting unauthenticated attackers modify server environment configuration via specific API."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-116485"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-116485, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-116485.yaml"
    strings:
        $path0 = "/api/cache/animes" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_11801_wpadverts {
    meta:
        attack_type = "cve_2026_11801"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WPAdverts <= 2.3.2 - Information Disclosure: WPAdverts Classifieds Plugin for WordPress <= 2.3.2 contains an authorization bypass caused by improper user authorization verification in classifieds-types REST endpoint, letting unauthenticated attackers retrieve internal site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-11801"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-11801, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-11801.yaml"
    strings:
        $path0 = "/wp-json/wpadverts/v1/classifieds-types" ascii nocase
        $param0 = "rest_route=/wpadverts/v1/classifieds-types" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_1207_django {
    meta:
        attack_type = "cve_2026_1207"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Django RasterField - SQL Injection: Django < 6.0.2, < 5.2.11, and < 4.2.28 contains a SQL injection caused by improper sanitization of the band index parameter in RasterField on PostGIS, letting remote attackers inject SQL, exploit requires crafted input."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-1207"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-1207, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1207.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/api/raster/search/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_12227_visualcomposer {
    meta:
        attack_type = "cve_2026_12227"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Visual Composer <= 45.16.0 - Unauthenticated LFI: Visual Composer Website Builder for WordPress <= 45.16.0 contains a local file inclusion vulnerability caused by improper validation of the vcv-template parameter, letting unauthenticated attackers include and execute arbitrary."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-12227"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-12227, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-12227.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "vcv-template=../../../../../../../etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_12394_memberglut {
    meta:
        attack_type = "cve_2026_12394"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress MemberGlut < 1.1.5 - Unauthenticated Privilege Escalation: MemberGlut WordPress plugin < 1.1.5 contains a broken access control vulnerability caused by lack of validation of roles during front-end registration, letting unauthenticated users register with arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-12394"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-12394, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-12394.yaml"
    strings:
        $param0 = "action=memberglut_register" ascii nocase
        $param1 = "password=Cve12394Test1!" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_12609_theia {
    meta:
        attack_type = "cve_2026_12609"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Eclipse Theia - Unauthenticated Path Traversal: Eclipse Theia's plugin-ext backend exposes the hostedPlugin endpoint without constraining the resolved path to the plugin directory. An unauthenticated request using encoded traversal sequences can therefore read files accessible."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-12609"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-12609, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-12609.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/hostedPlugin/vscode_bat/../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_12741_wp_fast_total_search {
    meta:
        attack_type = "cve_2026_12741"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WP Fast Total Search <= 1.80.280 - Unauthenticated Time-Based Blind SQL Injection: WP Fast Total Search (fulltext-search) versions up to and including 1.80.280 contain an unauthenticated time-based blind SQL injection. The wp_ajax_nopriv_wpfts_autocomplete handler reads the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-12741"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-12741, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-12741.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=wpfts_autocomplete" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_1277_url_shortify_1_12_1 {
    meta:
        attack_type = "cve_2026_1277"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "URL Shortify <= 1.12.1 - Open Redirect: The URL Shortify plugin for WordPress is vulnerable to Open Redirect in all versions up to, and including, 1.12.1 due to insufficient validation on the 'redirect_to' parameter in the promotional dismissal handler. This makes it possible."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-1277"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-1277, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1277.yaml"
    strings:
        $param0 = "option_name=bfcm_2025_offer" ascii nocase
        $param1 = "option_name=welcome_offer" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_13001_podlove_podcasting_plugin_for {
    meta:
        attack_type = "cve_2026_13001"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Podlove Podcast Publisher <= 4.5.1 - Arbitrary File Upload: Podlove Podcast Publisher plugin for WordPress through 4.5.1 is vulnerable to arbitrary file uploads due to missing file type validation in the podlove_handle_cache_files function. The image cache derives the stored."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-13001"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-13001, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-13001.yaml"
    strings:
        $path0 = "/wp-content/cache/podlove/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_1306_midi_synth {
    meta:
        attack_type = "cve_2026_1306"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress midi-Synth <= 1.1.0 - Unauthenticated Arbitrary File Upload: WordPress midi-Synth plugin /u003C= 1.1.0 contains an unrestricted file upload vulnerability caused by missing file type and extension validation in the 'export' AJAX action, letting unauthenticated."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-1306"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-1306, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1306.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/plugins/midi-synth/sound/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_13147_kirki {
    meta:
        attack_type = "cve_2026_13147"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Kirki < 6.0.12 - Server-Side Request Forgery: Kirki WordPress plugin < 6.0.12 contains a server-side request forgery caused by lack of URL validation, letting unauthenticated attackers make the site issue HTTP requests to arbitrary hosts, exploit requires no."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-13147"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-13147, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-13147.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = "endpoint=get-pre-built-html" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_13153_essential_blocks_6_4_0 {
    meta:
        attack_type = "cve_2026_13153"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Essential Blocks < 6.4.0 - Information Disclosure: Gutenberg Essential Blocks WordPress plugin < 6.4.0 contains an information disclosure caused by unrestricted access to a public REST route exposing non-public WooCommerce sales metrics, letting unauthenticated users read."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-13153"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-13153, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-13153.yaml"
    strings:
        $path0 = "/wp-json/essential-blocks/v1/products" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_1357_wpvivid_backuprestore {
    meta:
        attack_type = "cve_2026_1357"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WPvivid Backup & Migration <= 0.9.123 - Arbitrary File Upload: WPvivid Backup & Migration plugin for WordPress <= 0.9.123 contains an unauthenticated arbitrary file upload vulnerability caused by improper error handling in RSA decryption and lack of path sanitization, letting."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-1357"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-1357, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1357.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "wpvivid_action=send_to_site" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_1405_wordpress_slider_future_1_0_5 {
    meta:
        attack_type = "cve_2026_1405"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Slider Future <= 1.0.5 - Unauthenticated Arbitrary File Upload: Slider Future WordPress plugin <= 1.0.5 contains an unrestricted file upload vulnerability caused by missing file type validation in 'slider_future_handle_image_upload', letting unauthenticated attackers."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-1405"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-1405, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1405.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-json/slider-future/v1/upload-image/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_14870_contact_form_entries {
    meta:
        attack_type = "cve_2026_14870"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Database for Contact Form 7, WPforms, Elementor forms < 1.5.3 - Cross-Site Scripting: Database for Contact Form 7, WPforms, Elementor forms WordPress plugin < 1.5.3 contains a reflected XSS caused by improper sanitization and escaping of a parameter in an admin page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-14870"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-14870, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-14870.yaml"
        response_type = "xss"
    strings:
        $param0 = "form_id=x';alert(document.domain)//" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_1492_wordpress_user_registration_me {
    meta:
        attack_type = "cve_2026_1492"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress User Registration & Membership <= 5.1.2 - Unauthenticated Privilege Escalation: User Registration & Membership WordPress plugin <= 5.1.2 contains an improper privilege management vulnerability caused by accepting user-supplied roles without server-side allowlist."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-1492"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-1492, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1492.yaml"
    strings:
        $path0 = "/registration/" ascii nocase
        $param0 = "security=invalid" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_1557_wp_responsive_images_1_0 {
    meta:
        attack_type = "cve_2026_1557"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WP Responsive Images <= 1.0 - Arbitrary File Read: WP Responsive Images plugin for WordPress <= 1.0 contains a path traversal caused by improper sanitization of the 'src' parameter, letting unauthenticated attackers read arbitrary files on the server."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-1557"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-1557, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1557.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/wp-responsive-images/image_handler.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_15733_wgdashboard {
    meta:
        attack_type = "cve_2026_15733"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WGDashboard <= 4.3.2 - Authenticated OS Command Injection /etc/passwd Read: WGDashboard <= 4.2.3 contains a command injection caused by multiple OS command injection points, letting authenticated attackers execute arbitrary commands as root."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-15733"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-15733, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-15733.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/authenticate" ascii nocase
        $path1 = "/api/getWireguardConfigurations" ascii nocase
        $path2 = "/api/addPeers/" ascii nocase
        $path3 = "/api/updatePeerSettings/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_1603_endpoint_manager {
    meta:
        attack_type = "cve_2026_1603"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Ivanti Endpoint Manager - Authentication Bypass: Ivanti Endpoint Manager < 2024 SU5 contains an authentication bypass caused by improper access control, letting remote unauthenticated attackers leak stored credential data, exploit requires no special privileges."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-1603"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-1603, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1603.yaml"
    strings:
        $path0 = "/RemoteControlAuth/api/Auth" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_16268_newsletters_lite {
    meta:
        attack_type = "cve_2026_16268"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Newsletters < 4.16 - Unauthenticated SSRF via SNS Bounce Handler: Newsletters WordPress plugin < 4.16 contains a server-side request forgery caused by lack of authentication and validation in bounce-processing requests, letting unauthenticated attackers make arbitrary requests."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-16268"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-16268, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-16268.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = "wpmlmethod=bounce" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_16959_media_library_assistant {
    meta:
        attack_type = "cve_2026_16959"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Media Library Assistant < 3.40 - SQL Injection: The Media Library Assistant WordPress plugin before 3.40 does not validate a search parameter before concatenating it into a SQL query in one of its media-library query handlers, allowing users with the Author role and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-16959"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-16959, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-16959.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=mla-query-attachments" ascii nocase
        $param1 = "query[s]=zzqnomatchaaa zzqnomatchbbb" ascii nocase
        $param2 = "query[mla_search_fields][]=title" ascii nocase
        $param3 = "query[mla_search_fields][]=content" ascii nocase
        $param4 = "query[mla_search_connector]=OR SLEEP(8) OR" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_17540_file_manager {
    meta:
        attack_type = "cve_2026_17540"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Bit File Manager < 6.9.1 - Arbitrary File Read: The Bit File Manager WordPress plugin before 6.9.1 does not properly authorise its file management commands, allowing any authenticated user, such as a subscriber, to read and delete arbitrary files under the WordPress."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-17540"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-17540, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-17540.yaml"
    strings:
        $param0 = "action=bitapps_fm_connector" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_18072_advanced_responsive_video_embe {
    meta:
        attack_type = "cve_2026_18072"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Advanced Responsive Video Embedder 10.8.7/10.8.8 - Hardcoded Backdoor Authentication Bypass: The compromised Advanced Responsive Video Embedder WordPress plugin releases 10.8.7 and 10.8.8 accept a hardcoded token through the `_wplogin` parameter and establish an authenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-18072"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-18072, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-18072.yaml"
    strings:
        $param0 = "_wplogin=35fe7057ffed92ff7bc5a0b90f302a77fb5843ad6c972294d68da0b0553b3900" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_18110_concretecms {
    meta:
        attack_type = "cve_2026_18110"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Concrete CMS - User Enumeration: Concrete CMS versions 9.0.0 through 9.5.2 are vulnerable to unauthenticated user enumeration via a missing authorization check in the 'Preview As User' panel (concrete/controllers/panel/page/preview_as_user.php)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-18110"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-18110, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-18110.yaml"
    strings:
        $path0 = "/ccm/system/panels/page/preview_as_user" ascii nocase
        $path1 = "/ccm/system/user/autocomplete" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_18937_broken_link_checker {
    meta:
        attack_type = "cve_2026_18937"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Broken Link Checker < 2.4.12 - Remote Code Execution: The Broken Link Checker WordPress plugin before 2.4.12 does not limit which query variables it accepts from user input on sites using plain permalinks, allowing unauthenticated users to overwrite arbitrary PHP."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-18937"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-18937, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-18937.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "wp_registered_widgets[x][callback]=array_filter" ascii nocase
        $param1 = "wp_registered_widgets[x][params][0]=system" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_18963_keycloak {
    meta:
        attack_type = "cve_2026_18963"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Keycloak < 26.7.2 - Unauthenticated Account Takeover via Reset-Credentials Bypass: Keycloak versions prior to 26.7.2, 26.6.6, and 26.4.15 contain a flaw in the reset-credentials flow that allows an unauthenticated attacker to bypass email verification and take over any user."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-18963"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-18963, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-18963.yaml"
    strings:
        $param0 = "client_id=account" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_19089_product_input_fields_for_wooco {
    meta:
        attack_type = "cve_2026_19089"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Product Input Fields for WooCommerce < 2.0.2 - Arbitrary File Upload to RCE: WooCommerce WordPress plugin < 2.0.2 contains an unrestricted file upload vulnerability caused by lack of validation on uploaded file types when accepted-types setting is empty, letting unauthenticated."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-19089"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-19089, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-19089.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-json/wc/store/v1/cart" ascii nocase
        $path1 = "/wp-json/wc/store/v1/checkout" ascii nocase
        $path2 = "/wp-json/wc/store/v1/order/" ascii nocase
        $path3 = "/wp-content/uploads/woocommerce_uploads/alg_uploads/product_input_fields/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_19478_gitlab {
    meta:
        attack_type = "cve_2026_19478"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "GitLab CE/EE - GraphQL @gl_introduced Arbitrary Method Invocation: GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.2 before 18.11.11, 19.0 before 19.0.8, 19.1 before 19.1.6, and 19.2 before 19.2.4 that under certain conditions could allow an."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-19478"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-19478, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-19478.yaml"
    strings:
        $path0 = "/api/v4/projects" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_19632_translatepress_multilingual {
    meta:
        attack_type = "cve_2026_19632"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TranslatePress <= 3.3.1 - Unauthenticated Account Takeover: TranslatePress WordPress plugin <= 3.3.1 contains a sensitive information exposure caused by the 'trp_get_translations_regular' AJAX action saving password-reset URLs in translation dictionary, letting unauthenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-19632"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-19632, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-19632.yaml"
    strings:
        $param0 = "action=trp_get_translations_regular" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_19900_bl_wr9000_firmware {
    meta:
        attack_type = "cve_2026_19900"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LB-LINK Routers - Unauthenticated Command Injection: LB-LINK X-PRO 1.0.22-20231206 contains a hardcoded credentials vulnerability caused by manipulation of an unknown function in /etc/shadow, letting remote attackers use hardcoded credentials, exploit requires high complexity"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-19900"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-19900, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-19900.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/goform/set_cmd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_2025_mail_mint {
    meta:
        attack_type = "cve_2026_2025"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Mail Mint < 1.19.5 - Unauthenticated Email Disclosure: Mail Mint WordPress plugin < 1.19.5 contains an information disclosure vulnerability caused by lack of authorization in a REST API endpoint, letting unauthenticated users retrieve email addresses of blog users, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-2025"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-2025, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-2025.yaml"
    strings:
        $path0 = "/wp-json/mrm/v1/wp/admins" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_20253_splunk_enterprise_cloud_platfo {
    meta:
        attack_type = "cve_2026_20253"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Splunk Enterprise & Cloud Platform - Unrestricted File Upload: In Splunk Enterprise versions below 10.2.4 and 10.0.7, and Splunk Cloud Platform versions below 10.4.2604.3 and 10.2.2510.14, an unauthenticated user could create or truncate arbitrary files through a PostgreSQL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-20253"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-20253, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-20253.yaml"
    strings:
        $path0 = "/splunkd/__raw/v1/postgres/recovery/backup" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_2113_tpadmin {
    meta:
        attack_type = "cve_2026_2113"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "tpadmin <= 1.3.12 - Remote Code Execution: yuan1994 tpadmin up to version 1.3.12 is vulnerable to Remote Code Execution via unrestricted file upload in the WebUploader preview component (/public/static/admin/lib/webuploader/0.1.5/server/preview.php). An unauthenticated remote."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-2113"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-2113, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-2113.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/public/static/admin/lib/webuploader/0.1.5/server/preview.php" ascii nocase
        $path1 = "/static/admin/lib/webuploader/0.1.5/server/preview.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_21445_langflow {
    meta:
        attack_type = "cve_2026_21445"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Langflow - Broken Access Control: Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to version 1.7.0.dev45, multiple critical API endpoints in Langflow are missing authentication controls. The issue allows any unauthenticated user to access."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-21445"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-21445, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-21445.yaml"
    strings:
        $path0 = "/api/v1/monitor/messages" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_21484_anything_llm {
    meta:
        attack_type = "cve_2026_21484"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "AnythingLLM - Username Enumeration via Password Recovery: AnythingLLM is an application that turns pieces of content into context that any LLM can use as references during chatting. Prior to commit e287fab56089cf8fcea9ba579a3ecdeca0daa313, the password recovery endpoint returns."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-21484"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-21484, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-21484.yaml"
    strings:
        $path0 = "/api/system/recover-account" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_21589_jira_confluence_bitbucket {
    meta:
        attack_type = "cve_2026_21589"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Atlassian Jira/Confluence/Bitbucket - Pre-Auth Arbitrary File Read: Atlassian products including Jira, Confluence, and Bitbucket Data Center contain a pre-authentication arbitrary file read vulnerability in the shared atlassian-plugins-webresource library. The library."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-21589"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-21589, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-21589.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/download/resources/jira.webresources:color-picker-popup/images/..::..::..::..::..::WEB-INF::web.xml" ascii nocase
        $path1 = "/s/1/_/download/resources/com.atlassian.confluence.plugins.dashboard-actions/images/..::..::..::..::..::..::..::..::WEB-INF::web.xml" ascii nocase
        $path2 = "/s/1.0/_/download/resources/com.atlassian.bitbucket.server.bitbucket-webpack-INTERNAL:avatar/avatar/..::..::..::..::..::WEB-INF::urlrewrite.xml" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_21643_forticlientems {
    meta:
        attack_type = "cve_2026_21643"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Fortinet FortiClientEMS 7.4.4 - SQL Injection: Fortinet FortiClientEMS version 7.4.4 and earlier contains an unauthenticated SQL injection vulnerability in the /api/v1/init_consts endpoint. The 'Site' HTTP header value is passed directly into the PostgreSQL search_path without."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-21643"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-21643, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-21643.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/api/v1/init_consts" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_21875_clipbucket {
    meta:
        attack_type = "cve_2026_21875"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ClipBucket v5 <= 5.5.2 - Unauthenticated Blind SQL Injection: ClipBucket v5.5.2-#187 and below contain a blind SQL injection caused by unsanitized obj_id parameter in /actions/ajax.php used in user_exists function, letting attackers perform blind SQL injection remotely, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-21875"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-21875, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-21875.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "mode=add_comment" ascii nocase
        $param1 = "type=channel" ascii nocase
        $param2 = "email=test@gmail.com" ascii nocase
        $param3 = "comment=testing" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_22200_osticket {
    meta:
        attack_type = "cve_2026_22200"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "osTicket - Arbitrary File Read: Enhancesoft osTicket versions 1.18.x prior to 1.18.3 and 1.17.x prior to 1.17.7 contain an arbitrary file read vulnerability in the ticket PDF export functionality. A remote attacker can submit a ticket containing crafted rich-text HTML that."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-22200"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-22200, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-22200.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "subject=Test Ticket Submission" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_22557_unifi_network_application {
    meta:
        attack_type = "cve_2026_22557"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "UniFi Network Application - Path Traversal: UniFi Network Application contains a path traversal vulnerability allowing a network attacker to access and manipulate files on the underlying system, potentially leading to account access, exploit requires network access."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-22557"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-22557, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-22557.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/guest/s/default/login" ascii nocase
        $param0 = "page_error=../../web.xml" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_2262_easy_appointments_3_12_21 {
    meta:
        attack_type = "cve_2026_2262"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Easy Appointments <= 3.12.21 - Information Disclosure: Easy Appointments WordPress plugin <= 3.12.21 contains a sensitive information exposure caused by an unauthenticated REST API endpoint /wp-json/wp/v2/eablocks/ea_appointments/ registered with permission_callback allowing."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-2262"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-2262, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-2262.yaml"
    strings:
        $path0 = "/wp-json/wp/v2/eablocks/ea_appointments/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_22739_spring_cloud_config {
    meta:
        attack_type = "cve_2026_22739"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Spring Cloud Config Server - Path Traversal: Spring Cloud 3.1.x < 3.1.13, 4.1.x < 4.1.9, 4.2.x < 4.2.3, 4.3.x < 4.3.2, and 5.0.x < 5.0.2 contain a path traversal caused by profile parameter substitution in Config Server using native file system backend, letting attackers access."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-22739"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-22739, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-22739.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/application/..%2F..%2F..%2F..%2F..%2Fetc" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_23482_blinko {
    meta:
        attack_type = "cve_2026_23482"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Blinko < 1.8.4 - Path Traversal: Blinko < 1.8.4 contains a path traversal vulnerability caused by lack of permission checks and filtering on the temp/ path in the file server endpoint, letting unauthorized attackers read arbitrary files including backup files with user notes."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-23482"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-23482, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-23482.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/manifest.webmanifest" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_23491_invoiceplane {
    meta:
        attack_type = "cve_2026_23491"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "InvoicePlane <= 1.6.3 - Arbitrary File Read: InvoicePlane through 1.6.3 is vulnerable to an unauthenticated path traversal in the guest 'Get::get_file()' controller. The supplied filename is passed to readfile() after a single urldecode() with no directory-traversal validation."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-23491"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-23491, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-23491.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/index.php/guest/get/get_file/../../ipconfig.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_23550_modular_ds {
    meta:
        attack_type = "cve_2026_23550"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Modular DS - Broken Access Control: Modular DS = 2.5.1 contains a broken access control vulnerability caused by incorrect privilege assignment, letting attackers escalate their privileges, exploit requires no special conditions."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-23550"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-23550, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-23550.yaml"
    strings:
        $path0 = "/index.php/api/modular-connector/login/" ascii nocase
        $path1 = "/api/modular-connector/login/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_23696_windmill {
    meta:
        attack_type = "cve_2026_23696"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Windmill < 1.603.3 - SQL Injection: Windmill versions 1.276.0 through 1.603.2 contain an authenticated SQL injection vulnerability in the folder owner management endpoint. The addowner API endpoint passes user-supplied input directly into a SQL query without sanitization."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-23696"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-23696, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-23696.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/folders/addowner/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_23744_mcpjam {
    meta:
        attack_type = "cve_2026_23744"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MCPJam Inspector - Remote Code Execution: MCPJam inspector is the local-first development platform for MCP servers. The Latest version 1.4.2 and earlier are vulnerable to a remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-23744"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-23744, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-23744.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/mcp/connect" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_23760_smartertools_smartermail {
    meta:
        attack_type = "cve_2026_23760"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "SmarterTools SmarterMail - Admin Password Reset: Detected a SmartMail admin password reset vulnerability by sending a POST request to the `/api/v1/auth/force-reset-password` endpoint, indicating that administrative password resets could potentially be triggered without proper."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-23760"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-23760, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-23760.yaml"
    strings:
        $path0 = "/api/v1/auth/force-reset-password" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_24128_xwiki_platform_distribution_fl {
    meta:
        attack_type = "cve_2026_24128"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki Platform Distribution Flavor Main - Cross-Site Scripting: XWiki Platform Distribution Flavor Main versions prior to 17.6.0 are vulnerable to reflected cross-site scripting (XSS) due to improper sanitization of user-supplied input in the extensionId parameter. An attacker."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-24128"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-24128, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-24128.yaml"
        response_type = "xss"
    strings:
        $param0 = "extensionSection=progress" ascii nocase
        $param1 = "extensionVersion=17.6.0" ascii nocase
        $param2 = "extensionNamespace=wiki:xwiki" ascii nocase
        $param3 = "extensionAction=install" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_24423_smartermail {
    meta:
        attack_type = "cve_2026_24423"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "SmarterMail - Remote Code Execution: SmarterTools SmarterMail < build 9511 contains an unauthenticated remote code execution caused by malicious OS command execution via ConnectToHub API method, letting remote attackers execute arbitrary commands, exploit requires no."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-24423"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-24423, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-24423.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/v1/settings/sysadmin/connect-to-hub" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_25231_filerise {
    meta:
        attack_type = "cve_2026_25231"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "FileRise <= 3.3.0 - Unauthenticated File Read: FileRise <= 3.3.0 contains an unauthenticated file read vulnerability caused by a lack of access control on the /uploads directory, letting unauthenticated attackers access uploaded files directly, exploit requires knowledge or."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-25231"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-25231, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-25231.yaml"
    strings:
        $path0 = "/uploads/README.md" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_25512_group_office {
    meta:
        attack_type = "cve_2026_25512"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Group-Office < 26.0.5 - Remote Code Execution: Group-Office before versions 6.8.150, 25.0.82, and 26.0.5 is vulnerable to remote code execution via OS command injection. The endpoint email/message/tnefAttachmentFromTempFile directly concatenates the user-controlled parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-25512"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-25512, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-25512.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "r=email/message/tnefAttachmentFromTempFile" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_25527_changedetection_io {
    meta:
        attack_type = "cve_2026_25527"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "changedetection.io <= 0.52.9 - Unauthenticated Path Traversal: changedetection.io <= 0.53.9 contains a path traversal caused by improper validation of the 'group' parameter in /static/<group>/<filename> route, letting unauthenticated attackers read local application source files."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-25527"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-25527, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-25527.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/static/../flask_app.py" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_25616_blesta_5_13_1 {
    meta:
        attack_type = "cve_2026_25616"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Blesta <= 5.13.1 - Cross-Site Scripting: Blesta 3.x through 5.x before 5.13.3 contains an input validation vulnerability caused by mishandling input, letting attackers potentially exploit the system, exploit requires unspecified conditions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-25616"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-25616, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-25616.yaml"
        response_type = "xss"
    strings:
        $path0 = "/client_dialog/confirm/" ascii nocase
        $param0 = "confirm_url=javascript:alert(document.domain)" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_25703_neuvector_manager {
    meta:
        attack_type = "cve_2026_25703"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "NeuVector - Information Disclosure: NeuVector through 5.4.9 contains an information disclosure vulnerability caused by missing authentication and cached sensitive data in the manager /network/graph API, letting remote attackers access sensitive information, exploit requires no."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-25703"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-25703, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-25703.yaml"
    strings:
        $path0 = "/network/graph/layout" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_26077_discourse {
    meta:
        attack_type = "cve_2026_26077"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Discourse - Unauthenticated Mailpace Webhook Bounce-Score Forgery: Discourse's WebhooksController contains a missing-authentication flaw caused by accepting requests to provider webhook endpoints (including /webhooks/mailpace, SendGrid, Mailjet, Mandrill, Postmark, and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-26077"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-26077, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-26077.yaml"
    strings:
        $path0 = "/webhooks/mailpace" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_26217_crawl4ai_0_8_0 {
    meta:
        attack_type = "cve_2026_26217"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Crawl4AI < 0.8.0 - Local File Inclusion: The Crawl4AI Docker API endpoints accepted arbitrary URL schemes without an allow-list. An unauthenticated request with a file:// URL could read local files. Fixed in 0.8.0, which restricts accepted URL schemes."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-26217"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-26217, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-26217.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/execute_js" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_26341_tattile_camera_1_181_5 {
    meta:
        attack_type = "cve_2026_26341"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tattile Camera < 1.181.5 - Default Login: Tattile Smart+, Vega, and Basic device families firmware <= 1.181.5 contain a broken authentication caused by default credentials not forced to be changed, letting attackers with management interface access gain administrative privileges."
        mitre_attack = "T1078.001"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-26341"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-26341, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-26341.yaml"
    strings:
        $path0 = "/api/v1/security/login" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_2652_mlflow {
    meta:
        attack_type = "cve_2026_2652"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MLflow < 3.10.0 - Authentication Bypass on FastAPI Routes: A vulnerability in mlflow/mlflow versions 3.9.0 and earlier allows unauthenticated access to certain FastAPI routes when the server is started with authentication enabled (`--app-name basic-auth`) and served via uvicorn."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-2652"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-2652, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-2652.yaml"
    strings:
        $path0 = "/api/2.0/mlflow/experiments/list" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_26980_ghost {
    meta:
        attack_type = "cve_2026_26980"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ghost CMS Content API - SQL Injection: Ghost CMS before 6.19.1 is vulnerable to a blind SQL injection in the /ghost/api/content/tags/ endpoint via the filter parameter. This template checks for the vulnerability by sending a boolean-based payload."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-26980"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-26980, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-26980.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/ghost/api/content/tags/" ascii nocase
        $param0 = "filter=slug:-null" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_2699_sharefile_storage_zones_contro {
    meta:
        attack_type = "cve_2026_2699"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Progress ShareFile Storage Zones Controller - Authentication Bypass: Customer Managed ShareFile Storage Zones Controller (SZC) contains an authentication bypass (Execution After Redirect) that allows unauthenticated attackers to access restricted configuration pages. This leads."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-2699"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-2699, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-2699.yaml"
    strings:
        $path0 = "/ConfigService/Admin.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_27176_majordomo {
    meta:
        attack_type = "cve_2026_27176"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MajorDoMo - Cross-Site Scripting: MajorDoMo contains a reflected XSS caused by unsanitized $qry parameter in command.php, letting attackers inject arbitrary JavaScript via crafted URLs, exploit requires victim to visit malicious URL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-27176"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27176, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-27176.yaml"
        response_type = "xss"
    strings:
        $path0 = "/command.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_27454_discourse {
    meta:
        attack_type = "cve_2026_27454"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Discourse <=2026.2.0 - Hidden Post Revision Disclosure via revert_to Authorization Bypass: Discourse versions before 2026.1.2, 2026.2.1, and 2026.3.0-latest.1 contain an authorization bypass in PostsController#display_post. The controller calls post.revert_to(params[:version])."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-27454"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27454, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-27454.yaml"
    strings:
        $path0 = "/posts.json" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_27604_fossbilling {
    meta:
        attack_type = "cve_2026_27604"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FOSSBilling 0.5.4-0.7.x - Unauthenticated System API Role Authorization Bypass: FOSSBilling versions 0.5.4 through 0.7.x contain an authorization bypass in API role handling. The internal system role is accepted from the URL, resolves to the cron-admin identity, and reaches."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-27604"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27604, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-27604.yaml"
    strings:
        $path0 = "/api/system/system/error_reporting_enabled" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_27760_opencats {
    meta:
        attack_type = "cve_2026_27760"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OpenCATS - Command Injection: OpenCATS prior to commit 3002a29 contains a command injection caused by injection of PHP statements into the installer AJAX endpoint's databaseConnectivity action parameter, letting unauthenticated attackers execute arbitrary code, exploit requires."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-27760"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27760, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-27760.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "a=databaseConnectivity" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_27771_gitea {
    meta:
        attack_type = "cve_2026_27771"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Gitea Container Registry - Unauthorized Private Image Access: Gitea < 1.26.2 allows unauthenticated remote attackers to pull private container images.The /v2/token endpoint grants anonymous ghost tokens (UserID:-1) with no scope restriction.The ReqContainerAccess middleware."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-27771"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27771, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-27771.yaml"
    strings:
        $path0 = "/v2/_catalog" ascii nocase
        $param0 = "service=container_registry" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_27796_homarr {
    meta:
        attack_type = "cve_2026_27796"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Homarr < 1.54.0 - Information Disclosure: Homarr < 1.54.0 contains an information disclosure caused by the integration.all tRPC endpoint being exposed as a publicProcedure, letting unauthenticated users retrieve sensitive integration metadata, exploit requires no authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-27796"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27796, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-27796.yaml"
    strings:
        $path0 = "/api/trpc/integration.all" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_27833_piwigo {
    meta:
        attack_type = "cve_2026_27833"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Piwigo < 16.3.0 - Unauthenticated Information Disclosure via History API: Piwigo <= 16.3.0 contains an information disclosure vulnerability caused by the pwg.history.search API method lacking admin_only restriction, letting unauthenticated users access full browsing history."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-27833"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-27833, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-27833.yaml"
    strings:
        $param0 = "method=pwg.history.search" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_28358_nocodb {
    meta:
        attack_type = "cve_2026_28358"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "NocoDB - User Enumeration: NocoDB is software for building databases as spreadsheets. Prior to version 0.301.3, the password forgot endpoint returned different responses for registered and unregistered emails, allowing user enumeration. This issue has been patched in version."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-28358"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-28358, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-28358.yaml"
    strings:
        $path0 = "/api/v1/auth/password/forgot" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_28409_wegia {
    meta:
        attack_type = "cve_2026_28409"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WeGIA <= 3.6.4 - Remote Code Execution: WeGIA <= 3.6.5 contains a remote code execution caused by improper validation of backup file names in the database restoration functionality, letting attackers with administrative access execute arbitrary OS commands"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-28409"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-28409, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-28409.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/WeGIA/html/configuracao/importar_dump.php" ascii nocase
        $path1 = "/WeGIA/html/configuracao/gerenciar_backup.php" ascii nocase
        $param0 = "action=restore" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_28411_wegia {
    meta:
        attack_type = "cve_2026_28411"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WeGIA < 3.6.5 - Unauthenticated Authentication Bypass via extract(): WeGIA < 3.6.5 contains an authentication bypass caused by unsafe use of extract() on $_REQUEST, letting unauthenticated attackers bypass authentication and access protected areas, exploit requires no."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-28411"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-28411, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-28411.yaml"
    strings:
        $path0 = "/WeGIA/html/home.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_28496_fossbilling {
    meta:
        attack_type = "cve_2026_28496"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FOSSBilling - Server-Side Template Injection: A Server-Side Template Injection (SSTI) vulnerability exists in FOSSBilling's template rendering system. Administrators with access to features that render Twig templates (email templates, mass mail campaigns, custom payment."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-28496"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-28496, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-28496.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/api/system/system/string_render" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_29014_metinfo_cms_8_1 {
    meta:
        attack_type = "cve_2026_29014"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MetInfo CMS <= 8.1 - Remote Code Execution: MetInfo CMS 7.9, 8.0, and 8.1 contain an unauthenticated PHP code injection vulnerability caused by insufficient input neutralization in the execution path, letting remote attackers execute arbitrary code remotely, exploit requires."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-29014"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-29014, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-29014.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/app/system/entrance.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_29058_avideo {
    meta:
        attack_type = "cve_2026_29058"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WWBN AVideo Encoder < 7.0 - Unauthenticated OS Command Injection: AVideo < 7.0 contains a command injection caused by shell command substitution in the base64Url GET parameter, letting unauthenticated attackers execute arbitrary OS commands, exploit requires no authentication."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-29058"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-29058, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-29058.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/Encoder/objects/getImage.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_29059_windmill {
    meta:
        attack_type = "cve_2026_29059"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Windmill/Nextcloud Flow < 1.603.3 - Unauthenticated Path Traversal: Windmill < 1.603.3 contains a path traversal caused by unsanitized filename parameter in get_log_file endpoint, letting unauthenticated attackers read arbitrary files on the server, exploit requires no."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-29059"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-29059, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-29059.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/index.php/apps/app_api/proxy/flow/api/w/_/jobs_u/get_log_file/..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd" ascii nocase
        $path1 = "/index.php/apps/app_api/proxy/flow/api/w/_/jobs_u/get_log_file/..%252F..%252F..%252F..%252Fetc%252Fpasswd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_29962_mailinspector {
    meta:
        attack_type = "cve_2026_29962"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "HSC MailInspector - Local File Inclusion: HSC MailInspector v5.3.3-7 contains a path traversal caused by improper control of user-supplied file paths in /vendor/phpunit/phpunit.php, letting remote attackers read arbitrary files, exploit requires crafted request."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-29962"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-29962, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-29962.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/mailinspector" ascii nocase
        $path1 = "/mailinspector/vendor/phpunit/phpunit.php" ascii nocase
        $param0 = "--bootstrap=/etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_29963_mailinspector {
    meta:
        attack_type = "cve_2026_29963"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "HSC MailInspector - Unauthenticated Arbitrary File Read: HSC MailInspector 5.3.3-7 contains a path traversal caused by improper validation of user-supplied input in /tap/dw.php text parameter, letting remote attackers access arbitrary files, exploit requires crafted request."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-29963"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-29963, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-29963.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/mailinspector/tap/dw.php" ascii nocase
        $param0 = "ext=Li4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_3055_citrix_netscaler_saml_idp {
    meta:
        attack_type = "cve_2026_3055"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Citrix NetScaler SAML IDP - Memory Overread: NetScaler ADC and NetScaler Gateway contain an insufficient input validation vulnerability when configured as a SAML IDP, leading to memory overread, letting attackers potentially access sensitive memory, exploit requires."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-3055"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-3055, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-3055.yaml"
    strings:
        $path0 = "/wsfed/passive" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_30824_flowise {
    meta:
        attack_type = "cve_2026_30824"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Flowise - NVIDIA NIM Endpoints Missing Authentication: Flowise is a drag & drop user interface to build a customized large language model flow. Prior to version 3.0.13, the NVIDIA NIM router (/api/v1/nvidia-nim/*) is whitelisted in the global authentication middleware, allowing."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-30824"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-30824, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-30824.yaml"
    strings:
        $path0 = "/api/v1/nvidia-nim/get-token" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_30849_mantisbt {
    meta:
        attack_type = "cve_2026_30849"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MantisBT < 2.28.1 - SOAP API Authentication Bypass: Mantis Bug Tracker < 2.28.1 on MySQL databases contains an authentication bypass caused by improper type checking on the password parameter in the SOAP API, letting attackers login without the actual password using a crafted."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-30849"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-30849, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-30849.yaml"
    strings:
        $path0 = "/api/soap/mantisconnect.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_30958_oneuptime_10_0_21 {
    meta:
        attack_type = "cve_2026_30958"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OneUptime < 10.0.21 - Path Traversal: OneUptime < 10.0.21 contains a path traversal caused by unsanitized componentName parameter in /workflow/docs/:componentName endpoint, letting unauthenticated attackers read arbitrary files from the server filesystem."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-30958"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-30958, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-30958.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/workflow/docs/../../../../../../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_30965_parse_server {
    meta:
        attack_type = "cve_2026_30965"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Parse Server < 8.6.21 / 9.x < 9.5.2 - Session Token Exfiltration: Parse Server < 8.6.21 / 9.x < 9.5.2 contains an information disclosure vulnerability caused by improper handling of the redirectClassNameForKey query parameter, letting authenticated or unauthenticated attackers."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-30965"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-30965, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-30965.yaml"
    strings:
        $path0 = "/parse/health" ascii nocase
        $path1 = "/parse/classes/" ascii nocase
        $param0 = "redirectClassNameForKey=pivot" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_31831_tautulli {
    meta:
        attack_type = "cve_2026_31831"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tautulli <= 2.16.1 - Path Traversal: Tautulli is a monitoring and tracking tool for Plex Media Server. Prior to version 2.17.0, the `/newsletter/image/images` endpoint joins user-controlled path segments onto the newsletter image directory without containment validation.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-31831"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-31831, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-31831.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/newsletter/image/images/../../../../../../config/config.ini" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_32230_uptime_kuma {
    meta:
        attack_type = "cve_2026_32230"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Uptime-Kuma < v1.23.0 - Improper Access Control: Uptime-Kuma before v1.23.0 is vulnerable to an information disclosure issue due to missing authorization on the /api/badge/1/ping/24 endpoint. An unauthenticated attacker can access this endpoint to leak ping statistics, such as."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-32230"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-32230, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-32230.yaml"
    strings:
        $path0 = "/api/badge/1/ping/24" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_32255_kan {
    meta:
        attack_type = "cve_2026_32255"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kan <= 0.5.4 - Server-Side Request Forgery: Kan, an open-source project management tool (Trello alternative), versions 0.5.4 and below are vulnerable to an unauthenticated Server-Side Request Forgery in the /api/download/attatchment endpoint. The endpoint passes the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-32255"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-32255, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-32255.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/download/attatchment" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_32583_modern_events_calendar {
    meta:
        attack_type = "cve_2026_32583"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Webnus Inc. Modern Events Calendar - Broken Access Control: Webnus Inc. Modern Events Calendar <= 7.29.0 contains a broken access control vulnerability caused by incorrectly configured access control security levels, letting attackers bypass authorization, exploit requires no."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-32583"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-32583, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-32583.yaml"
    strings:
        $param0 = "action=mec_speaker_adding" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_32596_glances {
    meta:
        attack_type = "cve_2026_32596"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Glances - Information Disclosure: Glances < 4.5.2 contains an information disclosure vulnerability caused by the web server running without authentication by default, letting remote attackers access sensitive system information including credentials, exploit requires no special."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-32596"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-32596, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-32596.yaml"
    strings:
        $path0 = "/api/4/processlist" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_33032_nginx_ui {
    meta:
        attack_type = "cve_2026_33032"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Nginx UI - Broken Access Control: Network attackers can fully control nginx service, including config modification and service restart, leading to complete service takeover."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-33032"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-33032, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-33032.yaml"
    strings:
        $path0 = "/mcp_message" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_33425_discourse {
    meta:
        attack_type = "cve_2026_33425"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Discourse - Private Group Membership Inference via exclude_groups: Discourse < 2026.3.0-latest.1, 2026.2.1, and 2026.1.2 contains an information disclosure caused by unauthenticated users observing directory results changes with the exclude_groups parameter, letting attackers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-33425"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-33425, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-33425.yaml"
    strings:
        $param0 = "order=likes_received" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_33476_siyuan {
    meta:
        attack_type = "cve_2026_33476"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SiYuan <= v3.6.1 - Path Traversal: SiYuan is a personal knowledge management system. Prior to version 3.6.2, the Siyuan kernel exposes an unauthenticated file-serving endpoint under `/appearance/*filepath.` Due to improper path sanitization, attackers can perform directory."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-33476"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-33476, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-33476.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/appearance/langs/../../conf.json" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_33478_avideo_26_0 {
    meta:
        attack_type = "cve_2026_33478"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "AVideo <= 26.0 - WWBN AVideo - Remote Code Execution: WWBN AVideo <= 26.0 contains multiple vulnerabilities in the CloneSite plugin including unauthenticated exposure of clone secret keys and OS command injection in rsync command construction, letting unauthenticated attackers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-33478"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-33478, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-33478.yaml"
    strings:
        $path0 = "/plugin/CloneSite/clones.json.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_33497_langflow_1_7_0 {
    meta:
        attack_type = "cve_2026_33497"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Langflow < 1.7.0 - Path Traversal: Langflow < 1.7.1 contains a path traversal caused by insufficient filtering of folder_name and file_name parameters in download_profile_picture endpoint, letting attackers read secret_key across directories, exploit requires crafted request."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-33497"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-33497, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-33497.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/v1/files/profile_pictures/../secret_key" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_33534_espocrm {
    meta:
        attack_type = "cve_2026_33534"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "EspoCRM <= 9.3.3 - Server-Side Request Forgery: EspoCRM <= 9.3.3 contains an authenticated server-side request forgery caused by improper internal-host validation using alternative IPv4 formats in HostCheck::isNotInternalHost(), letting authenticated users access internal."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-33534"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-33534, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-33534.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/v1/Attachment/fromImageUrl" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_3395_maxsite_cms {
    meta:
        attack_type = "cve_2026_3395"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MaxSite CMS <=109.1 - Remote Code Execution: MaxSite CMS through 109.1 allows unauthenticated remote attackers to execute arbitrary code via the MarkItUp editor preview AJAX endpoint, preview-ajax.php. The endpoint insufficiently authenticates the request, failing to ensure the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-3395"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-3395, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-3395.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/ajax/YWRtaW4vcGx1Z2lucy9lZGl0b3JfbWFya2l0dXAvcHJldmlldy1hamF4LnBocA==" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_34036_dolibarr {
    meta:
        attack_type = "cve_2026_34036"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Dolibarr <=22.0.4 - Local File Inclusion: Dolibarr <= 22.0.4 contains a local file inclusion caused by manipulation of the objectdesc parameter and a fail-open logic flaw in restrictedArea() in /core/ajax/selectobject.php, letting authenticated users with no specific privileges."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-34036"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-34036, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-34036.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/core/ajax/selectobject.php" ascii nocase
        $param0 = "objectdesc=A:includes/.htaccess:0" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_34156_nocobase {
    meta:
        attack_type = "cve_2026_34156"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "NocoBase - VM Sandbox Escape to Remote Code Execution: NocoBase Workflow Script Node executes user-supplied JavaScript inside a Node.js vm sandbox with a custom require allowlist controlled by WORKFLOW_SCRIPT_MODULES env var. The console object passed into the sandbox context."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-34156"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-34156, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-34156.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/flow_nodes:test" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_34234_ctrlpanel {
    meta:
        attack_type = "cve_2026_34234"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CtrlPanel <= 1.1.1 - Remote Code Execution: CtrlPanel versions <= 1.1.1 are vulnerable to unauthenticated Remote Code Execution (RCE) via the web installer endpoint (public/installer/index.php). The installer loaded and executed form handler files before checking for the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-34234"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-34234, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-34234.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "clientkey=asdasdasd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_34413_xerte_online_toolkits {
    meta:
        attack_type = "cve_2026_34413"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Xerte Online Toolkits <= 3.15 - Remote Code Execution: Xerte Online Toolkits versions 3.15 and earlier expose the elFinder file manager connector at /editor/elfinder/php/connector.php without authentication (CVE-2026-34413), because the access-control redirect for."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-34413"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-34413, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-34413.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/editor/elfinder/php/connector.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_34908_unifi_os {
    meta:
        attack_type = "cve_2026_34908"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "UniFi OS - Authentication Bypass via Path Traversal (..%2f): UniFi OS devices contain an improper access control vulnerability caused by insufficient authorization checks, letting network attackers make unauthorized system changes, exploit requires network access."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-34908"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-34908, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-34908.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/proxy/users/api/v2/ucs/update/latest_package" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_35029_litellm {
    meta:
        attack_type = "cve_2026_35029"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LiteLLM - Arbitrary File Read: LiteLLM < 1.83.0 contains a broken access control vulnerability caused by lack of admin role enforcement on /config/update endpoint, letting authenticated users modify configurations, execute code, read files, and take over accounts."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-35029"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-35029, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-35029.yaml"
    strings:
        $path0 = "/health/liveliness" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_35037_ech0 {
    meta:
        attack_type = "cve_2026_35037"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ech0 < 4.2.8 - Server-Side Request Forgery: Ech0 before 4.2.8 exposes an unauthenticated SSRF vulnerability in GET /api/website/title. The website_url query parameter is fetched server-side without validating the target host or IP address."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-35037"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-35037, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-35037.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/website/title" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_35273_peoplesoft_enterprise_peopleto {
    meta:
        attack_type = "cve_2026_35273"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Oracle PeopleSoft PeopleTools PSEMHUB - Pre-Auth Java Deserialization RCE: Oracle PeopleSoft PeopleTools 8.61 and 8.62 contain a remote code execution vulnerability in Updates Environment Management, letting unauthenticated network attackers fully compromise the system, exploit."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-35273"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-35273, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-35273.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/PSEMHUB/hub" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_35616_forticlient_ems {
    meta:
        attack_type = "cve_2026_35616"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "FortiClient EMS - Authentication Bypass: Detects whether Fortinet hotfix FG-IR-26-099 for CVE-2026-35616 is missing by comparing behavioral responses from a certificate-authenticated endpoint. The template sends X-SSL-CLIENT-VERIFY: SUCCESS without certificate material and."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-35616"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-35616, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-35616.yaml"
    strings:
        $path0 = "/api/v1/fabric_device_auth/fortigate/init" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_3576_planyo_online_reservation_syst {
    meta:
        attack_type = "cve_2026_3576"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Planyo Online Reservation System <= 3.0 - Arbitrary File Read: The Planyo Online Reservation System plugin for WordPress through 3.0 ships ulap.php, an AJAX proxy that is directly reachable without WordPress bootstrapping or authentication. The send_http_post() function."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-3576"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-3576, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-3576.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/planyo-online-reservation-system/ulap.php" ascii nocase
        $param0 = "ulap_url=file://localhost/etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_3584_kali_forms {
    meta:
        attack_type = "cve_2026_3584"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Kali Forms <= 2.4.9 - Remote Code Execution: Kali Forms WordPress plugin <= 2.4.9 contains a remote code execution caused by unsafe user input handling in 'form_process' and 'prepare_post_data' functions, letting unauthenticated attackers execute code on the server."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-3584"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-3584, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-3584.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "action=kaliforms_form_process" ascii nocase
        $param1 = "data[email]=test@example.com" ascii nocase
        $param2 = "data[thisPermalink]=phpinfo" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_38360_dash_uploader {
    meta:
        attack_type = "cve_2026_38360"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "dash-uploader 0.1.0 - 0.7.0a2 - Unauthenticated Arbitrary File Write via Path Traversal: fohrloop dash-uploader v0.1.0 through v0.7.0a2 contains a directory traversal vulnerability caused by improper handling in dash_uploader/httprequesthandler.py components, letting remote."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-38360"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-38360, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-38360.yaml"
    strings:
        $path0 = "/API/dash-uploader" ascii nocase
        $path1 = "/API/resumable" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_3844_breeze_2_4_4 {
    meta:
        attack_type = "cve_2026_3844"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Breeze <= 2.4.4 - Arbitrary File Upload: Breeze Cache WordPress plugin <= 2.4.4 contains an unrestricted file upload vulnerability caused by missing file type validation in 'fetch_gravatar_from_remote' function, letting unauthenticated attackers upload arbitrary files, exploit."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-3844"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-3844, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-3844.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/cache/breeze-extra/gravatars/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_3891_payment_gateway_pix_for_woocom {
    meta:
        attack_type = "cve_2026_3891"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Pix for WooCommerce <= 1.5.0 - Unauthenticated Arbitrary File Upload: The Pix for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing capability check and missing file type validation in the 'lkn_pix_for_woocommerce_c6_save_settings' function."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-3891"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-3891, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-3891.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/plugins/payment-gateway-pix-for-woocommerce/Includes/files/certs_c6/" ascii nocase
        $param0 = "action=lkn_pix_for_woocommerce_generate_nonce" ascii nocase
        $param1 = "action_name=lkn_pix_for_woocommerce_c6_settings_nonce" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_39339_churchcrm {
    meta:
        attack_type = "cve_2026_39339"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ChurchCRM - API Authentication Bypass via URL Injection: ChurchCRM < 7.1.0 contains an authentication bypass caused by improper API middleware URL handling in ChurchCRM/Slim/Middleware/AuthMiddleware.php, letting unauthenticated attackers access protected API endpoints, exploit."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-39339"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-39339, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-39339.yaml"
    strings:
        $path0 = "/api/persons/latest" ascii nocase
        $param0 = "bypass=/api/public" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_39352_frappe {
    meta:
        attack_type = "cve_2026_39352"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Frappe Framework < 16.15.0 - Arbitrary File Read via render_include Path Traversal: Frappe is a full-stack web application framework. Versions prior to 15.105.0 and 16.15.0 contain a possible Arbitrary File Read vulnerability via Path Traversal. The issue is resolved in."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-39352"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-39352, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-39352.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/method/login" ascii nocase
        $path1 = "/api/method/frappe.desk.query_report.get_script" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_39365_vite_dev_server {
    meta:
        attack_type = "cve_2026_39365"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Vite Dev Server - Path Traversal in Optimized Deps .map Handling: Vite development server versions prior to 8.0.5, 7.3.2, and 6.4.2 are vulnerable to path traversal through the optimized dependencies sourcemap handler. The dev server's handling of .map requests for optimized."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-39365"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-39365, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-39365.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/node_modules/.vite/deps/../../../config.production.js.map" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_39808_fortisandbox {
    meta:
        attack_type = "cve_2026_39808"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Fortinet FortiSandbox - Command Injection: Fortinet FortiSandbox 4.4.0 through 4.4.8 contains a command injection caused by improper neutralization of special elements in OS commands, letting attackers execute unauthorized code or commands, exploit requires crafted input."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-39808"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-39808, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-39808.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/fortisandbox/job-detail/tracer-behavior" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_40105_xwiki_platform {
    meta:
        attack_type = "cve_2026_40105"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki - Cross-Site Scripting: XWiki is vulnerable to reflected Cross-Site Scripting (XSS) via the `viewer=changes` endpoint. The `rev2` parameter is not properly sanitised before being rendered in the response, allowing an attacker to inject arbitrary JavaScript. Affects XWiki."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-40105"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-40105, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-40105.yaml"
        response_type = "xss"
    strings:
        $path0 = "/bin/view/Sandbox/" ascii nocase
        $param0 = "viewer=changes" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_40151_praisonai {
    meta:
        attack_type = "cve_2026_40151"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PraisonAI AgentOS - Information Disclosure: PraisonAI's AgentOS FastAPI application server exposes an unauthenticated `GET /api/agents` endpoint that lists every registered agent's name, role and the opening of its instructions (system prompt). No authentication is enforced on."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-40151"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-40151, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-40151.yaml"
    strings:
        $path0 = "/api/agents" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_4020_gravitysmtp {
    meta:
        attack_type = "cve_2026_4020"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Gravity SMTP WordPress Plugin - Sensitive Information Exposure: Gravity SMTP WordPress plugin <= 2.1.4 contains a sensitive information exposure caused by an unrestricted REST API endpoint at /wp-json/gravitysmtp/v1/tests/mock-data, letting unauthenticated attackers retrieve."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-4020"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-4020, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-4020.yaml"
    strings:
        $path0 = "/wp-json/gravitysmtp/v1/tests/mock-data" ascii nocase
        $param0 = "page=gravitysmtp-settings" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_40217_litellm_1_25_0 {
    meta:
        attack_type = "cve_2026_40217"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LiteLLM < 1.25.0 - Remote Code Execution: LiteLLM before 1.25.0 allows authenticated users with the master API key to execute arbitrary Python code through the /guardrails/test_custom_code endpoint intended for custom guardrail testing. The endpoints insufficient filtering."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-40217"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-40217, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-40217.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/guardrails/test_custom_code" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_40242_arcane {
    meta:
        attack_type = "cve_2026_40242"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Arcane <= 1.17.2 - Server-Side Request Forgery: Arcane <= 1.17.3 contains an unauthenticated server-side request forgery caused by lack of URL scheme and host validation in /api/templates/fetch endpoint, letting remote attackers perform SSRF, exploit requires no authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-40242"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-40242, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-40242.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/templates/fetch" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_40280_gotenberg {
    meta:
        attack_type = "cve_2026_40280"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Gotenberg <= 8.30.1 - Server Side Request Forgery: Gotenberg is an API-based document conversion tool. In versions 8.30.1 and earlier, the default private-IP deny-lists for the --webhook-deny-list and --api-download-from-deny-list flags use a case-sensitive regular expression."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-40280"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-40280, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-40280.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/forms/chromium/convert/html" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_40281_gotenberg {
    meta:
        attack_type = "cve_2026_40281"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Gotenberg <= 8.30.1 - Remote Code Execution: Gotenberg through 8.30.1 sanitizes only the keys of the JSON metadata submitted to the PDF metadata write endpoint, leaving the values unvalidated. A newline inside a metadata value is written straight to the ExifTool process."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-40281"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-40281, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-40281.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/forms/pdfengines/metadata/write" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_41042_gravitino {
    meta:
        attack_type = "cve_2026_41042"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Gravitino < 1.2.1 - Unauthenticated Remote Code Execution: Apache Gravitino < 1.2.1 contains a remote code execution caused by unsanitized H2 JDBC URL via testConnection API using H2's INIT parameter, letting unauthenticated attackers execute arbitrary Java code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-41042"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-41042, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-41042.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/metalakes" ascii nocase
        $path1 = "/catalogs/testConnection" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_4106_ht_mega_for_elementor {
    meta:
        attack_type = "cve_2026_4106"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "HT Mega < 3.0.7 - Sensitive Information Disclosure: The HT Mega plugin for WordPress is vulnerable to Sensitive Information Exposure via AJAX actions. This template dynamically extracts the security nonce before exploitation."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-4106"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-4106, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-4106.yaml"
    strings:
        $param0 = "action=wcsales_purchased_products" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_41176_rclone {
    meta:
        attack_type = "cve_2026_41176"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Rclone RC - Broken Access Control: Rclone >= 1.45.0 and < 1.73.5 contains a broken access control vulnerability caused by unauthenticated access to the RC endpoint `options/set` allowing mutation of global runtime configuration, letting unauthenticated attackers access."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-41176"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-41176, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-41176.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/config/listremotes" ascii nocase
        $path1 = "/options/set" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_41179_rclone {
    meta:
        attack_type = "cve_2026_41179"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "RClone RC - Command Injection: Rclone >= 1.48.0 and < 1.73.5 contains an unauthenticated local command execution caused by unauthenticated access to the RC endpoint operations/fsinfo with attacker-controlled fs input, letting unauthenticated attackers execute local commands."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-41179"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-41179, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-41179.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/operations/fsinfo" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_41432_new_api_v0_12_10 {
    meta:
        attack_type = "cve_2026_41432"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "New API < v0.12.10 - Stripe Webhook Bypass: New API < v0.12.10 contains a broken authentication caused by unauthenticated attacker forging Stripe webhook events, letting attackers credit arbitrary quota without payment, exploit requires no authentication."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-41432"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-41432, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-41432.yaml"
    strings:
        $path0 = "/api/stripe/webhook" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_41492_dgraph {
    meta:
        attack_type = "cve_2026_41492"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dgraph <= 25.3.2 - Admin Token Disclosure: Dgraph <= 25.3.2 contains an information disclosure caused by unauthenticated access to the /debug/vars endpoint , which publishes the cmdline variable including the --security token= flag, letting unauthenticated remote attackers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-41492"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-41492, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-41492.yaml"
    strings:
        $path0 = "/debug/vars" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_41679_paperclipai {
    meta:
        attack_type = "cve_2026_41679"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Paperclip - Remote Code Execution: Paperclip < 2026.416.0 contains a remote code execution caused by a chain of six unauthenticated API calls in authenticated mode with default configuration, letting unauthenticated attackers execute arbitrary code remotely, exploit requires."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-41679"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-41679, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-41679.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/auth/sign-up/email" ascii nocase
        $path1 = "/api/cli-auth/challenges" ascii nocase
        $path2 = "/api/cli-auth/challenges/" ascii nocase
        $path3 = "/api/companies/import" ascii nocase
        $path4 = "/api/agents/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_41940_cpanel_whm {
    meta:
        attack_type = "cve_2026_41940"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "cPanel & WHM - Authentication Bypass via Session-File CRLF Injection: cPanel and WHM versions prior to 11.110.0.97, 11.118.0.63, 11.126.0.54, 11.132.0.29, 11.134.0.20, and 11.136.0.5 contain an authentication bypass vulnerability in the login flow that allows unauthenticated."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-41940"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-41940, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-41940.yaml"
    strings:
        $path0 = "/scripts2/listaccts" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_41948_dify {
    meta:
        attack_type = "cve_2026_41948"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dify <=1.14.1 - Unauthenticated Plugin Daemon Path Traversal: Dify version 1.14.1 and prior are affected by an unauthenticated path traversal in the Plugin Daemon icon proxy endpoint. The /console/api/workspaces/current/plugin/icon endpoint requires no authentication and passes."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-41948"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-41948, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-41948.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/console/api/workspaces/current/plugin/icon" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_42018_jfrog_artifactory {
    meta:
        attack_type = "cve_2026_42018"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "JFrog Artifactory - Anonymous Token Disclosure via Trailing Slash Auth Bypass: JFrog Artifactory contains an information disclosure caused by returning an internal anonymous-user token to unauthenticated callers when anonymous access is disabled, letting unauthenticated."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-42018"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-42018, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-42018.yaml"
    strings:
        $path0 = "/access/api/v1/aws/token" ascii nocase
        $path1 = "/access/api/v1/aws/token/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_42031_ckan_datastore_sql_search {
    meta:
        attack_type = "cve_2026_42031"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "CKAN DataStore SQL Search - SQL Injection: CKAN, an open-source data management system used for powering open data portals, contains an unauthenticated SQL injection vulnerability in the datastore_search_sql API endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-42031"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-42031, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-42031.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/api/action/datastore_search_sql" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_42461_arcane {
    meta:
        attack_type = "cve_2026_42461"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Arcane < 1.18.0 - Unauthenticated Template and Env Disclosure: Arcane < 1.18.0 contains an information disclosure caused by missing authorization on /api/templates GET endpoints, letting unauthenticated network clients read sensitive Compose YAML and .env content, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-42461"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-42461, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-42461.yaml"
    strings:
        $path0 = "/api/templates/all" ascii nocase
        $path1 = "/api/templates/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_42564_jotty {
    meta:
        attack_type = "cve_2026_42564"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "jotty.page < 1.22.0 - Path Traversal: jottypage < 1.22.0 contains a path traversal caused by lack of validation on filename parameter in /api/app-icons/[filename], letting unauthenticated attackers read arbitrary files outside intended directory."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-42564"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-42564, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-42564.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/app-icons/../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_42647_joomsport_sports_league_result {
    meta:
        attack_type = "cve_2026_42647"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JoomSport <= 5.7.7 - SQL Injection: The JoomSport WordPress plugin through 5.7.7 is vulnerable to unauthenticated time-based blind SQL injection via the 'sortf' GET parameter in the player list view. The parameter value is backtick-wrapped and directly concatenated into an."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-42647"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-42647, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-42647.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/wp-sitemap-posts-joomsport_season-1.xml" ascii nocase
        $param0 = "action=playerlist" ascii nocase
        $param1 = "sortf=post_title" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_42796_arelle {
    meta:
        attack_type = "cve_2026_42796"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Arelle < 2.39.10 - Remote Code Execution: Arelle before 2.39.10 contains an unauthenticated remote code execution vulnerability in the webserver's /rest/configure endpoint. The plugins query parameter is forwarded to the plugin manager without authentication, allowing an."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-42796"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-42796, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-42796.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/rest/configure" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_44177_kirby {
    meta:
        attack_type = "cve_2026_44177"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kirby CMS 5.3.0-5.4.0 - Path Traversal: Kirby CMS versions 5.3.0 through 5.4.0 are vulnerable to a path traversal vulnerability via the /api/auth/login endpoint. An unauthenticated attacker may supply a specially crafted email value in the request body containing traversal."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-44177"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-44177, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-44177.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/panel/installation" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_44551_open_webui_ldap_empty_password {
    meta:
        attack_type = "cve_2026_44551"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Open WebUI 'LDAP Empty Password' - Authentication Bypass: Open WebUI is a self-hosted artificial intelligence platform designed to operate entirely offline. Prior to 0.9.0, the LDAP authentication endpoint does not validate that the submitted password is non-empty before."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-44551"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-44551, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-44551.yaml"
    strings:
        $path0 = "/api/v1/auths/ldap" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_45298_dozzle {
    meta:
        attack_type = "cve_2026_45298"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dozzle - Server Side Request Forgery: Dozzle prior to 10.5.2 contains a server-side request forgery caused by unauthenticated access to POST /api/notifications/test-webhook forwarding attacker-controlled URLs, letting remote attackers send arbitrary HTTP POST requests and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-45298"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-45298, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-45298.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/notifications/test-webhook" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_45332_automad {
    meta:
        attack_type = "cve_2026_45332"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Automad < 2.0.0-beta.28 - Unauthenticated Admin Password Hash Disclosure: Automad 2.0.0-alpha.1 to 2.0.0-beta.27 contains a broken access control vulnerability caused by publicly accessible /_api/user-collection/create-first-user endpoint returning full serialized user data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-45332"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-45332, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-45332.yaml"
    strings:
        $path0 = "/_api/user-collection/create-first-user" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_45397_open_webui {
    meta:
        attack_type = "cve_2026_45397"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Open WebUI < 0.9.5 - Information Disclosure: Open WebUI < 0.9.5 contains an information disclosure vulnerability caused by unauthenticated access to GET /api/v1/retrieval/ endpoint, letting remote attackers retrieve live RAG pipeline configuration without authorization, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-45397"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-45397, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-45397.yaml"
    strings:
        $path0 = "/api/v1/retrieval/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_45695_kopia {
    meta:
        attack_type = "cve_2026_45695"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Kopia Server 0.23.0 - Remote Code Execution: Kopia before version 0.23.0 allows unauthenticated remote code execution when started in server mode with the --without-password flag. When the /api/v1/repo/exists endpoint is exposed, it enables instantiation of the SFTP storage."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-45695"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-45695, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-45695.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/v1/repo/exists" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_4631_cockpit {
    meta:
        attack_type = "cve_2026_4631"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cockpit Web Console < 360 - Remote Code Execution: Cockpit's remote login feature passes user-supplied hostnames and usernames from the web interface to the SSH client without validation or sanitization. An attacker with network access to the Cockpit web service can craft a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-4631"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-4631, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-4631.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/cockpit/static/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_46339_9router {
    meta:
        attack_type = "cve_2026_46339"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "9Router <= 0.4.36 - Unauthenticated RCE: 9Router <= 0.4.36 middleware only guards 8 explicitly listed routes, leaving /api/cli-tools/* and /api/mcp/* entirely unauthenticated. An attacker can POST to /api/cli-tools/cowork-settings to register a custom MCP plugin with."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-46339"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-46339, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-46339.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/cli-tools/cowork-settings" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_46372_sillytavern {
    meta:
        attack_type = "cve_2026_46372"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SillyTavern - Server-Side Request Forgery: SillyTavern versions up to and including 1.17.0 expose the /api/search/searxng endpoint, which accepts an attacker-controlled baseUrl parameter and uses it directly to build outbound server-side fetch requests. An authenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-46372"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-46372, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-46372.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/search/searxng" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_46442_flowise {
    meta:
        attack_type = "cve_2026_46442"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Flowise < 3.1.2 - node-custom-function Unauthorized RCE: Flowise is a drag & drop user interface to build a customized large language model flow. Prior to version 3.1.2, POST /api/v1/node-custom-function lacks route-level authorization, allowing any authenticated user or API."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-46442"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-46442, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-46442.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/v1/node-custom-function" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_47670_dbgate {
    meta:
        attack_type = "cve_2026_47670"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "DbGate - Remote Code Execution via Dynamic Import Bypass: DbGate versions <= 7.1.8 are vulnerable to authenticated remote code execution via the POST /runners/load-reader endpoint. The functionName parameter is directly interpolated into a JavaScript code template without."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-47670"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-47670, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-47670.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/runners/load-reader" ascii nocase
        $path1 = "/jsldata/get-rows" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_48030_pheditor {
    meta:
        attack_type = "cve_2026_48030"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Pheditor 2.0.1-2.0.3 - OS Command Injection: Pheditor 2.0.1 to - 2.0.4 contains an OS command injection caused by improper sanitization of the 'dir' POST parameter in the terminal action handler, letting authenticated users execute arbitrary OS commands with web server."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-48030"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-48030, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-48030.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/pheditor.php" ascii nocase
        $param0 = "action=terminal" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_4810_adk_python {
    meta:
        attack_type = "cve_2026_4810"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Google ADK-Python - Unauthenticated Builder Endpoint: Google Agent Development Kit (ADK) 1.7.0 through 1.28.1 and 2.0.0a1 through 2.0.0a2 on Python (OSS), Cloud Run, and GKE contains a code injection and missing authentication vulnerability, letting unauthenticated remote."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-4810"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-4810, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-4810.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/builder/save" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_48558_simplehelp {
    meta:
        attack_type = "cve_2026_48558"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "SimpleHelp <=5.5.15 - OIDC JWT Authentication Bypass: SimpleHelp <= 5.5.15 and 6.0 pre-release contain an authentication bypass caused by lack of cryptographic signature verification in OIDC tokens, letting remote unauthenticated attackers gain technician sessions, exploit."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-48558"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-48558, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-48558.yaml"
    strings:
        $path0 = "/allversions" ascii nocase
        $path1 = "/auth/v1/account/login_options" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_48611_phpbb {
    meta:
        attack_type = "cve_2026_48611"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "phpBB < 3.3.17 - Authentication Bypass: phpBB before 3.3.17 contains an authentication bypass vulnerability in the login-link feature. By setting the auth_provider query parameter to 'apache', an unauthenticated attacker can bypass password verification and log in as any user."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-48611"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-48611, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-48611.yaml"
    strings:
        $param0 = "auth_provider=apache" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_48939_icagenda {
    meta:
        attack_type = "cve_2026_48939"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Joomla iCagenda < 3.9.10 - Unauthenticated Arbitrary File Upload RCE: iCagenda extension for Joomla contains an unrestricted file upload vulnerability in the file attachment feature, letting attackers upload and execute arbitrary PHP code, exploit requires no special privileges."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-48939"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-48939, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-48939.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/images/icagenda/frontend/attachments/" ascii nocase
        $param0 = "option=com_icagenda" ascii nocase
        $param1 = "task=registration.submit" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_49060_hippoo {
    meta:
        attack_type = "cve_2026_49060"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hippoo Mobile App for WooCommerce - Broken Access Control: Hippoo Mobile App for WooCommerce <= 1.9.4 contains a broken access control vulnerability caused by incorrect privilege assignment, letting attackers escalate their privileges, exploit requires no special conditions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-49060"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-49060, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-49060.yaml"
    strings:
        $param0 = "rest_route=/wc-hippoo/v1/ext/wp/v2/users/1" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_49952_discuz_x {
    meta:
        attack_type = "cve_2026_49952"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Discuz! X5.0 - Authentication Bypass: Discuz! X5.0 20260320 through 20260501 contains an authentication bypass caused by exploitation of a shared cryptographic key and encryption oracle in dbbak.php and logging_ctl::logging_more(), letting unauthenticated remote attackers."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-49952"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-49952, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-49952.yaml"
    strings:
        $path0 = "/member.php" ascii nocase
        $path1 = "/api/db/dbbak.php" ascii nocase
        $param0 = "apptype=discuzx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_50160_hoppscotch {
    meta:
        attack_type = "cve_2026_50160"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hoppscotch <= 2026.4.1 - Mass Assignment JWT_SECRET Overwrite: Hoppscotch self-hosted backend <= 2026.4.1 contains a broken authentication caused by mass assignment via unauthenticated POST /v1/onboarding/config endpoint, letting unauthenticated attackers overwrite JWT_SECRET."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-50160"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-50160, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-50160.yaml"
    strings:
        $path0 = "/v1/onboarding/status" ascii nocase
        $path1 = "/v1/onboarding/config" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_50229_tomcat {
    meta:
        attack_type = "cve_2026_50229"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apache Tomcat - Cross-Site Scripting: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) vulnerability in the number guess example for Apache Tomcat. This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.22, from 10.1.0-M1 through 10.1.55."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-50229"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-50229, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-50229.yaml"
        response_type = "xss"
    strings:
        $path0 = "/examples/jsp/num/numguess.jsp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_5073_armember {
    meta:
        attack_type = "cve_2026_5073"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress ARMember Premium <= 7.3.1 - Unauthenticated SQL Injection: The ARMember Premium plugin for WordPress is vulnerable to SQL Injection via the 'order' parameter of the 'arm_directory_paging_action' AJAX action in all versions up to, and including, 7.3.1. This is due to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-5073"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-5073, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-5073.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=arm_directory_paging_action" ascii nocase
        $param1 = "pagination=infinite" ascii nocase
        $param2 = "type=directory" ascii nocase
        $param3 = "orderby=display_name,IF(1=1,SLEEP(6),0)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_52774_yeswiki {
    meta:
        attack_type = "cve_2026_52774"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "YesWiki Bazar Widget - Reflected XSS via 'id' Parameter: YesWiki's Bazar widget handler reflects the id GET parameter into HTML attributes using strip_tags() only. strip_tags() does not escape double quotes, allowing an attacker to break out of the data-formid attribute and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-52774"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-52774, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-52774.yaml"
        response_type = "xss"
    strings:
        $path0 = "/NoSuchPage/widget" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_52824_kimai {
    meta:
        attack_type = "cve_2026_52824"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Kimai <= 2.57.0 - Default APP_SECRET Authentication Bypass: Kimai Docker images <= 2.57.0 ship with a hardcoded APP_SECRET of 'change_this_to_something_unique'. This default secret is used by Symfony's SignatureHasher to HMAC-sign login links and remember-me cookies. An."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-52824"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-52824, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-52824.yaml"
    strings:
        $path0 = "/en/auth/link/check" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_53576_kestra {
    meta:
        attack_type = "cve_2026_53576"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Kestra <= 1.3.20 - Remote Code Execution: Kestra <= 1.3.20 contains an authentication bypass caused by misclassification of /configs endpoint in REST API filter, letting unauthenticated attackers create and execute root-level tasks, exploit requires unauthenticated access to."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-53576"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-53576, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-53576.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/v1/main/flows/configs" ascii nocase
        $path1 = "/api/v1/main/executions/configs/configs" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_53629_glpi {
    meta:
        attack_type = "cve_2026_53629"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GLPI - Blind SQL Injection in History Log Filter (LogBleed): GLPI versions before 10.0.26 and 11.0.8 are vulnerable to a blind SQL injection in the history log filter. The Log::convertFiltersValuesToSqlCriteria() function splits the affected_fields filter into."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-53629"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-53629, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-53629.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/front/user.form.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_53787_order_attributes {
    meta:
        attack_type = "cve_2026_53787"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Magento 2 Amasty Order Attributes < 4.0.0 - Unauthenticated Arbitrary File Upload: Amasty Order Attributes for Magento 2 < 4.0.0 contains an unrestricted file upload vulnerability caused by lack of authentication and validation in the upload endpoint, letting unauthenticated."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-53787"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-53787, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-53787.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/rest/V1/amasty_orderattr/uploadFile" ascii nocase
        $path1 = "/rest/all/V1/amasty_orderattr/uploadFile" ascii nocase
        $path2 = "/rest/default/V1/amasty_orderattr/uploadFile" ascii nocase
        $path3 = "/media/amasty_checkout/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_54066_siyuan {
    meta:
        attack_type = "cve_2026_54066"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SiYuan <= 3.6.5 - Unauthenticated Path Traversal: SiYuan <= 3.6.5 contains a path traversal via double URL-encoding in the /assets/ route (publish mode port 6808), allowing unauthenticated attackers to read arbitrary files inside WorkspaceDir including conf/conf.json which."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-54066"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-54066, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-54066.yaml"
    strings:
        $path0 = "/assets/%2e%2e/%2e%2e/conf/conf.json" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_54069_siyuan {
    meta:
        attack_type = "cve_2026_54069"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SiYuan Note <= 3.6.5 - Authentication Bypass: SiYuan Note 3.6.5 and prior is vulnerable to authentication bypass. The CheckAuth middleware unconditionally trusted all chrome-extension:// origins, granting RoleAdministrator access without token validation to any request with a."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-54069"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-54069, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-54069.yaml"
    strings:
        $path0 = "/api/system/getConf" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_54157_lobe_chat {
    meta:
        attack_type = "cve_2026_54157"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LobeHub LobeChat <= 2.1.56 - Server-Side Request Forgery: LobeHub LobeChat versions up to and including 2.1.56 are vulnerable to an unauthenticated server-side request forgery vulnerability in the /webapi/proxy endpoint. The endpoint accepts a URL in the POST request body and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-54157"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-54157, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-54157.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/webapi/proxy" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_54236_vllm {
    meta:
        attack_type = "cve_2026_54236"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "vLLM <= 0.23.0 - Anthropic Router Heap Address Information Leak: vLLM <= 0.23.0 incompletely fixes CVE-2026-22778. The original fix added sanitize_message to the OpenAI router but the Anthropic-compatible router (/v1/messages) echoes str(exc) directly."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-54236"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-54236, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-54236.yaml"
    strings:
        $path0 = "/v1/messages" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_54617_launchserver {
    meta:
        attack_type = "cve_2026_54617"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "GravitLauncher LaunchServer <=5.7.11 - Unauthenticated Path Traversal to Arbitrary File Read: LaunchServer's Netty FileServerHandler computes the served path by stripping one leading character on the assumption that every request-target begins with '/'. Netty's HttpServerCodec."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-54617"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-54617, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-54617.yaml"
    strings:
        $path0 = "/../../.keys/ecdsa_id" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_55224_mineadmin {
    meta:
        attack_type = "cve_2026_55224"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MineAdmin < 3.2.0-alpha.2 - Plugin Path Traversal to RCE: MineAdmin versions before 3.2.0-alpha.2 contain a path traversal vulnerability in the app-store plugin service. The identifier parameter is concatenated into filesystem paths without sanitization."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-55224"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-55224, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-55224.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/admin/passport/login" ascii nocase
        $path1 = "/admin/plugin/store/download" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_55549_yamcs {
    meta:
        attack_type = "cve_2026_55549"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Yamcs <=5.8.6 - Cross-Site Scripting: Yamcs < 5.9.4 contains a stored XSS caused by inadequate HTML escaping of attacker-controlled redirect_uri parameter in authorization template, letting attackers execute JavaScript to steal authentication data, exploit requires user to open."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-55549"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-55549, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-55549.yaml"
        response_type = "xss"
    strings:
        $path0 = "/auth/authorize" ascii nocase
        $param0 = "client_id=yamcs-web" ascii nocase
        $param1 = "state=stable-state" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_5562_kafka_ui {
    meta:
        attack_type = "cve_2026_5562"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Provectus kafka-ui <=0.7.2 - Remote Code Execution: Provectus kafka-ui versions 0.7.0 through 0.7.2 are vulnerable to code injection in the `/api/smartfilters/testexecutions` endpoint. The `filterCode` parameter is evaluated as a Groovy expression without sandboxing, allowing."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-5562"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-5562, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-5562.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/smartfilters/testexecutions" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_56265_crawl4ai {
    meta:
        attack_type = "cve_2026_56265"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Crawl4AI < 0.8.7 - Hardcoded JWT Signing Key Authentication Bypass: Crawl4AI Docker API server versions before 0.8.7 ship with a hardcoded default JWT signing key ('mysecret') used to sign and verify HS256 authentication tokens. Because the key is identical across every."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-56265"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-56265, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-56265.yaml"
    strings:
        $param0 = "context_type=code" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_56270_flowise {
    meta:
        attack_type = "cve_2026_56270"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Flowise <= 3.0.13 - Unauthenticated OAuth Configuration Disclosure: Flowise before 3.1.0 contains a missing authentication vulnerability in the /api/v1/loginmethod endpoint, allowing unauthenticated remote attackers to retrieve an organization's complete SSO configuration."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-56270"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-56270, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-56270.yaml"
    strings:
        $path0 = "/api/v1/loginmethod" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_56290_page_builder_ck {
    meta:
        attack_type = "cve_2026_56290"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Page Builder CK <= 3.5.10 - Unauthenticated Arbitrary File Upload: Joomla Page Builder CK contains an unrestricted file upload vulnerability caused by lack of proper validation, letting unauthenticated attackers upload executable files and achieve remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-56290"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-56290, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-56290.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/media/com_pagebuilderck/gfonts/" ascii nocase
        $param0 = "option=com_pagebuilderck" ascii nocase
        $param1 = "task=browse.ajaxAddPicture" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_56291_forms {
    meta:
        attack_type = "cve_2026_56291"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Balbooa Forms < 2.4.1 - Unauthenticated Arbitrary File Upload: Joomla Balbooa Forms contains an unrestricted file upload vulnerability caused by lack of authentication checks, letting unauthenticated attackers upload executable files and achieve remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-56291"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-56291, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-56291.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/images/baforms/uploads/form-0/" ascii nocase
        $param0 = "option=com_baforms" ascii nocase
        $param1 = "task=form.uploadAttachmentFile" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_56292_acymailing {
    meta:
        attack_type = "cve_2026_56292"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "AcyMailing < 10.11.1 - Unauthenticated SQL Injection: AcyMailing component for Joomla <10.11.1 contains a sql injection caused by improper input sanitization, letting attackers access unauthorized database data, exploit requires crafted input."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-56292"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-56292, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-56292.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "ctrl=frontentityselect" ascii nocase
        $param1 = "task=loadEntityFront" ascii nocase
        $param2 = "columns=id,name" ascii nocase
        $param3 = "join_table=1,CONCAT(0x41435953,VERSION(),0x454E4453) AS acym_sqli" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_56681_9router_0_5_4 {
    meta:
        attack_type = "cve_2026_56681"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "9router <=0.5.4 - Authentication Bypass: 9Router prior to 0.5.6 contains an authentication bypass caused by trusting client-supplied X-9r-Real-Ip header in src/dashboardGuard.js, letting remote unauthenticated attackers access local API routes and consume resources, exploit."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-56681"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-56681, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-56681.yaml"
    strings:
        $path0 = "/api/v1/models" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_5718_drag_and_drop_multiple_file_up {
    meta:
        attack_type = "cve_2026_5718"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Drag and Drop Multiple File Upload - CF7 <= 1.3.9.6 - Remote Code Execution: Drag and Drop Multiple File Upload for Contact Form 7 WordPress plugin <= 1.3.9.6 contains an unrestricted file upload caused by insufficient file type validation and bypass of filename sanitization."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-5718"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-5718, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-5718.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/uploads/wp_dndcf7_uploads/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_57582_core_geonetwork {
    meta:
        attack_type = "cve_2026_57582"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GeoNetwork - Reflected Cross-Site Scripting: GeoNetwork versions 4.4.5 through 4.4.11 are vulnerable to reflected cross-site scripting (XSS) in the public unauthenticated catalog search functionality. The uiconfig query parameter of the catalog.search endpoint is reflected into."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-57582"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-57582, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-57582.yaml"
        response_type = "xss"
    strings:
        $path0 = "/srv/eng/catalog.search" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_57827_rsfiles {
    meta:
        attack_type = "cve_2026_57827"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "RSFiles! for Joomla - Arbitrary File Upload: RSFiles! (com_rsfiles) for Joomla < 1.17.12 allows unauthenticated arbitrary file upload via the rsfiles.upload task. The write method performs no authentication, CSRF token, or file extension checks, allowing upload of executable."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-57827"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-57827, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-57827.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "task=rsfiles.checkupload" ascii nocase
        $param1 = "task=rsfiles.upload" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_58123_hermes_webui {
    meta:
        attack_type = "cve_2026_58123"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hermes WebUI < 0.51.788 - Remote Code Execution: Hermes WebUI < 0.51.788 contains an unauthenticated remote code execution caused by improper access control in embedded terminal API endpoints, letting remote attackers execute arbitrary shell commands without credentials."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-58123"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-58123, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-58123.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/terminal/start" ascii nocase
        $path1 = "/api/terminal/input" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_58138_conductor {
    meta:
        attack_type = "cve_2026_58138"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Orkes Conductor 3.21.21-3.30.1 - Remote Code Execution: Orkes Conductor from 3.21.21 before 3.30.2 is vulnerable to unauthenticated remote code execution. The INLINE workflow task evaluates a user-supplied JavaScript expression in a GraalVM context created with HostAccess.ALL."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-58138"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-58138, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-58138.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/metadata/workflow" ascii nocase
        $path1 = "/api/workflow/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_58191_appium {
    meta:
        attack_type = "cve_2026_58191"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Appium base-driver <=10.6.0 - Reflected Cross-Site Scripting: Appium <= 10.7.0 contains a reflected XSS caused by unescaped reflection of throwError query parameter, comments POST field, and User-Agent header in base-driver routes, letting remote attackers execute arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-58191"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-58191, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-58191.yaml"
        response_type = "xss"
    strings:
        $path0 = "/test/guinea-pig" ascii nocase
        $param0 = "throwError='+alert(document.domain)+'" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_58455_dockwatch {
    meta:
        attack_type = "cve_2026_58455"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dockwatch <= 0.6.567 - OS Command Injection: Dockwatch through 0.6.567 contains an unauthenticated command injection caused by missing exit() after authentication redirect in loader.php and unsanitized input in ajax/compose.php, letting remote attackers execute arbitrary shell."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-58455"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-58455, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-58455.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/ajax/compose.php" ascii nocase
        $param0 = "m=composePull" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_58467_cockpit {
    meta:
        attack_type = "cve_2026_58467"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cockpit CMS <= 2.14.0 - Path Traversal / Local File Inclusion: Cockpit CMS through 2.14.0 contains a path traversal and local file inclusion (LFI) vulnerability when executed under PHP's built-in CLI server (PHP_SAPI == 'cli-server') or non-normalizing reverse proxies. The."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-58467"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-58467, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-58467.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/:x/storage/../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_58644_sharepoint_server {
    meta:
        attack_type = "cve_2026_58644"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Microsoft SharePoint Server - WS-Federation BinaryFormatter Deserialization RCE: Microsoft SharePoint Server (2016, 2019, Subscription Edition <= 2026.3.1) contains a remote code execution vulnerability in the WS-Federation passive sign-in endpoint (/_trust/default.aspx). The."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-58644"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-58644, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-58644.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/_trust/default.aspx" ascii nocase
        $param0 = "wa=wsignin1.0" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_59509_cve_search {
    meta:
        attack_type = "cve_2026_59509"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "cve-search 4.0-6.0.0 - Unauthenticated NoSQL Injection: cve-search versions 4.0 through 6.0.0 expose an unauthenticated DataTables endpoint that accepts attacker-controlled MongoDB collection, projection, filtering, and pagination parameters. This detector uses a harmless."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-59509"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-59509, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-59509.yaml"
    strings:
        $path0 = "/fetch_cve_data" ascii nocase
        $param0 = "retrieve=cves" ascii nocase
        $param1 = "columns[0][data]=password" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_59774_gitea {
    meta:
        attack_type = "cve_2026_59774"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Gitea 1.22.1-1.27.0 - Unauthenticated Arbitrary File Read: Gitea versions 1.22.1 through 1.27.0 initialize the go-org markup renderer without replacing its default ReadFile callback. An unauthenticated attacker can submit Org-mode markup containing an #+INCLUDE directive with."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-59774"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-59774, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-59774.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "file_path=a.org" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_60004_gitea {
    meta:
        attack_type = "cve_2026_60004"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Gitea <= 1.27.0 - Pre-Auth Remote Code Execution: Gitea versions 1.17 through 1.27.0 contain a remote code execution vulnerability in the diffpatch endpoint caused by an add/add collision that writes an executable Git hook into the bare repository's GIT_DIR. An attacker with."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-60004"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-60004, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-60004.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/v1/user/repos" ascii nocase
        $path1 = "/api/v1/repos/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_6118_astrbot {
    meta:
        attack_type = "cve_2026_6118"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AstrBot <= 4.22.1 - Command Injection: AstrBot versions up to and including 4.22.1 contain a command injection vulnerability in the MCP server configuration endpoint. The /api/tools/mcp/add endpoint accepts arbitrary command and args fields that are passed directly to."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-6118"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-6118, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-6118.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/tools/mcp/add" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_61511_vbulletin {
    meta:
        attack_type = "cve_2026_61511"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "vBulletin 6.x - Remote Code Execution: vBulletin 5.x through 5.7.5 and 6.x through 6.2.1 contain an eval injection vulnerability caused by insufficiently restrictive regex filtering in vB5_Template_Runtime::runMaths(), letting unauthenticated remote attackers execute arbitrary."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-61511"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-61511, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-61511.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "routestring=ajax/render/pagenav" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_61808_lightrag {
    meta:
        attack_type = "cve_2026_61808"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LightRAG <= 1.5.4 - Missing Authentication: LightRAG through version 1.5.4 contains a broken access control vulnerability caused by the API server binding to all network interfaces with authentication disabled, letting unauthenticated network attackers fully control indexed."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-61808"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-61808, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-61808.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/documents" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_63030_wordpress {
    meta:
        attack_type = "cve_2026_63030"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "WordPress Core 6.9-7.0.1 - Pre-Auth Batch-Route Confusion: WordPress core versions 6.9.0 through 6.9.4 and 7.0.0 through 7.0.1 are vulnerable to a pre-authentication route confusion issue in the REST API batch endpoint (/?rest_route=/batch/v1). A malformed nested batch request."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-63030"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-63030, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-63030.yaml"
    strings:
        $param0 = "rest_route=/batch/v1" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_63077_teamcity {
    meta:
        attack_type = "cve_2026_63077"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "JetBrains TeamCity < 2026.1.3, 2025.11.7 - Remote Code Execution: JetBrains TeamCity < 2026.1.3, 2025.11.7 contains a remote code execution caused by unsafe XStream deserialization in the unauthenticated agent polling protocol. The XStream instance serving /app/agents/v1 is."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-63077"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-63077, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-63077.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/app/agents/v1/register" ascii nocase
        $path1 = "/app/agents/v1/commands/error" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_6377_csm {
    meta:
        attack_type = "cve_2026_6377"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Next4Biz CSM - Arbitrary File Read via DownloadFileHandler: Next4Biz CSM exposes the DownloadFileHandler.ashx endpoint, whose file parameter is passed to a path helper that never confirms the resolved path stays inside the upload directory before the file is streamed back.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-6377"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-6377, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-6377.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/Handlers/DownloadFileHandler.ashx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_6433_custom_css_js_php {
    meta:
        attack_type = "cve_2026_6433"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FlipperCode Custom CSS, JS & PHP <= 2.0.7 - Remote Code Execution: Custom css-js-php WordPress plugin through 2.0.7 contains a command injection caused by unsanitized user input used in SQL query and passed to eval(), letting unauthenticated attackers execute arbitrary PHP code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-6433"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-6433, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-6433.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "operation=wce_editor_inline_code" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_64849_mlflow_webhook_ssrf {
    meta:
        attack_type = "cve_2026_64849"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "MLflow Webhook SSRF - Unauthenticated Full-Read via Redirect Bypass: MLflow > 3.15.0 contains an information disclosure vulnerability caused by improper validation of webhook URLs allowing attackers to reach internal or cloud metadata services and obtain response details."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-64849"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-64849, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-64849.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/2.0/mlflow/webhooks" ascii nocase
        $path1 = "/api/2.0/mlflow/webhooks/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_65694_microweber {
    meta:
        attack_type = "cve_2026_65694"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Microweber CMS <= 2.0.20 - Unauthenticated Arbitrary File Read: Microweber CMS <= 2.0.20 contains a path traversal vulnerability caused by failure to normalize path query parameter in static file controller, letting unauthenticated remote attackers read arbitrary files."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-65694"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-65694, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-65694.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/userfiles/x" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_65761_easy_store {
    meta:
        attack_type = "cve_2026_65761"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Joomla Easy Store - SQL Injection: Joomla Easy Store extension 1.0.0-2.0.1 contains an unauthenticated SQL injection caused by improper validation of order parameters, letting unauthenticated attackers read the full database including credentials and sessions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-65761"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-65761, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-65761.yaml"
    strings:
        $param0 = "option=com_easystore" ascii nocase
        $param1 = "view=products" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_65919_meshery {
    meta:
        attack_type = "cve_2026_65919"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Meshery <1.0.57 - Arbitrary File Read: Meshery before 1.0.57 contains an unauthenticated arbitrary file read vulnerability in the /api/system/fileView and /api/system/fileDownload endpoints that pass user-supplied file parameters directly to os.Open without path validation.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-65919"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-65919, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-65919.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/system/fileView" ascii nocase
        $path1 = "/api/system/fileDownload" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_6639_ai_copilot_content_generator {
    meta:
        attack_type = "cve_2026_6639"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AI Copilot Content Generator <=1.4.6 - Unauthenticated Task Data Exposure: AIWU AI Chatbot & Workflow Automation WordPress plugin <= 1.4.6 contains a sensitive information exposure caused by unauthenticated access to getCurrentTaskResults() method, letting unauthenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-6639"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-6639, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-6639.yaml"
    strings:
        $param0 = "action=getCurrentTaskResults" ascii nocase
        $param1 = "mod=workspace" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_6826_concrete_cms_9_5_1 {
    meta:
        attack_type = "cve_2026_6826"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Concrete CMS <9.5.1 - Unauthenticated File Usage Disclosure: Concrete CMS 9.5.0 and below is vulnerable to unauthenticated file usage disclosure via missing permission check in the usage controller."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-6826"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-6826, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-6826.yaml"
    strings:
        $path0 = "/ccm/system/dialogs/file/usage/1" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_6854_my_calendar_3_7_9 {
    meta:
        attack_type = "cve_2026_6854"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "My Calendar < 3.7.9 - Unauthenticated SQL Injection: The My Calendar Accessible Event Manager plugin for WordPress is vulnerable to time-based blind SQL Injection via the 'mc_auth' parameter in all versions up to, and including, 3.7.8 due to insufficient escaping on the user."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-6854"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-6854, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-6854.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "mc_auth=1,2) OR SLEEP(7)-- x" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_6875_servicenow {
    meta:
        attack_type = "cve_2026_6875"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ServiceNow AI Platform - Pre-Auth JavaScript Sandbox Escape RCE: ServiceNow AI Platform (Brazil, Australia, Zurich, and Yokohama releases before patching) contains a pre-authentication remote code execution vulnerability. The /assessment_thanks.do endpoint passes the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-6875"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-6875, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-6875.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/assessment_thanks.do" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_69084_siyuan {
    meta:
        attack_type = "cve_2026_69084"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SiYuan - SQL Execution: SiYuan <= v3.7.2 contains a SQL injection caused by passing client-supplied SQL statements verbatim to the main read-write database handle in /api/search/searchEmbedBlock, letting attackers with publish RoleReader token or anonymous access read and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-69084"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-69084, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-69084.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/api/system/loginAuth" ascii nocase
        $path1 = "/api/search/searchEmbedBlock" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_69085_siyuan {
    meta:
        attack_type = "cve_2026_69085"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SiYuan <=3.7.2 - SQL Injection: SiYuan before v3.7.3 contains a SQL injection caused by direct concatenation of the keyword parameter in /api/filetree/searchDocs endpoint, letting attackers with publish RoleReader token or unauthenticated in publish mode read and modify."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-69085"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-69085, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-69085.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/api/notebook/lsNotebooks" ascii nocase
        $path1 = "/api/filetree/searchDocs" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_69137_suitecrm {
    meta:
        attack_type = "cve_2026_69137"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SuiteCRM <= 7.15.1, <= 8.10.1 - Authenticated SSRF: SuiteCRM CalendarAccount testConnection accepts an attacker-controlled server_url and passes it to cURL without destination validation. An authenticated user can cause a server-side request to loopback or internal network."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-69137"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-69137, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-69137.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = "module=CalendarAccount" ascii nocase
        $param1 = "action=testConnection" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_69251_flowise {
    meta:
        attack_type = "cve_2026_69251"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Flowise < 3.1.3 - Remote Code Execution: Flowise prior to 3.1.3 contains a remote code execution vulnerability caused by allowing authenticated users to set arbitrary TypeORM DataSource options including entities that load local JavaScript files, letting authenticated users."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-69251"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-69251, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-69251.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/v1/document-store/store" ascii nocase
        $path1 = "/api/v1/document-store/loader/save" ascii nocase
        $path2 = "/api/v1/document-store/loader/process/" ascii nocase
        $path3 = "/api/v1/document-store/vectorstore/insert" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_71209_audiobookshelf {
    meta:
        attack_type = "cve_2026_71209"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Audiobookshelf - Authentication Bypass: Audiobookshelf contains a path traversal caused by improper authentication-exemption check on URL-encoded paths in server/routers/Auth.js, letting unauthenticated attackers read arbitrary files, exploit requires crafted URL with encoded."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-71209"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-71209, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-71209.yaml"
    strings:
        $path0 = "/api/collections" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_71362_magento {
    meta:
        attack_type = "cve_2026_71362"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Adobe Commerce/Magento - Customer Session Identity Switch: Adobe Commerce contains an incorrect authorization vulnerability caused by improper access control, letting attackers escalate privileges to access sensitive resources, exploit requires no user interaction."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-71362"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-71362, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-71362.yaml"
    strings:
        $path0 = "/customer/account/create" ascii nocase
        $path1 = "/customer/account/createPost" ascii nocase
        $path2 = "/customer/account/edit" ascii nocase
        $path3 = "/customer/account/editPost" ascii nocase
        $path4 = "/customer/section/load" ascii nocase
        $param0 = "firstname=PoCTestCVE" ascii nocase
        $param1 = "lastname=Detector" ascii nocase
        $param2 = "current_password=wrong-password-forces-exception" ascii nocase
        $param3 = "sections=customer" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_72867_dokploy {
    meta:
        attack_type = "cve_2026_72867"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dokploy <= 0.29.12 - Authenticated RCE via Command Injection: Dokploy <= 0.29.12 is vulnerable to authenticated OS command injection through the customGitBranch field of a compose service. The value is concatenated unsanitized into git clone --branch <customGitBranch> ... and."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-72867"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-72867, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-72867.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/trpc/project.create" ascii nocase
        $path1 = "/api/trpc/compose.create" ascii nocase
        $path2 = "/api/trpc/compose.update" ascii nocase
        $path3 = "/api/trpc/compose.deploy" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_72898_metabase {
    meta:
        attack_type = "cve_2026_72898"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Metabase - Unauthenticated SQL Injection: Metabase contains a sql injection caused by improper sanitization of input in the '/reset_password' database endpoint, letting remote unauthenticated attackers gain administrator access, exploit requires no special privileges."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-72898"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-72898, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-72898.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/api/session/properties" ascii nocase
        $path1 = "/api/session/reset_password" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_73034_db_gpt {
    meta:
        attack_type = "cve_2026_73034"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "DB-GPT <= 0.8.1 - Arbitrary File Write: DB-GPT through 0.8.1 allows unauthenticated arbitrary file writes via a path traversal in the user_id HTTP header of the POST /api/v1/python/file/upload endpoint, letting attackers escape the intended upload directory and write files."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-73034"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-73034, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-73034.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/v1/python/file/upload" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_7467_expand_maker {
    meta:
        attack_type = "cve_2026_7467"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Read More & Accordion <= 3.5.7 - Authenticated Privilege Escalation: The Read More & Accordion (expand-maker) plugin for WordPress through 3.5.7 allows privilege escalation due to improper validation in the importData AJAX handler (yrm_import_data action). An authenticated user."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-7467"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-7467, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-7467.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = "page=readMore" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_76460_identity_services_engine {
    meta:
        attack_type = "cve_2026_76460"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Cisco Identity Services Engine - ise-kong API Gateway Authentication Bypass: Cisco Identity Services Engine contains an authentication bypass caused by insufficient authentication control on an API endpoint, letting unauthenticated remote attackers gain unauthorized access."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-76460"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-76460, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-76460.yaml"
    strings:
        $path0 = "/admin/API/mnt/Session/ActiveList" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_77806_spip_4_4_22 {
    meta:
        attack_type = "cve_2026_77806"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SPIP < 4.4.22 - Unauthenticated RCE: SPIP < 4.4.21 contains a remote code execution caused by mishandling of the X-Spip-Filtre HTTP request header in analyse_resultat_skel, letting unauthenticated remote attackers execute arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-77806"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-77806, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-77806.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "page=sommaire" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_80462_chef_automate {
    meta:
        attack_type = "cve_2026_80462"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Chef Automate API Gateway - Authentication Bypass: Chef Automate derives an internal service identity from an X.509 certificate supplied in a request header without verifying its issuer. The load balancer blanks X-Client-Cert but does not strip the Grpc-Metadata- prefixed."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-80462"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-80462, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-80462.yaml"
    strings:
        $path0 = "/api/v0/telemetry/config" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_8054_dotcms {
    meta:
        attack_type = "cve_2026_8054"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "dotCMS Core Publish Audit API - Unauthenticated SQL Injection: dotCMS Core 25.11.04-1 through 26.04.28-02 contains an SQL injection caused by unsanitized input in Publish Audit API endpoints (/api/auditPublishing/get and /api/auditPublishing/getAll), letting remote."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-8054"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-8054, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-8054.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/api/auditPublishing/getAll" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_8089_wemail {
    meta:
        attack_type = "cve_2026_8089"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress weMail < 2.1.3 - Cross-Site Scripting: The weMail plugin for WordPress < 2.1.3 is vulnerable to reflected cross-site scripting. The plugin does not properly escape a user-supplied parameter before reflecting it into an HTML attribute on a non-nonce-protected AJAX."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-8089"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-8089, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-8089.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=wemail_preview" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_81199_masterstudy_lms {
    meta:
        attack_type = "cve_2026_81199"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MasterStudy LMS < 3.7.46 - Unauthenticated Student Statistics Disclosure: MasterStudy LMS WordPress plugin before 3.7.46 contains an information disclosure vulnerability caused by missing authorization checks in student learning statistics, letting unauthenticated attackers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-81199"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-81199, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-81199.yaml"
    strings:
        $param0 = "rest_route=/masterstudy-lms/v2/student/stats/1" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_81578_papercut_ng_papercut_mf {
    meta:
        attack_type = "cve_2026_81578"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "PaperCut NG/MF <=26.0.4 - Unauthenticated ConfigEditor Access via Tapestry Complex-Direct: PaperCut NG and PaperCut MF versions 24.x through 26.x contain an authentication bypass vulnerability in the Apache Tapestry-based web interface. By crafting a complex-direct service."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-81578"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-81578, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-81578.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "Form0=$TextField,doQuickFind,clear" ascii nocase
        $param1 = "$TextField=server.name" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_82186_gdpr_cookie_consent {
    meta:
        attack_type = "cve_2026_82186"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WPLP Cookie Consent < 4.4.2 - SQL Injection: The WPLP Cookie Consent WordPress plugin before 4.4.2 does not properly validate a pagination parameter before using it in a SQL query, allowing users with administrator privileges to execute arbitrary SQL commands."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-82186"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-82186, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-82186.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=wpl_cookie_scanner" ascii nocase
        $param1 = "wpl_scanner_action=get_pages" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_82222_givewp {
    meta:
        attack_type = "cve_2026_82222"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "GiveWP <= 4.16.7.1 - Remote Code Execution: GiveWP <= 4.16.7.1 contains an insecure deserialization vulnerability caused by deserialization of untrusted data, letting attackers perform object injection remotely, exploit requires crafted input"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-82222"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-82222, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-82222.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-json/wp/v2/give_forms" ascii nocase
        $param0 = "give_action=user_register" ascii nocase
        $param1 = "_wp_http_referer=/wp-admin/profile.php" ascii nocase
        $param2 = "from=profile" ascii nocase
        $param3 = "give-amount=25.00" ascii nocase
        $param4 = "give_action=view_receipt" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_82329_jfrog_artifactory_access_blank {
    meta:
        attack_type = "cve_2026_82329"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "JFrog Artifactory Access Blank Join Key Authentication Bypass: JFrog Artifactory contains an authentication weakness that, under default configuration, may allow an unauthenticated attacker with network access to obtain administrative privileges."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-82329"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-82329, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-82329.yaml"
    strings:
        $path0 = "/access/api/v1/registry/join" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_8236_concrete_cms {
    meta:
        attack_type = "cve_2026_8236"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Concrete CMS <9.5.1 - Unauthenticated File-Usage Internal Metadata Disclosure: Concrete CMS 9.5.0 and below is vulnerable to IDOR combined with a missing authentication gate. The endpoint /ccm/system/dialogs/file/usage/{fID} accepts an integer file ID in the URL and returns."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-8236"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-8236, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-8236.yaml"
    strings:
        $path0 = "/index.php/ccm/system/dialogs/file/usage/1" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_8237_concrete_cms {
    meta:
        attack_type = "cve_2026_8237"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Concrete CMS <= 9.5.0 - Unauthenticated Conversation Message Disclosure (IDOR): Concrete CMS <= 9.5.0 contains an IDOR caused by insufficient access control in /ccm/frontend/conversations/message_detail endpoint, letting unauthenticated attackers enumerate conversation messages."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-8237"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-8237, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-8237.yaml"
    strings:
        $path0 = "/ccm/frontend/conversations/message_detail" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_82901_ultimate_addons_for_contact_fo {
    meta:
        attack_type = "cve_2026_82901"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ultimate Addons for Contact Form 7 <= 3.5.50 - Arbitrary File Upload: Ultimate Addons for Contact Form 7 (UACF7) <= 3.5.50 copies every file submitted through a Contact Form 7 [uacf7_signature] field into wp-content/uploads/uacf7-uploads/ with no file-type or extension."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-82901"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-82901, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-82901.yaml"
    strings:
        $path0 = "/wp-json/contact-form-7/v1/contact-forms/" ascii nocase
        $path1 = "/wp-content/uploads/uacf7-uploads/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_8385_wp_google_maps {
    meta:
        attack_type = "cve_2026_8385"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WP Go Maps < 10.0.10 - Unauthenticated Marker Data Disclosure: WP Go Maps WordPress plugin < 10.0.10 contains an information disclosure vulnerability caused by improper enforcement of marker approval filter in admin-ajax fallback for datatables route, letting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-8385"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-8385, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-8385.yaml"
    strings:
        $param0 = "action=wpgmza_rest_api_request" ascii nocase
        $param1 = "route=/datatables/" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_84434_gravityforms {
    meta:
        attack_type = "cve_2026_84434"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Gravity Forms Plugin <=3.1.0.4 - Unauthenticated Arbitrary File Upload: Gravity Forms WordPress plugin version 3.1.0.4 and earlier contains an unauthenticated arbitrary file upload vulnerability caused by bypassing extension validation in hidden file upload fields.."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-84434"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-84434, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-84434.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/plugins/gravityforms/gravityforms.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_85097_bricksforge {
    meta:
        attack_type = "cve_2026_85097"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Bricksforge WordPress Plugin <=3.1.8.9 - Unauthenticated Arbitrary File Upload: Bricksforge WordPress plugin versions up to and including 3.1.8.9 are vulnerable to unauthenticated arbitrary file upload leading to remote code execution. An attacker obtains a wp_rest nonce via."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-85097"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-85097, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-85097.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-json/bricksforge/v1/form_file_upload" ascii nocase
        $path1 = "/wp-json/bricksforge/v1/form_submit" ascii nocase
        $param0 = "action=bricksforge_regenerate_nonce" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_85200_geo_my_wp {
    meta:
        attack_type = "cve_2026_85200"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GEO my WP <=4.5.5.3 - Unauthenticated Local File Inclusion: GEO my WP WordPress plugin <= 4.5.5.3 contains a local file inclusion caused by improper handling in gmw_posts_locator_ajax_info_window_loader function, letting unauthenticated attackers execute arbitrary PHP code."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-85200"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-85200, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-85200.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "form[component]=posts_locator" ascii nocase
        $param1 = "form[info_window_template][content_path]=/etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_85688_ten_framework {
    meta:
        attack_type = "cve_2026_85688"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TEN Framework - Arbitrary File Read & Write: TEN Framework 0.11.71 contains unauthenticated arbitrary file read and write vulnerabilities in the TMAN Designer file-content API endpoints, letting attackers read or write arbitrary files and execute code. The exploit requires no."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-85688"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-85688, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-85688.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/designer/v1/file-content" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_85706_gitlab {
    meta:
        attack_type = "cve_2026_85706"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "GitLab CE/EE <=19.1.7/19.2.5/19.3.1 - Arbitrary File Read: GitLab CE/EE contains an unauthenticated arbitrary file read. Workhorse, the reverse proxy in front of Rails, matches upload routes using EscapedPath() and path.Clean without decoding percent sequences, while Puma."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-85706"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-85706, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-85706.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/v4/projects/1/repository/files/" ascii nocase
        $param0 = "Content-Type=application/x-www-form-urlencoded" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_86426_librenms {
    meta:
        attack_type = "cve_2026_86426"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LibreNMS <= 26.7.0 - Unauthenticated API Access: LibreNMS <= 26.8.0 contains an authentication bypass caused by MySQL type coercion in the REST API token validation, letting unauthenticated attackers access protected endpoints and execute remote code via alert templates."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-86426"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-86426, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-86426.yaml"
    strings:
        $path0 = "/api/v0/devices" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_87820_cyberpanel {
    meta:
        attack_type = "cve_2026_87820"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "CyberPanel 2.4.3-2.4.5 - AI Scanner Debug Disclosure: CyberPanel versions 2.4.3 through 2.4.5 expose unauthenticated AI Scanner debugging endpoints that disclose administrator usernames, API-key prefixes, scan identifiers, target domains, and account metadata. Unauthenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-87820"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-87820, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-87820.yaml"
    strings:
        $path0 = "/api/ai-scanner/list-api-keys" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_88062_omniroute {
    meta:
        attack_type = "cve_2026_88062"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OmniRoute < 3.8.49 - Unauthenticated RCE: OmniRoute <= 3.8.49 contains a remote code execution caused by insufficient validation of interpreter arguments in the POST /api/acp/agents endpoint, letting remote attackers execute arbitrary code, exploit requires anonymous access."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-88062"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-88062, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-88062.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/acp/agents" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_8857_easytimeline {
    meta:
        attack_type = "cve_2026_8857"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MediaWiki EasyTimeline - Code Injection RCE: MediaWiki EasyTimeline (Timeline) extension versions before 1.46.0, 1.45.4, 1.44.6, and 1.43.9 contain a code injection vulnerability caused by insufficient neutralization of newlines in TextData text attributes in EasyTimeline.pl /."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-8857"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-8857, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-8857.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "meta=siteinfo" ascii nocase
        $param1 = "contentmodel=wikitext" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_89013_dolibarr {
    meta:
        attack_type = "cve_2026_89013"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dolibarr < 24.0.0 - Authorization Bypass via hashp Parameter: Dolibarr ERP/CRM versions 23.0.4 through 24.0.0 contain an authorization bypass vulnerability in document.php and viewimage.php. The public share-link feature forces NOLOGIN when hashp is present, but the value."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-89013"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-89013, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-89013.yaml"
    strings:
        $param0 = "hashp=shared" ascii nocase
        $param1 = "modulepart=medias" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_89026_framework {
    meta:
        attack_type = "cve_2026_89026"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Issabel Framework - Hard-Coded PBX API JWT Key: Issabel Framework before commit b97dbaf uses a shared HS256 key for PBX API bearer tokens. This template uses the read-only AMI ExtensionState action to check whether the PBX API accepts a short-lived token signed with either the."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-89026"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-89026, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-89026.yaml"
    strings:
        $path0 = "/pbxapi/manager/extensionstate" ascii nocase
        $param0 = "context=from-internal" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_89063_bookly_responsive_appointment {
    meta:
        attack_type = "cve_2026_89063"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Bookly <=28.1 - IDOR Unauthenticated Sensitive Data Access: Bookly WordPress plugin <= 28.1 contains an insecure direct object reference caused by missing validation on 'conversation_id' parameter, letting unauthenticated attackers read and inject messages into any AI booking."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-89063"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-89063, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-89063.yaml"
    strings:
        $param0 = "action=bookly_ai_send_message" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_9062_agile_store_locator {
    meta:
        attack_type = "cve_2026_9062"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "WordPress Agile Store Locator < 1.6.9 - Arbitrary File Read: The Agile Store Locator WordPress plugin before 1.6.9 does not validate a parameter before using it in a file path, allowing high-privileged users such as administrators to read arbitrary .php files from the server."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-9062"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-9062, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-9062.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "sl-action=reset_custom_template" ascii nocase
        $param1 = "template=cards-templates" ascii nocase
        $param2 = "section=../../../../../wp-config" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_90817_redcap {
    meta:
        attack_type = "cve_2026_90817"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "REDCap >= 13.3.0 - Unauthenticated Remote Code Execution via Survey Passthru: REDCap versions 13.3.0 through 16.0.48 LTS, 17.3.9 LTS, and 17.4.3 Standard contain an unauthenticated remote code execution vulnerability. The application is vulnerable to an authentication bypass."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-90817"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-90817, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-90817.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "route=ParcelController:show" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_9082_drupal {
    meta:
        attack_type = "cve_2026_9082"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Drupal Core - Anonymous SQL Injection via PostgreSQL Entity Query: Drupal core from 8.9.0 before 10.4.10, 10.5.0 before 10.5.10, 10.6.0 before 10.6.9, 11.0.0 before 11.1.10, 11.2.0 before 11.2.12, and 11.3.0 before 11.3.10 contains an SQL injection caused by improper."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-9082"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-9082, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-9082.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/jsonapi/node/" ascii nocase
        $param0 = "filter[t][condition][path]=title" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_91136_divi_plus {
    meta:
        attack_type = "cve_2026_91136"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Divi Plus <= 2.4.0 - Unauthenticated Arbitrary File Read: The Divi Plus WordPress plugin through 2.4.0 exposes the /wp-json/elicus/v1/dipl-modules/svg-animator REST route with a permission callback that returns true unconditionally, and passes the svg_image parameter to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-91136"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-91136, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-91136.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-json/elicus/v1/dipl-modules/svg-animator" ascii nocase
        $param0 = "svg_image=/etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_9133_rabbitmq_aws {
    meta:
        attack_type = "cve_2026_9133"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Amazon rabbitmq-aws 0.1.0 through 0.2.0 - Arbitrary File Read: Amazon rabbitmq-aws versions 0.1.0 through 0.2.0 contain active debug code in the ARN resolver. An authenticated RabbitMQ user with management API access can submit an arn:aws-debug:file ARN to the validation."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-9133"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-9133, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-9133.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/aws/arn/validate" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_9282_w3_total_cache {
    meta:
        attack_type = "cve_2026_9282"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "W3 Total Cache <= 2.9.4 - Unauthenticated Arbitrary File Read: W3 Total Cache WordPress plugin <= 2.9.4 contains a directory traversal caused by improper handling in setupSources function, letting unauthenticated attackers read arbitrary files, exploit requires manual minify."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-9282"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-9282, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-9282.yaml"
    strings:
        $param0 = "f_array[]=wp-config.php" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_93485_wordpress {
    meta:
        attack_type = "cve_2026_93485"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Core < 7.1.1 - Unauthenticated Stored XSS via Comment (Comment2Shell): WordPress core before 7.1.1 is vulnerable to unauthenticated stored XSS via crafted blockquote comments. wp_kses_post accepts a <blockquote> with a literal newline in the cite attribute, wpautop's."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-93485"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-93485, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-93485.yaml"
        response_type = "xss"
    strings:
        $param0 = "_fields=id,comment_status" ascii nocase
        $param1 = "orderby=date" ascii nocase
        $param2 = "email=test@example.com" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_93616_quantum_security_management {
    meta:
        attack_type = "cve_2026_93616"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Check Point Security Management - Unauthenticated Directory Traversal to RCE: Check Point Management Server contains a directory traversal and unrestricted file upload vulnerability allowing unauthenticated attackers to upload and execute arbitrary scripts remotely, exploit."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-93616"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-93616, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-93616.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/cpmws/UpgradeSvcRemote" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2026_94169_the_grid {
    meta:
        attack_type = "cve_2026_94169"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "The Grid <= 2.8.1 - Unauthenticated Code Injection: Theme-one The Grid <= 2.8.1 contains a command injection caused by improper control of code generation, letting attackers execute arbitrary commands remotely, exploit requires crafted input."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-94169"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-94169, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-94169.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "grid_nonce=invalid" ascii nocase
        $param1 = "grid_data[grid_skins][evil][php]=/etc/passwd" ascii nocase
        $param2 = "grid_data[grid_skins][evil][type]=grid" ascii nocase
        $param3 = "grid_data[grid_skins][evil][slug]=evil" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2026_9506_bagisto {
    meta:
        attack_type = "cve_2026_9506"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Bagisto <= 2.4.1 - Unauthenticated Arbitrary File Read: Bagisto through 2.4.1 is vulnerable to unauthenticated path traversal in the ImageCache controller. The `original` image-cache route (/cache/original/{filename}) passes the user-supplied filename to getImagePath() without."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2026-9506"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-9506, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-9506.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/cache/original/../composer.json" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}
