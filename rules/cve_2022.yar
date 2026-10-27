// Baseline rules generated from public exploit and exposure checks in
// ProjectDiscovery nuclei-templates (MIT License,
// https://github.com/projectdiscovery/nuclei-templates). Each rule keys on the
// most specific request indicator of one check: a path, a static parameter or
// a vendor header that no other check and no benign request uses. Rules are
// confidence = "medium": a probe for the endpoint is a strong signal, but a
// rule cannot tell an exploit attempt from a scanner fingerprinting it.
// The `reference` field links the source check.

rule krawl_cve_2022_0140_visual_form_builder {
    meta:
        attack_type = "cve_2022_0140"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Visual Form Builder <3.0.8 - Information Disclosure: WordPress Visual Form Builder plugin before 3.0.8 contains a information disclosure vulnerability. The plugin does not perform access control on entry form export, allowing an unauthenticated user to export the form."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0140"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0140, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0140.yaml"
    strings:
        $param0 = "vfb-content=entries" ascii nocase
        $param1 = "submit=Download Export File" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0147_wp_gdpr_compliance {
    meta:
        attack_type = "cve_2022_0147"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Cookie Information/Free GDPR Consent Solution <2.0.8 - Cross-Site Scripting: WordPress Cookie Information/Free GDPR Consent Solution plugin prior to 2.0.8 contains a cross-site scripting vulnerability via the admin dashboard. An attacker can inject arbitrary script in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0147"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0147, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0147.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=wp-gdpr-compliance" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0148_mystickyelements {
    meta:
        attack_type = "cve_2022_0148"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress All-in-one Floating Contact Form <2.0.4 - Cross-Site Scripting: WordPress All-in-one Floating Contact Form, Call, Chat, and 50+ Social Icon Tabs plugin before 2.0.4 contains a reflected cross-site scripting vulnerability on the my-sticky-elements-leads admin page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0148"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0148, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0148.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=my-sticky-elements-leads" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0150_wp_accessibility_helper {
    meta:
        attack_type = "cve_2022_0150"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Accessibility Helper <0.6.0.7 - Cross-Site Scripting: WordPress Accessibility Helper plugin before 0.6.0.7 contains a cross-site scripting vulnerability. It does not sanitize and escape the wahi parameter before outputting back its base64 decode value in the page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0150"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0150, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0150.yaml"
        response_type = "xss"
    strings:
        $param0 = "wahi=JzthbGVydChkb2N1bWVudC5kb21haW4pOy8v" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0218_wordpress_email_template_desig {
    meta:
        attack_type = "cve_2022_0218"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "HTML Email Template Designer < 3.1 - Missing Authorization on Rest Route: The WP HTML Mail WordPress plugin is vulnerable to unauthorized access which allows unauthenticated attackers to retrieve and modify theme settings due to a missing capability check on the /themesettings."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0218"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0218, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0218.yaml"
    strings:
        $param0 = "rest_route=/whm/v3/themesettings" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0220_wordpress_gdpr_ccpa {
    meta:
        attack_type = "cve_2022_0220"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress GDPR & CCPA <1.9.27 - Cross-Site Scripting: WordPress GDPR & CCPA plugin before 1.9.27 contains a cross-site scripting vulnerability. The check_privacy_settings AJAX action, available to both unauthenticated and authenticated users, responds with JSON data without an."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0220"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0220, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0220.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=check_privacy_settings" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0234_woocs {
    meta:
        attack_type = "cve_2022_0234"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WOOCS < 1.3.7.5 - Cross-Site Scripting: WordPress WOOCS plugin before 1.3.7.5 is susceptible to cross-site scripting. The plugin does not sanitize and escape the woocs_in_order_currency parameter of the woocs_get_products_price_html AJAX action, available to both."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0234"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0234, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0234.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=woocs_get_products_price_html" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0250_redirection_for_contact_form_7 {
    meta:
        attack_type = "cve_2022_0250"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Redirection for Contact Form 7 < 2.5.0 - Cross-Site Scripting: The Redirection for Contact Form 7 WordPress plugin before 2.5.0 does not escape a link generated before outputting it in an attribute, leading to a Reflected Cross-Site Scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0250"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0250, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0250.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=Accessibility" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0271_learnpress {
    meta:
        attack_type = "cve_2022_0271"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LearnPress <4.1.6 - Cross-Site Scripting: WordPress LearnPress plugin before 4.1.6 contains a cross-site scripting vulnerability. It does not sanitize and escape the lp-dismiss-notice before outputting it back via the lp_background_single_email AJAX action."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0271"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0271, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0271.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=lp_background_single_email" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0281_microweber {
    meta:
        attack_type = "cve_2022_0281"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Microweber Information Disclosure: Microweber contains a vulnerability that allows exposure of sensitive information to an unauthorized actor in Packagist microweber/microweber prior to 1.2.11."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0281"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0281, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0281.yaml"
    strings:
        $path0 = "/api/users/search_authors" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_0342_usg40_firmware {
    meta:
        attack_type = "cve_2022_0342"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Zyxel - Authentication Bypass: An authentication bypass vulnerability in the CGI program of Zyxel USG/ZyWALL series firmware versions 4.20 through 4.70, USG FLEX series firmware versions 4.50 through 5.20, ATP series firmware versions 4.32 through 5.20, VPN series firmware."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0342"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0342, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0342.yaml"
    strings:
        $param0 = "category=config" ascii nocase
        $param1 = "arg0=startup-config.conf" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0349_notificationx {
    meta:
        attack_type = "cve_2022_0349"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress NotificationX <2.3.9 - SQL Injection: WordPress NotificationX plugin prior to 2.3.9 contains a SQL injection vulnerability. The plugin does not sanitize and escape the nx_id parameter before using it in a SQL statement, leading to an unauthenticated blind SQL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0349"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0349, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0349.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "nx_id=sleep(6) -- x" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0381_embed_swagger {
    meta:
        attack_type = "cve_2022_0381"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Embed Swagger <=1.0.0 - Cross-Site Scripting: WordPress Embed Swagger plugin 1.0.0 and prior contains a reflected cross-site scripting vulnerability due to insufficient escaping/sanitization and validation via the url parameter found in the ~/swagger-iframe.php file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0381"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0381, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0381.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/embed-swagger/swagger-iframe.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_0415_gogs {
    meta:
        attack_type = "cve_2022_0415"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Gogs <0.12.6 - Remote Command Execution: Gogs before 0.12.6 is susceptible to remote command execution via the uploading repository file in GitHub repository gogs/gogs. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0415"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0415, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0415.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/_upload/master/" ascii nocase
        $param0 = "url=git@github.com:torvalds/linux.git" ascii nocase
        $param1 = "remote=origin" ascii nocase
        $param2 = "merge=refs/heads/master" ascii nocase
        $param3 = "tree_path=/.git/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0422_white_label_cms {
    meta:
        attack_type = "cve_2022_0422"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress White Label CMS <2.2.9 - Cross-Site Scripting: WordPress White Label CMS plugin before 2.2.9 contains a reflected cross-site scripting vulnerability. It does not sanitize and validate the wlcms[_login_custom_js] parameter before outputting it back in the response."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0422"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0422, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0422.yaml"
        response_type = "xss"
    strings:
        $param0 = "wlcms-action=preview" ascii nocase
        $param1 = "wlcms[_login_custom_js]=alert(/XSS/);" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0424_popup {
    meta:
        attack_type = "cve_2022_0424"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Popup by Supsystic < 1.10.9 - Subscriber Email Addresses Disclosure: The Popup by Supsystic WordPress plugin before 1.10.9 does not have any authentication and authorisation in an AJAX action, allowing unauthenticated attackers to call it and get the email addresses of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0424"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0424, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0424.yaml"
    strings:
        $param0 = "page=subscribe" ascii nocase
        $param1 = "action=getListForTbl" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0429_wp_cerber_security_anti_spam_m {
    meta:
        attack_type = "cve_2022_0429"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP Cerber Security, Anti-spam & Malware Scan < 8.9.6 - Cross-Site Scripting: The WP Cerber Security, Anti-spam & Malware Scan WordPress plugin before 8.9.6 does not sanitise the $url variable before using it in an attribute in the Activity tab in the plugins dashboard, leading."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0429"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0429, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0429.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=cerber-security" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0434_page_view_count {
    meta:
        attack_type = "cve_2022_0434"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Page Views Count <2.4.15 - SQL Injection: WordPress Page Views Count plugin prior to 2.4.15 contains an unauthenticated SQL injection vulnerability. It does not sanitise and escape the post_ids parameter before using it in a SQL statement via a REST endpoint. An."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0434"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0434, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0434.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "rest_route=/pvc/v1/increase/1" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0479_popup_builder {
    meta:
        attack_type = "cve_2022_0479"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Popup Builder Plugin - SQL Injection and Cross-Site Scripting: The Popup Builder WordPress plugin before 4.1.1 is vulnerable to SQL Injection and Reflected XSS via the sgpb-subscription-popup-id parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0479"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0479, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0479.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "post_type=popupbuilder" ascii nocase
        $param1 = "page=sgpbSubscribers" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0482_easyappointments {
    meta:
        attack_type = "cve_2022_0482"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Easy!Appointments <1.4.3 - Broken Access Control: Easy!Appointments prior to 1.4.3 allows exposure of Private Personal Information to an unauthorized actor via the GitHub repository alextselegidis/easyappointments."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0482"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0482, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0482.yaml"
    strings:
        $path0 = "/index.php/backend_api/ajax_get_calendar_events" ascii nocase
        $param0 = "startDate=2022-01-01" ascii nocase
        $param1 = "endDate=2022-01-01" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0535_e2pdf {
    meta:
        attack_type = "cve_2022_0535"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress E2Pdf <1.16.45 - Cross-Site Scripting: WordPress E2Pdf plugin before 1.16.45 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape some of its settings, even when the unfiltered_html capability is disallowed. An attacker can inject."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0535"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0535, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0535.yaml"
        response_type = "xss"
    strings:
        $param0 = "e2pdf_api=api.e2pdf.com" ascii nocase
        $param1 = "e2pdf_url_format=siteurl" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0540_jira_data_center {
    meta:
        attack_type = "cve_2022_0540"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Atlassian Jira Seraph - Authentication Bypass: Jira Seraph allows a remote, unauthenticated attacker to bypass authentication by sending a specially crafted HTTP request. This affects Atlassian Jira Server and Data Center versions before 8.13.18, versions 8.14.0 and later."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0540"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0540, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0540.yaml"
    strings:
        $path0 = "/InsightPluginShowGeneralConfiguration.jspa;" ascii nocase
        $path1 = "/secure/WBSGanttManageScheduleJobAction.jspa;" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_0592_mapsvg {
    meta:
        attack_type = "cve_2022_0592"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MapSVG < 6.2.20 - Unauthenticated SQLi: The MapSVG WordPress plugin before 6.2.20 does not validate and escape a parameter via a REST endpoint before using it in a SQL statement, leading to a SQL Injection exploitable by unauthenticated users."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0592"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0592, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0592.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/wp-json/mapsvg/v1/maps/2" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_0594_shareaholic {
    meta:
        attack_type = "cve_2022_0594"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Shareaholic <9.7.6 - Information Disclosure: WordPress Shareaholic plugin prior to 9.7.6 is susceptible to information disclosure. The plugin does not have proper authorization check in one of the AJAX actions, available to both unauthenticated (before 9.7.5) and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0594"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0594, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0594.yaml"
    strings:
        $param0 = "action=shareaholic_debug_info" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0653_profile_builder {
    meta:
        attack_type = "cve_2022_0653"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Wordpress Profile Builder Plugin Cross-Site Scripting: The Profile Builder User Profile & User Registration Forms WordPress plugin is vulnerable to cross-site scripting due to insufficient escaping and sanitization of the site_url parameter found in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0653"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0653, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0653.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/profile-builder/assets/misc/fallback-page.php" ascii nocase
        $param0 = "site_url=javascript:alert(document.domain);" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0656_web_to_print_shop {
    meta:
        attack_type = "cve_2022_0656"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "uDraw <3.3.3 - Local File Inclusion: uDraw before 3.3.3 does not validate the url parameter in its udraw_convert_url_to_base64 AJAX action (available to both unauthenticated and authenticated users) before using it in the file_get_contents function and returning its content."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0656"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0656, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0656.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "action=udraw_convert_url_to_base64" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0658_commonsbooking {
    meta:
        attack_type = "cve_2022_0658"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CommonsBooking < 2.6.8 - SQL Injection: The plugin does not sanitise and escape the location parameter of the calendar_data AJAX action (available to unauthenticated users) before it is used in dynamically constructed SQL queries, leading to an unauthenticated SQL injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0658"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0658, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0658.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=calendar_data" ascii nocase
        $param1 = "location=(SELECT 1743 FROM (SELECT(SLEEP(6)))iXxL3)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0660_microweber {
    meta:
        attack_type = "cve_2022_0660"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Microweber <1.2.11 - Information Disclosure: Microweber before 1.2.11 is susceptible to information disclosure. An error message is generated in microweber/microweber which contains sensitive information while viewing comments from load_module:comments#search=. An attacker can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0660"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0660, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0660.yaml"
    strings:
        $param0 = "id=mw_admin_posts_with_comments" ascii nocase
        $param1 = "data-type=comments/manage" ascii nocase
        $param2 = "parent-module-id=mw-main-module-backend" ascii nocase
        $param3 = "parent-module=comments" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0679_narnoo_distributor {
    meta:
        attack_type = "cve_2022_0679"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Narnoo Distributor <=2.5.1 - Local File Inclusion: WordPress Narnoo Distributor plugin 2.5.1 and prior is susceptible to local file inclusion. The plugin does not validate and sanitize the lib_path parameter before being passed into a call to require() via the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0679"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0679, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0679.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "action=narnoo_distributor_lib_request" ascii nocase
        $param1 = "lib_path=/etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0747_infographic_maker {
    meta:
        attack_type = "cve_2022_0747"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Infographic Maker iList < 4.3.8 - SQL Injection: The Infographic Maker WordPress plugin before 4.3.8 does not validate and escape the post_id parameter before using it in a SQL statement via the qcld_upvote_action AJAX action (available to unauthenticated and authenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0747"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0747, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0747.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "post_id=1 AND (SELECT 1626 FROM (SELECT(SLEEP(6)))niPH)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0760_simple_link_directory {
    meta:
        attack_type = "cve_2022_0760"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Simple Link Directory <7.7.2 - SQL injection: WordPress Simple Link Directory plugin before 7.7.2 contains a SQL injection vulnerability. The plugin does not validate and escape the post_id parameter before using it in a SQL statement via the qcopd_upvote_action AJAX."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0760"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0760, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0760.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "post_id=(SELECT 3 FROM (SELECT SLEEP(7))enz)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0765_wordpress_loco_translate_2_6_1 {
    meta:
        attack_type = "cve_2022_0765"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Loco Translate < 2.6.1 - Cross-Site Scripting: Loco Translate WordPress plugin before 2.6.1 contains a stored cross-site scripting vulnerability caused by improper removal of inline events from source translation strings, allowing authenticated users to inject."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0765"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0765, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0765.yaml"
        response_type = "xss"
    strings:
        $param0 = "path=plugins/loco-translate/languages/loco-translate.pot" ascii nocase
        $param1 = "bundle=loco-translate/loco.php" ascii nocase
        $param2 = "domain=loco-translate" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0773_documentor {
    meta:
        attack_type = "cve_2022_0773"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Documentor <= 1.5.3 - Unauthenticated SQL Injection: The Documentor WordPress plugin through 1.5.3 fails to sanitize and escape user input before it is being interpolated in an SQL statement and then executed, leading to an SQL Injection exploitable by unauthenticated users."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0773"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0773, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0773.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=doc_search_results" ascii nocase
        $param1 = "docid=1 AND (SELECT 6288 FROM (SELECT(SLEEP(6)))HRaz)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0781_nirweb_support {
    meta:
        attack_type = "cve_2022_0781"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Nirweb Support <2.8.2 - SQL Injection: WordPress Nirweb support plugin before 2.8.2 contains a SQL injection vulnerability. The plugin does not sanitize and escape a parameter before using it in a SQL statement via an AJAX action. An attacker can possibly obtain."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0781"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0781, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0781.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=answerd_ticket" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0783_multiple_shipping_addresses_fo {
    meta:
        attack_type = "cve_2022_0783"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Multiple Shipping Address Woocommerce < 2.0 - SQL Injection: The Multiple Shipping Address Woocommerce plugin before 2.0 does not properly sanitize and escape numerous parameters before using them in SQL statements via some AJAX actions available to unauthenticated users."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0783"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0783, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0783.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=ocwma_choice_address" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0787_limit_login_attempts {
    meta:
        attack_type = "cve_2022_0787"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Limit Login Attempts (Spam Protection) < 5.1 - SQL Injection: The Limit Login Attempts (Spam Protection) WordPress plugin before 5.1 does not sanitise and escape some parameters before using them in SQL statements via AJAX actions (available to unauthenticated users), leading."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0787"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0787, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0787.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "columns[][data]=(SELECT 7382 FROM (SELECT(SLEEP(6)))ameU)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0814_ubigeo_de_peru_para_woocommerc {
    meta:
        attack_type = "cve_2022_0814"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ubigeo de Peru < 3.6.4 - SQL Injection: The plugin does not properly sanitise and escape some parameters before using them in SQL statements via various AJAX actions, some of which are available to unauthenticated users, leading to SQL Injections."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0814"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0814, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0814.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=rt_ubigeo_load_distritos_address" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0817_badgeos {
    meta:
        attack_type = "cve_2022_0817"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress BadgeOS <=3.7.0 - SQL Injection: WordPress BadgeOS plugin through 3.7.0 contains a SQL injection vulnerability. It does not sanitize and escape a parameter before using it in a SQL statement via an AJAX action. An attacker can possibly obtain sensitive information."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0817"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0817, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0817.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=get-achievements" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0824_webmin {
    meta:
        attack_type = "cve_2022_0824"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Webmin <1.990 - Improper Access Control: Webmin before 1.990 is susceptible to improper access control in GitHub repository webmin/webmin. This in turn can lead to remote code execution, by which an attacker can execute malware, obtain sensitive information, modify data, and/or."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0824"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0824, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0824.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/extensions/file-manager/http_download.cgi" ascii nocase
        $param0 = "module=filemin" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0826_wp_video_gallery_free {
    meta:
        attack_type = "cve_2022_0826"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress WP Video Gallery <=1.7.1 - SQL Injection: WordPress WP Video Gallery plugin through 1.7.1 contains a SQL injection vulnerability. The plugin does not sanitise and escape a parameter before using it in a SQL statement via an AJAX action. An attacker can possibly obtain."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0826"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0826, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0826.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=wp_video_gallery_ajax_add_single_youtube" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0827_bestbooks {
    meta:
        attack_type = "cve_2022_0827"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Best Books <=2.6.3 - SQL Injection: WordPress Best Books plugin through 2.6.3 is susceptible to SQL injection. The plugin does not sanitize and escape some parameters before using them in a SQL statement via an AJAX action. An attacker can possibly obtain sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0827"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0827, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0827.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=bestbooks_add_transaction" ascii nocase
        $param1 = "debit=(CASE WHEN (9277=9277) THEN SLEEP(6) ELSE 9277 END)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0846_speakout_email_petitions {
    meta:
        attack_type = "cve_2022_0846"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SpeakOut Email Petitions < 2.14.15.1 - SQL Injection: The SpeakOut! Email Petitions WordPress plugin before 2.14.15.1 does not sanitise and escape the id parameter before using it in a SQL statement via the dk_speakout_sendmail AJAX action, leading to an SQL Injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0846"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0846, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0846.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=dk_speakout_sendmail" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0864_updraftplus {
    meta:
        attack_type = "cve_2022_0864"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "UpdraftPlus < 1.22.9 - Cross-Site Scripting: The plugin does not sanitise and escape the updraft_interval parameter before outputting it back in an admin page, leading to a Reflected Cross-Site Scripting (XSS) vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0864"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0864, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0864.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=updraftplus" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0867_pricing_table {
    meta:
        attack_type = "cve_2022_0867"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress ARPrice <3.6.1 - SQL Injection: WordPress ARPrice plugin prior to 3.6.1 contains a SQL injection vulnerability. It fails to properly sanitize and escape user supplied POST data before being inserted in an SQL statement and executed via an AJAX action. An attacker can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0867"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0867, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0867.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=arplite_insert_plan_id" ascii nocase
        $param1 = "arp_template_id=1 AND (SELECT 8948 FROM (SELECT(SLEEP(6)))iIic)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0869_spirit {
    meta:
        attack_type = "cve_2022_0869"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "nitely/spirit 0.12.3 - Open Redirect: Multiple Open Redirect in GitHub repository nitely/spirit prior to 0.12.3."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0869"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0869, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0869.yaml"
    strings:
        $path0 = "/user/resend-activation" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_0870_gogs {
    meta:
        attack_type = "cve_2022_0870"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Gogs <0.12.5 - Server-Side Request Forgery: Gogs GitHub repository before 0.12.5 is susceptible to server-side request forgery. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0870"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0870, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0870.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/repo/migrate" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_0873_gmedia_gallery {
    meta:
        attack_type = "cve_2022_0873"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Gmedia Photo Gallery Plugin < 1.20.0 - Cross-Site Scripting: The Gmedia Photo Gallery WordPress plugin before 1.20.0 does not sanitise and escape the album's name before outputting it in pages or posts with a media embed, which could allow high privilege users such as."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0873"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0873, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0873.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=GrandMedia_Albums" ascii nocase
        $param1 = "term[status]=publish" ascii nocase
        $param2 = "term[taxonomy]=gmedia_album" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0885_member_hero {
    meta:
        attack_type = "cve_2022_0885"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Member Hero <=1.0.9 - Remote Code Execution: WordPress Member Hero plugin through 1.0.9 is susceptible to remote code execution. The plugin lacks authorization checks and does not validate the a request parameter in an AJAX action, allowing an attacker to call arbitrary PHP."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0885"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0885, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0885.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "action=memberhero_send_form" ascii nocase
        $param1 = "_memberhero_hook=phpinfo" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0928_microweber {
    meta:
        attack_type = "cve_2022_0928"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microweber < 1.2.12 - Stored Cross-Site Scripting: Microweber prior to 1.2.12 contains a stored cross-site scripting vulnerability via the Type parameter in the body of POST request, which is triggered by Add/Edit Tax."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0928"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0928, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0928.yaml"
        response_type = "xss"
    strings:
        $param0 = "parent-module-id=settings-admin-mw-main-module-backend-shop-taxes-admin" ascii nocase
        $param1 = "parent-module=shop/taxes/admin" ascii nocase
        $param2 = "data-type=shop/taxes/admin_list_taxes" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0949_block_and_stop_bad_bots {
    meta:
        attack_type = "cve_2022_0949"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Stop Bad Bots <6.930 - SQL Injection: WordPress Stop Bad Bots plugin before 6.930 contains a SQL injection vulnerability. The plugin does not properly sanitise and escape the fingerprint parameter before using it in a SQL statement via the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0949"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0949, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0949.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=stopbadbots_grava_fingerprint" ascii nocase
        $param1 = "fingerprint=(SELECT SLEEP(6))" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0952_sitemap {
    meta:
        attack_type = "cve_2022_0952"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Sitemap by click5 <1.0.36 - Missing Authorization: WordPress Sitemap by click5 plugin before 1.0.36 is susceptible to missing authorization. The plugin does not have authorization or CSRF checks when updating options via a REST endpoint and does not ensure that the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0952"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0952, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0952.yaml"
    strings:
        $path0 = "/wp-json/click5_sitemap/API/update_html_option_AJAX" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_0954_microweber {
    meta:
        attack_type = "cve_2022_0954"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microweber <1.2.11 - Stored Cross-Site Scripting: Microweber before 1.2.1 contains multiple stored cross-site scripting vulnerabilities in Shop's Other Settings, Autorespond E-mail Settings, and Payment Methods."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0954"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0954, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0954.yaml"
        response_type = "xss"
    strings:
        $path0 = "/api/save_option" ascii nocase
        $param0 = "option_key=checkout_url" ascii nocase
        $param1 = "option_group=shop" ascii nocase
        $param2 = "id=settings_admin_mw-main-module-backend-settings-admin" ascii nocase
        $param3 = "class=card-body pt-3" ascii nocase
        $param4 = "option_group=shop/orders/settings/other" ascii nocase
        $param5 = "style=position: relative;" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_0963_microweber {
    meta:
        attack_type = "cve_2022_0963"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microweber <1.2.12 - Stored Cross-Site Scripting: Microweber prior to 1.2.12 contains a stored cross-site scripting vulnerability. It allows unrestricted upload of XML files,."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0963"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0963, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0963.yaml"
        response_type = "xss"
    strings:
        $path0 = "/userfiles/media/default/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_0968_microweber {
    meta:
        attack_type = "cve_2022_0968"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microweber <1.2.12 - Integer Overflow: Microweber before 1.2.12 is susceptible to integer overflow. The application allows large characters to insert in the input field 'first & last name,' which can allow an attacker to cause a denial of service via a crafted HTTP request."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-0968"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-0968, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-0968.yaml"
    strings:
        $param0 = "_method=PATCH" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1007_advanced_booking_calendar {
    meta:
        attack_type = "cve_2022_1007"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Advanced Booking Calendar <1.7.1 - Cross-Site Scripting: WordPress Advanced Booking Calendar plugin before 1.7.1 contains a cross-site scripting vulnerability. It does not sanitize and escape the room parameter before outputting it back in an admin page. An attacker."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1007"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1007, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1007.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=advanced-booking-calendar-show-seasons-calendars" ascii nocase
        $param1 = "setting=changeSaved" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1013_personal_dictionary {
    meta:
        attack_type = "cve_2022_1013"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Personal Dictionary <1.3.4 - Blind SQL Injection: WordPress Personal Dictionary plugin before 1.3.4 contains a blind SQL injection vulnerability. The plugin fails to properly sanitize user-supplied POST data before being interpolated in an SQL statement and executed.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1013"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1013, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1013.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "groupsIds[]=1) AND (SELECT 3066 FROM (SELECT(SLEEP(7)))CEHy)-- -" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1020_woo_product_table {
    meta:
        attack_type = "cve_2022_1020"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress WooCommerce <3.1.2 - Arbitrary Function Call: WordPress WooCommerce plugin before 3.1.2 does not have authorisation and CSRF checks in the wpt_admin_update_notice_option AJAX action (available to both unauthenticated and authenticated users), as well as does not."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1020"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1020, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1020.yaml"
    strings:
        $param0 = "perpose=update" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1026_net_viewer {
    meta:
        attack_type = "cve_2022_1026"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kyocera Net View Address Book Exposure: Kyocera multifunction printers running vulnerable versions of Net View unintentionally expose sensitive user information, including usernames and passwords, through an insufficiently protected address book export function."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1026"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1026, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1026.yaml"
    strings:
        $path0 = "/ws/km-wsdl/setting/address_book" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_1029_limit_login_attempts {
    meta:
        attack_type = "cve_2022_1029"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Limit Login Attempts - Stored Cross-Site Scripting: Limit Login Attempts WordPress plugin < 4.0.72 contains a stored cross-site scripting caused by unsanitized and unescaped settings, letting malicious administrators inject Javascript code, exploit requires administrator."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1029"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1029, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1029.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=advancedblocking" ascii nocase
        $param1 = "option=mo_wpns_block_referrer" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1119_simple_file_list {
    meta:
        attack_type = "cve_2022_1119"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Simple File List <3.2.8 - Local File Inclusion: WordPress Simple File List before 3.2.8 is vulnerable to local file inclusion via the eeFile parameter in the ~/includes/ee-downloader.php due to missing controls which make it possible for unauthenticated attackers."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1119"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1119, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1119.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/simple-file-list/includes/ee-downloader.php" ascii nocase
        $param0 = "eeFile=../../../../wp-config.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1168_jobsearch_wp_job_board {
    meta:
        attack_type = "cve_2022_1168"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WP JobSearch <1.5.1 - Cross-Site Scripting: WordPress WP JobSearch plugin prior to 1.5.1 contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1168"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1168, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1168.yaml"
        response_type = "xss"
    strings:
        $path0 = "/plugins/jobsearch/" ascii nocase
        $param0 = "sort-by=recent" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1221_gwyn_s_imagemap_selector {
    meta:
        attack_type = "cve_2022_1221"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Gwyn's Imagemap Selector <=0.3.3 - Cross-Site Scripting: Wordpress Gwyn's Imagemap Selector plugin 0.3.3 and prior contains a reflected cross-site scripting vulnerability. It does not sanitize the id and class parameters before returning them back in attributes."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1221"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1221, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1221.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/gwyns-imagemap-selector/popup.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_1386_fusion_builder {
    meta:
        attack_type = "cve_2022_1386"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Fusion Builder <3.6.2 - Server-Side Request Forgery: WordPress Fusion Builder plugin before 3.6.2 is susceptible to server-side request forgery. The plugin does not validate a parameter in its forms, which can be used to initiate arbitrary HTTP requests. The data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1386"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1386, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1386.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = "cy_expiration_action=ignore" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1390_admin_word_count_column {
    meta:
        attack_type = "cve_2022_1390"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Admin Word Count Column 2.2 - Local File Inclusion: The plugin does not validate the path parameter given to readfile(), which could allow unauthenticated attackers to read arbitrary files on server running old version of PHP susceptible to the null byte technique.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1390"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1390, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1390.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/admin-word-count-column/download-csv.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_1391_cab_fare_calculator {
    meta:
        attack_type = "cve_2022_1391"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Cab fare calculator < 1.0.4 - Local File Inclusion: The Cab fare calculator WordPress plugin before 1.0.4 does not validate the controller parameter before using it in require statements, which could lead to Local File Inclusion issues."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1391"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1391, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1391.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/cab-fare-calculator/tblight.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_1392_videos_sync_pdf {
    meta:
        attack_type = "cve_2022_1392"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Videos sync PDF <=1.7.4 - Local File Inclusion: WordPress Videos sync PDF 1.7.4 and prior does not validate the p parameter before using it in an include statement, which could lead to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1392"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1392, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1392.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/video-synchro-pdf/reglages/Menu_Plugins/tout.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_1398_external_media_without_import {
    meta:
        attack_type = "cve_2022_1398"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "External Media without Import <=1.1.2 - Authenticated Blind Server-Side Request Forgery: WordPress External Media without Import plugin through 1.1.2 is susceptible to authenticated blind server-side request forgery. The plugin has no authorization and does not ensure that."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1398"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1398, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1398.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = "action=add_external_media_without_import" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1442_metform_elementor_contact_form {
    meta:
        attack_type = "cve_2022_1442"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Metform <=2.1.3 - Information Disclosure: WordPress Metform plugin through 2.1.3 is susceptible to information disclosure due to improper access control in the ~/core/forms/action.php file. An attacker can view all API keys and secrets of integrated third-party APIs."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1442"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1442, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1442.yaml"
    strings:
        $path0 = "/wp-json/metform/v1/forms/templates/0" ascii nocase
        $path1 = "/wp-json/metform/v1/forms/get/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_1574_html2wp {
    meta:
        attack_type = "cve_2022_1574"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress HTML2WP <=1.0.0 - Arbitrary File Upload: WordPress HTML2WP plugin through 1.0.0 contains an arbitrary file upload vulnerability. The plugin does not perform authorization and CSRF checks when importing files and does not validate them. As a result, an attacker can."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1574"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1574, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1574.yaml"
    strings:
        $path0 = "/wp-content/uploads/html2wp/" ascii nocase
        $param0 = "page=html2wp-settings" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1597_wpqa_builder {
    meta:
        attack_type = "cve_2022_1597"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WPQA <5.4 - Cross-Site Scripting: WordPress WPQA plugin prior to 5.4 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape a parameter on its reset password form."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1597"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1597, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1597.yaml"
        response_type = "xss"
    strings:
        $param0 = "form_type=wpqa-signup" ascii nocase
        $param1 = "action=wpqa_ajax_signup_process" ascii nocase
        $param2 = "form_type=wpqa_forget" ascii nocase
        $param3 = "action=wpqa_ajax_password_process" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1598_wpqa_builder {
    meta:
        attack_type = "cve_2022_1598"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WPQA <5.5 - Improper Access Control: WordPress WPQA plugin before 5.5 is susceptible to improper access control. The plugin lacks authentication in a REST API endpoint. An attacker can potentially discover private questions sent between users on the site."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1598"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1598, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1598.yaml"
    strings:
        $path0 = "/wp-json/wp/v2/asked-question" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_1609_school_management {
    meta:
        attack_type = "cve_2022_1609"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "The School Management < 9.9.7 - Remote Code Execution: The School Management plugin before version 9.9.7 contains an obfuscated backdoor injected in it's license checking code that registers a REST API handler, allowing an unauthenticated attacker to execute arbitrary PHP code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1609"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1609, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1609.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-json/am-member/license" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_1692_cp_image_store_with_slideshow {
    meta:
        attack_type = "cve_2022_1692"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CP Image Store with Slideshow <= 1.0.67 - SQL Injection: The CP Image Store with Slideshow WordPress plugin before 1.0.68 does not sanitise and escape the ordering_by query parameter before using it in a SQL statement in pages where the [codepeople-image-store] is embed."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1692"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1692, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1692.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "s=codepeople-image-store" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1724_simple_membership {
    meta:
        attack_type = "cve_2022_1724"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Simple Membership <4.1.1 - Cross-Site Scripting: WordPress Simple Membership plugin before 4.1.1 contains a reflected cross-site scripting vulnerability. It does not properly sanitize and escape parameters before outputting them back in AJAX actions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1724"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1724, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1724.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=swpm_validate_email" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1756_newsletter {
    meta:
        attack_type = "cve_2022_1756"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Newsletter < 7.4.5 - Cross-Site Scripting: The Newsletter WordPress plugin before 7.4.5 does not sanitize and escape the $_SERVER['REQUEST_URI'] before echoing it back in admin pages. Although this uses addslashes, and most modern browsers automatically URLEncode requests, this."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1756"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1756, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1756.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=newsletter_main_index" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1768_rsvpmaker {
    meta:
        attack_type = "cve_2022_1768"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress RSVPMaker <=9.3.2 - SQL Injection: WordPress RSVPMaker plugin through 9.3.2 contains a SQL injection vulnerability due to insufficient escaping and parameterization on user-supplied data passed to multiple SQL queries in ~/rsvpmaker-email.php. An attacker can possibly."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1768"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1768, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1768.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "rsvp_id=(select(0)from(select(sleep(7)))a)" ascii nocase
        $param1 = "email=randomtext" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1903_armember {
    meta:
        attack_type = "cve_2022_1903"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ARMember < 3.4.8 - Unauthenticated Admin Account Takeover: The ARMember WordPress plugin before 3.4.8 is vulnerable to account takeover (even the administrator) due to missing nonce and authorization checks in an AJAX action available to unauthenticated users, allowing them to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1903"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1903, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1903.yaml"
    strings:
        $param0 = "action=arm_shortcode_form_ajax_action" ascii nocase
        $param1 = "arm_action=change-password" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1904_easy_pricing_tables {
    meta:
        attack_type = "cve_2022_1904"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Easy Pricing Tables <3.2.1 - Cross-Site Scripting: WordPress Easy Pricing Tables plugin before 3.2.1 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape a parameter before reflecting it back in a page available to any user both."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1904"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1904, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1904.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=ptp_design4_color_columns" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1910_shortcodes_and_extra_features {
    meta:
        attack_type = "cve_2022_1910"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Shortcodes and Extra Features for Phlox <2.9.8 - Cross-Site Scripting: WordPress Shortcodes and extra features plugin for the Phlox theme before 2.9.8 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape a parameter before outputting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1910"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1910, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1910.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=aux_the_recent_products" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1933_collect_and_deliver_interface {
    meta:
        attack_type = "cve_2022_1933"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress CDI <5.1.9 - Cross Site Scripting: WordPress CDI plugin prior to 5.1.9 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape a parameter before outputting it back in the response of an AJAX action. An attacker can inject arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1933"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1933, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1933.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=cdi_collect_follow" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1937_awin_data_feed {
    meta:
        attack_type = "cve_2022_1937"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Awin Data Feed <=1.6 - Cross-Site Scripting: WordPress Awin Data Feed plugin 1.6 and prior contains a cross-site scripting vulnerability. It does not sanitize and escape a parameter before outputting it back via an AJAX action, available to both unauthenticated and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1937"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1937, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1937.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=get_sw_product" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1950_youzify {
    meta:
        attack_type = "cve_2022_1950"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Youzify < 1.2.0 - Unauthenticated SQLi: The Youzify WordPress plugin before 1.2.0 does not sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to an unauthenticated SQL injection"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1950"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1950, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1950.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=youzify_media_pagination" ascii nocase
        $param1 = "data[type]=photos" ascii nocase
        $param2 = "data[group_id]=(SELECT 7958 FROM (SELECT(SLEEP(6)))XVfJ)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_1952_free_booking_plugin_for_hotels {
    meta:
        attack_type = "cve_2022_1952"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress eaSYNC Booking <1.1.16 - Arbitrary File Upload: WordPress eaSync Booking plugin bundle for hotel, restaurant and car rental before 1.1.16 is susceptible to arbitrary file upload. The plugin contains insufficient input validation of an AJAX action. An allowlist of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-1952"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-1952, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-1952.yaml"
    strings:
        $param0 = "action=easync_success_and_save" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2034_sensei_lms {
    meta:
        attack_type = "cve_2022_2034"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Sensei LMS <4.5.0 - Information Disclosure: WordPress Sensei LMS plugin before 4.5.0 is susceptible to information disclosure. The plugin does not have proper permissions set in a REST endpoint, which can allow an attacker to access private messages."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2034"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2034, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2034.yaml"
    strings:
        $path0 = "/wp-json/wp/v2/sensei-messages/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_2130_microweber {
    meta:
        attack_type = "cve_2022_2130"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microweber < 1.2.17 - Cross-Site Scripting: Cross-site Scripting (XSS) vulnerability in the /demo/editor_tools/module endpoint via the 'type' parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2130"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2130, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2130.yaml"
        response_type = "xss"
    strings:
        $path0 = "/editor_tools/module" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_21500_e_business_suite {
    meta:
        attack_type = "cve_2022_21500"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Oracle E-Business Suite <=12.2 - Authentication Bypass: Oracle E-Business Suite (component: Manage Proxies) 12.1 and 12.2 are susceptible to an easily exploitable vulnerability that allows an unauthenticated attacker with network access via HTTP to compromise it by."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-21500"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-21500, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-21500.yaml"
    strings:
        $path0 = "/OA_HTML/ibeCAcpSSOReg.jsp" ascii nocase
        $path1 = "/OA_HTML/ibeCRgpPrimaryCreate.jsp" ascii nocase
        $path2 = "/OA_HTML/ibeCRgpIndividualUser.jsp" ascii nocase
        $path3 = "/OA_HTML/ibeCRgpPartnerPriCreate.jsp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_21661_wordpress {
    meta:
        attack_type = "cve_2022_21661"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress <5.8.3 - SQL Injection: WordPress before 5.8.3 is susceptible to SQL injection through multiple plugins or themes due to improper sanitization in WP_Query, An attacker can potentially obtain sensitive information, modify data, and/or execute unauthorized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-21661"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-21661, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-21661.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=ecsload" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2168_download_manager {
    meta:
        attack_type = "cve_2022_2168"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Download Manager < 3.2.44 - Authenticated Cross-Site Scripting: The WordPress Download Manager plugin before version 3.2.44 does not properly sanitize and escape the user_ids parameter in the stats history dashboard. This allows authenticated attackers to perform."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2168"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2168, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2168.yaml"
        response_type = "xss"
    strings:
        $param0 = "post_type=wpdmpro" ascii nocase
        $param1 = "type=history" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_21705_october {
    meta:
        attack_type = "cve_2022_21705"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "October CMS - Remote Code Execution: October CMS is susceptible to remote code execution. In affected versions, user input is not properly sanitized before rendering. An authenticated user with the permissions to create, modify, and delete website pages can bypass cms.safe_mode."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-21705"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-21705, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-21705.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/backend/cms" ascii nocase
        $param0 = "templateType=page" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2219_unyson {
    meta:
        attack_type = "cve_2022_2219"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Unyson < 2.7.27 - Cross Site Scripting: The plugin does not sanitise and escape the QUERY_STRING before outputting it back in an admin page, leading to a Reflected Cross-Site Scripting in browsers which do not encode characters"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2219"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2219, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2219.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=fw-extensions" ascii nocase
        $param1 = "sub-page=extension" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_22956_identity_manager {
    meta:
        attack_type = "cve_2022_22956"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "VMware Workspace ONE Access - Authentication Bypass: VMware Workspace ONE Access has two authentication bypass vulnerabilities (CVE-2022-22955 & CVE-2022-22956) in the OAuth2 ACS framework. A malicious actor may bypass the authentication mechanism and execute any operation due."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-22956"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-22956, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-22956.yaml"
    strings:
        $path0 = "/SAAS/API/1.0/REST/oauth2/generateActivationToken/Service__OAuth2Client" ascii nocase
        $path1 = "/SAAS/API/1.0/REST/oauth2/activate" ascii nocase
        $path2 = "/SAAS/auth/oauthtoken" ascii nocase
        $param0 = "grant_type=client_credentials" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_22972_identity_manager {
    meta:
        attack_type = "cve_2022_22972"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "VMware Workspace ONE Access/Identity Manager/vRealize Automation - Authentication Bypass: VMware Workspace ONE Access, Identity Manager and vRealize Automation contain an authentication bypass vulnerability affecting local domain users. A malicious actor with network access to."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-22972"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-22972, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-22972.yaml"
    strings:
        $path0 = "/SAAS/auth/login/embeddedauthbroker/callback" ascii nocase
        $param0 = "original_uri=/vcac" ascii nocase
        $param1 = "password=horizon" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_23131_zabbix {
    meta:
        attack_type = "cve_2022_23131"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Zabbix - SAML SSO Authentication Bypass: When SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor because a user login stored in the session was not verified."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-23131"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-23131, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-23131.yaml"
    strings:
        $path0 = "/zabbix/index_sso.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_23134_zabbix {
    meta:
        attack_type = "cve_2022_23134"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Zabbix Setup Configuration Authentication Bypass: After the initial setup process, some steps of setup.php file are reachable not only by super-administrators but also by unauthenticated users. A malicious actor can pass step checks and potentially change the configuration of."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-23134"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-23134, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-23134.yaml"
    strings:
        $path0 = "/zabbix/setup.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_2314_vr_calendar {
    meta:
        attack_type = "cve_2022_2314"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress VR Calendar <=2.3.2 - Remote Code Execution: WordPress VR Calendar plugin through 2.3.2 is susceptible to remote code execution. The plugin allows any user to execute arbitrary PHP functions on the site. An attacker can execute malware, obtain sensitive information."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2314"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2314, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2314.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "vrc_cmd=phpinfo" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_23347_bigant_server {
    meta:
        attack_type = "cve_2022_23347"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "BigAnt Server v5.6.06 - Local File Inclusion: BigAnt Server v5.6.06 is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-23347"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-23347, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-23347.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/index.php/Pan/ShareUrl/downloadSharedFile" ascii nocase
        $param0 = "true_path=../../../../../../windows/win.ini" ascii nocase
        $param1 = "file_name=win.ini" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_23348_bigant_server {
    meta:
        attack_type = "cve_2022_23348"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "BigAnt Server 5.6.06 - Improper Access Control: BigAnt Server 5.6.06 is susceptible to improper access control. The software utililizes weak password hashes. An attacker can craft a password hash and thereby possibly possibly obtain sensitive information, modify data, and/or."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-23348"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-23348, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-23348.yaml"
    strings:
        $path0 = "/Runtime/Data/ms_admin.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_23397_ez_net_portal {
    meta:
        attack_type = "cve_2022_23397"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Cedar Gate EZ-NET <= 6.8.0 - Cross-Site Scripting: The Cedar Gate EZ-NET portal 6.5.5 6.8.0 Internet portal has a call to display messages to users which does not properly sanitize data sent in through a URL parameter. This leads to a Reflected Cross-Site Scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-23397"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-23397, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-23397.yaml"
        response_type = "xss"
    strings:
        $path0 = "/EZ-NET60/AlertMessages.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_2376_directorist {
    meta:
        attack_type = "cve_2022_2376"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Directorist <7.3.1 - Information Disclosure: WordPress Directorist plugin before 7.3.1 is susceptible to information disclosure. The plugin discloses the email address of all users in an AJAX action available to both unauthenticated and authenticated users."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2376"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2376, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2376.yaml"
    strings:
        $param0 = "action=directorist_author_pagination" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2379_easy_student_results {
    meta:
        attack_type = "cve_2022_2379"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Easy Student Results <=2.2.8 - Improper Authorization: WordPress Easy Student Results plugin through 2.2.8 is susceptible to information disclosure. The plugin lacks authorization in its REST API, which can allow an attacker to retrieve sensitive information related."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2379"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2379, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2379.yaml"
    strings:
        $path0 = "/wp-json/rps_result/v1/route/student_fields" ascii nocase
        $path1 = "/wp-json/rps_result/v1/route/search_student" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_23808_phpmyadmin {
    meta:
        attack_type = "cve_2022_23808"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "phpMyAdmin < 5.1.2 - Cross-Site Scripting: An issue was discovered in phpMyAdmin 5.1 before 5.1.2 that could allow an attacker to inject malicious code into aspects of the setup script, which can allow cross-site or HTML injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-23808"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-23808, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-23808.yaml"
        response_type = "xss"
    strings:
        $path0 = "/phpmyadmin/setup/index.php" ascii nocase
        $param0 = "page=servers" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2383_feed_them_social {
    meta:
        attack_type = "cve_2022_2383"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Feed Them Social <3.0.1 - Cross-Site Scripting: WordPress Feed Them Social plugin before 3.0.1 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape a parameter before outputting it back in the page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2383"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2383, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2383.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=fts_refresh_token_ajax" ascii nocase
        $param1 = "feed=instagram" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_23854_intouch_access_anywhere {
    meta:
        attack_type = "cve_2022_23854"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AVEVA InTouch Access Anywhere Secure Gateway - Local File Inclusion: AVEVA InTouch Access Anywhere Secure Gateway is vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-23854"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-23854, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-23854.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/AccessAnywhere/%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_24086_commerce {
    meta:
        attack_type = "cve_2022_24086"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Adobe Commerce (Magento) - Remote Code Execution: Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier) are affected by an improper input validation vulnerability during the checkout process. Exploitation of this issue does not require user interaction and."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24086"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24086, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24086.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/checkout/cart/add/uenc/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_24112_apisix {
    meta:
        attack_type = "cve_2022_24112"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Apache APISIX - Remote Code Execution: A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. When the admin key was."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24112"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24112, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24112.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/apisix/batch-requests" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_24124_casdoor {
    meta:
        attack_type = "cve_2022_24124"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Casdoor 1.13.0 - Unauthenticated SQL Injection: Casdoor version 1.13.0 suffers from a remote unauthenticated SQL injection vulnerability via the query API in Casdoor before 1.13.1 related to the field and value parameters, as demonstrated by api/get-organizations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24124"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24124, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24124.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/api/get-organizations" ascii nocase
        $param0 = "field=updatexml(1,version(),1)" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_24129_oidc_op {
    meta:
        attack_type = "cve_2022_24129"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Shibboleth OIDC OP <3.0.4 - Server-Side Request Forgery: The Shibboleth Identity Provider OIDC OP plugin before 3.0.4 is vulnerable to server-side request forgery (SSRF) due to insufficient restriction of the request_uri parameter, which allows attackers to interact with."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24129"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24129, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24129.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/idp/profile/oidc/authorize" ascii nocase
        $param0 = "client_id=demo_rp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2414_dogtagpki {
    meta:
        attack_type = "cve_2022_2414"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "FreeIPA - XML Entity Injection: Access to external entities when parsing XML documents can lead to XML external entity (XXE) attacks. This flaw allows a remote attacker to potentially retrieve the content of arbitrary files by sending specially crafted HTTP requests."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2414"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2414, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2414.yaml"
    strings:
        $path0 = "/ca/rest/certrequests" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_24181_open_journal_systems {
    meta:
        attack_type = "cve_2022_24181"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PKP Open Journal Systems 2.4.8-3.3 - Cross-Site Scripting: PKP Open Journal Systems 2.4.8 to 3.3 contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary code via the X-Forwarded-Host Header."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24181"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24181, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24181.yaml"
        response_type = "xss"
    strings:
        $path0 = "/iupjournals/index.php/esj" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_24260_voipmonitor {
    meta:
        attack_type = "cve_2022_24260"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "VoipMonitor - Pre-Auth SQL Injection: A SQL injection vulnerability in Voipmonitor GUI before v24.96 allows attackers to escalate privileges to the Administrator level."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24260"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24260, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24260.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "module=relogin" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_24264_cuppacms {
    meta:
        attack_type = "cve_2022_24264"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cuppa CMS v1.0 - SQL injection: Cuppa CMS v1.0 was discovered to contain a SQL injection vulnerability in /administrator/components/table_manager/ via the search_word parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24264"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24264, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24264.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "path=component/table_manager/view/cu_countries" ascii nocase
        $param1 = "uniqueClass=wrapper_content_518284" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_24265_cuppacms {
    meta:
        attack_type = "cve_2022_24265"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cuppa CMS v1.0 - SQL injection: Cuppa CMS v1.0 was discovered to contain a SQL injection vulnerability in /administrator/components/menu/ via the path=component/menu/&menu_filter=3 parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24265"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24265, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24265.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "data_get=eyJtZW51X2ZpbHRlciI6IjMifQ==" ascii nocase
        $param1 = "uniqueClass=wrapper_content_906185" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_24266_cuppacms {
    meta:
        attack_type = "cve_2022_24266"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cuppa CMS v1.0 - SQL injection: Cuppa CMS v1.0 was discovered to contain a SQL injection vulnerability in /administrator/components/table_manager/ via the order_by parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24266"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24266, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24266.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "uniqueClass=wrapper_content_919044" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_24288_airflow {
    meta:
        attack_type = "cve_2022_24288"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache Airflow OS Command Injection: Apache Airflow prior to version 2.2.4 is vulnerable to OS command injection attacks because some example DAGs do not properly sanitize user-provided parameters, making them susceptible to OS Command Injection from the web UI."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24288"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24288, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24288.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/admin/airflow/code" ascii nocase
        $param0 = "dag_id=example_passing_params_via_test_command" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2461_transposh_wordpress_translatio {
    meta:
        attack_type = "cve_2022_2461"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Transposh WordPress Translation <= 1.0.8 - Unauthenticated Settings Change: The Transposh WordPress Translation plugin for WordPress is vulnerable to unauthorized setting changes by unauthenticated users in versions up to, and including, 1.0.8.1. This is due to insufficient."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2461"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2461, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2461.yaml"
    strings:
        $param0 = "action=tp_translation" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2462_transposh_wordpress_translatio {
    meta:
        attack_type = "cve_2022_2462"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Transposh <=1.0.8.1 - Information Disclosure: WordPress Transposh plugin through is susceptible to information disclosure via the AJAX action tp_history, which is intended to return data about who has translated a text given by the token parameter. However, the plugin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2462"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2462, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2462.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=tp_history" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_24627_device_manager_express {
    meta:
        attack_type = "cve_2022_24627"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "AudioCodes Device Manager Express - SQL Injection: An issue was discovered in AudioCodes Device Manager Express through 7.8.20002.47752. It is an unauthenticated SQL injection in the p parameter of the process_login.php login form."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24627"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24627, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24627.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/admin/AudioCodes_files/process_login.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_24637_open_web_analytics {
    meta:
        attack_type = "cve_2022_24637"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Open Web Analytics 1.7.3 - Remote Code Execution: Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated remote attacker to obtain sensitive user information, which can be used to gain admin privileges by leveraging cache hashes. This occurs because files generated."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24637"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24637, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24637.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/owa-data/caches/1/owa_user/c30da9265ba0a4704db9229f864c9eb7.php" ascii nocase
        $path1 = "/owa-data/caches/" ascii nocase
        $param0 = "owa_do=base.loginForm" ascii nocase
        $param1 = "owa_password=wrong password xyz" ascii nocase
        $param2 = "owa_action=base.login" ascii nocase
        $param3 = "owa_action=base.usersChangePassword" ascii nocase
        $param4 = "owa_submit_btn=Save Your New Password" ascii nocase
        $param5 = "owa_do=base.optionsGeneral" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2467_garage_management_system {
    meta:
        attack_type = "cve_2022_2467"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Garage Management System 1.0 - SQL Injection: Garage Management System 1.0 contains a SQL injection vulnerability in /login.php via manipulation of the argument username with input 1@a.com' AND (SELECT 6427 FROM (SELECT(SLEEP(5)))LwLu) AND 'hsvT'='hsvT. An attacker can possibly."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2467"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2467, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2467.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "login=test2334" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_24716_icinga_web_2 {
    meta:
        attack_type = "cve_2022_24716"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Icinga Web 2 - Arbitrary File Disclosure: Icinga Web 2 is an open source monitoring web interface, framework and command-line interface. Unauthenticated users can leak the contents of files of the local system accessible to the web-server user, including `icingaweb2`."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24716"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24716, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24716.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/lib/icinga/icinga-php-thirdparty/etc/passwd" ascii nocase
        $path1 = "/icinga2/lib/icinga/icinga-php-thirdparty/etc/passwd" ascii nocase
        $path2 = "/icinga-web/lib/icinga/icinga-php-thirdparty/etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_24816_jai_ext {
    meta:
        attack_type = "cve_2022_24816"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "GeoServer <1.2.2 - Remote Code Execution: Programs run on GeoServer before 1.2.2 which use jt-jiffle and allow Jiffle script to be provided via network request are susceptible to remote code execution. The Jiffle script is compiled into Java code via Janino, and executed. In."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24816"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24816, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24816.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/geoserver/wms" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_24819_xwiki {
    meta:
        attack_type = "cve_2022_24819"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki < 12.10.11, 13.4.4 & 13.9-rc-1 - Information Disclosure: An unauthenticated user can retrieve a list of users and their full names through a publicly accessible URL in XWiki. The issue affects versions before 12.10.11, 13.4.4, and 13.9-rc-1."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24819"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24819, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24819.yaml"
    strings:
        $path0 = "/bin/login/XWikiLogin" ascii nocase
        $path1 = "/xwiki/bin/login/XWikiLogin" ascii nocase
        $param0 = "xpage=uorgsuggest" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2486_wl_wn535k2 {
    meta:
        attack_type = "cve_2022_2486"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Wavlink WN535K2/WN535K3 - OS Command Injection: Wavlink WN535K2 and WN535K3 routers are susceptible to OS command injection in an unknown part of the file /cgi-bin/mesh.cgi?page=upgrade via manipulation of the argument key. An attacker can execute malware, obtain sensitive."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2486"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2486, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2486.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "page=upgrade" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2488_wl_wn535k2_firmware {
    meta:
        attack_type = "cve_2022_2488"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Wavlink WN535K2/WN535K3 - OS Command Injection: Wavlink WN535K2 and WN535K3 routers are susceptible to OS command injection in /cgi-bin/touchlist_sync.cgi via manipulation of the argument IP. An attacker can execute malware, obtain sensitive information, modify data, and/or."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2488"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2488, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2488.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/cgi-bin/touchlist_sync.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_24900_piano_led_visualizer {
    meta:
        attack_type = "cve_2022_24900"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Piano LED Visualizer 1.3 - Local File Inclusion: Piano LED Visualizer 1.3 and prior are vulnerable to local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-24900"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-24900, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-24900.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/change_setting" ascii nocase
        $param0 = "second_value=no_reload" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_25061_tl_wr840n_firmware {
    meta:
        attack_type = "cve_2022_25061"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TP-Link TL-WR840N - Command Injection: The TP-Link TL-WR840N(ES)_V6.20_180709 router contains a command injection vulnerability in the oal_setIp6DefaultRoute component. This vulnerability allows authenticated attackers to execute arbitrary system commands, leading to complete."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-25061"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-25061, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-25061.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "__ifAliasName=ewan_ipoev6_d" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_25082_a950rg_firmware {
    meta:
        attack_type = "cve_2022_25082"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TOTOLink - Unauthenticated Command Injection: TOTOLink A950RG V5.9c.4050_B20190424 and V4.1.2cu.5204_B20210112 were discovered to contain a command injection vulnerability in the Main function. This vulnerability allows attackers to execute arbitrary commands via the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-25082"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-25082, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-25082.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/cgi-bin/downloadFlile.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_25125_mcms {
    meta:
        attack_type = "cve_2022_25125"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MCMS 5.2.4 - SQL Injection: MCMS 5.2.4 contains a SQL injection vulnerability via search.do in the file /mdiy/dict/listExcludeApp. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-25125"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-25125, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-25125.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/mdiy/dict/listExcludeApp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_25237_bonita {
    meta:
        attack_type = "cve_2022_25237"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Bonita Web 2021.2 - Authentication/Authorization Bypass: Bonita Web 2021.2 contains an authentication/authorization bypass vulnerability caused by an overly broad exclude pattern in RestAPIAuthorizationFilter, allowing unauthenticated users to access privileged API endpoints by."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-25237"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-25237, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-25237.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/bonita/loginservice" ascii nocase
        $path1 = "/bonita/API/pageUpload;i18ntranslation" ascii nocase
        $path2 = "/bonita/API/portal/page/;i18ntranslation" ascii nocase
        $path3 = "/bonita/API/extension/rce" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_25322_web_server {
    meta:
        attack_type = "cve_2022_25322"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ZEROF Web Server 2.0 - SQL Injection: ZEROF Web Server 2.0 allows SQL Injection via the /HandleEvent endpoint. Attackers can exploit this vulnerability by manipulating the request parameters to execute arbitrary SQL queries."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-25322"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-25322, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-25322.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "Evt=keypress" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2535_searchwp_live_ajax_search {
    meta:
        attack_type = "cve_2022_2535"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SearchWP Live Ajax Search < 1.6.2 - Unauthenticated Arbitrary Post Title Disclosure: The plugin does not ensure that users making. alive search are limited to published posts only, allowing unauthenticated users to make a crafted query disclosing private/draft/pending post."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2535"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2535, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2535.yaml"
    strings:
        $param0 = "action=searchwp_live_search" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_25356_securitygateway {
    meta:
        attack_type = "cve_2022_25356"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Alt-n/MDaemon Security Gateway <=8.5.0 - XML Injection: Alt-n/MDaemon Security Gateway through 8.5.0 is susceptible to XML injection via SecurityGateway.dll?view=login. An attacker can inject an arbitrary XML argument by adding a new parameter in the HTTP request URL. As a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-25356"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-25356, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-25356.yaml"
    strings:
        $path0 = "/SecurityGateway.dll" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_25369_dynamicweb_9_5_0 {
    meta:
        attack_type = "cve_2022_25369"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dynamicweb 9.5.0 - 9.12.7 Unauthenticated Admin User Creation: Dynamicweb contains a vulnerability which allows an unauthenticated attacker to create a new administrative user."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-25369"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-25369, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-25369.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/Admin/Access/Setup/Default.aspx" ascii nocase
        $param0 = "Action=createadministrator" ascii nocase
        $param1 = "adminemail=test@test.com" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2544_ninja_job_board {
    meta:
        attack_type = "cve_2022_2544"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Ninja Job Board < 1.3.3 - Direct Request: WordPress Ninja Job Board plugin prior to 1.3.3 is susceptible to a direct request vulnerability. The plugin does not protect the directory where it stores uploaded resumes, making it vulnerable to unauthenticated directory."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2544"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2544, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2544.yaml"
    strings:
        $path0 = "/wp/wp-content/uploads/wpjobboard/" ascii nocase
        $path1 = "/wp-content/uploads/wpjobboard/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_25486_cuppacms {
    meta:
        attack_type = "cve_2022_25486"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cuppa CMS v1.0 - Local File Inclusion: CuppaCMS v1.0 was discovered to contain a local file inclusion via the url parameter in /alerts/alertConfigField.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-25486"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-25486, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-25486.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/alerts/alertConfigField.php" ascii nocase
        $param0 = "urlConfig=../../../../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_25488_atomcms {
    meta:
        attack_type = "cve_2022_25488"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Atom CMS v2.0 - SQL Injection: Atom CMS v2.0 was discovered to contain a SQL injection vulnerability via the id parameter in /admin/ajax/avatar.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-25488"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-25488, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-25488.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/admin/ajax/avatar.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_25489_atomcms {
    meta:
        attack_type = "cve_2022_25489"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Atom CMS v2.0 - Cross-Site Scripting: Atom CMS v2.0 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the 'A' parameter in /widgets/debug.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-25489"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-25489, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-25489.yaml"
        response_type = "xss"
    strings:
        $path0 = "/widgets/debug.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_2551_duplicator {
    meta:
        attack_type = "cve_2022_2551"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Duplicator <1.4.7 - Authentication Bypass: WordPress Duplicator plugin before 1.4.7 is susceptible to authentication bypass. The plugin discloses the URL of the backup to unauthenticated visitors accessing the main installer endpoint. If the installer script has been."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2551"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2551, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2551.yaml"
    strings:
        $path0 = "/wp-content/dup-installer/main.installer.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_26138_questions_for_confluence {
    meta:
        attack_type = "cve_2022_26138"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Atlassian Questions For Confluence - Hardcoded Credentials: Atlassian Questions For Confluence contains a hardcoded credentials vulnerability. When installing versions 2.7.34, 2.7.35, and 3.0.2, a Confluence user account is created in the confluence-users group with the."
        mitre_attack = "T1078.001"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-26138"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-26138, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-26138.yaml"
    strings:
        $param0 = "os_destination=/httpvoid.action" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_26159_ametys {
    meta:
        attack_type = "cve_2022_26159"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ametys CMS Information Disclosure: Ametys CMS before 4.5.0 allows a remote unauthenticated attacker to read documents such as plugins/web/service/search/auto-completion/domain/en.xml (and similar pathnames for other languages) via the auto-completion plugin, which contain all."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-26159"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-26159, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-26159.yaml"
    strings:
        $path0 = "/plugins/web/service/search/auto-completion/domain/en.xml" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_2627_newspaper {
    meta:
        attack_type = "cve_2022_2627"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Newspaper < 12 - Cross-Site Scripting: WordPress Newspaper theme before 12 is susceptible to cross-site scripting. The does not sanitize a parameter before outputting it back in an HTML attribute via an AJAX action. An attacker can potentially execute malware, obtain."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2627"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2627, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2627.yaml"
        response_type = "xss"
    strings:
        $param0 = "td_theme_name=Newspaper" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_26564_hoteldruid {
    meta:
        attack_type = "cve_2022_26564"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "HotelDruid Hotel Management Software 3.0.3 - Cross-Site Scripting: HotelDruid Hotel Management Software 3.0.3 contains a cross-site scripting vulnerability via the prezzoperiodo4 parameter in creaprezzi.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-26564"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-26564, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-26564.yaml"
        response_type = "xss"
    strings:
        $path0 = "/modifica_cliente.php" ascii nocase
        $path1 = "/dati/availability_tpl.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_26833_oas_platform {
    meta:
        attack_type = "cve_2022_26833"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Open Automation Software OAS Platform V16.00.0121 - Missing Authentication: An improper authentication vulnerability exists in the REST API functionality of Open Automation Software OAS Platform V16.00.0121. A specially-crafted series of HTTP requests can lead to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-26833"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-26833, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-26833.yaml"
    strings:
        $path0 = "/OASREST/v2/authenticate" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_27228_bitrix24 {
    meta:
        attack_type = "cve_2022_27228"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Bitrix Site Manager - Remote Code Execution: In the vote (aka 'Polls, Votes') module before 21.0.100 of Bitrix Site Manager, a remote unauthenticated attacker can execute arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-27228"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-27228, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-27228.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/bitrix/admin/" ascii nocase
        $path1 = "/bitrix/tools/vote/uf.php" ascii nocase
        $param0 = "attachId[ENTITY_TYPE]=CFileUploader" ascii nocase
        $param1 = "attachId[ENTITY_ID][events][onFileIsStarted][]=CAllAgent" ascii nocase
        $param2 = "attachId[ENTITY_ID][events][onFileIsStarted][]=Update" ascii nocase
        $param3 = "attachId[MODULE_ID]=vote" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_2733_openemr {
    meta:
        attack_type = "cve_2022_2733"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Openemr < 7.0.0.1 - Cross-Site Scripting: Cross-site Scripting (XSS) - Reflected in GitHub repository openemr/openemr prior to 7.0.0.1."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2733"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2733, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2733.yaml"
        response_type = "xss"
    strings:
        $path0 = "/interface/forms/fee_sheet/review/fee_sheet_options_ajax.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_27593_photo_station {
    meta:
        attack_type = "cve_2022_27593"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "QNAP QTS Photo Station External Reference - Local File Inclusion: QNAP QTS Photo Station External Reference is vulnerable to local file inclusion via an externally controlled reference to a resource vulnerability. If exploited, this could allow an attacker to modify system."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-27593"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-27593, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-27593.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/photo/combine.php" ascii nocase
        $param0 = "g=core-r7rules/../../../hello.php." ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_27849_simple_ajax_chat {
    meta:
        attack_type = "cve_2022_27849"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Simple Ajax Chat <20220116 - Sensitive Information Disclosure vulnerability: WordPress Simple Ajax Chat before 20220216 is vulnerable to sensitive information disclosure. The plugin does not properly restrict access to the exported data via the sac-export.csv file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-27849"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-27849, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-27849.yaml"
    strings:
        $path0 = "/wp-content/plugins/simple-ajax-chat/sac-export.csv" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_27927_microfinance_management_system {
    meta:
        attack_type = "cve_2022_27927"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Microfinance Management System 1.0 - SQL Injection: Microfinance Management System 1.0 is susceptible to SQL Injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-27927"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-27927, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-27927.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/mims/updatecustomer.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_27984_cuppacms {
    meta:
        attack_type = "cve_2022_27984"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cuppa CMS v1.0 - SQL injection: CuppaCMS v1.0 was discovered to contain a SQL injection vulnerability via the menu_filter parameter at /administrator/templates/default/html/windows/right.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-27984"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-27984, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-27984.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "uniqueClass=window_right_7526357" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_27985_cuppacms {
    meta:
        attack_type = "cve_2022_27985"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cuppa CMS v1.0 - SQL injection: CuppaCMS v1.0 was discovered to contain a SQL injection vulnerability via /administrator/alerts/alertLightbox.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-27985"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-27985, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-27985.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "url=components/permissions/list_permissions_lightbox.php" ascii nocase
        $param1 = "title=Permissions: profile" ascii nocase
        $param2 = "uniqueClass=new_content_3983163" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_28079_college_management_system {
    meta:
        attack_type = "cve_2022_28079"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "College Management System 1.0 - SQL Injection: College Management System 1.0 contains a SQL injection vulnerability via the course code parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-28079"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-28079, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-28079.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/admin/asign-single-student-subjects.php" ascii nocase
        $param0 = "submit=Press" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_28117_navigate_cms {
    meta:
        attack_type = "cve_2022_28117"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Navigate CMS 2.9.4 - Server-Side Request Forgery: Navigate CMS 2.9.4 is susceptible to server-side request forgery via feed_parser class. This can allow a remote attacker to force the application to make arbitrary requests via injection of arbitrary URLs into the feed."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-28117"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-28117, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-28117.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/navigate/login.php" ascii nocase
        $path1 = "/navigate/navigate.php" ascii nocase
        $path2 = "/navigate/private/1/cache/0f1726ba83325848d47e216b29d5ab99.feed" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_28219_manageengine_adaudit_plus {
    meta:
        attack_type = "cve_2022_28219"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Zoho ManageEngine ADAudit Plus <7600 - XML Entity Injection/Remote Code Execution: Zoho ManageEngine ADAudit Plus before version 7060 is vulnerable to an unauthenticated XML entity injection attack that can lead to remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-28219"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-28219, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-28219.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/agent/tabs/agentData" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_28290_wordpress_country_selector {
    meta:
        attack_type = "cve_2022_28290"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Country Selector <1.6.6 - Cross-Site Scripting: WordPress Country Selector plugin prior to 1.6.6 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape the country and lang parameters before outputting them back in the response. An."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-28290"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-28290, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-28290.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=check_country_selector" ascii nocase
        $param1 = "site_locate=en-US" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_28363_reprise_license_manager {
    meta:
        attack_type = "cve_2022_28363"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Reprise License Manager 14.2 - Cross-Site Scripting: Reprise License Manager 14.2 contains a reflected cross-site scripting vulnerability in the /goform/login_process 'username' parameter via GET, whereby no authentication is required."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-28363"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-28363, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-28363.yaml"
        response_type = "xss"
    strings:
        $path0 = "/goform/login_process" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_28365_reprise_license_manager {
    meta:
        attack_type = "cve_2022_28365"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Reprise License Manager 14.2 - Information Disclosure: Reprise License Manager 14.2 is susceptible to information disclosure via a GET request to /goforms/rlminfo. No authentication is required. The information disclosed is associated with software versions, process IDs."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-28365"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-28365, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-28365.yaml"
    strings:
        $path0 = "/goforms/rlminfo" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_28508_mantisbt_2_25_2 {
    meta:
        attack_type = "cve_2022_28508"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MantisBT < 2.25.2 - Cross-Site Scripting: MantisBT before 2.25.2 contains a cross-site scripting vulnerability in browser_search_plugin.php. The application does not properly sanitize the 'type' parameter, which allows attackers to inject arbitrary web script or HTML via a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-28508"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-28508, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-28508.yaml"
        response_type = "xss"
    strings:
        $path0 = "/browser_search_plugin.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_2863_migration_backup_staging {
    meta:
        attack_type = "cve_2022_2863"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WPvivid Backup <0.9.76 - Local File Inclusion: WordPress WPvivid Backup version 0.9.76 is vulnerable to local file inclusion because the plugin does not sanitize and validate a parameter before using it to read the content of a file, allowing high privilege users to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-2863"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2863, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-2863.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "page=WPvivid" ascii nocase
        $param1 = "action=wpvivid_download_export_backup" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_28666_custom_product_tabs_for_woocom {
    meta:
        attack_type = "cve_2022_28666"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Custom Product Tabs for WooCommerce < 1.7.8 - Unauthenticated Toggle Content Setting Update: YIKES Inc. Custom Product Tabs for WooCommerce plugin /u003C= 1.7.7 contains a broken access control caused by improper permission checks in &yikes-the-content-toggle option update."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-28666"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-28666, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-28666.yaml"
    strings:
        $path0 = "/wp-json/yikes/cpt/v1/settings" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_28955_dir_816l_firmware {
    meta:
        attack_type = "cve_2022_28955"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "D-Link DIR-816L - Improper Access Control: D-Link DIR-816L_FW206b01 is susceptible to improper access control. An attacker can access folders folder_view.php and category_view.php and thereby possibly obtain sensitive information, modify data, and/or execute unauthorized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-28955"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-28955, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-28955.yaml"
    strings:
        $path0 = "/category_view.php" ascii nocase
        $path1 = "/folder_view.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_28987_zoho_manageengine_adselfservic {
    meta:
        attack_type = "cve_2022_28987"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Zoho ManageEngine ADSelfService Plus 6121 - Username Enumeration: Zoho ManageEngine ADSelfService Plus 6121 is vulnerable to username enumeration (CVE-2022-28987). The Forgot Password functionality responds differently for existing and non-existing users, allowing attackers to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-28987"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-28987, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-28987.yaml"
    strings:
        $path0 = "/ServletAPI/accounts/login" ascii nocase
        $param0 = "loginName=asdfnonexistent" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_29004_e_diary_management_system {
    meta:
        attack_type = "cve_2022_29004"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Diary Management System 1.0 - Cross-Site Scripting: Diary Management System 1.0 contains a cross-site scripting vulnerability via the Name parameter in search-result.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-29004"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-29004, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-29004.yaml"
        response_type = "xss"
    strings:
        $path0 = "/edms/search-result.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_29005_online_birth_certificate_syste {
    meta:
        attack_type = "cve_2022_29005"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Online Birth Certificate System 1.2 - Stored Cross-Site Scripting: Online Birth Certificate System 1.2 contains multiple stored cross-site scripting vulnerabilities in the component /obcs/user/profile.php, which allows an attacker to execute arbitrary web script or HTML via a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-29005"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-29005, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-29005.yaml"
        response_type = "xss"
    strings:
        $path0 = "/obcs/user/profile.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_29007_dairy_farm_shop_management_sys {
    meta:
        attack_type = "cve_2022_29007"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dairy Farm Shop Management System 1.0 - SQL Injection: Dairy Farm Shop Management System 1.0 contains multiple SQL injection vulnerabilities via the username and password parameters in the Admin panel. An attacker can possibly obtain sensitive information from a database."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-29007"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-29007, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-29007.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/dfsms/index.php" ascii nocase
        $path1 = "/dfsms/add-category.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_29081_zoho_manageengine {
    meta:
        attack_type = "cve_2022_29081"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Zoho ManageEngine - Access Control Bypass: Zoho ManageEngine Access Manager Plus before 4302, Password Manager Pro before 12007, and PAM360 before 5401 are vulnerable to access-control bypass on a few Rest API URLs (for SSOutAction. SSLAction. LicenseMgr. GetProductDetails.."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-29081"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-29081, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-29081.yaml"
    strings:
        $path0 = "/x/../RestAPI/LicenseMgr" ascii nocase
        $param0 = "operation=getLicenseDetails" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_29153_consul {
    meta:
        attack_type = "cve_2022_29153"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "HashiCorp Consul/Consul Enterprise - Server-Side Request Forgery: HashiCorp Consul and Consul Enterprise up to 1.9.16, 1.10.9, and 1.11 are susceptible to server-side request forgery. When redirects are returned by HTTP health check endpoints, Consul follows these HTTP."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-29153"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-29153, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-29153.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/v1/agent/check/register" ascii nocase
        $path1 = "/v1/agent/check/deregister/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_29316_complete_online_job_search_sys {
    meta:
        attack_type = "cve_2022_29316"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Complete Online Job Search System 1.0 - Cross-Site Scripting: Complete Online Job Search System 1.0 contains a cross-site scripting vulnerability via index.php?q=advancesearch."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-29316"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-29316, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-29316.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "searchfor=advancesearch" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_29383_ssl312_firmware {
    meta:
        attack_type = "cve_2022_29383"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "NETGEAR ProSafe SSL VPN firmware - SQL Injection: NETGEAR ProSafe SSL VPN multiple firmware versions were discovered to contain a SQL injection vulnerability via USERDBDomains.Domainname at cgi-bin/platform.cgi."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-29383"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-29383, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-29383.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "thispage=index.htm" ascii nocase
        $param1 = "USERDBUsers.UserName=NjVI" ascii nocase
        $param2 = "Login.userAgent=MDpd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_29464_api_manager {
    meta:
        attack_type = "cve_2022_29464"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "WSO2 Management - Arbitrary File Upload & Remote Code Execution: Certain WSO2 products allow unrestricted file upload with resultant remote code execution. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-29464"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-29464, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-29464.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/fileupload/toolsAny" ascii nocase
        $path1 = "/authenticationendpoint/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_29495_wordpress_popup_builder_4_1_11 {
    meta:
        attack_type = "cve_2022_29495"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Popup Builder <= 4.1.11 - Cross-Site Request Forgery: Sygnoos Popup Builder plugin <= 4.1.11 for WordPress contains a cross-site request forgery caused by lack of CSRF protection in plugin settings update, letting attackers change settings without authorization."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-29495"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-29495, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-29495.yaml"
    strings:
        $param0 = "action=sgpbSaveSettings" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_29548_api_manager {
    meta:
        attack_type = "cve_2022_29548"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WSO2 - Cross-Site Scripting: WSO2 contains a reflected cross-site scripting vulnerability in the Management Console of API Manager 2.2.0, 2.5.0, 2.6.0, 3.0.0, 3.1.0, 3.2.0, and 4.0.0; API Manager Analytics 2.2.0, 2.5.0, and 2.6.0; API Microgateway 2.2.0; Data Analytics Server."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-29548"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-29548, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-29548.yaml"
        response_type = "xss"
    strings:
        $param0 = "errorCode=');alert(document.domain)//" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_29775_ispy {
    meta:
        attack_type = "cve_2022_29775"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "iSpy 7.2.2.0 - Authentication Bypass: iSpy 7.2.2.0 contains an authentication bypass vulnerability. An attacker can craft a URL and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-29775"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-29775, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-29775.yaml"
    strings:
        $param0 = "d=crossdomain.xml" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_30073_wbce_cms {
    meta:
        attack_type = "cve_2022_30073"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WBCE CMS 1.5.2 - Cross-Site Scripting: WBCE CMS 1.5.2 contains a stored cross-site scripting vulnerability via /admin/user/save.php Display Name parameters."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-30073"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-30073, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-30073.yaml"
        response_type = "xss"
    strings:
        $param0 = "username_fieldname=username_axh5kevh" ascii nocase
        $param1 = "password_fieldname=password_axh5kevh" ascii nocase
        $param2 = "username_fieldname=username_tep83j9z" ascii nocase
        $param3 = "username_tep83j9z=testme2" ascii nocase
        $param4 = "password=temp1234" ascii nocase
        $param5 = "password2=temp1234" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_30489_wn535g3_firmware {
    meta:
        attack_type = "cve_2022_30489"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Wavlink WN-535G3 - Cross-Site Scripting: Wavlink WN-535G3 contains a POST cross-site scripting vulnerability via the hostname parameter at /cgi-bin/login.cgi."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-30489"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-30489, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-30489.yaml"
        response_type = "xss"
    strings:
        $param0 = "ipaddr=x.x.x.x" ascii nocase
        $param1 = "key=M27234733" ascii nocase
        $param2 = "password=63a36bceec2d3bba30d8611c323f4cda" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_30512_school_dormitory_management_sy {
    meta:
        attack_type = "cve_2022_30512"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "School Dormitory Management System 1.0 - SQL Injection: School Dormitory Management System 1.0 contains a SQL injection vulnerability via accounts/payment_history.php:31. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-30512"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-30512, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-30512.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/dms/admin/accounts/payment_history.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_30776_atmail {
    meta:
        attack_type = "cve_2022_30776"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Atmail 6.5.0 - Cross-Site Scripting: Atmail 6.5.0 contains a cross-site scripting vulnerability via the index.php/admin/index/ 'error' parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-30776"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-30776, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-30776.yaml"
        response_type = "xss"
    strings:
        $path0 = "/atmail/index.php/admin/index/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_31126_roxy_wi {
    meta:
        attack_type = "cve_2022_31126"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Roxy-WI - Remote Code Execution: Roxy-WI before 6.1.1.0 is susceptible to remote code execution. System commands can be run remotely via the ssh_command function without processing the inputs received from the user in the /app/funct.py file."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-31126"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-31126, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-31126.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "getcert=;id;" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_31137_roxy_wi {
    meta:
        attack_type = "cve_2022_31137"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Roxy-WI < 6.1.1.0 - Remote Code Execution: Roxy-WI before 6.1.1.0 is susceptible to remote code execution. System commands can be run remotely via the subprocess_execute function without processing the inputs received from the user in the /app/options.py file."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-31137"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-31137, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-31137.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "backend_server=127.0.0.1" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_31161_roxy_wi {
    meta:
        attack_type = "cve_2022_31161"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Roxy-WI - Remote Code Execution: Roxy-WI before 6.1.1.0 is susceptible to remote code execution. System commands can be run remotely via the delcert parameter without proper input validation in the /app/options.py file, allowing attackers to inject arbitrary OS commands."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-31161"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-31161, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-31161.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "alert_consumer=notNull" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_31181_prestashop {
    meta:
        attack_type = "cve_2022_31181"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PrestaShop - SQL Injection to Eval Injection: PrestaShop versions from 1.6.0.10 and before 1.7.8.7 contain an SQL injection caused by unsanitized user input, letting attackers chain the vulnerability to call PHP's Eval function, exploit requires attacker to send malicious input."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-31181"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-31181, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-31181.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/module/blockwishlist/action" ascii nocase
        $path1 = "/module/blockwishlist/view" ascii nocase
        $param0 = "action=getAllWishlist" ascii nocase
        $param1 = "action=addProductToWishlist" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_3124_frontend_file_manager {
    meta:
        attack_type = "cve_2022_3124"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Frontend File Manager < 21.3 - Unauthenticated File Renaming: The Frontend File Manager Plugin WordPress plugin before 21.3 allows any unauthenticated user to rename uploaded files from users. Furthermore, due to the lack of validation in the destination filename, this could."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-3124"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-3124, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-3124.yaml"
    strings:
        $path0 = "/wp-json/wpfm/v1/file-rename" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_31260_resourcespace {
    meta:
        attack_type = "cve_2022_31260"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ResourceSpace - Metadata Export: In Montala ResourceSpace through 9.8 before r19636, csv_export_results_metadata.php allows attackers to export collection metadata via a non-NULL k value."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-31260"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-31260, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-31260.yaml"
    strings:
        $path0 = "/pages/csv_export_results_metadata.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_31299_haraj {
    meta:
        attack_type = "cve_2022_31299"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Haraj 3.7 - Cross-Site Scripting: Haraj 3.7 contains a cross-site scripting vulnerability in the User Upgrade Form. An attacker can inject malicious script and thus steal authentication credentials and launch other attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-31299"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-31299, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-31299.yaml"
        response_type = "xss"
    strings:
        $path0 = "/payform.php" ascii nocase
        $param0 = "type=upgrade" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_31474_backupbuddy {
    meta:
        attack_type = "cve_2022_31474"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "BackupBuddy - Local File Inclusion: BackupBuddy versions 8.5.8.0 - 8.7.4.1 are vulnerable to a local file inclusion vulnerability via the 'download' and 'local-destination-id' parameters."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-31474"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-31474, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-31474.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "page=pb_backupbuddy_destinations" ascii nocase
        $param1 = "local-destination-id=/etc/passwd" ascii nocase
        $param2 = "local-download=/etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_31846_wn535g3_firmware {
    meta:
        attack_type = "cve_2022_31846"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WAVLINK WN535 G3 - Information Disclosure: WAVLINK WN535 G3 M35G3R.V5030.180927 is susceptible to information disclosure in the live_mfg.shtml page. An attacker can obtain sensitive router information via the exec cmd function and possibly obtain additional sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-31846"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-31846, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-31846.yaml"
    strings:
        $path0 = "/live_mfg.shtml" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_31854_codoforum {
    meta:
        attack_type = "cve_2022_31854"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Codoforum 5.1 - Arbitrary File Upload: Codoforum 5.1 contains an arbitrary file upload vulnerability via the logo change option in the admin panel. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-31854"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-31854, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-31854.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/sites/default/assets/img/attachments/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_31984_online_fire_reporting_system {
    meta:
        attack_type = "cve_2022_31984"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Online Fire Reporting System v1.0 - SQL injection: Online Fire Reporting System v1.0 is vulnerable to SQL Injection via /ofrs/admin/requests/take_action.php?id=."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-31984"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-31984, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-31984.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/admin/requests/take_action.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_32007_complete_online_job_search_sys {
    meta:
        attack_type = "cve_2022_32007"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Complete Online Job Search System 1.0 - SQL Injection: Complete Online Job Search System 1.0 contains a SQL injection vulnerability via /eris/admin/company/index.php?view=edit&id=. An attacker can possibly obtain sensitive information from a database, modify data, and execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-32007"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-32007, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-32007.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/admin/company/index.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_32024_car_rental_management_system {
    meta:
        attack_type = "cve_2022_32024"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Car Rental Management System 1.0 - SQL Injection: Car Rental Management System 1.0 contains an SQL injection vulnerability via /booking.php?car_id=. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-32024"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-32024, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-32024.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/booking.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_32026_car_rental_management_system {
    meta:
        attack_type = "cve_2022_32026"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Car Rental Management System 1.0 - SQL Injection: Car Rental Management System 1.0 contains an SQL injection vulnerability via /admin/manage_booking.php?id=. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-32026"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-32026, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-32026.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/admin/manage_booking.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_32028_car_rental_management_system {
    meta:
        attack_type = "cve_2022_32028"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Car Rental Management System 1.0 - SQL Injection: Car Rental Management System 1.0 contains an SQL injection vulnerability via /admin/manage_user.php?id=. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-32028"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-32028, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-32028.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/admin/manage_user.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_3236_firewall {
    meta:
        attack_type = "cve_2022_3236"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Sophos Firewall <= 19.0 MR1 - Remote Code Execution: Sophos Firewall version v19.0 MR1 and older is vulnerable to code injection in the User Portal and Webadmin, allowing a remote unauthenticated attacker to execute arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-3236"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-3236, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-3236.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/webconsole/Controller" ascii nocase
        $param0 = "__RequestType=ajax" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_32409_i3geo {
    meta:
        attack_type = "cve_2022_32409"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Portal do Software Publico Brasileiro i3geo 7.0.5 - Local File Inclusion: Portal do Software Publico Brasileiro i3geo 7.0.5 is vulnerable to local file inclusion in the component codemirror.php, which allows attackers to execute arbitrary PHP code via a crafted HTTP request."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-32409"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-32409, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-32409.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/i3geo/exemplos/codemirror.php" ascii nocase
        $param0 = "pagina=../../../../../../../../../../../../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_32429_msnswitch_firmware {
    meta:
        attack_type = "cve_2022_32429"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MSNSwitch Firmware MNT.2408 - Authentication Bypass: MSNSwitch Firmware MNT.2408 is susceptible to authentication bypass in the component http://MYDEVICEIP/cgi-bin-sdb/ExportSettings.sh. An attacker can arbitrarily configure settings, leading to possible remote code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-32429"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-32429, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-32429.yaml"
    strings:
        $path0 = "/cgi-bin-hax/ExportSettings.sh" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_32430_lin_cms_spring_boot {
    meta:
        attack_type = "cve_2022_32430"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Lin CMS Spring Boot - Default JWT Token: An access control issue in Lin CMS Spring Boot v0.2.1 allows attackers to access the backend information and functions within the application."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-32430"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-32430, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-32430.yaml"
    strings:
        $path0 = "/cms/admin/group/all" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_32444_u5cms {
    meta:
        attack_type = "cve_2022_32444"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "u5cms v8.3.5 - Open Redirect: u5cms version 8.3.5 contains a URL redirection vulnerability that can cause a user's browser to be redirected to another site via /loginsave.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-32444"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-32444, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-32444.yaml"
    strings:
        $path0 = "/loginsave.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_3254_awp_classifieds_4_2_1 {
    meta:
        attack_type = "cve_2022_3254"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "AWP Classifieds <= 4.2.1 - Unauthenticated SQL Injection: WordPress Classifieds Plugin before 4.3 contains a SQL injection caused by improper sanitization and escaping of parameters in an AJAX action, letting unauthenticated attackers execute arbitrary SQL commands, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-3254"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-3254, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-3254.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=awpcp-get-regions-options" ascii nocase
        $param1 = "parent_type=country" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_33174_basic_pdu_firmware {
    meta:
        attack_type = "cve_2022_33174"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Powertek Firmware <3.30.30 - Authorization Bypass: Powertek firmware (multiple brands) before 3.30.30 running Power Distribution Units are vulnerable to authorization bypass in the web interface. To exploit the vulnerability, an attacker must send an HTTP packet to the data."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-33174"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-33174, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-33174.yaml"
    strings:
        $path0 = "/cgi/get_param.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_33198_accordions {
    meta:
        attack_type = "cve_2022_33198"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Accordions - Unauthenticated Settings Update: Unauthenticated WordPress Options Change vulnerability in Biplob Adhikari's Accordions plugin <= 2.0.2 at WordPress."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-33198"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-33198, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-33198.yaml"
    strings:
        $path0 = "/wp-json/oxiaccordionsultimate/v1/oxi_settings" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_33901_multisafepay_plugin_for_woocom {
    meta:
        attack_type = "cve_2022_33901"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress MultiSafepay for WooCommerce <=4.13.1 - Arbitrary File Read: WordPress MultiSafepay for WooCommerce plugin through 4.13.1 contains an arbitrary file read vulnerability. An attacker can potentially obtain sensitive information, modify data, and/or execute unauthorized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-33901"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-33901, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-33901.yaml"
    strings:
        $param0 = "log_filename=../../../../../../../../../../../../../etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_34046_wn533a8_firmware {
    meta:
        attack_type = "cve_2022_34046"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WAVLINK WN533A8 - Improper Access Control: WAVLINK WN533A8 M33A8.V5030.190716 is susceptible to improper access control. An attacker can obtain usernames and passwords via view-source:http://IP_ADDRESS/sysinit.shtml?r=52300 and searching for [logincheck(user);] and thereby."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-34046"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-34046, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-34046.yaml"
    strings:
        $path0 = "/sysinit.shtml" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_34047_wl_wn530hg4_firmware {
    meta:
        attack_type = "cve_2022_34047"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WAVLINK WN530HG4 - Improper Access Control: WAVLINK WN530HG4 M30HG4.V5030.191116 is susceptible to improper access control. An attacker can obtain usernames and passwords via view-source:http://IP_ADDRESS/set_safety.shtml?r=52300 and searching for [var syspasswd] and thereby."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-34047"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-34047, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-34047.yaml"
    strings:
        $path0 = "/set_safety.shtml" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_34048_wn533a8_firmware {
    meta:
        attack_type = "cve_2022_34048"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Wavlink WN-533A8 - Cross-Site Scripting: Wavlink WN-533A8 M33A8.V5030.190716 contains a reflected cross-site scripting vulnerability via the login_page parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-34048"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-34048, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-34048.yaml"
        response_type = "xss"
    strings:
        $param0 = "ipaddr=196.219.234.10" ascii nocase
        $param1 = "homepage=main.html" ascii nocase
        $param2 = "wizardpage=wiz.shtml" ascii nocase
        $param3 = "key=M94947765" ascii nocase
        $param4 = "password=ab4e98e4640b6c1ee88574ec0f13f908" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_34093_i3geo {
    meta:
        attack_type = "cve_2022_34093"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Software Publico Brasileiro i3geo v7.0.5 - Cross-Site Scripting: Portal do Software Publico Brasileiro i3geo v7.0.5 was discovered to contain a cross-site scripting (XSS) vulnerability via access_token.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-34093"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-34093, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-34093.yaml"
        response_type = "xss"
    strings:
        $path0 = "/i3geo/pacotes/linkedinoauth/example/access_token.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_34094_i3geo {
    meta:
        attack_type = "cve_2022_34094"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Software Publico Brasileiro i3geo v7.0.5 - Cross-Site Scripting: Portal do Software Publico Brasileiro i3geo v7.0.5 was discovered to contain a cross-site scripting (XSS) vulnerability via request_token.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-34094"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-34094, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-34094.yaml"
        response_type = "xss"
    strings:
        $path0 = "/i3geo/pacotes/linkedinoauth/example/request_token.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_34121_cuppacms {
    meta:
        attack_type = "cve_2022_34121"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "CuppaCMS v1.0 - Local File Inclusion: Cuppa CMS v1.0 is vulnerable to local file inclusion via the component /templates/default/html/windows/right.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-34121"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-34121, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-34121.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/templates/default/html/windows/right.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_34267_worldserver {
    meta:
        attack_type = "cve_2022_34267"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "RWS WorldServer - Authentication Bypass: An issue was discovered in RWS WorldServer before 11.7.3. Adding a token parameter with the value of 02 bypasses all authentication requirements. Arbitrary Java code can be uploaded and executed via a .jar archive to the."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-34267"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-34267, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-34267.yaml"
    strings:
        $path0 = "/ws-api/v2/users/me/details" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_34305_tomcat {
    meta:
        attack_type = "cve_2022_34305"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apache Tomcat Examples Web Application - Cross-Site Scripting: Apache Tomcat 8.5.50 to 8.5.81, 9.0.30 to 9.0.64, 10.0.0-M1 to 10.0.22, and 10.1.0-M1 to 10.1.0-M16 contain a reflected cross-site scripting caused by displaying unfiltered user data in the Form authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-34305"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-34305, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-34305.yaml"
        response_type = "xss"
    strings:
        $path0 = "/examples/jsp/security/protected/index.jsp" ascii nocase
        $path1 = "/examples/jsp/security/protected/j_security_check;jsessionid=" ascii nocase
        $param0 = "dataValue=demo" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_34487_shortcode_addons {
    meta:
        attack_type = "cve_2022_34487"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ShortCode Addons - Unauthenticated Options Update: WordPress plugin Shortcode Addons <= 3.0.2 contains an unauthenticated arbitrary option update caused by insufficient access controls in the plugin, letting attackers modify options without authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-34487"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-34487, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-34487.yaml"
    strings:
        $path0 = "/wp-json/ShortCodeAddonsUltimate/v2/addons_settings" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_34534_spectrum_server_firmware {
    meta:
        attack_type = "cve_2022_34534"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Digital Watchdog DW Spectrum Server 4.2.0.32842 - Information Disclosure: Digital Watchdog DW Spectrum Server 4.2.0.32842 allows attackers to access sensitive infromation via a crafted API call."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-34534"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-34534, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-34534.yaml"
    strings:
        $path0 = "/api/moduleInformation" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_34753_spacelogic_c_bus_home_controll {
    meta:
        attack_type = "cve_2022_34753"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SpaceLogic C-Bus Home Controller <=1.31.460 - Remote Command Execution: SpaceLogic C-Bus Home Controller through 1.31.460 is susceptible to remote command execution via improper neutralization of special elements. Remote root exploit can be enabled when the command is."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-34753"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-34753, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-34753.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/delsnap.pl" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_3484_wpb_show_core {
    meta:
        attack_type = "cve_2022_3484"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WPB Show Core - Cross-Site Scripting: WordPress wpb-show-core plugin through TODO contains a cross-site scripting vulnerability. The plugin does not sanitize and escape a parameter before outputting it back in the page. An attacker can inject arbitrary script in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-3484"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-3484, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-3484.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/wpb-show-core/modules/jplayer_new/jplayer_twitter_ver_1.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_3506_related_posts {
    meta:
        attack_type = "cve_2022_3506"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Related Posts <2.1.3 - Stored Cross-Site Scripting: WordPress Related Posts plugin prior to 2.1.3 contains a cross-site scripting vulnerability in the rp4wp[heading_text] parameter. User input is not properly sanitized, allowing the insertion of arbitrary code that."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-3506"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-3506, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-3506.yaml"
        response_type = "xss"
    strings:
        $param0 = "option_page=rp4wp" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_35493_eshop_ecommerce_store_website {
    meta:
        attack_type = "cve_2022_35493"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "eShop 3.0.4 - Cross-Site Scripting: eShop 3.0.4 contains a reflected cross-site scripting vulnerability in json search parse and json response in wrteam.in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-35493"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-35493, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-35493.yaml"
        response_type = "xss"
    strings:
        $path0 = "/home/get_products" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_35914_glpi {
    meta:
        attack_type = "cve_2022_35914"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "GLPI <=10.0.2 - Remote Command Execution: GLPI through 10.0.2 is susceptible to remote command execution injection in /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-35914"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-35914, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-35914.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/vendor/htmlawed/htmlawed/htmLawedTest.php" ascii nocase
        $param0 = "hhook=array_map" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_36446_webmin {
    meta:
        attack_type = "cve_2022_36446"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Webmin <1.997 - Authenticated Remote Code Execution: Webmin before 1.997 is susceptible to authenticated remote code execution via software/apt-lib.pl, which lacks HTML escaping for a UI command. An attacker can perform command injection attacks and thereby execute malware."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-36446"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-36446, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-36446.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/package-updates/update.cgi" ascii nocase
        $param0 = "confirm=Install+Now" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_36553_hwl_2511_ss_firmware {
    meta:
        attack_type = "cve_2022_36553"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hytec Inter HWL-2511-SS - Remote Command Execution: Hytec Inter HWL-2511-SS v1.05 and below was discovered to contain a command injection vulnerability via the component /www/cgi-bin/popen.cgi."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-36553"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-36553, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-36553.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/cgi-bin/popen.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_36642_omnia_mpx_node_firmware {
    meta:
        attack_type = "cve_2022_36642"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Omnia MPX 1.5.0+r1 - Local File Inclusion: Telos Alliance Omnia MPX Node through 1.5.0+r1 is vulnerable to local file inclusion via logs/downloadMainLog. By retrieving userDB.json allows an attacker to retrieve cleartext credentials and escalate privileges via the control panel."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-36642"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-36642, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-36642.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/logs/downloadMainLog" ascii nocase
        $param0 = "fname=../../../../../../..//etc/passwd" ascii nocase
        $param1 = "fname=../../../../../../..///config/MPXnode/www/appConfig/userDB.json" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_36883_git {
    meta:
        attack_type = "cve_2022_36883"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Jenkins Git <=4.11.3 - Missing Authorization: Jenkins Git plugin through 4.11.3 contains a missing authorization check. An attacker can trigger builds of jobs configured to use an attacker-specified Git repository and to cause them to check out an attacker-specified commit.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-36883"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-36883, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-36883.yaml"
    strings:
        $path0 = "/git/notifyCommit" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_36923_manageengine_firewall_analyzer {
    meta:
        attack_type = "cve_2022_36923"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Zoho ManageEngine - getUserAPIKey Authentication Bypass: Zoho ManageEngine OpManager, OpManager Plus, OpManager MSP, Network Configuration Manager, NetFlow Analyzer, Firewall Analyzer, and OpUtils before 2022-07-27 through 2022-07-28 (125657, 126002, 126104, and 126118) allow."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-36923"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-36923, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-36923.yaml"
    strings:
        $path0 = "/RestAPI/getAPIKey" ascii nocase
        $param0 = "operation=getUserAPIKey" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_37122_pcoweb_hvac_bacnet_gateway {
    meta:
        attack_type = "cve_2022_37122"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Carel pCOWeb HVAC BACnet Gateway 2.1.0 - Path Traversal: Carel pCOWeb HVAC BACnet Gateway 2.1.0 contains an unauthenticated arbitrary file disclosure caused by improper verification of the 'file' GET parameter in logdownload.cgi, letting attackers disclose sensitive files via."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-37122"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-37122, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-37122.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/usr-cgi/logdownload.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_37299_shirne_cms {
    meta:
        attack_type = "cve_2022_37299"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Shirne CMS 1.2.0 - Local File Inclusion: Shirne CMS 1.2.0 is vulnerable to local file inclusion which could cause arbitrary file read via /static/ueditor/php/controller.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-37299"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-37299, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-37299.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/static/ueditor/php/controller.php" ascii nocase
        $param0 = "remote=php://filter/convert.base64-encode/resource=/etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_37932_officeconnect_1820_j9979a_firm {
    meta:
        attack_type = "cve_2022_37932"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "HP Switch - Authentication Bypass: A potential security vulnerability has been identified in Hewlett Packard Enterprise OfficeConnect 1820, 1850, and 1920S Network switches. The vulnerability could be remotely exploited to allow authentication bypass. HPE has made the following."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-37932"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-37932, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-37932.yaml"
    strings:
        $path0 = "/login/default_password_cfg.lua" ascii nocase
        $path1 = "/htdocs/login/default_password_cfg.lua" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_38130_sensor_management_server {
    meta:
        attack_type = "cve_2022_38130"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "KeySight RF - smsRestoreDatabaseZip UNC path to Remote Code Execution: The com.keysight.tentacle.config.ResourceManager.smsRestoreDatabaseZip() method is used to restore the HSQLDB database used in SMS. It takes the path of the zipped database file as the single parameter. An."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-38130"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-38130, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-38130.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/server/service/smsConfigServiceHttpInvoker" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_38295_cuppacms {
    meta:
        attack_type = "cve_2022_38295"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Cuppa CMS v1.0 - Cross Site Scripting: Cuppa CMS v1.0 was discovered to contain a cross-site scripting vulnerability at /table_manager/view/cu_user_groups. This vulnerability allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Name."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-38295"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-38295, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-38295.yaml"
        response_type = "xss"
    strings:
        $path0 = "/components/table_manager/classes/functions.php" ascii nocase
        $param0 = "function=saveAdminTable" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_38296_cuppacms {
    meta:
        attack_type = "cve_2022_38296"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cuppa CMS v1.0 - Arbitrary File Upload: Cuppa CMS v1.0 was discovered to contain an arbitrary file upload vulnerability via the File Manager."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-38296"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-38296, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-38296.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/js/jquery_file_upload/server/php/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_38463_servicenow {
    meta:
        attack_type = "cve_2022_38463"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ServiceNow - Cross-Site Scripting: ServiceNow through San Diego Patch 4b and Patch 6 contains a cross-site scripting vulnerability in the logout functionality, which can enable an unauthenticated remote attacker to execute arbitrary JavaScript."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-38463"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-38463, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-38463.yaml"
        response_type = "xss"
    strings:
        $path0 = "/logout_redirect.do" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_38467_crm_perks_forms {
    meta:
        attack_type = "cve_2022_38467"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "CRM Perks Forms < 1.1.1 - Cross Site Scripting: The plugin does not sanitise and escape some parameters from a sample file before outputting them back in the page, leading to Reflected Cross-Site Scripting"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-38467"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-38467, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-38467.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/crm-perks-forms/templates/sample_file.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_38627_emerge_e3_firmware {
    meta:
        attack_type = "cve_2022_38627"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Nortek Linear eMerge E3-Series - SQL Injection: Nortek Linear eMerge E3-Series 0.32-08f, 0.32-07p, 0.32-07e, 0.32-09c, 0.32-09b, 0.32-09a, and 0.32-08e were discovered to contain a SQL injection vulnerability via the idt parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-38627"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-38627, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-38627.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/badging/badge_template_print.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_38812_aerocms {
    meta:
        attack_type = "cve_2022_38812"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "AeroCMS 0.1.1 - SQL Injection: AeroCMS 0.1.1 contains a SQL injection caused by unsanitized author parameter, letting attackers execute arbitrary SQL commands, exploit requires crafted author input."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-38812"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-38812, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-38812.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/author_posts.php" ascii nocase
        $path1 = "/cms/author_posts.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_38817_dapr_dashboard {
    meta:
        attack_type = "cve_2022_38817"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dapr Dashboard 0.1.0-0.10.0 - Improper Access Control: Dapr Dashboard 0.1.0 through 0.10.0 is susceptible to improper access control. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-38817"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-38817, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-38817.yaml"
    strings:
        $path0 = "/components/statestore" ascii nocase
        $path1 = "/controlplane" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_38840_man_eam_0003 {
    meta:
        attack_type = "cve_2022_38840"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Gralp MAN-EAM-0003 3.2.4 - XML External Entity (XXE): cgi-bin/xmlstatus.cgi in Gralp MAN-EAM-0003 3.2.4 is vulnerable to an XML External Entity (XXE) issue via XML file upload, which leads to local file disclosure."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-38840"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-38840, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-38840.yaml"
    strings:
        $path0 = "/cgi-bin/xmlstatus.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_38870_free5gc {
    meta:
        attack_type = "cve_2022_38870"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Free5gc 3.2.1 - Information Disclosure: Free5gc 3.2.1 is susceptible to information disclosure. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-38870"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-38870, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-38870.yaml"
    strings:
        $path0 = "/api/subscriber" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_39048_servicenow {
    meta:
        attack_type = "cve_2022_39048"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ServiceNow - Cross-site Scripting: A XSS vulnerability was identified in the ServiceNow UI page assessment_redirect. To exploit this vulnerability, an attacker would need to persuade an authenticated user to click a maliciously crafted URL. Successful exploitation potentially."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-39048"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-39048, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-39048.yaml"
        response_type = "xss"
    strings:
        $path0 = "/navpage.do" ascii nocase
        $path1 = "/assessment_redirect.do" ascii nocase
        $param0 = "screensize=1920x1080" ascii nocase
        $param1 = "sys_action=sysverb_login" ascii nocase
        $param2 = "sysparm_login_url=welcome.do" ascii nocase
        $param3 = "sysparm_survey_url=javascript:alert(document.domain)//assessment_take2.do" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_3908_helloprint {
    meta:
        attack_type = "cve_2022_3908"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Helloprint <1.4.7 - Cross-Site Scripting: WordPress Helloprint plugin before 1.4.7 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape a parameter before outputting it back in the page. An attacker can inject arbitrary script in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-3908"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-3908, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-3908.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=language-translate.php" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_39195_listserv {
    meta:
        attack_type = "cve_2022_39195"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LISTSERV 17 - Cross-Site Scripting: LISTSERV 17 web interface contains a cross-site scripting vulnerability. An attacker can inject arbitrary JavaScript or HTML via the 'c' parameter, thereby possibly allowing the attacker to steal cookie-based authentication credentials and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-39195"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-39195, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-39195.yaml"
        response_type = "xss"
    strings:
        $path0 = "/scripts/wa-HAP.exe" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_3933_essential_real_estate {
    meta:
        attack_type = "cve_2022_3933"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Essential Real Estate <3.9.6 - Authenticated Cross-Site Scripting: WordPress Essential Real Estate plugin before 3.9.6 contains an authenticated cross-site scripting vulnerability. The plugin does not sanitize and escape some parameters, which can allow someone with a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-3933"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-3933, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-3933.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=ere_property_gallery_fillter_ajax" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_3982_booking_calendar {
    meta:
        attack_type = "cve_2022_3982"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Booking Calendar <3.2.2 - Arbitrary File Upload: WordPress Booking Calendar plugin before 3.2.2 is susceptible to arbitrary file upload possibly leading to remote code execution. The plugin does not validate uploaded files, which can allow an attacker to upload."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-3982"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-3982, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-3982.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/uploads/booking_calendar/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_39952_fortinac {
    meta:
        attack_type = "cve_2022_39952"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Fortinet FortiNAC - Arbitrary File Write: Fortinet FortiNAC is susceptible to arbitrary file write. An external control of the file name or path can allow an attacker to execute unauthorized code or commands via specifically crafted HTTP request, thus making it possible to."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-39952"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-39952, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-39952.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/configWizard/keyUpload.jsp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_39960_group_export {
    meta:
        attack_type = "cve_2022_39960"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jira Netic Group Export <1.0.3 - Missing Authorization: Jira Netic Group Export add-on before 1.0.3 contains a missing authorization vulnerability. The add-on does not perform authorization checks, which can allow an unauthenticated user to export all groups from the Jira."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-39960"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-39960, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-39960.yaml"
    strings:
        $path0 = "/plugins/servlet/groupexportforjira/admin/json" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_39986_raspap {
    meta:
        attack_type = "cve_2022_39986"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "RaspAP 2.8.7 - Unauthenticated Command Injection: A Command injection vulnerability in RaspAP 2.8.0 thru 2.8.7 allows unauthenticated attackers to execute arbitrary commands via the cfg_id parameter in /ajax/openvpn/activate_ovpncfg.php and /ajax/openvpn/del_ovpncfg.php."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-39986"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-39986, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-39986.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/ajax/openvpn/del_ovpncfg.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_40022_syncserver_s650 {
    meta:
        attack_type = "cve_2022_40022"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Symmetricom SyncServer Unauthenticated - Remote Command Execution: Microchip Technology (Microsemi) SyncServer S650 was discovered to contain a command injection vulnerability."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-40022"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-40022, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-40022.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/controller/ping.php" ascii nocase
        $param0 = "currentTab=ping" ascii nocase
        $param1 = "pingType=ping" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_40443_zzcms {
    meta:
        attack_type = "cve_2022_40443"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "ZZCMS 2022 - Path Information Disclosure: An absolute path traversal vulnerability in ZZCMS 2022 allows attackers to obtain sensitive information via a crafted GET request."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-40443"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-40443, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-40443.yaml"
    strings:
        $path0 = "/one/siteinfo.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_4057_autooptimize {
    meta:
        attack_type = "cve_2022_4057"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Autoptimize < 3.1.0 - Information Disclosure: The Autoptimize WordPress plugin before 3.1.0 uses an easily guessable path to store plugin's exported settings and logs."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4057"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4057, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4057.yaml"
    strings:
        $path0 = "/wp-content/uploads/ao_ccss/queuelog.html" ascii nocase
        $path1 = "/blog/wp-content/uploads/ao_ccss/queuelog.html" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_4060_user_post_gallery {
    meta:
        attack_type = "cve_2022_4060"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress User Post Gallery <=2.19 - Remote Code Execution: WordPress User Post Gallery plugin through 2.19 is susceptible to remote code execution. The plugin does not limit which callback functions can be called by users, making it possible for an attacker execute malware."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4060"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4060, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4060.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "action=upg_datatable" ascii nocase
        $param1 = "field=field:exec:head -1 /etc/passwd:NULL:NULL" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_4063_inpost_gallery {
    meta:
        attack_type = "cve_2022_4063"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress InPost Gallery <2.1.4.1 - Local File Inclusion: WordPress InPost Gallery plugin before 2.1.4.1 is susceptible to local file inclusion. The plugin insecurely uses PHP's extract() function when rendering HTML views, which can allow attackers to force inclusion of."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4063"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4063, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4063.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "action=inpost_gallery_get_gallery" ascii nocase
        $param1 = "popup_shortcode_key=inpost_fancy" ascii nocase
        $param2 = "popup_shortcode_attributes=eyJwYWdlcGF0aCI6ICJmaWxlOi8vL2V0Yy9wYXNzd2QifQ==" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_40734_laravel_filemanager {
    meta:
        attack_type = "cve_2022_40734"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Laravel Filemanager v2.5.1 - Local File Inclusion: Laravel Filemanager (aka UniSharp) through version 2.5.1 is vulnerable to local file inclusion via download?working_dir=%2F."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-40734"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-40734, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-40734.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/laravel-filemanager/download" ascii nocase
        $param0 = "working_dir=/../../../../../../../../../../../../../../../../../../../etc" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_40843_ac1200_v_w15ev2 {
    meta:
        attack_type = "cve_2022_40843"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Tenda AC1200 V-W15Ev2 - Authentication Bypass: The Tenda AC1200 V-W15Ev2 router is affected by improper authorization/improper session management. The software does not perform or incorrectly perform an authorization check when a user attempts to access a resource or perform an."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-40843"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-40843, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-40843.yaml"
    strings:
        $path0 = "/goform/downloadSyslog/syslog.log" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_40881_solarview_compact {
    meta:
        attack_type = "cve_2022_40881"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SolarView 6.00 - Remote Command Execution: SolarView Compact 6.00 is vulnerable to a command injection via network_test.php."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-40881"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-40881, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-40881.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/network_test.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_4117_iws_geo_form_fields {
    meta:
        attack_type = "cve_2022_4117"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress IWS Geo Form Fields <=1.0 - SQL Injection: WordPress IWS Geo Form Fields plugin through 1.0 contains a SQL injection vulnerability. The plugin does not properly escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4117"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4117, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4117.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "country_id=1 AND (SELECT 42 FROM (SELECT(SLEEP(6)))b)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_4140_welcart_e_commerce {
    meta:
        attack_type = "cve_2022_4140"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Welcart e-Commerce <2.8.5 - Arbitrary File Access: WordPress Welcart e-Commerce plugin before 2.8.5 is susceptible to arbitrary file access. The plugin does not validate user input before using it to output the content of a file, which can allow an attacker to read."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4140"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4140, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4140.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/usc-e-shop/functions/content-log.php" ascii nocase
        $param0 = "logfile=/etc/passwd" ascii nocase
        $param1 = "logfile=/Windows/win.ini" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_41412_perfsonar {
    meta:
        attack_type = "cve_2022_41412"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "perfSONAR 4.x <= 4.4.4 - Server-Side Request Forgery: An issue in the graphData.cgi component of perfSONAR v4.4.5 and prior allows attackers to access sensitive data and execute Server-Side Request Forgery (SSRF) attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-41412"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-41412, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-41412.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/perfsonar-graphs/cgi-bin/graphData.cgi" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_41441_reqlogic {
    meta:
        attack_type = "cve_2022_41441"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ReQlogic v11.3 - Cross Site Scripting: ReQlogic v11.3 allow attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the POBatch and WaitDuration parameters."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-41441"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-41441, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-41441.yaml"
        response_type = "xss"
    strings:
        $path0 = "/ProcessWait.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_41678_apache_activemq_5_16_5_5_17_3 {
    meta:
        attack_type = "cve_2022_41678"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache ActiveMQ < 5.16.5/5.17.3 - Remote Code Execution: Once an user is authenticated on Jolokia, he can potentially trigger arbitrary code execution. In details, in ActiveMQ configurations, jetty allows org.jolokia.http.AgentServlet to handler request to /api/jolokia."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-41678"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-41678, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-41678.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/jolokia/list/org.apache.logging.log4j2" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_41697_ghost {
    meta:
        attack_type = "cve_2022_41697"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ghost CMS - User Enumeration: Ghost CMS 5.9.4 contains a user enumeration vulnerability in the login functionality. The application reveals whether a user account exists through different error messages, allowing attackers to enumerate valid user accounts via specially-crafted."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-41697"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-41697, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-41697.yaml"
    strings:
        $path0 = "/ghost/api/admin/session" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_41800_big_ip_access_policy_manager {
    meta:
        attack_type = "cve_2022_41800"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "F5 BIG-IP Appliance Mode - Command Injection: When running in Appliance mode, an authenticated user assigned the Administrator role may bypass Appliance mode restrictions, utilizing an undisclosed iControl REST endpoint."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-41800"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-41800, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-41800.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/mgmt/shared/iapp/rpm-spec-creator" ascii nocase
        $path1 = "/mgmt/shared/iapp/build-package" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_41840_welcart_e_commerce {
    meta:
        attack_type = "cve_2022_41840"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Welcart eCommerce <=2.7.7 - Local File Inclusion: Welcart eCommerce 2.7.7 and before are vulnerable to unauthenticated local file inclusion."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-41840"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-41840, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-41840.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/plugins/usc-e-shop/functions/progress-check.php" ascii nocase
        $param0 = "progressfile=../../../../../../../../../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_42095_backdrop_cms {
    meta:
        attack_type = "cve_2022_42095"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Backdrop CMS version 1.23.0 - Cross Site Scripting (Stored): Backdrop CMS version 1.23.0 was discovered to contain a stored cross-site scripting (XSS) vulnerability via the Page content."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-42095"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-42095, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-42095.yaml"
        response_type = "xss"
    strings:
        $param0 = "scheduled[date]=2023-04-14" ascii nocase
        $param1 = "scheduled[time]=21:00:54" ascii nocase
        $param2 = "date[date]=2023-04-13" ascii nocase
        $param3 = "date[time]=21:00:54" ascii nocase
        $param4 = "menu[parent]=main-menu:0" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_42118_liferay_portal {
    meta:
        attack_type = "cve_2022_42118"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Liferay Portal - Cross-site Scripting: A Cross-site scripting (XSS) vulnerability in the Portal Search module in Liferay Portal 7.1.0 through 7.4.2, and Liferay DXP 7.1 before fix pack 27, 7.2 before fix pack 15, and 7.3 before service pack 3 allows remote attackers to inject."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-42118"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-42118, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-42118.yaml"
        response_type = "xss"
    strings:
        $path0 = "/web/guest/home" ascii nocase
        $param0 = "p_p_id=com_liferay_portal_search_web_portlet_SearchPortlet" ascii nocase
        $param1 = "_com_liferay_portal_search_web_portlet_SearchPortlet_scope=this-site" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_4223_pgadmin_6_17 {
    meta:
        attack_type = "cve_2022_4223"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "pgAdmin < 6.17 - Unauthenticated Remote Code Execution: pgAdmin prior to 6.17 contains an insecure HTTP API caused by improper access control, letting unauthenticated users execute arbitrary external utilities via path manipulation, exploit requires no authentication."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4223"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4223, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4223.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/misc/validate_binary_path" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_4260_wp_ban {
    meta:
        attack_type = "cve_2022_4260"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress WP-Ban <1.69.1 - Stored Cross-Site Scripting: WordPress WP-Ban plugin before 1.69.1 contains a stored cross-site scripting vulnerability. The plugin does not sanitize and escape some of its settings, which can allow high-privilege users to steal cookie-based."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4260"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4260, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4260.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=wp-ban/ban-options.php" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_43016_opencats {
    meta:
        attack_type = "cve_2022_43016"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "OpenCATS 0.9.6 - Cross-Site Scripting: OpenCATS 0.9.6 contains a cross-site scripting vulnerability via the callback component. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-43016"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-43016, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-43016.yaml"
        response_type = "xss"
    strings:
        $param0 = "a=authenticate" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_43018_opencats {
    meta:
        attack_type = "cve_2022_43018"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "OpenCATS 0.9.6 - Cross-Site Scripting: OpenCATS 0.9.6 contains a cross-site scripting vulnerability via the email parameter in the Check Email function. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-43018"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-43018, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-43018.yaml"
        response_type = "xss"
    strings:
        $param0 = "a=checkEmailIsInSystem" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_4305_login_as_user_or_customer_user {
    meta:
        attack_type = "cve_2022_4305"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Login as User or Customer < 3.3 - Privilege Escalation: The plugin lacks authorization checks to ensure that users are allowed to log in as another one, which could allow unauthenticated attackers to obtain a valid admin session."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4305"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4305, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4305.yaml"
    strings:
        $param0 = "action=loginas_return_admin" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_4306_panda_pods_repeater_field {
    meta:
        attack_type = "cve_2022_4306"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Panda Pods Repeater Field <1.5.4 - Cross-Site Scripting: WordPress Panda Pods Repeater Field before 1.5.4 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape a parameter before outputting it back in the page. This can be leveraged."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4306"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4306, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4306.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/panda-pods-repeater-field/fields/pandarepeaterfield.php" ascii nocase
        $param0 = "podid=1); alert(document.domain);/*x" ascii nocase
        $param1 = "iframe_id=panda-repeater-add-new" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_43167_rukovoditel {
    meta:
        attack_type = "cve_2022_43167"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Rukovoditel <= 3.2.1 - Cross Site Scripting: A stored cross-site scripting (XSS) vulnerability in the Users Alerts feature (/index.php?module=users_alerts/users_alerts) of Rukovoditel v3.2.1 allows authenticated attackers to execute arbitrary web scripts or HTML via a crafted."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-43167"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-43167, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-43167.yaml"
        response_type = "xss"
    strings:
        $param0 = "type=warning" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_43170_rukovoditel {
    meta:
        attack_type = "cve_2022_43170"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Rukovoditel <= 3.2.1 - Cross Site Scripting: A stored cross-site scripting (XSS) vulnerability in the Dashboard Configuration feature (index.php?module=dashboard_configure/index) of Rukovoditel v3.2.1 allows authenticated attackers to execute arbitrary web scripts or HTML via a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-43170"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-43170, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-43170.yaml"
        response_type = "xss"
    strings:
        $param0 = "module=dashboard_configure/index" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_43185_rukovoditel {
    meta:
        attack_type = "cve_2022_43185"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Rukovoditel <= 3.2.1 - Cross-Site Scripting: A stored cross-site scripting (XSS) vulnerability in the Global Lists feature (/index.php?module=global_lists/lists) of Rukovoditel v3.2.1 allows authenticated attackers to execute arbitrary web scripts or HTML via a crafted payload."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-43185"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-43185, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-43185.yaml"
        response_type = "xss"
    strings:
        $param0 = "module=holidays/holidays" ascii nocase
        $param1 = "start_date=2023-05-22" ascii nocase
        $param2 = "end_date=2023-05-31" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_4320_wordpress_events_calendar_plug {
    meta:
        attack_type = "cve_2022_4320"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Events Calendar <1.4.5 - Cross-Site Scripting: WordPress Events Calendar plugin before 1.4.5 contains multiple cross-site scripting vulnerabilities. The plugin does not sanitize and escape a parameter before outputting it back in the page. An attacker can inject."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4320"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4320, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4320.yaml"
        response_type = "xss"
    strings:
        $param0 = "subaction=cd_calendar" ascii nocase
        $param1 = "subaction=cd_dismisshint" ascii nocase
        $param2 = "subaction=cd_displayday" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_4321_pdf_generator_for_wordpress {
    meta:
        attack_type = "cve_2022_4321"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PDF Generator for WordPress < 1.1.2 - Cross Site Scripting: The plugin includes a vendored dompdf example file which is susceptible to Reflected Cross-Site Scripting and could be used against high privilege users such as admin"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4321"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4321, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4321.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/pdf-generator-for-wp/package/lib/dompdf/vendor/dompdf/dompdf/I18N/Arabic/Examples/Query.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_4325_post_status_notifier_lite {
    meta:
        attack_type = "cve_2022_4325"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Post Status Notifier Lite <1.10.1 - Cross-Site Scripting: WordPress Post Status Notifier Lite plugin before 1.10.1 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape a parameter before outputting it back in the page. An attacker can."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4325"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4325, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4325.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=post-status-notifier-lite" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_4375_mcms {
    meta:
        attack_type = "cve_2022_4375"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Mingsoft MCMS - SQL Injection: SQL injection vulnerability in Mingsoft MCMS up to 5.2.9 via the sqlWhere parameter in /cms/category/list."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4375"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4375, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4375.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/cms/category/list" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_43939_vantara_pentaho_business_analy {
    meta:
        attack_type = "cve_2022_43939"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Hitachi Pentaho Business Analytics Server - Bypass Authorization: Hitachi Vantara Pentaho Business Analytics Server versions before 9.4.0.1 and 9.3.0.2, including 8.3.x contain security restrictions using non-canonical URLs which can be circumvented."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-43939"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-43939, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-43939.yaml"
    strings:
        $path0 = "/pentaho/Login" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_44944_rukovoditel {
    meta:
        attack_type = "cve_2022_44944"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Rukovoditel <= 3.2.1 - Cross Site Scripting: Rukovoditel v3.2.1 was discovered to contain a stored cross-site scripting (XSS) vulnerability in the Add Announcement function at /index.php?module=help_pages/pages&entities_id=24. This vulnerability allows attackers to execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-44944"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-44944, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-44944.yaml"
        response_type = "xss"
    strings:
        $param0 = "type=announcement" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_44946_rukovoditel {
    meta:
        attack_type = "cve_2022_44946"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Rukovoditel <= 3.2.1 - Cross-Site Scripting: Rukovoditel v3.2.1 was discovered to contain a stored cross-site scripting (XSS) vulnerability in the Add Page function at /index.php?module=help_pages/pages&entities_id=24. This vulnerability allows attackers to execute arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-44946"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-44946, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-44946.yaml"
        response_type = "xss"
    strings:
        $param0 = "position=listing" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_44947_rukovoditel {
    meta:
        attack_type = "cve_2022_44947"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Rukovoditel <= 3.2.1 - Cross Site Scripting: Rukovoditel v3.2.1 was discovered to contain a stored cross-site scripting (XSS) vulnerability in the Highlight Row feature at /index.php?module=entities/listing_types&entities_id=24. This vulnerability allows attackers to execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-44947"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-44947, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-44947.yaml"
        response_type = "xss"
    strings:
        $param0 = "module=entities/listing_highlight" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_44948_rukovoditel {
    meta:
        attack_type = "cve_2022_44948"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Rukovoditel <= 3.2.1 - Cross-Site Scripting: Rukovoditel v3.2.1 was discovered to contain a stored cross-site scripting (XSS) vulnerability in the Entities Group feature at/index.php?module=entities/entities_groups. This vulnerability allows attackers to execute arbitrary web."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-44948"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-44948, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-44948.yaml"
        response_type = "xss"
    strings:
        $param0 = "module=entities/entities_groups" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_44951_rukovoditel {
    meta:
        attack_type = "cve_2022_44951"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Rukovoditel <= 3.2.1 - Cross Site Scripting: Rukovoditel v3.2.1 was discovered to contain a stored cross-site scripting (XSS) vulnerability in the Add New Form tab function at /index.php?module=entities/forms&entities_id=24. This vulnerability allows attackers to execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-44951"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-44951, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-44951.yaml"
        response_type = "xss"
    strings:
        $param0 = "module=entities/forms" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_45038_wbce_cms {
    meta:
        attack_type = "cve_2022_45038"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WBCE CMS v1.5.4 - Cross Site Scripting (Stored): A cross-site scripting (XSS) vulnerability in /admin/settings/save.php of WBCE CMS v1.5.4 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Website Footer field."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-45038"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-45038, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-45038.yaml"
        response_type = "xss"
    strings:
        $param0 = "wbmailer_default_sendername=WBCE CMS Mailer" ascii nocase
        $param1 = "wbmailer_routine=phpmail" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_45354_download_monitor {
    meta:
        attack_type = "cve_2022_45354"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Download Monitor <= 4.7.60 - Sensitive Information Exposure: The Download Monitor plugin for WordPress is vulnerable to Sensitive Information Exposure in versions up to, and including, 4.7.60 via REST API. This can allow unauthenticated attackers to extract sensitive data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-45354"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-45354, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-45354.yaml"
    strings:
        $path0 = "/wp-json/download-monitor/v1/user_data" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_45362_payment_gateway {
    meta:
        attack_type = "cve_2022_45362"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Paytm Payment Gateway <=2.7.0 - Server-Side Request Forgery: WordPress Paytm Payment Gateway plugin through 2.7.0 contains a server-side request forgery vulnerability. An attacker can cause a website to execute website requests to an arbitrary domain, thereby making."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-45362"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-45362, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-45362.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = "paytm_action=curltest" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_45365_stock_ticker {
    meta:
        attack_type = "cve_2022_45365"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Stock Ticker <= 3.23.2 - Cross-Site-Scripting: The Stock Ticker plugin for WordPress is vulnerable to Reflected Cross-Site Scripting in the ajax_stockticker_symbol_search_test function in versions up to, and including, 3.23.2 due to insufficient input sanitization and output."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-45365"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-45365, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-45365.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=stockticker_symbol_search_test" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_45808_learnpress {
    meta:
        attack_type = "cve_2022_45808"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LearnPress Plugin < 4.2.0 - Unauthenticated Time-Based Blind SQLi: SQL Injection vulnerability in LearnPress WordPress LMS Plugin <= 4.1.7.3.2 versions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-45808"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-45808, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-45808.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "order_by=ID AND (SELECT 1471 FROM (SELECT(SLEEP(6)))VcSO)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_45835_phonepe {
    meta:
        attack_type = "cve_2022_45835"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress PhonePe Payment Solutions <=1.0.15 - Server-Side Request Forgery: WordPress PhonePe Payment Solutions plugin through 1.0.15 is susceptible to server-side request forgery. An attacker can cause a website to execute website requests to an arbitrary domain, thereby."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-45835"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-45835, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-45835.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = "phonepe_action=curltestPhonePe" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_45917_ilias {
    meta:
        attack_type = "cve_2022_45917"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ILIAS eLearning <7.16 - Open Redirect: ILIAS eLearning before 7.16 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-45917"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-45917, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-45917.yaml"
        response_type = "xss"
    strings:
        $path0 = "/ilias/shib_logout.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_45933_kubeview {
    meta:
        attack_type = "cve_2022_45933"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "KubeView <=0.1.31 - Information Disclosure: KubeView through 0.1.31 is susceptible to information disclosure. An attacker can obtain control of a Kubernetes cluster because api/scrape/kube-system does not require authentication and retrieves certificate files that can be used."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-45933"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-45933, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-45933.yaml"
    strings:
        $path0 = "/api/scrape/kube-system" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_46020_wbce_cms {
    meta:
        attack_type = "cve_2022_46020"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WBCE CMS v1.5.4 - Remote Code Execution: WBCE CMS v1.5.4 can implement getshell by modifying the upload file type."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-46020"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-46020, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-46020.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/modules/elfinder/ef/php/connector.wbce.php" ascii nocase
        $param0 = "wysiwyg_editor=ckeditor" ascii nocase
        $param1 = "default_charset=utf-8" ascii nocase
        $param2 = "pages_directory=/pages" ascii nocase
        $param3 = "media_directory=/media" ascii nocase
        $param4 = "page_extension=.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_46169_cacti {
    meta:
        attack_type = "cve_2022_46169"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Cacti <=1.2.22 - Remote Command Injection: Cacti through 1.2.22 is susceptible to remote command injection. There is insufficient authorization within the remote agent when handling HTTP requests with a custom Forwarded-For HTTP header. An attacker can send a specially crafted."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-46169"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-46169, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-46169.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/remote_agent.php" ascii nocase
        $param0 = "action=polldata" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_46443_bangresto {
    meta:
        attack_type = "cve_2022_46443"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Bangresto - SQL Injection: Bangresto 1.0 is vulnberable to SQL Injection via the itemqty%5B%5D parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-46443"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-46443, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-46443.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/bangresto-main/staff/process.php" ascii nocase
        $path1 = "/bangresto-main/staff/insertorder.php" ascii nocase
        $param0 = "sentorder=Sent to kitchen" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_46934_kkfileview {
    meta:
        attack_type = "cve_2022_46934"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "kkFileView 4.1.0 - Cross-Site Scripting: kkFileView 4.1.0 is susceptible to cross-site scripting via the url parameter at /controller/OnlinePreviewController.java. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-46934"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-46934, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-46934.yaml"
        response_type = "xss"
    strings:
        $param0 = "currentUrl=aHR0cDovLyIpO2FsZXJ0KGRvY3VtZW50LmRvbWFpbik7Ly8=" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_47075_smartoffice {
    meta:
        attack_type = "cve_2022_47075"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Smart Office Web 20.28 - Information Disclosure: An issue was discovered in Smart Office Web 20.28 and earlier allows attackers to download sensitive information via the action name parameter to ExportEmployeeDetails.aspx, and to ExportReportingManager.aspx."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-47075"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-47075, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-47075.yaml"
    strings:
        $path0 = "/ExportReportingManager.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_47501_ofbiz {
    meta:
        attack_type = "cve_2022_47501"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache OFBiz < 18.12.07 - Local File Inclusion: Arbitrary file reading vulnerability in Apache Software Foundation Apache OFBiz when using the Solr plugin. This is a pre-authentication attack. This issue affects Apache OFBiz: before 18.12.07."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-47501"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-47501, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-47501.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/solr/solrdefault/debug/dump" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_47615_learnpress {
    meta:
        attack_type = "cve_2022_47615"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LearnPress Plugin < 4.2.0 - Local File Inclusion: Local File Inclusion vulnerability in LearnPress WordPress LMS Plugin <= 4.1.7.3.2 versions."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-47615"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-47615, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-47615.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "template_path=../../../etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_47945_thinkphp {
    meta:
        attack_type = "cve_2022_47945"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Thinkphp Lang - Local File Inclusion: ThinkPHP Framework before 6.0.14 allows local file inclusion via the lang parameter when the language pack feature is enabled (lang_switch_on=true). An unauthenticated and remote attacker can exploit this to execute arbitrary operating."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-47945"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-47945, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-47945.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "lang=../../thinkphp/base" ascii nocase
        $param1 = "lang=../../../../../vendor/topthink/think-trace/src/TraceDebug" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_47966_manageengine_access_manager_pl {
    meta:
        attack_type = "cve_2022_47966"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "ManageEngine - Remote Command Execution: Multiple Zoho ManageEngine on-premise products, such as ServiceDesk Plus through 14003, allow remote code execution due to use of Apache xmlsec (aka XML Security for Java) 1.4.1, because the xmlsec XSLT features, by design in that."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-47966"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-47966, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-47966.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/SamlResponseServlet" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_47986_linux_kernel {
    meta:
        attack_type = "cve_2022_47986"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "IBM Aspera Faspex <=4.4.2 PL1 - Remote Code Execution: IBM Aspera Faspex through 4.4.2 Patch Level 1 is susceptible to remote code execution via a YAML deserialization flaw. This can allow an attacker to send a specially crafted obsolete API call and thereby execute arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-47986"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-47986, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-47986.yaml"
    strings:
        $path0 = "/aspera/faspex/package_relay/relay_package" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2022_48323_sunflower {
    meta:
        attack_type = "cve_2022_48323"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Sunflower Simple and Personal 1.0.1.43315 - Remote Code Execution: Sunlogin Sunflower Simplified (aka Sunflower Simple and Personal) 1.0.1.43315 is vulnerable to a path traversal issue. A remote and unauthenticated attacker can execute arbitrary programs on the victim host by."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-48323"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-48323, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-48323.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "cmd=ping../../../windows/system32/windowspowershell/v1.0/powershell.exe ipconfig" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_4897_backupbuddy {
    meta:
        attack_type = "cve_2022_4897"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress BackupBuddy <8.8.3 - Cross Site Scripting: WordPress BackupBuddy plugin before 8.8.3 contains a cross-site vulnerability. The plugin does not sanitize and escape some parameters before outputting them back in various locations. An attacker can inject arbitrary script."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4897"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4897, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4897.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=pb_backupbuddy_backupbuddy" ascii nocase
        $param1 = "function=destination_picker" ascii nocase
        $param2 = "filter=local" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2022_4940_wcfm_membership {
    meta:
        attack_type = "cve_2022_4940"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WCFM Membership <= 2.10.0 - Broken Access Control: The WCFM Membership plugin for WordPress is vulnerable to unauthorized modification and access of data in versions up to, and including, 2.10.0 due to missing capability checks true the AJAX actions: wcfm-memberships."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2022-4940"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-4940, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2022/CVE-2022-4940.yaml"
    strings:
        $param0 = "action=wcfm_ajax_controller" ascii nocase
        $param1 = "controller=wcfm-memberships" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}
