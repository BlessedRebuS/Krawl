// Baseline rules generated from public exploit and exposure checks in
// ProjectDiscovery nuclei-templates (MIT License,
// https://github.com/projectdiscovery/nuclei-templates). Each rule keys on the
// most specific request indicator of one check: a path, a static parameter or
// a vendor header that no other check and no benign request uses. Rules are
// confidence = "medium": a probe for the endpoint is a strong signal, but a
// rule cannot tell an exploit attempt from a scanner fingerprinting it.
// The `reference` field links the source check.

rule krawl_cve_2025_0107_palo_alto_networks_expedition {
    meta:
        attack_type = "cve_2025_0107"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Palo Alto Networks Expedition - OS Command Injection: An OS command injection vulnerability in Palo Alto Networks Expedition enables an unauthenticated attacker to run arbitrary OS commands as the www-data user in Expedition, which results in the disclosure of usernames."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-0107"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-0107, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-0107.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/API/regionsDiscovery.php" ascii nocase
        $param0 = "project=your_project" ascii nocase
        $param1 = "devices=device1,device2" ascii nocase
        $param2 = "mtserver=127.0.0.1:3306" ascii nocase
        $param3 = "mtpassword=paloalto" ascii nocase
        $param4 = "mode=pre-analysis" ascii nocase
        $param5 = "parquetPath=/tmp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_0133_pan_os {
    meta:
        attack_type = "cve_2025_0133"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PAN-OS - Reflected Cross-Site Scripting: A reflected cross-site scripting (XSS) vulnerability in the GlobalProtect gateway and portal features of Palo Alto Networks PAN-OS software enables execution of malicious JavaScript in the context of an authenticated Captive Portal."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-0133"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-0133, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-0133.yaml"
        response_type = "xss"
    strings:
        $path0 = "/ssl-vpn/getconfig.esp" ascii nocase
        $param0 = "app-version=3.0.1-10" ascii nocase
        $param1 = "clientos=Linux" ascii nocase
        $param2 = "os-version=linux-64" ascii nocase
        $param3 = "hmac-algo=sha1,md5" ascii nocase
        $param4 = "enc-algo=aes-128-cbc,aes-256-cbc" ascii nocase
        $param5 = "authcookie=12cea70227d3aafbf25082fac1b6f51d" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_0520_showdoc {
    meta:
        attack_type = "cve_2025_0520"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ShowDoc - Remote Code Execution: The open-source API documentation tool ShowDoc had a remote code execution vulnerability before version 2.8.7 This vulnerability allowed unauthenticated remote attackers to upload .php files because the image upload function was not."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-0520"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-0520, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-0520.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "s=/home/page/uploadImg" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_0674_elber_ese_dvb_s_s2 {
    meta:
        attack_type = "cve_2025_0674"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Elber ESE DVB-S/S2 - Authentication Bypass: Multiple Elber products are affected by an authentication bypass vulnerability which allows unauthorized access to the password management functionality. Attackers can exploit this issue by manipulating the endpoint to overwrite any."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-0674"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-0674, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-0674.yaml"
    strings:
        $param0 = "pass=admin1234" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_0868_docsgpt {
    meta:
        attack_type = "cve_2025_0868"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "DocsGPT - Unauthenticated Remote Code Execution: A vulnerability, that could result in Remote Code Execution (RCE), has been found in DocsGPT. Due to improper parsing of JSON data using eval() an unauthorized attacker could send arbitrary Python code to be executed via."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-0868"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-0868, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-0868.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/remote" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_10035_goanywhere {
    meta:
        attack_type = "cve_2025_10035"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "GoAnywhere - Authentication Bypass: Fortra GoAnywhere MFT contains an insecure deserialization vulnerability in the License Servlet caused by deserializing attacker-controlled objects with a valid forged license response signature, letting attackers perform command injection."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-10035"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-10035, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-10035.yaml"
    strings:
        $path0 = "/goanywhere/license/Unlicensed.xhtml/" ascii nocase
        $path1 = "/license/Unlicensed.xhtml/" ascii nocase
        $param0 = "GARequestAction=activate" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_10162_wordpress_orderconvo_14 {
    meta:
        attack_type = "cve_2025_10162"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress OrderConvo < 14 - Path Traversal: WooCommerce OrderConvo WordPress plugin /u003C 14 contains a path traversal vulnerability caused by improper validation of file download paths, letting unauthenticated attackers read or download arbitrary files remotely"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-10162"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-10162, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-10162.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-json/wooconvo/v1/download-file" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_10204_ac_smart_ii {
    meta:
        attack_type = "cve_2025_10204"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AC Smart II - Authentication Bypass: AC Smart II contains an authentication bypass caused by a hidden password reset form that can be manipulated to change the administrator password without verifying login or permissions, letting attackers change admin passwords without."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-10204"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-10204, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-10204.yaml"
    strings:
        $path0 = "/Doc/WebLogin.asp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_10211_chancms_3_3_0 {
    meta:
        attack_type = "cve_2025_10211"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ChanCMS <= 3.3.0 - Server-Side Request Forgery: yanyutao0402 ChanCMS 3.3.0 contains a server-side request forgery caused by manipulation of the 'taskUrl' argument in /cms/collect/getArticle, letting remote attackers make arbitrary requests, exploit requires no special privileges."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-10211"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-10211, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-10211.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/cms/collect/getArticle" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_1023_churchcrm {
    meta:
        attack_type = "cve_2025_1023"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ChurchCRM - SQL Injection: A vulnerability exists in ChurchCRM 5.13.0 and prior that allows an attacker to execute arbitrary SQL queries by exploiting a time-based blind SQL Injection vulnerability in the EditEventTypes functionality. The newCountName parameter is directly."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-1023"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-1023, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-1023.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "newEvtStartTime=10:30:00" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_1025_cockpit_2_4_1 {
    meta:
        attack_type = "cve_2025_1025"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cockpit < 2.4.1 - Arbitrary File Upload: Versions of the package cockpit-hq/cockpit before 2.4.1 are vulnerable to Arbitrary File Upload where an attacker can use different extensions to bypass the upload filter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-1025"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-1025, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-1025.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/storage/uploads/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_1035_klog_server {
    meta:
        attack_type = "cve_2025_1035"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "KLog Server - Path Traversal: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Komtera Technolgies KLog Server allows Manipulating Web Input to File System Calls.This issue affects KLog Server: before 3.1.1."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-1035"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-1035, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-1035.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/actions/entree.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_10353_melis_platform {
    meta:
        attack_type = "cve_2025_10353"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Melis Technology Melis Platform - Unrestricted File Upload & Remote Code Execution: Melis Technology Melis Platform contains an unrestricted file upload caused by insufficient validation of 'mcsdetail_img' parameter in."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-10353"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-10353, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-10353.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/melis/MelisCmsSlider/MelisCmsSliderDetails/saveDetailsForm" ascii nocase
        $path1 = "/media/sliders/0/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_10897_woocommerce_designer_pro_1_9_2 {
    meta:
        attack_type = "cve_2025_10897"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WooCommerce Designer Pro <= 1.9.28 - Arbitrary File Read: WooCommerce Designer Pro theme for WordPress <= 1.9.28 contains an arbitrary file read vulnerability caused by improper input validation, letting unauthenticated attackers read arbitrary files including sensitive."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-10897"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-10897, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-10897.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "action=wcdp_convert_resource_cmyk" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_11307_wp_google_maps {
    meta:
        attack_type = "cve_2025_11307"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WP Google Maps < 9.0.48 - Cross-Site Scripting: WP Google Maps WordPress plugin < 9.0.48 contains a stored XSS vulnerability caused by unsanitized user input in AJAX actions, letting unauthenticated attackers execute scripts via stored payloads."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-11307"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-11307, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-11307.yaml"
        response_type = "xss"
    strings:
        $param0 = "action=wpgmza_store_nominatim_cache" ascii nocase
        $param1 = "action=wpgmza_query_nominatim_cache" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_11371_gladinet_centrestack_triofox {
    meta:
        attack_type = "cve_2025_11371"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Gladinet CentreStack & TrioFox - Local File Inclusion: In the default installation and configuration of Gladinet CentreStack and TrioFox, there is an unauthenticated Local File Inclusion Flaw that allows unintended disclosure of system files. Exploitation of this vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-11371"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-11371, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-11371.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/storage/t.dn" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_11693_export_wp_page_to_static_html {
    meta:
        attack_type = "cve_2025_11693"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Export WP Page to Static HTML <= 4.3.4 - Cookie Exposure: Export WP Page to Static HTML & PDF WordPress plugin <= 4.3.4 contains a sensitive information exposure caused by publicly exposed cookies.txt files with authentication cookies, letting unauthenticated attackers access."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-11693"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-11693, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-11693.yaml"
    strings:
        $path0 = "/wp-content/uploads/exported_html_files/cookie.txt" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_11700_n_central {
    meta:
        attack_type = "cve_2025_11700"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "N-central - XML External Entities Injection: N-central versions < 2025.4 are vulnerable to an XML External Entities injection leading to information disclosure."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-11700"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-11700, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-11700.yaml"
    strings:
        $path0 = "/dms/services/ServerMMS" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_11833_post_smtp_mailer {
    meta:
        attack_type = "cve_2025_11833"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Post SMTP <= 3.6.0 - Email Log Disclosure: Post SMTP WordPress plugin <= 3.6.0 contains an unauthorized data access vulnerability caused by missing capability check in __construct function, letting unauthenticated attackers read arbitrary logged emails, exploit requires no."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-11833"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-11833, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-11833.yaml"
    strings:
        $param0 = "page=postman_email_log" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_12055_mpdv_mikrolab_gmbh_hydra_x_mip {
    meta:
        attack_type = "cve_2025_12055"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MPDV Mikrolab GmbH HYDRA X, MIP 2 & FEDRA 2 - Path Traversal: MPDV Mikrolab GmbH HYDRA X, MIP 2, and FEDRA 2 <= Maintenance Pack 36 with Servicepack 8 (week 36/2025) contain an unauthenticated local file disclosure vulnerability caused by improper validation of the 'Filename'."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-12055"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-12055, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-12055.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/hx/resources/public/$SCHEMAS$" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_1232_site_reviews {
    meta:
        attack_type = "cve_2025_1232"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Site Reviews < 7.2.5 - Unauthenticated Stored XSS: Site Reviews WordPress plugin before 7.2.5 contains a stored cross-site scripting caused by improper sanitization and escaping of review fields, letting unauthenticated users execute malicious scripts, exploit requires no."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-1232"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-1232, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-1232.yaml"
        response_type = "xss"
    strings:
        $param0 = "site-reviews[_action]=submit-review" ascii nocase
        $param1 = "site-reviews[title]=Great Service" ascii nocase
        $param2 = "site-reviews[name]=TestReviewer" ascii nocase
        $param3 = "site-reviews[email]=reviewer@example.com" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_12480_triofox {
    meta:
        attack_type = "cve_2025_12480"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Triofox - Improper Access Control: The Gladinet Triofox solution before 12.91.1126.65588 and CentreStack before 12.10.595.65696 allow unauthenticated access to the /management/admindatabase.aspx endpoint, exposing sensitive database management functionality to anyone with."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-12480"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-12480, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-12480.yaml"
    strings:
        $path0 = "/management/admindatabase.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_1302_jsonpath_plus_10_3_0 {
    meta:
        attack_type = "cve_2025_1302"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JSONPath Plus < 10.3.0 - Remote Code Execution: Versions of the package jsonpath-plus before 10.3.0 are vulnerable to Remote Code Execution (RCE) due to improper input sanitization. An attacker can execute aribitrary code on the system by exploiting the unsafe default usage of."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-1302"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-1302, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-1302.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/expression" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_1303_plugin_oficial_getnet_para_woo {
    meta:
        attack_type = "cve_2025_1303"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Plugin Oficial Getnet para WooCommerce <= 1.8.0 - Cross-Site Scripting: The Plugin Oficial Getnet para WooCommerce plugin for WordPress is vulnerable to Reflected Cross-Site Scripting in all versions up to, and including, 1.8.0 due to insufficient input sanitization and output."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-1303"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-1303, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-1303.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/wc-checkout-getnet/views/partials/settings/privacy-policy.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_13138_wp_directory_kit_1_4_3 {
    meta:
        attack_type = "cve_2025_13138"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WP Directory Kit <= 1.4.3 - Unauthenticated SQL Injection: The WP Directory Kit plugin for WordPress is vulnerable to SQL Injection via the 'columns_search' parameter of the select_2_ajax() function in all versions up to, and including, 1.4.3 due to insufficient escaping on the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-13138"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-13138, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-13138.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "table=category_m" ascii nocase
        $param1 = "columns_search=category_title) AND (SELECT 1 FROM (SELECT(SLEEP(7)))a)-- -" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_13315_twonky_server_8_5_2_on_linux_a {
    meta:
        attack_type = "cve_2025_13315"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Twonky Server 8.5.2 on Linux and Windows - Log File Exposure: Twonky Server 8.5.2 contains a broken access control vulnerability caused by bypassing web service API authentication, letting unauthenticated attackers read log files with administrator credentials, exploit requires."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-13315"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-13315, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-13315.yaml"
    strings:
        $path0 = "/nmc/rpc/log_getfile" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_13339_hippoo_mobile_app_for_woocomme {
    meta:
        attack_type = "cve_2025_13339"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hippoo Mobile App for WooCommerce <= 1.7.1 - Unauthenticated Arbitrary File Read: The Hippoo Mobile App for WooCommerce plugin for WordPress is vulnerable to Path Traversal in all versions up to and including 1.7.1 via the template_redirect() function. The plugin registers."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-13339"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-13339, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-13339.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "hippoo_serve=../../../../../../../etc/passwd" ascii nocase
        $param1 = "hippoo_serve=../../../../wp-config.php" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_13342_frontend_admin {
    meta:
        attack_type = "cve_2025_13342"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "DynamiApps Frontend Admin <= 3.28.20 - Unauthenticated Arbitrary Options Update: DynamiApps Frontend Admin plugin for WordPress <.= 3.28.20 contains a broken access control vulnerability caused by insufficient capability checks and input validation in ActionOptions::run() save."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-13342"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-13342, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-13342.yaml"
    strings:
        $param0 = "action=frontend_admin/form_submit" ascii nocase
        $param1 = "acff[admin_options][default_role]=administrator" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_1338_nuuo_camera_20250203 {
    meta:
        attack_type = "cve_2025_1338"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "NUUO Camera <=20250203 - OS Command Injection: NUUO Camera up to 20250203 contains a command injection caused by manipulation of the 'log' argument in /handle_config.php, letting remote attackers execute arbitrary commands, exploit requires remote access."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-1338"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-1338, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-1338.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/handle_config.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_13390_wp_directory_kit_1_4_4 {
    meta:
        attack_type = "cve_2025_13390"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WP Directory Kit <= 1.4.4 - Authentication Bypass: The WP Directory Kit plugin for WordPress version 1.4.4 and below contains an authentication bypass vulnerability in its auto-login functionality. The vulnerability allows unauthenticated attackers to gain administrative access."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-13390"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-13390, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-13390.yaml"
    strings:
        $param0 = "token=c4ca4238a0" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_13418_responsive_pricing_table {
    meta:
        attack_type = "cve_2025_13418"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Responsive Pricing Table <= 5.1.12 - Cross-Site Scripting: The Responsive Pricing Table plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'plan_icons' parameter in all versions up to, and including, 5.1.12 due to insufficient input sanitization and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-13418"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-13418, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-13418.yaml"
        response_type = "xss"
    strings:
        $param0 = "post_type=rpt_pricing_table" ascii nocase
        $param1 = "post_title=CVE-2025-13418 XSS Test" ascii nocase
        $param2 = "publish=Publish" ascii nocase
        $param3 = "plan_titles[]=XSS Test Plan" ascii nocase
        $param4 = "plan_features[]=Feature" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_13486_advanced_custom_fields_extende {
    meta:
        attack_type = "cve_2025_13486"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Advanced Custom Fields Extended < 0.9.2 - Remote Code Execution: Advanced Custom Fields: Extended WordPress plugin 0.9.0.5 through 0.9.1.1 contains a remote code execution caused by unsafe use of call_user_func_array() in prepare_form() function, letting unauthenticated."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-13486"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-13486, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-13486.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "form[render]=wp_insert_user" ascii nocase
        $param1 = "form[role]=administrator" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_13652_cbx_bookmark_favorite {
    meta:
        attack_type = "cve_2025_13652"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress CBX Bookmark & Favorite Plugin <= 2.0.4 - SQL Injection: CBX Bookmark & Favorite WordPress plugin <= 2.0.4 contains a SQL injection caused by insufficient escaping of the 'orderby' parameter, letting authenticated attackers with Subscriber-level access extract."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-13652"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-13652, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-13652.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=cbx_bookmark_loadmore" ascii nocase
        $param1 = "orderby=(SELECT 1 FROM (SELECT SLEEP(6))x)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_13920_wpdirectorykit {
    meta:
        attack_type = "cve_2025_13920"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP Directory Kit < 1.5.0 - Unauthenticated Email Exposure: WP Directory Kit plugin for WordPress <= 1.4.9 contains a sensitive information exposure caused by improper access control in wdk_public_action AJAX handler, letting unauthenticated attackers extract email addresses of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-13920"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-13920, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-13920.yaml"
    strings:
        $param0 = "table=user_m" ascii nocase
        $param1 = "print_column=user_email" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_13956_learnpress {
    meta:
        attack_type = "cve_2025_13956"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LearnPress < 4.3.2 - Broken Access Control: The LearnPress WordPress LMS Plugin plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the statistic function in all versions up to, and including, 4.3.1. This makes it possible for."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-13956"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-13956, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-13956.yaml"
    strings:
        $path0 = "/wp-json/lp/v1/orders/statistic" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_14155_premium_addons_for_elementor {
    meta:
        attack_type = "cve_2025_14155"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Premium Addons for Elementor - Unauthenticated Information Disclosure: Premium Addons for Elementor plugin for WordPress version 4.11.53 and below contains an unauthenticated information disclosure vulnerability.The vulnerability exists due to a missing authorization check in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-14155"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-14155, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-14155.yaml"
    strings:
        $param0 = "action=get_elementor_template_content" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_14437_hummingbird_performance {
    meta:
        attack_type = "cve_2025_14437"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Hummingbird <= 3.18.0 - Sensitive Information Exposure via Log File: Hummingbird Performance WordPress plugin <= 3.18.0 contains a sensitive information exposure caused by improper handling in the 'request' function, letting unauthenticated attackers extract sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-14437"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-14437, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-14437.yaml"
    strings:
        $path0 = "/wp-content/wphb-logs/api-debug.log" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_14611_gladinet_centrestack_triofox {
    meta:
        attack_type = "cve_2025_14611"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Gladinet CentreStack & Triofox - Hardcoded Credentials: Gladinet CentreStack and Triofox < 16.12.10420.56791 contain a hardcoded credentials vulnerability caused by use of hardcoded AES cryptoscheme values, letting attackers perform arbitrary local file inclusion without."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-14611"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-14611, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-14611.yaml"
    strings:
        $path0 = "/storage/filesvr.dn" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_14726_wordpress_widgets_for_social_p {
    meta:
        attack_type = "cve_2025_14726"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Widgets for Social Photo Feed <= 1.8 - Information Disclosure: Widgets for Social Photo Feed WordPress plugin <= 1.8 contains a broken access control caused by missing capability checks on specific REST API endpoints, letting unauthenticated attackers access and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-14726"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-14726, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-14726.yaml"
    strings:
        $path0 = "/wp-json/trustindex_feed_hook_instagram/troubleshooting" ascii nocase
        $path1 = "/wp-json/trustindex_feed_hook_instagram/get-token" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_15503_sangfor_osm {
    meta:
        attack_type = "cve_2025_15503"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Sangfor OSM - Arbitrary File Upload: Sangfor Operation and Maintenance Management System <= 3.0.8 contains an unrestricted file upload vulnerability caused by manipulation of the /'File/' argument in /fort/trust/version/common/common.jsp, letting remote attackers upload."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-15503"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-15503, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-15503.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/fort/trust/version/common/common.jsp" ascii nocase
        $path1 = "/fort/trust/version/common/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_1562_recover_woocommerce_cart_aband {
    meta:
        attack_type = "cve_2025_1562"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Recover WooCommerce Cart Abandonment, Newsletter, Email Marketing, Marketing Automation By FunnelKit - Broken Access.: The Recover WooCommerce Cart Abandonment, Newsletter, Email Marketing, Marketing Automation By FunnelKit plugin for WordPress is vulnerable to unauthorized."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-1562"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-1562, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-1562.yaml"
    strings:
        $path0 = "/wp-json/autonami-app/plugin/install_and_activate" ascii nocase
        $param0 = "page=autonami" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_1595_easycvr {
    meta:
        attack_type = "cve_2025_1595"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "EasyCVR <=2.1.2 - Information Disclosure: A vulnerability has been found in Anhui Xufan Information Technology EasyCVR up to 2.7.0 and classified as problematic. This vulnerability affects unknown code of the file /api/v1/getbaseconfig. The manipulation leads to information."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-1595"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-1595, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-1595.yaml"
    strings:
        $path0 = "/api/v1/getbaseconfig" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_1661_husky_products_filter_professi {
    meta:
        attack_type = "cve_2025_1661"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "HUSKY Products Filter Professional for WooCommerce <= 1.3.6.5 - Unauthenticated Local File Inclusion: The HUSKY Products Filter Professional for WooCommerce plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 1.3.6.5 via the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-1661"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-1661, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-1661.yaml"
    strings:
        $param0 = "template=../../../../../../../wp-configx" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_1743_pichome {
    meta:
        attack_type = "cve_2025_1743"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Pichome 2.1.0 - Arbitrary File Read: A vulnerability, which was classified as critical, was found in zyx0814 Pichome 2.1.0. This affects an unknown part of the file /index.php?mod=textviewer. The manipulation of the argument src leads to path traversal. It is possible to."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-1743"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-1743, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-1743.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "mod=textviewer" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_2011_slider_popup_builder_by_depict {
    meta:
        attack_type = "cve_2025_2011"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Slider & Popup Builder by Depicter <= 3.6.1 - Unauthenticated SQL Injection: The Slider & Popup Builder by Depicter plugin for WordPress is vulnerable to generic SQL Injection via the s' parameter in all versions up to, and including, 3.6.1 due to insufficient escaping on the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2011"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2011, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2011.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "orderBy=source_id" ascii nocase
        $param1 = "action=depicter-lead-index" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_20281_identity_services_engine {
    meta:
        attack_type = "cve_2025_20281"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Cisco ISE - Remote Code Execution: A vulnerability in a specific API of Cisco ISE and Cisco ISE-PIC could allow an unauthenticated, remote attacker to execute arbitrary code on the underlying operating system as root. The attacker does not require any valid credentials to."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-20281"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-20281, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-20281.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/deployment-rpc/enableStrongSwanTunnel" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_20362_adaptive_security_appliance_so {
    meta:
        attack_type = "cve_2025_20362"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Cisco Secure Firewall ASA & FTD - Authentication Bypass: A vulnerability in the VPN web server of Cisco Secure Firewall Adaptive Security Appliance (ASA) Software and Cisco Secure Firewall Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to access."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-20362"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-20362, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-20362.yaml"
    strings:
        $path0 = "/+CSCOU+/../+CSCOE+/files/file_action.html" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_2075_uncanny_automator_6_3_0_2 {
    meta:
        attack_type = "cve_2025_2075"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Uncanny Automator <= 6.3.0.2 - Missing Authorization to Authenticated (Subscriber+) Privilege Escalation: The Uncanny Automator - Easy Automation, Integration, Webhooks & Workflow Builder Plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2075"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2075, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2075.yaml"
    strings:
        $path0 = "/wp-json/uap/v2/async_action/" ascii nocase
        $param0 = "action_data[meta][code]=USERROLE" ascii nocase
        $param1 = "action_data[meta][WPROLE]=administrator" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_2127_jux_real_estate {
    meta:
        attack_type = "cve_2025_2127"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "JoomlaUX JUX Real Estate 3.4.0 - Reflected XSS: A vulnerability was found in JoomlaUX JUX Real Estate 3.4.0 on Joomla. It has been classified as problematic. Affected is an unknown function of the file /extensions/realestate/index.php/properties/list/list-with-sidebar/realties.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2127"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2127, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2127.yaml"
    strings:
        $path0 = "/extensions/realestate/index.php/properties/list/list-with-sidebar/realties" ascii nocase
        $param0 = "view=realties" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_2129_mage_ai {
    meta:
        attack_type = "cve_2025_2129"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Mage AI - Insecure Default Authentication Setup: A vulnerability was found in Mage AI 0.9.75. It has been classified as problematic. This affects an unknown part. The manipulation leads to insecure default initialization of resource. It is possible to initiate the attack."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2129"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2129, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2129.yaml"
    strings:
        $path0 = "/api/kernels" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_22214_landray_eis_sql {
    meta:
        attack_type = "cve_2025_22214"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Landray EIS SQL: Landray EIS 2001 through 2006 contains a SQL injection caused by unsanitized input in Message/fi_message_receiver.aspx?replyid=, letting attackers execute arbitrary SQL commands, exploit requires crafted input."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-22214"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-22214, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-22214.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/Message/fi_message_receiver.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_22785_course_booking_system_6_0_6 {
    meta:
        attack_type = "cve_2025_22785"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Course Booking System <= 6.0.6 - SQL Injection: The Course Booking System plugin for WordPress is vulnerable to SQL Injection in versions up to, and including, 6.0.6 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-22785"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-22785, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-22785.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=cbs_action_booking_delete" ascii nocase
        $param1 = "course_id=1 AND (SELECT 1 FROM (SELECT(SLEEP(8)))sqltest)" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_2294_kubio_ai_page_builder_2_5_1 {
    meta:
        attack_type = "cve_2025_2294"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Kubio AI Page Builder <= 2.5.1 - Local File Inclusion: The Kubio AI Page Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.5.1 via thekubio_hybrid_theme_load_template function. This makes it possible for unauthenticated."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2294"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2294, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2294.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "__kubio-site-edit-iframe-classic-template=../../../../../../../../etc/passwd" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_22952_elestio_memos_v0_24_0 {
    meta:
        attack_type = "cve_2025_22952"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Elestio Memos <= v0.24.0 - Server-Side Request Forgery: elestio memos v0.23.0 is vulnerable to Server-Side Request Forgery (SSRF) due to insufficient validation of user-supplied URLs, which can be exploited to perform SSRF attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-22952"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-22952, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-22952.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/v1/markdown/link:metadata" ascii nocase
        $param0 = "link=http://localhost:13042" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_23211_tandoor_recipes_1_5_24 {
    meta:
        attack_type = "cve_2025_23211"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Tandoor Recipes < 1.5.24 - Jinja2 SSTI RCE: Tandoor Recipes < 1.5.24 has a Jinja2 SSTI vulnerability that allows command execution via recipe steps."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-23211"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-23211, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-23211.yaml"
        response_type = "template_eval"
    strings:
        $path0 = "/api/recipe/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_24016_wazuh {
    meta:
        attack_type = "cve_2025_24016"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Wazuh - Unsafe Deserialization Remote Code Execution: A critical Remote Code Execution (RCE) vulnerability exists in Wazuh server versions >= 4.4.0 and < 4.9.1. The vulnerability occurs due to unsafe deserialization in the wazuh-manager package, specifically in the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-24016"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-24016, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-24016.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/security/user/authenticate/run_as" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_24354_imgproxy {
    meta:
        attack_type = "cve_2025_24354"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Imgproxy < 3.27.2 - Server-Side Request Forgery (SSRF): imgproxy contains an issue caused by not blocking the 0.0.0.0 address even when IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES is set to false, letting local services be exposed, exploit requires network access."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-24354"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-24354, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-24354.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/unsafe/plain/http:/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_24582_12_step_meeting_list {
    meta:
        attack_type = "cve_2025_24582"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "12 Step Meeting List < 3.16.6 - Unauthenticated Sensitive Information Exposure: The 12 Step Meeting List plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 3.16.5.This makes it possible for unauthenticated attackers to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-24582"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-24582, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-24582.yaml"
    strings:
        $param0 = "action=tsml_geocodes" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_24893_xwiki {
    meta:
        attack_type = "cve_2025_24893"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "XWiki Platform - Remote Code Execution: Any guest can perform arbitrary remote code execution through a request to SolrSearch. This impacts the confidentiality, integrity, and availability of the whole XWiki installation. This vulnerability has been patched in XWiki 15.10.11."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-24893"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-24893, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-24893.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/bin/get/Main/SolrSearch" ascii nocase
        $path1 = "/xwiki/bin/get/Main/SolrSearch" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_24963_vitest_browser_mode {
    meta:
        attack_type = "cve_2025_24963"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Vitest Browser Mode - Local File Read: Vitest is a testing framework powered by Vite. The `__screenshot-error` handler on the browser mode HTTP server that responds any file on the file system. Especially if the server is exposed on the network by `browser.api.host- true`, an."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-24963"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-24963, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-24963.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/__screenshot-error" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_25034_sugarcrm {
    meta:
        attack_type = "cve_2025_25034"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SugarCRM - Unauthenticated Remote Code Execution via PHP Object Injection: A PHP object injection vulnerability exists in SugarCRM versions prior to 6.5.24, 6.7.13, 7.5.2.5, 7.6.2.2, and 7.7.1.0 due to improper validation of PHP serialized input in the SugarRestSerialize.php."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-25034"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-25034, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-25034.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "input_type=Serialize" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_25037_controller {
    meta:
        attack_type = "cve_2025_25037"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Aquatronica Controller System <= 5.1.6 - Information Disclosure: Aquatronica Controller System firmware 5.1.6 and earlier and web interface 2.0 and earlier contain an information disclosure vulnerability caused by unauthenticated access to tcp.php endpoint, letting remote."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-25037"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-25037, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-25037.yaml"
    strings:
        $param0 = "function_id=tcp_xml_request" ascii nocase
        $param1 = "command=WS_GET_NETWORK_CFG" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_2505_wordpress_age_gate_3_5_3 {
    meta:
        attack_type = "cve_2025_2505"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Age Gate <= 3.5.3 - Unauthenticated Local File Inclusion: The Age Gate plugin for WordPress up to version 3.5.3 contains a local PHP file inclusion caused by the 'lang' parameter, letting unauthenticated attackers include and execute arbitrary PHP files, exploit."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2505"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2505, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2505.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "rest_route=/age-gate/v3/check" ascii nocase
        $param1 = "age_gate[lang]=../../../../../../../../wp-config" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_25231_workspace_one_uem_console {
    meta:
        attack_type = "cve_2025_25231"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Omnissa Workspace ONE UEM - Path Traversal: Omnissa Workspace ONE UEM contains a path traversal caused by crafted GET requests to restricted API endpoints, letting malicious actors access sensitive information, exploit requires sending crafted requests."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-25231"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-25231, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-25231.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/DevicesGateway/apps/system-app-metadata/1" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_2539_file_away_3_9_9_0_1 {
    meta:
        attack_type = "cve_2025_2539"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "File Away <= 3.9.9.0.1 - Missing Authorization to Unauthenticated Arbitrary File Read: The File Away plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the ajax() function in all versions up to, and including, 3.9.9.0.1. This."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2539"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2539, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2539.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "action=fileaway-stats" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_25570_vue_vben_admin {
    meta:
        attack_type = "cve_2025_25570"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Vue Vben Admin - Default Credentials: Vue Vben Admin 2.10.1 contains a broken authentication caused by hardcoded credentials in the backend, letting attackers log in without proper authorization, exploit requires access to the login interface."
        mitre_attack = "T1078.001"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-25570"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-25570, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-25570.yaml"
    strings:
        $path0 = "/basic-api/login" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_2563_user_registration_membership_4 {
    meta:
        attack_type = "cve_2025_2563"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "User Registration & Membership <= 4.1.1 - Unauthenticated Privilege Escalation: The User Registration & Membership plugin for WordPress is vulnerable to privilege escalation in versions up to, and including, 4.1.1. This is due to insufficient restrictions on role type in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2563"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2563, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2563.yaml"
    strings:
        $path0 = "/membership-registration/" ascii nocase
        $param0 = "registration_language=en-US" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_2609_magnusbilling {
    meta:
        attack_type = "cve_2025_2609"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MagnusBilling Login Logs - Cross-Site Scripting: Improper neutralization of input during web page generation vulnerability in MagnusSolution MagnusBilling login logging allows unauthenticated users to store HTML content in the viewable log component accessible at."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2609"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2609, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2609.yaml"
        response_type = "xss"
    strings:
        $path0 = "/mbilling/index.php/logUsers/read" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_2610_magnusbilling {
    meta:
        attack_type = "cve_2025_2610"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MagnusBilling Alarm Module - Cross-Site Scripting: Improper neutralization of input during web page generation vulnerability in MagnusSolution MagnusBilling (Alarm Module modules) allows authenticated stored cross-site scripting. This vulnerability is associated with program."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2610"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2610, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2610.yaml"
        response_type = "xss"
    strings:
        $path0 = "/mbilling/index.php/alarm/save" ascii nocase
        $path1 = "/mbilling/index.php/alarm/read" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_26319_flowise {
    meta:
        attack_type = "cve_2025_26319"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "FlowiseAI Flowise <= 2.2.6 - Arbitrary File Upload: FlowiseAI Flowise version 2.2.6 and below contains an arbitrary file upload vulnerability in the /api/v1/attachments endpoint. This vulnerability allows an unauthenticated attacker to upload files outside the intended."
        mitre_attack = "T1190, T1505.003"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-26319"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-26319, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-26319.yaml"
    strings:
        $path0 = "/api/v1/attachments/../../../../../root/.flowise" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_2636_instawp_connect_0_1_0_86 {
    meta:
        attack_type = "cve_2025_2636"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "InstaWP Connect < 0.1.0.86 - Local PHP File Inclusion: The InstaWP Connect - 1-click WP Staging & Migration plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 0.1.0.85 via the 'instawp-database-manager' parameter. This makes it."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2636"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2636, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2636.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "instawp-database-manager=/../../.././migrate/templates/debug/db-table" ascii nocase
        $param1 = "table_name=wp_users-- -" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_26793_freedom_administration {
    meta:
        attack_type = "cve_2025_26793"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FREEDOM Administration - Default Login: The Web GUI configuration panel of Hirsch (formerly Identiv and Viscount) Enterphone MESH through 2024 ships with default credentials (username freedom, password viscount). The administrator is not prompted to change these credentials on."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-26793"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-26793, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-26793.yaml"
    strings:
        $path0 = "/mesh/servlet/mesh.webadmin.MESHAdminServlet" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_27007_ottokit_1_0_83 {
    meta:
        attack_type = "cve_2025_27007"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OttoKit < 1.0.83 - SureTriggers allows Privilege Escalation: Incorrect Privilege Assignment vulnerability in Brainstorm Force SureTriggers allows Privilege Escalation.This issue affects SureTriggers- from n/a through 1.0.82."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-27007"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-27007, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-27007.yaml"
    strings:
        $path0 = "/wp-json/sure-triggers/v1/connection/create-wp-connection" ascii nocase
        $param0 = "selected_options[role]=administrator" ascii nocase
        $param1 = "integration=WordPress" ascii nocase
        $param2 = "type_event=create_user_if_not_exists" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_2711_ufida_erp_nc {
    meta:
        attack_type = "cve_2025_2711"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Yonyou UFIDA ERP-NC V5.0 - Cross-Site Scripting: Yonyou UFIDA ERP-NC V5.0 is vulnerable to reflected cross-site scripting (XSS) via the langcode parameter in /help/systop.jsp and /help/top.jsp. Unsanitized user input is reflected in the response, allowing arbitrary JavaScript."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2711"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2711, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2711.yaml"
        response_type = "xss"
    strings:
        $path0 = "/help/systop.jsp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_27112_navidrome {
    meta:
        attack_type = "cve_2025_27112"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Navidrome <=0.54.5 - Authentication Bypass in Subsonic API: Navidrome is an open source web-based music collection server and streamer. Starting in version 0.52.0 and prior to version 0.54.5, in certain Subsonic API endpoints, a flaw in the authentication check process allows."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-27112"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-27112, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-27112.yaml"
    strings:
        $path0 = "/rest/getPlaylists" ascii nocase
        $param0 = "c=castafiore" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_27222_trufusion_enterprise_7_10_4_0 {
    meta:
        attack_type = "cve_2025_27222"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TRUfusion Enterprise <= 7.10.4.0 - Path Traversal: Pre-Auth Path Traversal Allowing to Leak Local server files disclosing sensitive clear-text passwords."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-27222"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-27222, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-27222.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/trufusionPortal/getCobrandingData" ascii nocase
        $param0 = "cobrandingImageName=../../../../../../Windows/System32/drivers/etc/hosts" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_27223_trufusion_enterprise_7_10_4_0 {
    meta:
        attack_type = "cve_2025_27223"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TRUfusion Enterprise <= 7.10.4.0 - Authentication Bypass: Hard-Coded Cryptographic key allowing to forge session cookies that can be used to entirely bypass authentication"
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-27223"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-27223, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-27223.yaml"
    strings:
        $path0 = "/trufusionPortal/getProjectList" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_27225_trufusion_enterprise_7_10_4_0 {
    meta:
        attack_type = "cve_2025_27225"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "TRUfusion Enterprise <= 7.10.4.0 - Admin Contact Portal: TRUfusion Enterprise versions 7.10.4.0 and earlier contained a vulnerability that allowed unauthenticated access to the Internal Admin Contact Page, resulting in the disclosure of PII (including partner and contact names)."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-27225"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-27225, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-27225.yaml"
    strings:
        $path0 = "/trufusionPortal/jsp/internal_admin_contact_login.jsp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_2748_kentico_xperience_cms {
    meta:
        attack_type = "cve_2025_2748"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Kentico Xperience CMS - Unauthenticated Stored XSS: The Kentico Xperience application does not fully validate or filter files uploaded via the multiple-file upload functionality, which allows for stored XSS.This issue affects Kentico Xperience through 13.0.178."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2748"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2748, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2748.yaml"
        response_type = "xss"
    strings:
        $path0 = "/CMSModules/Content/CMSPages/MultiFileUploader.ashx" ascii nocase
        $path1 = "/CMSPages/GetResource.ashx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_27505_geoserver {
    meta:
        attack_type = "cve_2025_27505"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "GeoServer - Missing Authorization on REST API Index: GeoServer contains a missing authorization vulnerability that allows unauthorized access to the REST API Index page, potentially exposing sensitive configuration information."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-27505"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-27505, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-27505.yaml"
    strings:
        $path0 = "/geoserver/rest.html" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_2776_sysaid {
    meta:
        attack_type = "cve_2025_2776"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "SysAid On-Prem <= 23.3.40 - XML External Entity: SysAid On-Prem versions <= 23.3.40 are vulnerable to an unauthenticated XML External Entity (XXE) vulnerability in the Server URL processing functionality, allowing for administrator account takeover and file read primitives."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-2776"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-2776, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-2776.yaml"
    strings:
        $path0 = "/mdm/serverurl" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_27888_druid {
    meta:
        attack_type = "cve_2025_27888"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache Druid - Server-Side Request Forgery: Server-Side Request Forgery (SSRF), Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'), URL Redirection to Untrusted Site ('Open Redirect') vulnerability in Apache Druid.This issue affects all."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-27888"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-27888, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-27888.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/unified-console.html" ascii nocase
        $path1 = "/proxy/coordinator@" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_28367_mojoportal_2_9_0_1 {
    meta:
        attack_type = "cve_2025_28367"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "mojoPortal <=2.9.0.1 - Directory Traversal: mojoPortal <=2.9.0.1 is vulnerable to Directory Traversal via BetterImageGallery API Controller - ImageHandler Action. An attacker can exploit this vulnerability to access the Web.Config file and obtain the MachineKey."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-28367"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-28367, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-28367.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/BetterImageGallery/imagehandler" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_28906_skitter_slideshow_2_5_2 {
    meta:
        attack_type = "cve_2025_28906"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Skitter Slideshow <= 2.5.2 - Authenticated (Administrator+) Stored Cross-Site Scripting: The Skitter Slideshow plugin for WordPress is vulnerable to Stored Cross-Site Scripting in versions up to, and including, 2.5.2 due to insufficient input sanitization and output escaping."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-28906"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-28906, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-28906.yaml"
        response_type = "xss"
    strings:
        $param0 = "page=wp_skitter_menu" ascii nocase
        $param1 = "option_page=wp_skitter_settings" ascii nocase
        $param2 = "wp_skitter_type=posts" ascii nocase
        $param3 = "wp_skitter_theme=square" ascii nocase
        $param4 = "wp_skitter_animation=random" ascii nocase
        $param5 = "wp_skitter_type_navigation=numbers" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_29085_vipshop_saturn_console_3_5_1 {
    meta:
        attack_type = "cve_2025_29085"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Vipshop Saturn Console <= 3.5.1 - SQL Injection via ClusterKey Component: SQL injection vulnerability in vipshop Saturn v.3.5.1 and before allows a remote attacker to execute arbitrary code via /console/dashboard/executorCount?zkClusterKey component."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-29085"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-29085, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-29085.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/console/dashboard/executorCount" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_29635_dir_823x_firmware {
    meta:
        attack_type = "cve_2025_29635"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "D-Link DIR-823X set_prohibiting - Command Injection: D-Link DIR-823X 240126 and 240802 contain a command injection caused by sending a POST request to /goform/set_prohibiting, letting an authorized attacker execute arbitrary commands remotely, exploit requires attacker to be."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-29635"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-29635, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-29635.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/goform/set_prohibiting" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_30208_vite {
    meta:
        attack_type = "cve_2025_30208"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Vite - Arbitrary File Read: Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-30208"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-30208, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-30208.yaml"
    strings:
        $path0 = "/C:/Windows/System32/drivers/etc/hosts" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_30406_gladinet_centrestack_16_4_1031 {
    meta:
        attack_type = "cve_2025_30406"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Gladinet CentreStack < 16.4.10315.56368 Use of Hard-coded Key Leads to Unauthenticated RCE: Gladinet CentreStack through 16.1.10296.56315 (fixed in 16.4.10315.56368) has a deserialization vulnerability due to the CentreStack portal's hardcoded machineKey use, as exploited in."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-30406"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-30406, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-30406.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/portal/loginpage.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_30567_wp01 {
    meta:
        attack_type = "cve_2025_30567"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress WP01 - Path Traversal: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in wp01ru WP01 allows Path Traversal. This issue affects WP01: from n/a through 2.6.2."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-30567"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-30567, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-30567.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "action=wp01_generate_zip_archive" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_31125_vite_development_server {
    meta:
        attack_type = "cve_2025_31125"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Vite Development Server - Path Traversal: Path traversal vulnerability in Vite development server's @fs endpoint allows attackers to access files outside the intended directory. When exposed to the network, attackers can exploit this via crafted URLs to access sensitive system."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-31125"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-31125, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-31125.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/@fs/%2e%2e/%2e%2e/%2e%2e/etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_31131_yeswiki_4_5_2 {
    meta:
        attack_type = "cve_2025_31131"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Yeswiki < 4.5.2 - Unauthenticated Path Traversal: YesWiki is a wiki system written in PHP. The squelette parameter is vulnerable to path traversal attacks, enabling read access to arbitrary files on the server."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-31131"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-31131, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-31131.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "squelette=../../../../../../../../etc/passwd" ascii nocase
        $param1 = "style=margot.css" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_31161_crushftp {
    meta:
        attack_type = "cve_2025_31161"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "CrushFTP - Authentication Bypass: CrushFTP versions 10.0.0 through 10.8.3 and 11.0.0 through 11.3.0 are affected by a vulnerability that may result in unauthenticated access. Remote and unauthenticated HTTP requests to CrushFTP may allow attackers to gain unauthorized access."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-31161"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-31161, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-31161.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "command=getUserList" ascii nocase
        $param1 = "serverGroup=MainUsers" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_32257_1_click_migration {
    meta:
        attack_type = "cve_2025_32257"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "1 Click WordPress Migration <= 2.2 - Unauthenticated Information Disclsoure: 1 Click WordPress Migration <= 2.2 contains an information disclosure caused by uncleared debug information, letting attackers retrieve embedded sensitive data, exploit requires no specific privileges."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-32257"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32257, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32257.yaml"
    strings:
        $path0 = "/wp-content/plugins/1-click-migration/ocm_debug.log" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_32429_xwiki {
    meta:
        attack_type = "cve_2025_32429"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "XWiki Platform - SQL Injection: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. In versions 9.4-rc-1 through 16.10.5 and 17.0.0-rc-1 through 17.2.2, it's possible for anyone to inject SQL using the parameter sort of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-32429"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32429, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32429.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/xwiki/rest/liveData/sources/liveTable/entries" ascii nocase
        $param0 = "sourceParams.template=getdeleteddocuments.vm" ascii nocase
        $param1 = "sort=injected" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_32430_xwiki_platform {
    meta:
        attack_type = "cve_2025_32430"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki Platform - Cross-Site Scripting: XWiki Platform versions >= 4.2-milestone-3 and < 16.4.8, >= 16.5.0-rc-1 and < 16.10.6, and >= 17.0.0-rc-1 and < 17.3.0-rc-1 are vulnerable to reflected XSS in two templates. The vulnerability allows an attacker to execute malicious."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-32430"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32430, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32430.yaml"
        response_type = "xss"
    strings:
        $param0 = "xpage=job_status_json" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_32432_craftcms {
    meta:
        attack_type = "cve_2025_32432"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "CraftCMS - Remote Code Execution: Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-32432"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32432, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32432.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "p=admin/actions/assets/generate-transform" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_32778_web_check {
    meta:
        attack_type = "cve_2025_32778"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Web-Check < 2.0.1 Screenshot API - OS Command Injection: Lissy93/web-check contains a command injection caused by unsanitized user input in the screenshot API, letting attackers execute arbitrary system commands, exploit requires sending crafted url parameters."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-32778"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32778, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32778.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/screenshot" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_32813_netmri {
    meta:
        attack_type = "cve_2025_32813"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Infoblox NetMRI < 7.6.1 - Unauthenticated Command Injection in get_saml_request: An issue was discovered in Infoblox NETMRI before 7.6.1. Remote Unauthenticated Command Injection can occur."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-32813"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32813, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32813.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/webui/application/get_saml_request" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_32814_netmri {
    meta:
        attack_type = "cve_2025_32814"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "NetMRI Unauthenticated SQL Injection via skipjackUsername: An issue was discovered in Infoblox NETMRI before 7.6.1. Unauthenticated SQL Injection can occur."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-32814"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32814, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32814.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/netmri/config/userAdmin/login.tdf" ascii nocase
        $param0 = "skipjackPassword=anything" ascii nocase
        $param1 = "eulaAccepted=Accept" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_32815_netmri {
    meta:
        attack_type = "cve_2025_32815"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "NetMRI < 7.6.1 - Authentication Bypass via Hardcoded Credentials: An issue was discovered in Infoblox NETMRI before 7.6.1. Authentication Bypass via a Hardcoded credential can occur."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-32815"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32815, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32815.yaml"
    strings:
        $path0 = "/netmri/common/SetRawCookie.tdf" ascii nocase
        $path1 = "/visual/ViewerFileServlet" ascii nocase
        $param0 = "name=letmein" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_32966_dataease {
    meta:
        attack_type = "cve_2025_32966"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "DataEase 2.10.4-2.10.7 - Remote Code Execution: DataEase prior to version 2.10.8 contains a remote code execution caused by insecure backend JDBC link handling, letting authenticated users execute arbitrary code, exploit requires user authentication."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-32966"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32966, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32966.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/de2api/datasource/validate" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_32970_xwiki {
    meta:
        attack_type = "cve_2025_32970"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki WYSIWYG API - Open Redirect: A vulnerability in XWiki's WYSIWYG API allows an attacker to redirect users to arbitrary external URLs through the xerror parameter. This could be used in phishing attacks to redirect users to malicious websites."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-32970"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32970, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-32970.yaml"
    strings:
        $param0 = "foo_syntax=invalid" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_34026_concerto {
    meta:
        attack_type = "cve_2025_34026"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Versa Concerto Actuator Endpoint - Authentication Bypass: An authentication bypass vulnerability affected the Spring Boot Actuator endpoints in Versa Concerto due to improper handling of the X-Real-Ip header.Attackers could access restricted endpoints by omitting this."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34026"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34026, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34026.yaml"
    strings:
        $path0 = "/portalapi/actuator" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_34027_concerto {
    meta:
        attack_type = "cve_2025_34027"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Versa Concerto API Path Based - Authentication Bypass: Authentication bypass in the Versa Concerto API, caused by URL decoding inconsistencies. It allowed unauthorized access to certain API endpoints by manipulating the URL path.This issue enabled attackers to bypass."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34027"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34027, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34027.yaml"
    strings:
        $path0 = "/portalapi/v1/roles/option;/v1/ping" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_34028_commvault {
    meta:
        attack_type = "cve_2025_34028"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Commvault - SSRF via /commandcenter/deployWebpackage.do: A path traversal vulnerability in Commvault Command Center Innovation Release allows an unauthenticated actor to upload ZIP files, which, when expanded by the target server, result in Remote Code Execution. This issue."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34028"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34028, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34028.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/commandcenter/deployWebpackage.do" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_34033_blue_angel_software_suite {
    meta:
        attack_type = "cve_2025_34033"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Blue Angel Software Suite (5V Technologies) - OS Command Injection: Blue Angel 5V Technologies Blue Angel Software Suite through 20230920, as used in Analog Telephone Adapter (ATA) and Voice over IP (VoIP) devices, allows remote authenticated attackers to execute arbitrary OS."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34033"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34033, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34033.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/cgi-bin/webctrl.cgi" ascii nocase
        $param0 = "action=login_authentication" ascii nocase
        $param1 = "redirect_action=sysinfo_page" ascii nocase
        $param2 = "login_username=blueangel" ascii nocase
        $param3 = "login_password=blueangel" ascii nocase
        $param4 = "action=pingtest_update" ascii nocase
        $param5 = "ping_addr=127.0.0.1;id" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_34038_fanwei_e_cology {
    meta:
        attack_type = "cve_2025_34038"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Fanwei e-cology - SQL Injection: Fanwei e-cology 8.0 contains a sql injection caused by unsanitized user input in the sql parameter of getdata.jsp, letting unauthenticated attackers execute arbitrary SQL queries and access sensitive data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34038"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34038, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34038.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/js/hrm/getdata.jsp" ascii nocase
        $param0 = "cmd=getSelectAllId" ascii nocase
        $param1 = "sql=select 547653*865674 as id" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_34045_weiphp_5_0 {
    meta:
        attack_type = "cve_2025_34045"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WeiPHP 5.0 - Path Traversal: WeiPHP 5.0 contains a path traversal caused by insufficient input validation of the picUrl parameter in /public/index.php/material/Material/_download_imgage, letting unauthenticated remote attackers read arbitrary files."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34045"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34045, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34045.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/public/index.php/material/Material/_download_imgage" ascii nocase
        $param0 = "picUrl=./../config/database.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_34077_wordpress_pie_register_3_7_1_4 {
    meta:
        attack_type = "cve_2025_34077"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Pie Register <= 3.7.1.4 - Authentication Bypass: An authentication bypass vulnerability exists in the WordPress Pie Register plugin 3.7.1.4 that allows unauthenticated attackers to impersonate arbitrary users by submitting a crafted POST request to the login endpoint.."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34077"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34077, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34077.yaml"
    strings:
        $param0 = "_wp_http_referer=/login/" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_34141_reliance {
    meta:
        attack_type = "cve_2025_34141"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ETQ Reliance - Reflected XSS via SQLConverterServlet: A reflected cross-site scripting (XSS) vulnerability exists in ETQ Reliance CG (legacy) platform within the SQLConverterServlet component. This vulnerability requires user interaction, such as clicking a crafted link, and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34141"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34141, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34141.yaml"
        response_type = "xss"
    strings:
        $path0 = "/reliance/SQLConverterServlet" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_34143_etq_reliance {
    meta:
        attack_type = "cve_2025_34143"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ETQ Reliance - Authentication Bypass via Trailing Space: An authentication bypass vulnerability exists in ETQ Reliance on the CG (legacy) platform. The application allowed login as the privileged internal SYSTEM user by manipulating the username field. The SYSTEM account does."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34143"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34143, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34143.yaml"
    strings:
        $path0 = "/reliance/resources/sessions" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_3415_grafana {
    meta:
        attack_type = "cve_2025_3415"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Grafana - Exposes DingDing API Keys: An incident occurred where the DingDing alerting integration URL was inadvertently exposed to viewers due to a setting oversight in versions below or equals to 12.0.1."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-3415"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-3415, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-3415.yaml"
    strings:
        $path0 = "/api/alertmanager/grafana/config/api/v1/alerts" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_34152_shenzhen_aitemi_m300_wi_fi_rep {
    meta:
        attack_type = "cve_2025_34152"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Shenzhen Aitemi M300 Wi-Fi Repeater Unauthenticated Remote Command Execution via `time` Parameter: An unauthenticated OS command injection vulnerability exists in the Shenzhen Aitemi M300 Wi-Fi Repeater (hardware model MT02) via the 'time' parameter of the '/protocol.csp?'."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34152"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34152, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34152.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/protocol.csp" ascii nocase
        $param0 = "fname=system" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_34291_langflow {
    meta:
        attack_type = "cve_2025_34291"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Langflow AI <= 1.6.9 - CORS Misconfiguration: Langflow AI versions 1.6.9 and earlier are vulnerable to a CORS misconfiguration that allows any origin to make credentialed requests. Combined with SameSite=None cookies, this enables cross-origin token theft and subsequent remote."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34291"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34291, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34291.yaml"
    strings:
        $path0 = "/api/v1/refresh" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_34300_sawtoothsoftware_lighthouse_st {
    meta:
        attack_type = "cve_2025_34300"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SawtoothSoftware Lighthouse Studio < 9.16.14 - Pre-Auth Remote Code Execution: A pre-authentication remote code execution vulnerability exists in Sawtooth Softwares Lighthouse Studio versions prior to 9.16.14. The issue arises from the unsafe use of the `eval` function within."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34300"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34300, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34300.yaml"
        response_type = "template_eval"
    strings:
        $path0 = "/cgi-bin/ciwweb.pl" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_34509_experience_commerce_experience {
    meta:
        attack_type = "cve_2025_34509"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Sitecore Experience Manager (XM) and Experience Platform (XP) - Hardcoded Credentials: Sitecore Experience Manager (XM) and Experience Platform (XP) versions 10.1 to 10.1.4 rev. 011974 PRE, all versions of 10.2, 10.3 to 10.3.3 rev. 011967 PRE, and 10.4 to 10.4.1 rev. 011941 PRE."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-34509"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-34509, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-34509.yaml"
    strings:
        $path0 = "/sitecore/api/ssc/auth/login" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_3472_ocean_extra {
    meta:
        attack_type = "cve_2025_3472"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ocean Extra <= 2.4.6 - Unauthenticated Shortcode Execution: The Ocean Extra plugin for WordPress is vulnerable to arbitrary shortcode execution in all versions up to, and including, 2.4.6. This is due to the software allowing users to supply arbitrary shortcodes in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-3472"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-3472, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-3472.yaml"
    strings:
        $param0 = "post_type=product" ascii nocase
        $param1 = "action=update_oceanwp_woo_free_shipping_left_shortcode" ascii nocase
        $param2 = "content_rech_data=[woocommerce_my_account]" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_3605_wordpress_frontend_login_and_r {
    meta:
        attack_type = "cve_2025_3605"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Frontend Login and Registration Blocks Plugin 1.0.7 - Privilege Escalation: Privilege escalation vulnerability exists in the Frontend Login and Registration Blocks plugin for WordPress (versions <= 1.0.7). An unauthenticated attacker can exploit the AJAX endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-3605"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-3605, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-3605.yaml"
    strings:
        $param0 = "action=flrblocksusersettingsupdatehandle" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_36845_eveo_urve_web_manager {
    meta:
        attack_type = "cve_2025_36845"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Eveo URVE Web Manager - Server-Side Request Forgery: Eveo URVE Web Manager 27.02.2025 contains a server-side request forgery caused by improper validation of URL input in /_internal/redirect.php, letting attackers make requests to internal endpoints, exploit requires crafted."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-36845"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-36845, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-36845.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/_internal/redirect.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_37164_hpe_oneview {
    meta:
        attack_type = "cve_2025_37164"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "HPE OneView - Remote Code Execution: HPE OneView contains a remote code execution vulnerability, letting remote attackers execute arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-37164"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-37164, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-37164.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/rest/id-pools/executeCommand" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_4008_meteobridge_6_1 {
    meta:
        attack_type = "cve_2025_4008"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "MeteoBridge <= 6.1 - Remote Code Execution: The Meteobridge web interface let meteobridge administrator manage their weather station data collection and administer their meteobridge system through a web application written in CGI shell scripts and C.This web interface exposes."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-4008"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-4008, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-4008.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/public/template.cgi" ascii nocase
        $param0 = "templatefile=$(id)" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_4009_evertz_sdvn_3080ipx_10g {
    meta:
        attack_type = "cve_2025_4009"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Evertz SDVN 3080ipx-10G - Unauthenticated Arbitrary Command Injection: The Evertz SDVN 3080ipx-10G is a High Bandwidth Ethernet Switching Fabric for Video Application. This device exposes a web management interface on port 80. This web management interface can be used by."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-4009"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-4009, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-4009.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/v.1.5/php/features/feature-transfer-export.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_40551_web_help_desk {
    meta:
        attack_type = "cve_2025_40551"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "SolarWinds Web Help Desk < 2026.1 - Unauthenticated JNDI Injection RCE: SolarWinds Web Help Desk before version 2026.1 contains an insecure deserialization vulnerability in the jabsorb JSON-RPC library. When chained with a CSRF whitelist bypass (CVE-2025-40536), remote."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-40551"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-40551, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-40551.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/helpdesk/WebObjects/Helpdesk.woa/wo/bogus.wo/" ascii nocase
        $path1 = "/helpdesk/WebObjects/Helpdesk.woa/wo/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_40552_web_help_desk {
    meta:
        attack_type = "cve_2025_40552"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SolarWinds Web Help Desk - Authentication Bypass: SolarWinds Web Help Desk contains an authentication bypass vulnerability caused by improper access control, letting attackers execute protected actions without authentication, exploit requires no special conditions."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-40552"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-40552, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-40552.yaml"
    strings:
        $path0 = "/helpdesk/WebObjects/Helpdesk.woa/wo/1.2" ascii nocase
        $param0 = "wopage=LookAndFeelPref" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_4123_grafana {
    meta:
        attack_type = "cve_2025_4123"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Grafana - XSS / Open Redirect / SSRF via Client Path Traversal: An open redirect vulnerability in Grafana can be chained with other issues, such as XSS or SSRF, to increase impact. An attacker may exploit the redirect to target internal services or deliver malicious JavaScript."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-4123"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-4123, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-4123.yaml"
    strings:
        $path0 = "/render/public/..%2f%5C" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_41243_spring_cloud_gateway_server_we {
    meta:
        attack_type = "cve_2025_41243"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Spring Cloud Gateway Server Webflux - Broken Access Control: Spring Cloud Gateway Server Webflux contains a vulnerability caused by unsecured and exposed actuator endpoints allowing modification of Spring Environment properties, letting attackers modify configuration, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-41243"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-41243, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-41243.yaml"
    strings:
        $path0 = "/actuator/gateway/routes/" ascii nocase
        $path1 = "/actuator/gateway/refresh" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_4334_simple_user_registration {
    meta:
        attack_type = "cve_2025_4334"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Simple User Registration <= 6.3 - Unauthenticated Privilege Escalation: The Simple User Registration plugin 6.3 is vulnerable to privilege escalation. It lacks proper restrictions on user meta values during registration. Unauthenticated attackers can exploit this to register as."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-4334"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-4334, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-4334.yaml"
    strings:
        $param0 = "_wp_http_referer=/register/" ascii nocase
        $param1 = "wpr[wp_field][role]=administrator" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_4380_ads_pro {
    meta:
        attack_type = "cve_2025_4380"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Ads Pro Plugin <= 4.89 - Local File Inclusion: The Ads Pro Plugin - Multi-Purpose WordPress Advertising Manager plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 4.89 via the 'bsa_template' parameter of the `bsa_preview_callback`."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-4380"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-4380, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-4380.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "action=bsa_preview_callback" ascii nocase
        $param1 = "bsa_template=../php/example" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_4388_liferay_portal {
    meta:
        attack_type = "cve_2025_4388"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Liferay Portal - Cross-Site Scripting: A reflected cross-site scripting (XSS) vulnerability in the Liferay Portal 7.4.0 through 7.4.3.131, and Liferay DXP 2024.Q4.0 through 2024.Q4.5, 2024.Q3.1 through 2024.Q3.13, 2024.Q2.0 through 2024.Q2.13, 2024.Q1.1 through 2024.Q1.12, 7.4."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-4388"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-4388, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-4388.yaml"
        response_type = "xss"
    strings:
        $path0 = "/o/marketplace-app-manager-web/icon.jsp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_44136_maptiler_tileserver_php_v2_0 {
    meta:
        attack_type = "cve_2025_44136"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MapTiler Tileserver-php v2.0 - Unauthenticated XSS: MapTiler Tileserver-php v2.0 contains a reflected XSS caused by unencoded reflection of the GET parameter /'layer/' in an error message, letting unauthenticated attackers execute arbitrary script on victim browsers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-44136"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-44136, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-44136.yaml"
        response_type = "xss"
    strings:
        $path0 = "/tileserver.php/wmts/x/1/1/asd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_44137_maptiler_tileserver_php_v2_0 {
    meta:
        attack_type = "cve_2025_44137"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MapTiler Tileserver-php v2.0 - Unauthenticated File Read: MapTiler Tileserver-php v2.0 contains a directory traversal caused by improper sanitization of GET parameters in renderTile function, letting attackers read arbitrary files on the server, exploit requires crafted web."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-44137"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-44137, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-44137.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/tileserver.php/x/1/1/1" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_44148_mailenable_mail_service_v10 {
    meta:
        attack_type = "cve_2025_44148"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MailEnable Mail Service < v10 - Cross-Site Scripting: Cross Site Scripting (XSS) vulnerability in MailEnable before v10 allows a remote attacker to execute arbitrary code via the failure.aspx component."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-44148"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-44148, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-44148.yaml"
        response_type = "xss"
    strings:
        $path0 = "/Mondo/lang/sys/Failure.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_44177_protop {
    meta:
        attack_type = "cve_2025_44177"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "White Star Software ProTop - Directory Traversal: A directory traversal vulnerability was discovered in White Star Software Protop version 4.4.2-2024-11-27, specifically in the /pt3upd/ endpoint. An unauthenticated attacker can remotely read arbitrary files on the underlying OS."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-44177"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-44177, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-44177.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/pt3upd/../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_4427_endpoint_manager_mobile {
    meta:
        attack_type = "cve_2025_4427"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Ivanti Endpoint Manager Mobile - Unauthenticated Remote Code Execution: An authentication bypass in Ivanti Endpoint Manager Mobile allowing attackers to access protected resources without proper credentials. This leads to unauthenticated Remote Code Execution via unsafe."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-4427"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-4427, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-4427.yaml"
        response_type = "template_eval"
    strings:
        $path0 = "/api/v2/featureusage_history" ascii nocase
        $path1 = "/api/v2/featureusage" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_4524_wordpress_madara_theme_2_2_2_1 {
    meta:
        attack_type = "cve_2025_4524"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Madara Theme < 2.2.2.1 - Local File Inclusion: Madara WordPress theme <= 2.2.2 contains a local file inclusion vulnerability caused by improper sanitization of the 'template' parameter, letting unauthenticated attackers execute arbitrary files on the server, exploit."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-4524"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-4524, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-4524.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "vars[orderby]=meta_value_num" ascii nocase
        $param1 = "vars[post_type]=wp-manga" ascii nocase
        $param2 = "vars[post_status]=publish" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_4576_liferay_portal_dxp {
    meta:
        attack_type = "cve_2025_4576"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Liferay Portal & DXP - Cross-Site Scripting: Liferay Portal 7.4.0 through 7.4.3.133 and Liferay DXP 2024.Q1.1 through 2025.Q1.4 contain a reflected XSS caused by improper sanitization in entry_cover_image_caption.jsp, letting remote non-authenticated attackers inject JavaScript."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-4576"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-4576, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-4576.yaml"
        response_type = "xss"
    strings:
        $path0 = "/o/blogs-web/blogs/entry_cover_image_caption.jsp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_45854_jehc_bpm {
    meta:
        attack_type = "cve_2025_45854"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JEHC-BPM - Remote Code Execute: A Remote Command Execution vulnerability in the component /server/executeExec of JEHC-BPM <= v2.0.1 allows attackers to execute arbitrary code. The vulnerability exists due to insufficient authorization checks in the executeExec endpoint which."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-45854"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-45854, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-45854.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/server/executeExec" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_45985_blink_router {
    meta:
        attack_type = "cve_2025_45985"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Blink Router - Command Injection: Blink routers BL-WR9000 V2.4.9 , BL-AC2100_AZ3 V1.0.4, BL-X10_AC8 v1.0.5 , BL-LTE300 v1.2.3, BL-F1200_AT1 v1.0.0, BL-X26_AC8 v1.2.8, BLAC450M_AE4 v4.0.0 and BL-X26_DA3 v1.2.7 were discovered to contain a command injection vulnerability via the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-45985"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-45985, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-45985.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/goform/set_hidessid_cfg" ascii nocase
        $param0 = "type=sethide2" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_4652_broadstreet {
    meta:
        attack_type = "cve_2025_4652"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Broadstreet WordPress plugin - Reflected XSS: Broadstreet WordPress plugin < 1.51.8 contains a reflected XSS caused by unsanitised and unescaped parameter output, letting attackers execute scripts against high privilege users such as admin, exploit requires victim interaction."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-4652"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-4652, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-4652.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/broadstreet/Broadstreet/Vendor/broadstreet-partner/index.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_47188_mitel_6000 {
    meta:
        attack_type = "cve_2025_47188"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Mitel 6000 - OS Command Injection: A vulnerability in the Mitel 6800 Series, 6900 Series, and 6900w Series SIP Phones through 6.4 SP4 (R6.4.0.4006), and the 6970 Conference Unit through 6.4 SP4 (R6.4.0.4006) or version V1 R0.1.0, could allow an unauthenticated attacker to."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-47188"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-47188, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-47188.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/cgi-bin/webconfig" ascii nocase
        $param0 = "page=upload_ringtone" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_47204_bootstrap_multiselect_1_1_2 {
    meta:
        attack_type = "cve_2025_47204"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Bootstrap Multiselect <= 1.1.2 - Cross-Site Scripting: A PHP script in the source code release echoes arbitrary POST data. If a developer adopts this structure wholesale in a live application, it could create a Reflective Cross-Site Scripting (XSS) vulnerability exploitable."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-47204"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-47204, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-47204.yaml"
        response_type = "xss"
    strings:
        $path0 = "/bootstrap-multiselect/post.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_47423_personal_weather_station_dashb {
    meta:
        attack_type = "cve_2025_47423"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Personal Weather Station Dashboard 12 - Directory Traversal: Personal Weather Station Dashboard 12_lts allows unauthenticated remote attackers to read arbitrary files via ../ directory traversal in the test parameter to /others/_test.php, as demonstrated by reading the server's."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-47423"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-47423, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-47423.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/others/_test.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_47539_eventin {
    meta:
        attack_type = "cve_2025_47539"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Eventin <= 4.0.26 - Privilege Escalation: The Eventin WordPress plugin before 4.0.27 suffers from an unauthenticated privilege escalation vulnerability. Due to a missing permission check in the a REST API endpoint, unauthenticated attackers can import users with arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-47539"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-47539, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-47539.yaml"
    strings:
        $path0 = "/wp-json/eventin/v2/speakers/import" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_47813_wftpserver {
    meta:
        attack_type = "cve_2025_47813"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Wing FTP Server <= 7.4.3 - Path Disclosure via Overlong UID Cookie: Wing FTP Server versions prior to 7.4.4 are vulnerable to an authenticated information disclosure vulnerability (CVE-2025-47813). The vulnerability occurs due to improper validation of the 'UID' session cookie."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-47813"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-47813, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-47813.yaml"
    strings:
        $param0 = "username=anonymous" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_47916_invision_community_5_0_6_unaut {
    meta:
        attack_type = "cve_2025_47916"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Invision Community <=5.0.6 Unauthenticated RCE via Template Injection: Invision Community 5.0.0 before 5.0.7 allows remote code execution via crafted template strings to themeeditor.php. The issue lies within the themeeditor controller."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-47916"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-47916, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-47916.yaml"
        response_type = "template_eval"
    strings:
        $param0 = "controller=themeeditor" ascii nocase
        $param1 = "do=customCss" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_48157_wordpress_formality_plugin_1_5 {
    meta:
        attack_type = "cve_2025_48157"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Formality Plugin <= 1.5.9 - Local File Inclusion: Michele Giorgi Formality <= 1.5.9 contains a file inclusion vulnerability caused by improper control of filename in include/require statements, letting attackers include local files, exploit requires crafted input."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-48157"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-48157, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-48157.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/wp-content/uploads/formality/storage/download.php" ascii nocase
        $param0 = "action=export_formality_result" ascii nocase
        $param1 = "wproot=/var/www/html" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_48703_cwp_control_web_panel_0_9_8_12 {
    meta:
        attack_type = "cve_2025_48703"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "CWP (Control Web Panel) < 0.9.8.1205 - Remote Code Execution: CWP (Control Web Panel) < 0.9.8.1205 contains a remote code execution caused by shell metacharacters in the t_total parameter in filemanager changePerm request, letting unauthenticated attackers execute code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-48703"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-48703, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-48703.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "module=filemanager" ascii nocase
        $param1 = "acc=changePerm" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_48827_vbulletin {
    meta:
        attack_type = "cve_2025_48827"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "vBulletin 5.0.0-6.0.3 - Authentication Bypass: vBulletin 5.0.0 through 5.7.5 and 6.0.0 through 6.0.3 contain an authentication bypass caused by unauthenticated access to protected API controllers on PHP 8.1 or later, letting unauthenticated attackers invoke protected methods."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-48827"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-48827, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-48827.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/ajax/api/ad/wrapAdTemplate" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_48828_vbulletin {
    meta:
        attack_type = "cve_2025_48828"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "vBulletin replaceAdTemplate - Remote Code Execution: vBulletin versions 5.0.0 through 6.0.3 contain a Remote Code Execution (RCE) vulnerability in the ajax/api/ad/replaceAdTemplate endpoint. This flaw arises from improper use of PHP's Reflection API, allowing unauthenticated."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-48828"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-48828, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-48828.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "routestring=ajax/api/ad/replaceAdTemplate" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_48954_discourse_oauth_social_login {
    meta:
        attack_type = "cve_2025_48954"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Discourse OAuth Social Login - Cross-site Scripting: Discourse versions prior to 3.5.0.beta6 contain a stored Cross-Site Scripting (XSS) vulnerability in the OAuth/social login functionality. The vulnerability is caused by lack of proper content security policy enforcement when."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-48954"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-48954, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-48954.yaml"
        response_type = "xss"
    strings:
        $path0 = "/auth/failure" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_49002_dataease {
    meta:
        attack_type = "cve_2025_49002"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "DataEase - Remote Code Execution: DataEase is an open-source business intelligence and data visualization platform. Public advisories state that CVE-2025-49002 is related to a bypass in the previous fix for CVE-2025-32966 involving case-insensitive handling of restricted H2."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-49002"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-49002, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-49002.yaml"
    strings:
        $path0 = "/de2api/datasource/getSchema" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_49029_wordpress_custom_login_and_sig {
    meta:
        attack_type = "cve_2025_49029"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Custom Login And Signup Widget Plugin <= 1.0 - Arbitrary Code Execution: Improper Control of Generation of Code ('Code Injection') vulnerability in bitto.Kazi Custom Login And Signup Widget allows Code Injection.This issue affects Custom Login And Signup Widget: from."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-49029"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-49029, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-49029.yaml"
    strings:
        $path0 = "/wp-content/plugins/custom-login-and-signup-widget/content/sn.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_49132_panel {
    meta:
        attack_type = "cve_2025_49132"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Pterodactyl Panel - Remote Code Execution: Pterodactyl is a free, open-source game server management panel. Using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-49132"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-49132, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-49132.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/locales/locale.json" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_49493_cloudtest {
    meta:
        attack_type = "cve_2025_49493"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Akamai CloudTest < 60 2025.06.02 - XML External Entity (XXE): Akamai CloudTest before 60 2025.06.02 (12988) allows file inclusion via XML External Entity (XXE) injection."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-49493"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-49493, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-49493.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/concerto/services/RepositoryService" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_49533_adobe_experience_manager_forms {
    meta:
        attack_type = "cve_2025_49533"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Adobe Experience Manager Forms - Insecure Deserialization: Adobe Experience Manager versions 6.5.23 and earlier are affected by a Misconfiguration vulnerability that could result in arbitrary code execution. An attacker could leverage this vulnerability to bypass security."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-49533"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-49533, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-49533.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/lc/libs/livecycle/core/content/login.html" ascii nocase
        $path1 = "/FormServer/servlet/GetDocumentServlet" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_49706_microsoft_sharepoint_server {
    meta:
        attack_type = "cve_2025_49706"
        classification = "attack"
        severity = 6
        confidence = "medium"
        description = "Microsoft SharePoint Server - Authentication Bypass: Improper authentication in Microsoft Office SharePoint allows an unauthorized attacker to perform spoofing over a network."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-49706"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-49706, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-49706.yaml"
    strings:
        $path0 = "/_layouts/15/ToolPane.aspx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_5086_dassault_syst_mes_delmia_apris {
    meta:
        attack_type = "cve_2025_5086"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Dassault Systmes DELMIA Apriso (up to 2025) - Insecure Deserialization: A deserialization of untrusted data vulnerability affecting DELMIA Apriso from Release 2020 through Release 2025 could lead to a remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-5086"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-5086, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-5086.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/apriso/WebServices/FlexNetOperationsService.svc/Invoke" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_51482_letta {
    meta:
        attack_type = "cve_2025_51482"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Letta Letta 0.7.12 - Remote Code Execution: Letta 0.7.12 is vulnerable to remote code execution via POST /v1/tools/run in letta.server.rest_api.routers.v1.tools.run_tool_from_source, allowing attackers to execute arbitrary Python and OS commands via crafted tool source code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-51482"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-51482, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-51482.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/v1/tools/run" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_51501_microweber {
    meta:
        attack_type = "cve_2025_51501"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Microweber CMS2.0 - Cross-Site Scripting: Reflected Cross-Site Scripting (XSS) in the `id` parameter of the `live_edit.module_settings` API endpoint in Microweber CMS2.0 allows execution of arbitrary JavaScript."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-51501"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-51501, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-51501.yaml"
        response_type = "xss"
    strings:
        $param0 = "type=shop/shipping/gateways/country/admin" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_51586_prestashop {
    meta:
        attack_type = "cve_2025_51586"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "PrestaShop - Information Disclosure: User enumeration vulnerability in the AdminLogin controller in PrestaShop 1.7 through 8.2.2 allows remote attackers to obtain administrators user email addresses via manipulation of the id_employee and reset_token parameters. An attacker who."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-51586"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-51586, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-51586.yaml"
    strings:
        $param0 = "controller=AdminLogin" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_51991_xwiki {
    meta:
        attack_type = "cve_2025_51991"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "XWiki <= 17.3.0 - Server-Side Template Injection (SSTI): XWiki <= 17.3.0 contains a server-side template injection caused by improper validation of Apache Velocity template code in the Administration interface HTTP Meta Info field, letting authenticated administrators execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-51991"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-51991, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-51991.yaml"
        response_type = "template_eval"
    strings:
        $path0 = "/bin/view/XWiki/XWikiPreferences" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_52207_mikopbx {
    meta:
        attack_type = "cve_2025_52207"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MikoPBX - Unrestricted File Upload: MikoPBX through 2024.1.114 contains an authenticated unrestricted file upload vulnerability caused by allowing PHP script uploads in PBXCoreREST/Controllers/Files/PostController.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-52207"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-52207, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-52207.yaml"
    strings:
        $path0 = "/admin-cabinet/session/start" ascii nocase
        $path1 = "/pbxcore/api/files/uploadFile" ascii nocase
        $path2 = "/pbxcore/files/cache/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_52472_xwiki {
    meta:
        attack_type = "cve_2025_52472"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "XWiki - HQL Injection: XWiki is vulnerable to Hibernate Query Language (HQL) injection in the wiki and space search REST API starting in version 4.3-milestone-1 and prior to versions 16.10.9, 17.4.2, and 17.5.0. The vulnerability allows attackers to inject malicious HQL queries."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-52472"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-52472, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-52472.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/xwiki/rest/wikis/xwiki/search" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_5287_likes_and_dislikes_plugin_1_0 {
    meta:
        attack_type = "cve_2025_5287"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Likes and Dislikes Plugin <= 1.0.0 - Unauthenticated SQL Injection: The Likes and Dislikes Plugin plugin for WordPress is vulnerable to SQL Injection via the 'post' parameter in all versions up to, and including, 1.0.0 due to insufficient escaping on the user supplied parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-5287"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-5287, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-5287.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "action=my_likes_dislikes_action" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_5301_onlyoffice_docs_documentserver {
    meta:
        attack_type = "cve_2025_5301"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ONLYOFFICE Docs (DocumentServer) - Reflected Cross-Site Scripting: ONLYOFFICE Docs (DocumentServer) <= 8.3.1 contains a reflected XSS caused by improper sanitization of crafted HTTP POST requests via the WOPI protocol, letting attackers inject malicious scripts reflected in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-5301"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-5301, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-5301.yaml"
        response_type = "xss"
    strings:
        $path0 = "/hosting/wopi/word/edit" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_53118_securden_unified_pam {
    meta:
        attack_type = "cve_2025_53118"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Securden Unified PAM - Authentication Bypass: An authentication bypass vulnerability exists which allows an unauthenticated attacker to control administrator backup functions, leading to compromise of passwords, secrets, and application session tokens stored by the Unified PAM."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-53118"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-53118, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-53118.yaml"
    strings:
        $path0 = "/thirdparty-access" ascii nocase
        $path1 = "/get_date_picker_format" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_5350_api_manager {
    meta:
        attack_type = "cve_2025_5350"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WSO2 - Server Side Request Forgery: WSO2 products contain SSRF and reflected XSS vulnerabilities in the deprecated Try-It feature accessible only to administrative users, caused by improper URL validation and direct content reflection, letting attackers trick admins into."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-5350"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-5350, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-5350.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/carbon/admin/jsp/WSRequestXSSproxy_ajaxprocessor.jsp;b=.jar" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_54123_hoverfly_1_11_3 {
    meta:
        attack_type = "cve_2025_54123"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hoverfly <= 1.11.3 - Remote Code Execution: Hoverfly versions 1.11.3 and below are vulnerable to remote code execution (RCE) via command injection in the middleware API endpoint (/api/v2/hoverfly/middleware). Insufficient validation of the 'binary' and 'script' parameters."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-54123"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-54123, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-54123.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/v2/hoverfly/middleware" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_54236_adobe_commerce {
    meta:
        attack_type = "cve_2025_54236"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Adobe Commerce - Authentication Bypass: Adobe Commerce versions 2.4.9-alpha2, 2.4.8-p2, 2.4.7-p7, 2.4.6-p12, 2.4.5-p14, 2.4.4-p15 and earlier are affected by an Improper Input Validation vulnerability. A successful attacker can abuse this to achieve session takeover, increasing."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-54236"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-54236, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-54236.yaml"
    strings:
        $path0 = "/customer/address_file/upload" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_54249_experience_manager {
    meta:
        attack_type = "cve_2025_54249"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Adobe Experience Manager 6.5.23.0 SSRF: Adobe Experience Manager versions 6.5.23.0 and earlier are affected by a Server-Side Request Forgery (SSRF) vulnerability that could result in a Security feature bypass"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-54249"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-54249, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-54249.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/services/accesstoken/verify;x='.pdf/x'" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_54251_experience_manager {
    meta:
        attack_type = "cve_2025_54251"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Adobe Experience Manager 6.5.23.0 - XML Injection: Adobe Experience Manager versions 6.5.23.0 and earlier are affected by an XML Injection vulnerability that could result in a Security feature bypass."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-54251"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-54251, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-54251.yaml"
    strings:
        $path0 = "/crx/packmgr/service/exec.json;x='x/graphql/execute/json/x'" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_55150_stirling_pdf {
    meta:
        attack_type = "cve_2025_55150"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Stirling-PDF < 1.1.0 - Server-Side Request Forgery: Stirling-PDF < 1.1.0 contains a server side request forgery caused by bypassing the sanitizer in the /api/v1/convert/html/pdf endpoint when processing HTML to PDF conversion, letting attackers perform SSRF, exploit requires."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-55150"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-55150, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-55150.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/v1/convert/html/pdf" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_55161_stirling_pdf_ssrf_via_markdown {
    meta:
        attack_type = "cve_2025_55161"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Stirling-PDF SSRF via Markdown: Stirling-PDF is a locally hosted web application that performs various operations on PDF files. Prior to version 1.1.0, when using the /api/v1/convert/markdown/pdf endpoint to convert Markdown to PDF, the backend calls a third-party tool to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-55161"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-55161, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-55161.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/api/v1/convert/markdown/pdf" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_55169_wegia {
    meta:
        attack_type = "cve_2025_55169"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WeGIA - Directory Traversal: WeGIA is an open source web manager with a focus on the Portuguese language and charitable institutions. Prior to version 3.4.8, a path traversal vulnerability was discovered in the WeGIA application, html/socio/sistema/download_remessa.php."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-55169"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-55169, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-55169.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/html/socio/sistema/download_remessa.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_55190_argocd_project_api_token_repos {
    meta:
        attack_type = "cve_2025_55190"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ArgoCD Project API Token Repository Credentials Exposure: Argo CD API tokens with project-level permissions are able to retrieve sensitive repository credentials (usernames, passwords) through the project details API endpoint, even when the token only has standard application."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-55190"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-55190, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-55190.yaml"
    strings:
        $path0 = "/api/v1/projects/default/detailed" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_5569_ideacms {
    meta:
        attack_type = "cve_2025_5569"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "IdeaCMS <= 1.7 - SQL Injection: IdeaCMS up to 1.7 is vulnerable to SQL injection via the field parameter in article and product query interfaces. This template uses a time-based payload to safely detect the vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-5569"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-5569, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-5569.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/api/v1.index.article/getList.html" ascii nocase
        $path1 = "/api/v1.index.goods/getList.html" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_55747_xwiki_platform {
    meta:
        attack_type = "cve_2025_55747"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "XWiki Platform - Information Disclosure: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. In versions 6.1-milestone-2 through 16.10.6, configuration files are accessible through the webjars API."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-55747"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-55747, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-55747.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/xwiki/webjars/wiki:xwiki/../../../../../WEB-INF/xwiki.cfg" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_55748_xwiki_platform {
    meta:
        attack_type = "cve_2025_55748"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "XWiki Platform - Path Traversal: XWiki Platform 4.2-milestone-2 through 16.10.6 contains a path traversal caused by improper access control in jsx and sx endpoints, letting remote attackers read configuration files, exploit requires no special privileges."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-55748"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-55748, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-55748.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/bin/ssx/Main/WebHome" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_55749_xwiki {
    meta:
        attack_type = "cve_2025_55749"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "XWiki - Information Disclosure: XWiki 16.7.0 to 16.10.11, 17.4.4, and 17.7.0 using XJetty contains an information disclosure vulnerability caused by exposed context allowing static access to files in webapp/ folder, letting attackers access sensitive files, exploit requires use."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-55749"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-55749, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-55749.yaml"
    strings:
        $path0 = "/webapps/xwiki/WEB-INF/xwiki.properties" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_5605_wso2_management_console {
    meta:
        attack_type = "cve_2025_5605"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WSO2 Management Console - Authentication Bypass: An authentication bypass vulnerability exists in the Management Console of multiple WSO2 products. A malicious actor with access to the console can manipulate the request URI to bypass authentication and access certain restricted."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-5605"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-5605, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-5605.yaml"
    strings:
        $path0 = "/carbon/server-admin/memory_info.jsp;.jar" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_56132_liquidfiles {
    meta:
        attack_type = "cve_2025_56132"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LiquidFiles < 4.2 - User Enumeration via Password Reset: LiquidFiles filetransfer server before 4.2 contains a user enumeration vulnerability caused by distinguishable responses in password reset functionality, letting unauthenticated attackers enumerate valid user accounts."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-56132"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-56132, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-56132.yaml"
    strings:
        $path0 = "/password_reset" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_56520_dify_v1_6_0 {
    meta:
        attack_type = "cve_2025_56520"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dify v1.6.0 - Server-Side Request Forgery: Dify v1.6.0 contains a server side request forgery caused by improper validation in controllers.console.remote_files.RemoteFileUploadApi, letting attackers make arbitrary requests from the server, exploit requires network access."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-56520"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-56520, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-56520.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/console/api/remote-files/http:/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_56819_datart {
    meta:
        attack_type = "cve_2025_56819"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Datart v1.0.0-rc.3 - Remote Code Execution: Datart v1.0.0-rc.3 contains a vulnerability that allows remote attackers to execute arbitrary code via INIT connection parameters."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-56819"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-56819, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-56819.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/v1/data-provider/test" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_57231_docmost {
    meta:
        attack_type = "cve_2025_57231"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Docmost 0.2.1-0.21.0 - Arbitrary File Read: Docmost v0.21.0 contains a path traversal caused by improper handling of avatar attachments, letting unauthenticated attackers disclose local files via a POST request on a public URL."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-57231"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-57231, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-57231.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/attachments/img/avatar/../../../../../etc/passwd" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_5777_citrix_netscaler_memory_disclo {
    meta:
        attack_type = "cve_2025_5777"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Citrix NetScaler Memory Disclosure - CitrixBleed 2: Insufficient input validation leading to memory overread on the NetScaler Management Interface NetScaler ADC and NetScaler Gateway"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-5777"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-5777, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-5777.yaml"
    strings:
        $path0 = "/p/u/doAuthentication.do" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_57788_commvault_unauthenticated_pass {
    meta:
        attack_type = "cve_2025_57788"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Commvault Unauthenticated Password Disclosure (WT-2025-0047): An issue was discovered in Commvault before 11.36.60. A vulnerability in a known login mechanism allows unauthenticated attackers to execute API calls without requiring user credentials. RBAC helps limit the exposure."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-57788"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-57788, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-57788.yaml"
    strings:
        $path0 = "/commandcenter/RestServlet/Database/GetUmUserById/1" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_58360_geoserver {
    meta:
        attack_type = "cve_2025_58360"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "GeoServer - XML External Entity Injection: GeoServer 2.26.0 to 2.26.2 and 2.25.6 contains an XML External Entity (XXE) injection caused by insufficient sanitization of XML input in /geoserver/wms GetMap operation, letting attackers disclose files or cause DoS, exploit requires."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-58360"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-58360, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-58360.yaml"
    strings:
        $param0 = "request=GetMap" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_58434_flowise_3_0_5 {
    meta:
        attack_type = "cve_2025_58434"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Flowise <= 3.0.5 - Account Takeover: Flowise versions 3.0.5 and earlier had a vulnerability in the forgot-password endpoint, which returned valid reset tokens without authenticationallowing attackers to reset passwords and take over accounts."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-58434"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-58434, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-58434.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/api/v1/account/forgot-password" ascii nocase
        $path1 = "/api/v1/account/reset-password" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_58443_fogproject {
    meta:
        attack_type = "cve_2025_58443"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FOGProject < 1.5.10.1693 - Authentication Bypass: FOGProject version 1.5.10.1673 suffers from an authentication bypass vulnerability that allows unauthenticated users to access the management interface without proper authentication. This can lead to unauthorized access to."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-58443"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-58443, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-58443.yaml"
    strings:
        $path0 = "/fog/service/getversion.php" ascii nocase
        $path1 = "/fog/status/getfiles.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_58751_vite_dev_server {
    meta:
        attack_type = "cve_2025_58751"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "Vite Dev Server - Path Traversal: Vite is a frontend tooling framework for JavaScript. Prior to versions 7.1.5, 7.0.7, 6.3.6, and 5.4.20, files starting with the same name with the public directory were served bypassing the `server.fs` settings. Only apps that explicitly expose."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-58751"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-58751, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-58751.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/../package.json" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_59287_windows_server_update_service {
    meta:
        attack_type = "cve_2025_59287"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Windows Server Update Service - Insecure Deserialization: Windows Server Update Service contains an insecure deserialization vulnerability caused by deserialization of untrusted data. An unauthorized attacker with network access can exploit this to execute arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-59287"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-59287, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-59287.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/ReportingWebService/ReportingWebService.asmx" ascii nocase
        $path1 = "/SimpleAuthWebService/SimpleAuth.asmx" ascii nocase
        $path2 = "/ClientWebService/Client.asmx" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_59342_esm_sh {
    meta:
        attack_type = "cve_2025_59342"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "esm.sh <= v136 - Arbitrary File Write via Path Traversal: esm.sh <= 136 contains a path traversal caused by improper canonicalization of the X-Zone-Id HTTP header, letting attackers write files outside the intended storage directory, exploit requires crafted header input."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-59342"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-59342, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-59342.yaml"
    strings:
        $path0 = "/transform" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_59474_jenkins_sidepanel {
    meta:
        attack_type = "cve_2025_59474"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Jenkins Sidepanel - Unauthorized Agent/Queue Exposure: Jenkins 2.527 and earlier, LTS 2.516.2 and earlier does not perform a permission check in the sidepanel of a page intentionally accessible to users lacking Overall/Read permission, allowing attackers without Overall/Read."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-59474"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-59474, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-59474.yaml"
    strings:
        $path0 = "/securityRealm/signup" ascii nocase
        $path1 = "/jenkins/securityRealm/signup" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_59582_ajax_load_more_7_6_1 {
    meta:
        attack_type = "cve_2025_59582"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ajax Load More < 7.6.1 - Unauthenticated Sensitive Information Exposure: The Ajax Load More Infinite Scroll plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 7.6.0.2. The plugin's AJAX endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-59582"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-59582, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-59582.yaml"
    strings:
        $param0 = "custom_args=post_status:draft" ascii nocase
        $param1 = "custom_args=post_status:private" ascii nocase
        $param2 = "custom_args=post_status:pending" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_5961_wordpress_wpvivid_backup_migra {
    meta:
        attack_type = "cve_2025_5961"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress WPvivid Backup & Migration Plugin <= 0.9.116 - Authenticated Arbitrary File Upload: The Migration, Backup, Staging WPvivid Backup & Migration plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-5961"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-5961, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-5961.yaml"
    strings:
        $path0 = "/wp-content/wpvividbackups/ImportandExport/" ascii nocase
        $param0 = "page=wpvivid-export-import" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_59716_guests {
    meta:
        attack_type = "cve_2025_59716"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ownCloud Guests - User Enumeration: ownCloud Guests before 0.12.5 contains an unauthenticated user enumeration vulnerability caused by insufficient validation of the token in showPasswordForm at /apps/guests/register/{email}/{token}, letting unauthenticated attackers enumerate."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-59716"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-59716, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-59716.yaml"
    strings:
        $path0 = "/apps/guests/register/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_60188_atarim_4_2_2 {
    meta:
        attack_type = "cve_2025_60188"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Atarim < 4.2.2 - Sensitive Information Exposure: Vito Peleg Atarim <= 4.2 contains an insertion of sensitive information into sent data vulnerability caused by improper handling of embedded sensitive data, letting attackers retrieve embedded sensitive data remotely, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-60188"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-60188, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-60188.yaml"
    strings:
        $path0 = "/wp-json/atarim/v1/db/vc" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_6174_wordpress_qwizcards_3_95 {
    meta:
        attack_type = "cve_2025_6174"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Qwizcards < 3.95 - Cross-Site Scripting (Reflected): The WordPress Qwizcards plugin before version 3.95 does not sanitise and escape the 'theme_stylesheet' parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting vulnerability."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-6174"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-6174, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-6174.yaml"
        response_type = "xss"
    strings:
        $path0 = "/wp-content/plugins/qwiz-online-quizzes-and-flashcards/qwiz_admin_sample_buttons.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_61757_identity_manager {
    meta:
        attack_type = "cve_2025_61757"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Oracle Identity Manager REST WebServices - Authentication Bypass: Vulnerability in the Identity Manager product of Oracle Fusion Middleware (component: REST WebServices). Supported versions that are affected are 12.2.1.4.0 and 14.1.2.1.0. Easily exploitable vulnerability allows."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-61757"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-61757, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-61757.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus" ascii nocase
        $path1 = "/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus;.wadl" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_61882_oracle_e_business_suite_12_2_3 {
    meta:
        attack_type = "cve_2025_61882"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Oracle E-Business Suite 12.2.312.2.14 Remote Code Execution: Oracle Concurrent Processing 12.2.3-12.2.14 contains a remote code execution caused by unauthenticated network access via HTTP, letting unauthenticated attackers fully compromise the system, exploit requires network."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-61882"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-61882, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-61882.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/OA_HTML/SyncServlet" ascii nocase
        $path1 = "/OA_HTML/help/../ieshostedsurvey.jsp" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_61884_oracle_e_business_suite {
    meta:
        attack_type = "cve_2025_61884"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Oracle E-Business Suite - Server-Side Request Forgery: Vulnerability in the Oracle Configurator product of Oracle E-Business Suite (component: Runtime UI). Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-61884"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-61884, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-61884.yaml"
    strings:
        $path0 = "/OA_HTML/configurator/UiServlet" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_62039_ai_chatbot_with_chatgpt_by_ays {
    meta:
        attack_type = "cve_2025_62039"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AI ChatBot with ChatGPT by AYS <= 2.6.6 - Unauthenticated API Key Exposure: AYS AI ChatBot with ChatGPT and Content Generator <= 2.6.6 contains an insertion of sensitive information into sent data vulnerability caused by improper handling of embedded sensitive data, letting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-62039"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-62039, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-62039.yaml"
    strings:
        $param0 = "function=get_chatgpt_api_key" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_6204_delmia_apriso {
    meta:
        attack_type = "cve_2025_6204"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "DELMIA Apriso - Command Injection: An Improper Control of Generation of Code (code injection / file upload RCE) vulnerability affecting DELMIA Apriso (Release 2020 Release 2025). When an authenticated user can upload files and the upload handler fails to canonicalize filenames."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-6204"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-6204, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-6204.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/Apriso/Portal/Kiosk/Login.aspx" ascii nocase
        $path1 = "/Apriso/webservices/1.1/operation.svc/UploadFile" ascii nocase
        $path2 = "/Apriso/Portal/Uploads/" ascii nocase
        $param0 = "ctl04$LogInButton=Log In" ascii nocase
        $param1 = "ctl04$HiddenValue=Initial Value" ascii nocase
        $param2 = "ctl04$HiddenValue2=Initial Value" ascii nocase
        $param3 = "o=cmd.StdOut.Readall()" ascii nocase
        $param4 = "Set fso=Nothing" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_62126_varnish_caching_wordpress_plug {
    meta:
        attack_type = "cve_2025_62126"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Varnish/Nginx Proxy Caching <= 1.8.3 - Information Exposure: Razvan Stanga Varnish/Nginx Proxy Caching <= 1.8.3 contains an insertion of sensitive information into sent data vulnerability caused by improper handling of embedded sensitive data, letting attackers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-62126"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-62126, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-62126.yaml"
    strings:
        $param0 = "action=varnish_caching_download" ascii nocase
        $param1 = "option_page=varnish_caching_download" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_62512_piwigo {
    meta:
        attack_type = "cve_2025_62512"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Piwigo - User Enumeration via Password Reset: Piwigo is an open source photo gallery application for the web. In version 15.5.0 and likely earlier 15.x releases, the password reset functionality in Piwigo allows an unauthenticated attacker to determine whether a given username."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-62512"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-62512, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-62512.yaml"
    strings:
        $path0 = "/password.php" ascii nocase
        $param0 = "submit=Change my password" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_62613_vdo_ninja {
    meta:
        attack_type = "cve_2025_62613"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "VDO.Ninja - DOM-Based Cross-Site Scripting: VDO.Ninja 28.0 to 28.3 contains a reflected XSS caused by improper sanitization of the room parameter in examples/control.html, letting remote attackers execute scripts, exploit requires crafted URL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-62613"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-62613, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-62613.yaml"
        response_type = "xss"
    strings:
        $path0 = "/examples/control.html" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_63387_dify_v1_9_1 {
    meta:
        attack_type = "cve_2025_63387"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Dify v1.9.1 - Broken Access Control: Dify v1.9.1 contains an insecure permissions vulnerability caused by lack of authorization checks in /console/api/system-features endpoint, letting unauthenticated attackers access sensitive system configuration data."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-63387"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-63387, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-63387.yaml"
    strings:
        $path0 = "/console/api/system-features" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_6389_sneeit_framework {
    meta:
        attack_type = "cve_2025_6389"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Sneeit WP Social WordPress Plugin - Unauthenticated RCE via call_user_func: The Sneeit Framework plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 8.3 via the sneeit_articles_pagination_callback() function. This is due to the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-6389"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-6389, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-6389.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "action=sneeit_articles_pagination" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_6403_code_projects_school_fees_paym {
    meta:
        attack_type = "cve_2025_6403"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Code-Projects School Fees Payment System 1.0 - SQL Injection: A vulnerability was found in code-projects School Fees Payment System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /student.php. The manipulation of the argument ID leads."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-6403"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-6403, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-6403.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/student.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_64328_freepbx {
    meta:
        attack_type = "cve_2025_64328"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "FreePBX >= 17.0.2.36 && < 17.0.3 - Authenticated Command Injection: FreePBX Endpoint Manager 17.0.2.36 to < 17.0.3 contains a command injection caused by improper sanitization in filestore module's testconnection check_ssh_connect() function, letting authenticated users execute."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-64328"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-64328, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-64328.yaml"
        response_type = "command_injection"
    strings:
        $param0 = "module=filestore" ascii nocase
        $param1 = "command=testconnection" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_64764_astro {
    meta:
        attack_type = "cve_2025_64764"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Astro - Reflected XSS via server islands feature: Astro 5.15.8 contains a reflected XSS caused by improper handling of server islands feature, letting remote attackers execute scripts, exploit requires use of server islands in the application."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-64764"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-64764, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-64764.yaml"
        response_type = "xss"
    strings:
        $path0 = "/_server-islands/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_66472_xwiki {
    meta:
        attack_type = "cve_2025_66472"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki DeleteApplication - Cross-Site Scripting: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Versions 6.2-milestone-1 through 16.10.9 and 17.0.0-rc-1 through 17.4.1 of both XWiki Platform Flamingo Skin Resources and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-66472"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-66472, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-66472.yaml"
        response_type = "xss"
    strings:
        $param0 = "appName=Help.Applications.Contributors" ascii nocase
        $param1 = "xredirect=/bin/view/Help/Applications/Contributors/';alert(document.domain)//" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_66744_yonyou_yonbip {
    meta:
        attack_type = "cve_2025_66744"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Yonyou YonBIP - Path Traversal: Yonyou YonBIP v3 and before contains a path traversal caused by improper validation in the LoginWithV8 interface of the series data application service system, letting unauthorized attackers access sensitive information."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-66744"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-66744, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-66744.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/bi/api/Portal/LoginWithV8/" ascii nocase
        $param0 = "ticket=/../../../../Windows/win.ini" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_67303_comfyui_manager {
    meta:
        attack_type = "cve_2025_67303"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ComfyUI-Manager < 3.38 - Configuration Overwrite: ComfyUI-Manager < 3.38 contains an insecure file storage vulnerability caused by storing files in an insufficiently protected location accessible via the web interface, letting remote attackers manipulate configuration and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-67303"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-67303, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-67303.yaml"
    strings:
        $path0 = "/userdata/ComfyUI-Manager/config.ini" ascii nocase
        $param0 = "security_level=weak" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_68273_signalk_server {
    meta:
        attack_type = "cve_2025_68273"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Signal K Server <= 2.18.0 - Information Disclosure: Signal K Server versions up to and including 2.18.0 expose the /skServer/serialports, /skServer/availablePaths, and /skServer/hasAnalyzer endpoints without authentication. These routes were missing from the authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-68273"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-68273, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-68273.yaml"
    strings:
        $path0 = "/skServer/serialports" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_68493_struts {
    meta:
        attack_type = "cve_2025_68493"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache Struts XWork - XML External Entity Injection: Apache Struts 2.0.0 < 2.2.1 and 2.2.1 <= versions <= 6.1.0 contain an XML external entity injection caused by missing XML validation, letting attackers potentially disclose files or cause denial of service, exploit requires."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-68493"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-68493, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-68493.yaml"
    strings:
        $path0 = "/struts2-xml-parser/xmlParserNoDtdParse" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_6851_broken_link_notifier {
    meta:
        attack_type = "cve_2025_6851"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Broken Link Notifier < 1.3.1 - Unauthenticated SSRF: The Broken Link Notifier plugin for WordPress is vulnerable to Server-Side Request Forgery in all versions up to, and including, 1.3.0 via the ajax_blinks() function which ultimately calls the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-6851"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-6851, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-6851.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = "action=blnotifier_blinks" ascii nocase
        $param1 = "source_url=http://test" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_68645_zimbra_collaboration {
    meta:
        attack_type = "cve_2025_68645"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Zimbra Collaboration - Local File Inclusion: Zimbra Collaboration (ZCS) 10.0 and 10.1 contain a local file inclusion caused by improper handling of user-supplied parameters in the RestFilter servlet, letting unauthenticated remote attackers include arbitrary files from WebRoot."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-68645"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-68645, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-68645.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = "javax.servlet.include.servlet_path=/WEB-INF/web.xml" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_6934_opal_estate_pro {
    meta:
        attack_type = "cve_2025_6934"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "The Opal Estate Pro Property Management <= 1.7.5 - Unauthenticated Privilege Escalation: The Opal Estate Pro plugin ( 1.7.5) is vulnerable to privilege escalation. Due to missing role restrictions in the on_register_user function, users can register with any role. This allows."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-6934"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-6934, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-6934.yaml"
    strings:
        $param0 = "action=opalestate_register_form" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_6970_events_manager {
    meta:
        attack_type = "cve_2025_6970"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Events Manager <= 7.0.3 - SQL Injection: The Events Manager - Calendar, Bookings, Tickets, and more! plugin for WordPress is vulnerable to time-based SQL Injection via the 'orderby' parameter in all versions up to, and including, 7.0.3 due to insufficient escaping on."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-6970"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-6970, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-6970.yaml"
        response_type = "sql_error"
    strings:
        $param0 = "orderby=1*(select(sleep(8)))" ascii nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_71258_footprints {
    meta:
        attack_type = "cve_2025_71258"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "BMC FootPrints 'searchWeb' - Server-Side Request Forgery: BMC FootPrints versions 20.20.02 through 20.24.01.001 contain a Server-Side Request Forgery (SSRF) vulnerability in the /footprints/servicedesk/import/searchWeb endpoint. The 'url' parameter allows unauthenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-71258"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-71258, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-71258.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/footprints/servicedesk/import/searchWeb" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_71259_footprints {
    meta:
        attack_type = "cve_2025_71259"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "BMC FootPrints 'feedUrl' - Server-Side Request Forgery: BMC FootPrints versions 20.20.02 through 20.24.01.001 contain a Server-Side Request Forgery (SSRF) vulnerability in the /footprints/servicedesk/externalfeed/RSS endpoint. The 'feedUrl' parameter allows unauthenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-71259"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-71259, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-71259.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/footprints/servicedesk/externalfeed/RSS" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_71324_flowise {
    meta:
        attack_type = "cve_2025_71324"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Flowise - Path Traversal: Flowise < 3.0.6 contains a path traversal vulnerability caused by improper validation of the chatId parameter in /api/v1/get-upload-file and /api/v1/openai-assistants-file/download endpoints, letting unauthenticated attackers read arbitrary files."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-71324"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-71324, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-71324.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/v1/vector/upsert/" ascii nocase
        $param0 = "chatId=/../../" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_71334_flowise {
    meta:
        attack_type = "cve_2025_71334"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Flowise - Path Traversal: Flowise <= 2.2.8 contains a path traversal vulnerability caused by missing validation of chatflowId and chatId parameters in file handling, letting unauthenticated attackers read and write arbitrary files, exploit requires no authentication."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-71334"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-71334, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-71334.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/api/v1/chatflows" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_8085_ditty_3_1_58 {
    meta:
        attack_type = "cve_2025_8085"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ditty < 3.1.58 - Server-Side Request Forgery: The plugin lacks authorization and authentication for requests to its displayItems endpoint, allowing unauthenticated visitors to make requests to arbitrary URLs. v3.1.57 attempted to fix the issue with a nonce check, however any."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-8085"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-8085, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-8085.yaml"
    strings:
        $path0 = "/wp-json/dittyeditor/v1/displayItems" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_8266_chancms_3_1 {
    meta:
        attack_type = "cve_2025_8266"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ChanCMS <= 3.1. - Remote Code Execution: yanyutao0402 ChanCMS <= 3.1.2 contains an insecure deserialization caused by manipulation of the /'targetUrl/' argument in getArticle function of app/modules/cms/controller/collect.js, letting remote attackers execute arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-8266"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-8266, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-8266.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/cms/gather/getArticle" ascii nocase
        $param0 = "targetUrl=http://jsonplaceholder.typicode.com/posts/1" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2025_8868_chef_automate_4_13_295_sql_inj {
    meta:
        attack_type = "cve_2025_8868"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Chef Automate < 4.13.295 SQL Injection: In Progress Chef Automate, versions earlier than 4.13.295, on Linux x86 platform, an authenticated attacker can gain access to Chef Automate restricted functionality in the compliance service via improperly neutralized inputs used in an."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-8868"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-8868, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-8868.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/api/v0/compliance/profiles/search" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_9196_trinity_audio {
    meta:
        attack_type = "cve_2025_9196"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Trinity Audio <= 5.21.0 - Information Exposure: The Trinity Audio Text to Speech AI audio player to convert content into audio plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 5.21.0 via the ~/admin/inc/phpinfo.php file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-9196"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-9196, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-9196.yaml"
    strings:
        $path0 = "/wp-content/plugins/trinity-audio/admin/inc/phpinfo.php" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_9808_the_events_calendar_6_15_2 {
    meta:
        attack_type = "cve_2025_9808"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "The Events Calendar <= 6.15.2 - Information Disclosure: The Events Calendar WordPress plugin <= 6.15.2 contains an information disclosure vulnerability caused by REST endpoint exposure, letting unauthenticated attackers extract data about password-protected vendors or venues."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-9808"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-9808, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-9808.yaml"
    strings:
        $path0 = "/wp-json/tribe/events/v1/organizers" ascii nocase
        $path1 = "/wp-json/tribe/events/v1/venues" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2025_9985_featured_image_from_url_fifu_5 {
    meta:
        attack_type = "cve_2025_9985"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Featured Image from URL (FIFU) <= 5.2.7 - Unauthenticated Information Exposure via Log File: The Featured Image from URL (FIFU) plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 5.2.7 through publicly exposed log files.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2025-9985"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-9985, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-9985.yaml"
    strings:
        $path0 = "/wp-content/uploads/fifu-cloud.log" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}
