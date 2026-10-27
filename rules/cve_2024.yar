// Baseline rules generated from public exploit and exposure checks in
// ProjectDiscovery nuclei-templates (MIT License,
// https://github.com/projectdiscovery/nuclei-templates). Each rule keys on the
// most specific request indicator of one check: a path, a static parameter or
// a vendor header that no other check and no benign request uses. Rules are
// confidence = "medium": a probe for the endpoint is a strong signal, but a
// rule cannot tell an exploit attempt from a scanner fingerprinting it.
// The `reference` field links the source check.

rule krawl_cve_2024_0195_spider_flow {
    meta:
        attack_type = "cve_2024_0195"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SpiderFlow Crawler Platform - Remote Code Execution: A vulnerability, which was classified as critical, was found in spider-flow 0.4.3. Affected is the function FunctionService.saveFunction of the file src/main/java/org/spiderflow/controller/FunctionController.java. The."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0195"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0195, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0195.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/function\/save(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_0200_enterprise_server {
    meta:
        attack_type = "cve_2024_0200"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Github Enterprise - Remote Code Execution: An unsafe reflection vulnerability was identified in GitHub Enterprise Server that could lead to reflection injection. This vulnerability could lead to the execution of user-controlled methods and remote code execution. To exploit this."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0200"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0200, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0200.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/settings\/actions\/repository_items(\/|;|$)/ nocase
        $param0 = /(^|[?&;])rid_key=nw_fsck(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_0204_goanywhere_managed_file_transf {
    meta:
        attack_type = "cve_2024_0204"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Fortra GoAnywhere MFT - Authentication Bypass: Authentication bypass in Fortra's GoAnywhere MFT prior to 7.4.1 allows an unauthorized user to create an admin user via the administration portal."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0204"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0204, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0204.yaml"
    strings:
        $path0 = /\/goanywhere\/images\/\.\.;\/wizard\/InitialAccountSetup\.xhtml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_0235_eventon {
    meta:
        attack_type = "cve_2024_0235"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "EventON (Free < 2.2.8, Premium < 4.5.5) - Information Disclosure: The EventON WordPress plugin before 4.5.5, EventON WordPress plugin before 2.2.7 do not have authorization in an AJAX action, allowing unauthenticated users to retrieve email addresses of any users on the blog."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0235"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0235, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0235.yaml"
    strings:
        $param0 = /(^|[?&;])action=eventon_get_virtual_users(&|$)/ nocase
        $param1 = /(^|[?&;])_user_role=administrator(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_0250_analytics_insights_for_google {
    meta:
        attack_type = "cve_2024_0250"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Analytics Insights for Google Analytics 4 < 6.3 - Open Redirect: The plugin is vulnerable to Open Redirect due to insufficient validation on the redirect oauth2callback.php file. This makes it possible for unauthenticated attackers to redirect users to potentially malicious."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0250"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0250, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0250.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/analytics-insights\/tools\/oauth2callback\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_0305_ncast {
    meta:
        attack_type = "cve_2024_0305"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ncast busiFacade - Remote Command Execution: The Ncast Yingshi high-definition intelligent recording and playback system is a newly developed audio and video recording and playback system. The system has RCE vulnerabilities in versions 2017 and earlier."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0305"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0305, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0305.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/classes\/common\/busiFacade\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_0352_likeshop {
    meta:
        attack_type = "cve_2024_0352"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Likeshop < 2.5.7.20210311 - Arbitrary File Upload: A vulnerability classified as critical was found in Likeshop up to 2.5.7.20210311. This vulnerability affects the function FileServer::userFormImage of the file server/application/api/controller/File.php of the component HTTP."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0352"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0352, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0352.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/file\/formimage(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_0692_security_event_manager {
    meta:
        attack_type = "cve_2024_0692"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SolarWinds Security Event Manager - Unauthenticated RCE: The SolarWinds Security Event Manager was susceptible to Remote Code Execution Vulnerability. This vulnerability allows an unauthenticated user to abuse SolarWinds service, resulting in remote code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0692"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0692, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0692.yaml"
    strings:
        $path0 = /\/services\/messagebroker\/streamingamf(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_0799_udp {
    meta:
        attack_type = "cve_2024_0799"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Arcserve Unified Data Protection - Authentication Bypass: An authentication bypass vulnerability exists in Arcserve Unified Data Protection 9.2 and 8.1 in the edge-app-base-webui.jar!com.ca.arcserve.edge.app.base.ui.server.EdgeLoginServiceImpl.doLogin() function within."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0799"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0799, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0799.yaml"
    strings:
        $path0 = /\/management\/wizardLogin(\/|;|$)/ nocase
        $path1 = /\/management\/centralmanagementui\/service\/configuration(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_0801_udp {
    meta:
        attack_type = "cve_2024_0801"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Arcserve Unified Data Protection - Unauthenticated DoS in ASNative.dll: A denial of service vulnerability exists in Arcserve Unified Data Protection 9.2 and 8.1 in ASNative.dll."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0801"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0801, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0801.yaml"
    strings:
        $path0 = /\/management\/services\/EdgeServiceConsoleImpl(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_0881_combo_blocks_2_2_76 {
    meta:
        attack_type = "cve_2024_0881"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Combo Blocks < 2.2.76 - Improper Access Control: The Post Grid, Form Maker, Popup Maker, WooCommerce Blocks, Post Blocks, Post Carousel WordPress plugin before 2.2.76 does not prevent password protected posts from being displayed in the result of some unauthenticated AJAX."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0881"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0881, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0881.yaml"
    strings:
        $param0 = /(^|[?&;])action=post_grid_paginate_ajax_free(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_0939_smart_s210_firmware {
    meta:
        attack_type = "cve_2024_0939"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Smart S210 Management Platform - Arbitary File Upload: A vulnerability has been found in Byzoro Smart S210 Management Platform up to 20240117 and classified as critical. This vulnerability affects unknown code of the file /Tool/uploadfile.php. The manipulation of the argument."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0939"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0939, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0939.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/Tool\/uploadfile\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_0986_pbx {
    meta:
        attack_type = "cve_2024_0986"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Issabel Authenticated - Remote Code Execution: A vulnerability was found in Issabel PBX 4.0.0. It has been rated as critical. This issue affects some unknown processing of the file /index.php?menu=asterisk_cli of the component Asterisk-Cli. The manipulation of the argument."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-0986"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-0986, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-0986.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/modules\/backup_restore\/restore\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])menu=asterisk_cli(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_10081_codechecker_6_24_1 {
    meta:
        attack_type = "cve_2024_10081"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CodeChecker <= 6.24.1 - Authentication Bypass: Authentication bypass occurs when the API URL ends with Authentication, Configuration or ServerInfo. This bypass allows superuser access to all API endpoints other than Authentication. These endpoints include the ability to add."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-10081"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-10081, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-10081.yaml"
    strings:
        $path0 = /\/v6\.58\/Products\/Authentication(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_10146_simple_file_list {
    meta:
        attack_type = "cve_2024_10146"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Simple File List < 6.1.13 - Reflected Cross-Site Scripting: Simple File List WordPress plugin /u003C 6.1.13 contains a reflected cross-site scripting caused by unsanitized URL output in an attribute, letting attackers execute malicious scripts in admin browsers, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-10146"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-10146, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-10146.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])subtab=uploader_settings(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_10152_simple_certain_time_to_show_co {
    meta:
        attack_type = "cve_2024_10152"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Simple Certain Time to Show Content - Cross-Site Scripting: Simple Certain Time to Show Content WordPress plugin < 1.3.1 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-10152"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-10152, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-10152.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=simple-certain-time-to-show-content(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_1021_rebuild {
    meta:
        attack_type = "cve_2024_1021"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Rebuild <= 3.5.5 - Server-Side Request Forgery: There is a security vulnerability in Rebuild 3.5.5, which is due to a server-side request forgery vulnerability in the URL parameter of the readRawText function of the HTTP Request Handler component."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-1021"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-1021, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-1021.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/filex\/read-raw(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_10486_google_for_woocommerce_2_8_6 {
    meta:
        attack_type = "cve_2024_10486"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Google for WooCommerce <= 2.8.6 - Information Disclosure via Publicly Accessible PHP Info File: The Google for WooCommerce plugin for WordPress is vulnerable to Information Disclosure in all versions up to, and including, 2.8.6. This is due to publicly accessible."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-10486"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-10486, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-10486.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/google-listings-and-ads\/vendor\/googleads\/google-ads-php\/scripts\/print_php_information\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_10516_swift_performance_lite {
    meta:
        attack_type = "cve_2024_10516"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Swift Performance Lite < 2.3.7.2 - Local PHP File Inclusion: A vulnerability in Swift Performance Lite before version 2.3.7.2 allows unauthenticated attackers to perform local PHP file inclusion via the 'ajaxify' parameter. This can lead to arbitrary code execution on the server."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-10516"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-10516, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-10516.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])action=swift_performance_ajaxify(&|$)/ nocase
        $param1 = /(^|[?&;])data=WyJ0ZW1wbGF0ZS1wYXJ0IiwibnVsbCIsIi4uLy4uLy4uLy4uLy4uL2V0Yy9wYXNzd2QiXQ==(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_10571_chartify {
    meta:
        attack_type = "cve_2024_10571"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Chartify WordPress Chart Plugin < 2.9.6 - Local File Inclusion: The Chartify WordPress Chart Plugin plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.9.5 via the 'source' parameter. This makes it possible for unauthenticated."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-10571"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-10571, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-10571.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])function=display_plugin_charts_page(&|$)/ nocase
        $param1 = /(^|[?&;])source=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/wp-content\/plugins\/chart-builder\/uninstall(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_10708_system_dashboard {
    meta:
        attack_type = "cve_2024_10708"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "System Dashboard < 2.8.15 - Admin+ Path Traversal: The System Dashboard WordPress plugin before 2.8.15 does not validate user input used in a path, which could allow high privilege users such as admin to perform path traversal attacks an read arbitrary files on the server"
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-10708"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-10708, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-10708.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])load_plugins\[\]=system-dashboard\/system-dashboard\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_1071_ultimate_member {
    meta:
        attack_type = "cve_2024_1071"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Ultimate Member 2.1.3 - 2.8.2 SQL Injection: The Ultimate Member - User Profile, Registration, Login, Member Directory, Content Restriction & Membership Plugin plugin for WordPress is vulnerable to SQL Injection via the sorting parameter in versions 2.1.3 to 2.8.2 due."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-1071"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-1071, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-1071.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])directory_id=b9238(&|$)/ nocase
        $param1 = /(^|[?&;])sorting=user_login,SLEEP\(5\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_10763_wordpress_campress_theme_1_35 {
    meta:
        attack_type = "cve_2024_10763"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Campress Theme <= 1.35 - Unauthenticated Local File Inclusion: Campress theme for WordPress up to 1.35 contains a local file inclusion caused by 'campress_woocommerce_get_ajax_products' function, letting unauthenticated attackers include and execute arbitrary PHP."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-10763"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-10763, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-10763.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])action=campress_woocommerce_get_ajax_products(&|$)/ nocase
        $param1 = /(^|[?&;])layout=php:\/\/filter\/convert\.base64-encode\/resource=\/var\/www\/html\/wp-config(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_11238_landray_ekp {
    meta:
        attack_type = "cve_2024_11238"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Landray EKP - Path Traversal: A vulnerability, which was classified as critical, was found in Landray EKP up to 16.0. This affects the function delPreviewFile of the file /sys/ui/sys_ui_component/sysUiComponent.do?method=delPreviewFile. The manipulation of the argument."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-11238"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-11238, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-11238.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])method=delPreviewFile(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_11305_energy_communication_unit_firm {
    meta:
        attack_type = "cve_2024_11305"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Altenergy Power Control Software - SQL Injection: A vulnerability classified as critical was found in Altenergy Power Control Software up to 20241108. This vulnerability affects the function get_status_zigbee of the file /index.php/display/status_zigbee. The manipulation of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-11305"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-11305, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-11305.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/index\.php\/display\/status_zigbee(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_11320_pandora_fms {
    meta:
        attack_type = "cve_2024_11320"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Pandora v7.0NG.777.3 - Remote Code Execution: Arbitrary commands execution on the server by exploiting a command injection vulnerability in the LDAP authentication mechanism.This issue affects Pandora FMS- from 700 through <=777.4"
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-11320"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-11320, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-11320.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])sec=general\/logon_ok(&|$)/ nocase
        $param1 = /(^|[?&;])sec2=godmode\/setup\/setup(&|$)/ nocase
        $param2 = /(^|[?&;])section=auth(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_11587_idccms {
    meta:
        attack_type = "cve_2024_11587"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "idcCMS V1.60 - Cross-Site Scripting: idcCMS V1.60 is vulnerable to reflected cross-site scripting (XSS) via the idName parameter in read.php. Unsanitized user input is reflected in the response, allowing arbitrary JavaScript execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-11587"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-11587, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-11587.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])mudi=getCityData(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_11680_projectsend {
    meta:
        attack_type = "cve_2024_11680"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "ProjectSend <= r1605 - Improper Authorization: An improper authorization check was identified within ProjectSend version r1605 that allows an attacker to perform sensitive actions such as enabling user registration and auto validation, or adding new entries in the whitelist of."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-11680"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-11680, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-11680.yaml"
    strings:
        $path0 = /\/options\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])section=general(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_11728_kivicare {
    meta:
        attack_type = "cve_2024_11728"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "KiviCare Clinic & Patient Management System (EHR) <= 3.6.4 - SQL Injection: The KiviCare Clinic & Patient Management System (EHR) plugin for WordPress is vulnerable to SQL Injection via the 'visit_type[service_id]' parameter of the tax_calculated_data AJAX action in all."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-11728"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-11728, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-11728.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])route_name=tax_calculated_data(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_11868_learnpress {
    meta:
        attack_type = "cve_2024_11868"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LearnPress < 4.2.7.4 - Course Material - Information Disclosure: LearnPress WordPress LMS Plugin contains a sensitive information exposure caused by insecure handling in class-lp-rest-material-controller.php, letting unauthenticated attackers extract paid course material."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-11868"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-11868, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-11868.yaml"
    strings:
        $path0 = "/wp-json/lp/v1/material/item-materials/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_1208_learndash {
    meta:
        attack_type = "cve_2024_1208"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LearnDash LMS < 4.10.3 - Sensitive Information Exposure: The LearnDash LMS plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 4.10.2 via API. This makes it possible for unauthenticated attackers to obtain access to quiz."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-1208"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-1208, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-1208.yaml"
    strings:
        $path0 = /\/wp-json\/wp\/v2\/sfwd-question(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_1209_learndash {
    meta:
        attack_type = "cve_2024_1209"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LearnDash LMS < 4.10.2 - Sensitive Information Exposure via assignments: The LearnDash LMS plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 4.10.1 via direct file access due to insufficient protection of uploaded."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-1209"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-1209, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-1209.yaml"
    strings:
        $path0 = /\/wp-json\/wp\/v2\/sfwd-assignment(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_1210_learndash {
    meta:
        attack_type = "cve_2024_1210"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LearnDash LMS < 4.10.2 - Sensitive Information Exposure: The LearnDash LMS plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 4.10.1 via API. This makes it possible for unauthenticated attackers to obtain access to quizzes."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-1210"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-1210, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-1210.yaml"
    strings:
        $path0 = /\/wp-json\/ldlms\/v1\/sfwd-quiz(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_1212_progress_kemp_loadmaster {
    meta:
        attack_type = "cve_2024_1212"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Progress Kemp LoadMaster - Command Injection: Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-1212"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-1212, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-1212.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/access\/set(\/|;|$)/ nocase
        $param0 = /(^|[?&;])param=enableapi(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_12638_bulk_me_now {
    meta:
        attack_type = "cve_2024_12638"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Bulk Me Now! Plugin <= 2.0 - Cross-Site Scripting: Bulk Me Now! WordPress plugin <= 2.0 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers execute malicious scripts in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-12638"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-12638, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-12638.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=bulkmenow-list(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_12724_wp_desklite {
    meta:
        attack_type = "cve_2024_12724"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP DeskLite - Reflected XSS: WP DeskLite WordPress plugin through 1.0.0 contains a reflected XSS caused by unsanitized and unescaped parameter output, letting attackers execute scripts against high privilege users such as admin, exploit requires crafted request."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-12724"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-12724, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-12724.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=wpdl_ticket(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_12737_wp_base_booking {
    meta:
        attack_type = "cve_2024_12737"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP BASE Booking - Reflected XSS: WP BASE Booking of Appointments, Services and Events WordPress plugin < 5.0.0 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before output, letting attackers execute malicious scripts in high."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-12737"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-12737, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-12737.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=appointments(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_12749_competition_form {
    meta:
        attack_type = "cve_2024_12749"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Competition Form Plugin <= 2.0 - Cross-Site Scripting: Competition Form WordPress plugin <= 2.0 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers execute malicious."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-12749"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-12749, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-12749.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=entries(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_12824_nokri_job_board_wordpress_them {
    meta:
        attack_type = "cve_2024_12824"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Nokri Job Board WordPress Theme <= 1.6.2 - Unauthenticated Arbitrary Password Change: The Nokri Job Board WordPress Theme theme for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 1.6.2. This is due to the plugin not."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-12824"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-12824, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-12824.yaml"
    strings:
        $param0 = /(^|[?&;])action=sb_reset_password(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_12849_error_log_viewer_wp {
    meta:
        attack_type = "cve_2024_12849"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Error Log Viewer By WP Guru <= 1.0.1.3 - Missing Authorization to Arbitrary File Read: The Error Log Viewer By WP Guru plugin for WordPress is vulnerable to Arbitrary File Read in all versions up to, and including, 1.0.1.3 via the wp_ajax_nopriv_elvwp_log_download AJAX action.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-12849"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-12849, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-12849.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])elvwp_error_log=\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_12873_custom_field_manager {
    meta:
        attack_type = "cve_2024_12873"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Custom Field Manager WordPress - Cross-Site Scripting: Custom Field Manager WordPress plugin through 1.0 contains a reflected XSS caused by unsanitized and unescaped parameter output, letting attackers execute scripts against high privilege users such as admin, exploit requires."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-12873"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-12873, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-12873.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=custom-field-manager-customfields(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_12878_lazy_blocks_3_8_2 {
    meta:
        attack_type = "cve_2024_12878"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Lazy Blocks <= 3.8.2 - Cross-Site Scripting: Custom Block Builder WordPress plugin < 3.8.3 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before output, letting attackers execute malicious scripts in high privilege users'."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-12878"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-12878, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-12878.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=lazyblocks(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_12987_vigor300b {
    meta:
        attack_type = "cve_2024_12987"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "DrayTek Vigor - Command Injection: DrayTek Gateway devices (Vigor2960, Vigor300B, etc.) are vulnerable to command injection via the session parameter in the /cgi-bin/mainfunction.cgi/apmcfgupload endpoint. An attacker can inject arbitrary commands and retrieve their output."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-12987"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-12987, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-12987.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cgi-bin\/mainfunction\.cgi\/apmcfgupload(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_13055_dyn_business_panel {
    meta:
        attack_type = "cve_2024_13055"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Dyn Business Panel Plugin <= 1.0.0 - Cross-Site Scripting: Dyn Business Panel WordPress plugin <= 1.0.0 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter in output, letting attackers execute scripts in the context of high."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13055"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13055, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13055.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=dbp_clients(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13094_wp_triggers_lite {
    meta:
        attack_type = "cve_2024_13094"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WP Triggers Lite - Cross-Site Scripting: WP Triggers Lite WordPress plugin v2.5.3 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers execute malicious scripts in the context of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13094"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13094, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13094.yaml"
    strings:
        $param0 = /(^|[?&;])page=add-trigger(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13097_wp_finance {
    meta:
        attack_type = "cve_2024_13097"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP Finance Plugin <= 1.3.6 - Cross-Site Scripting: WP Finance WordPress plugin <= 1.3.6 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before output, letting attackers execute scripts in high privilege users' browsers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13097"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13097, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13097.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=wpfinance(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13098_wordpress_email_newsletter {
    meta:
        attack_type = "cve_2024_13098"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Email Newsletter - Reflected XSS: WordPress Email Newsletter plugin through 1.1 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers execute malicious scripts in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13098"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13098, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13098.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=view-subscriber(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13099_widget4call {
    meta:
        attack_type = "cve_2024_13099"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Widget4Call WordPress - Cross-Site Scripting: Widget4Call WordPress plugin <= 1.0.7 contains a reflected cross-site scripting caused by unsanitized parameter output in the page, letting attackers execute arbitrary scripts in the context of high privilege users, exploit requires."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13099"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13099, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13099.yaml"
    strings:
        $param0 = /(^|[?&;])page=w4c_devmode(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13112_wp_mediatagger {
    meta:
        attack_type = "cve_2024_13112"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP MediaTagger <= 4.1.1 - Cross-Site Scripting: WP MediaTagger WordPress plugin <= 4.1.1 contains a reflected cross-site scripting caused by unsanitized parameter output in the page, letting attackers execute malicious scripts in the context of high privilege users, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13112"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13112, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13112.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=mediatagger_database(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13114_wp_projects_portfolio_with_cli {
    meta:
        attack_type = "cve_2024_13114"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP Projects Portfolio <= 3.0 - Cross-Site Scripting: WP Projects Portfolio with Client Testimonials WordPress plugin <= 3.0 contains a reflected cross-site scripting caused by unsanitized parameter output, letting attackers execute scripts in the context of high privilege."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13114"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13114, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13114.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=wpprojects_portfolio(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13219_privacy_policy_genius {
    meta:
        attack_type = "cve_2024_13219"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Privacy Policy Genius - Cross-Site Scripting: Privacy Policy Genius WordPress plugin v2.0.4 contains a reflected cross-site scripting caused by unsanitized parameter output in the page, letting attackers execute malicious scripts in the context of high privilege users, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13219"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13219, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13219.yaml"
    strings:
        $param0 = /(^|[?&;])page=privacy_guru(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13220_google_map_professional {
    meta:
        attack_type = "cve_2024_13220"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress Google Map Professional - Cross-Site Scripting: WordPress Google Map Professional (Map In Your Language) plugin through 1.0 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13220"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13220, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13220.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=googlemarker-admin(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13221_fantastic_elasticsearch {
    meta:
        attack_type = "cve_2024_13221"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Fantastic ElasticSearch Plugin <= 4.1.0 - Cross-Site Scripting: Fantastic ElasticSearch WordPress plugin <= 4.1.0 contains a reflected cross-site scripting caused by unsanitized parameter output, letting attackers execute malicious scripts in the context of high privilege."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13221"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13221, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13221.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=elastic_search(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13222_wordpress_user_messages_1_2_4 {
    meta:
        attack_type = "cve_2024_13222"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress User Messages <= 1.2.4 - Reflected XSS: WordPress User Messages plugin <= 1.2.4 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers execute malicious scripts in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13222"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13222, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13222.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=user-messages(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13224_slidedeck_1_lite_content_slide {
    meta:
        attack_type = "cve_2024_13224"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SlideDeck 1 Lite Content Slider - Cross-Site Scripting: SlideDeck 1 Lite Content Slider WordPress plugin <= 1.4.8 contains a reflected cross-site scripting caused by unsanitized parameter output, letting attackers execute malicious scripts in the context of high privilege."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13224"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13224, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13224.yaml"
    strings:
        $param0 = /(^|[?&;])page=slidedeck\.php\/slidedeck_dynamic(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13225_ect_home_page_products {
    meta:
        attack_type = "cve_2024_13225"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ECT Home Page Products - Reflected XSS: ECT Home Page Products WordPress plugin through 1.9 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers execute malicious scripts in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13225"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13225, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13225.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=ect_homepage_prod_add(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13322_ads_pro_plugin_4_88 {
    meta:
        attack_type = "cve_2024_13322"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Ads Pro Plugin <= 4.88 - Unauthenticated SQL Injection: The Ads Pro Plugin - Multi-Purpose WordPress Advertising Manager plugin for WordPress is vulnerable to SQL Injection via the 'a_id' parameter in all versions up to, and including, 4.88 due to insufficient escaping on the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13322"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13322, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13322.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=bsa_stats_chart_callback(&|$)/ nocase
        $param1 = /(^|[?&;])ad_id=1 and \(select\*from\(select\(sleep\(7\)\)\)a\)-- -(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13326_ibuildapp_0_2_0 {
    meta:
        attack_type = "cve_2024_13326"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "iBuildApp <= 0.2.0 - Reflected Cross-Site Scripting: iBuildApp WordPress plugin through 0.2.0 contains a reflected cross-site scripting caused by unsanitized parameter output in the page, letting attackers execute malicious scripts in the context of high privilege users."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13326"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13326, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13326.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=ibuildapp-iframe-redirect(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13327_musicbox_wordpress {
    meta:
        attack_type = "cve_2024_13327"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Musicbox WordPress - Reflected XSS: contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers execute malicious scripts in the context of high privilege users, exploit requires."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13327"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13327, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13327.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=webdesignby-musicbox(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13330_justrows_free {
    meta:
        attack_type = "cve_2024_13330"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "JustRows WordPress - Cross-Site Scripting: JustRows free WordPress plugin v0.2 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers execute malicious scripts in the context of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13330"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13330, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13330.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=justrows-edit(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13331_wp_dream_carousel {
    meta:
        attack_type = "cve_2024_13331"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP Dream Carousel < 1.0.1b - Cross-Site Scripting: WP Dream Carousel WordPress plugin < 1.0.1b contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers execute arbitrary scripts in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13331"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13331, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13331.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=wp_dream_carousel(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13569_front_end_users {
    meta:
        attack_type = "cve_2024_13569"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Front End Users - Reflected XSS: WordPress Front End Users plugin <= 3.2.32 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers execute malicious scripts in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13569"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13569, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13569.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=EWD-FEUP-options(&|$)/ nocase
        $param1 = /(^|[?&;])DisplayPage=Fields(&|$)/ nocase
        $param2 = /(^|[?&;])OrderBy=Field_Description(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13619_lifterlms_8_0_1 {
    meta:
        attack_type = "cve_2024_13619"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LifterLMS < 8.0.1 - Cross-Site Scripting: LifterLMS WordPress plugin before 8.0.1 contains a reflected XSS caused by unsanitized and unescaped parameter output, letting attackers execute scripts against high privilege users such as admin via a crafted request."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13619"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13619, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13619.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=llms_form(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13624_wpmovielibrary {
    meta:
        attack_type = "cve_2024_13624"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress WPMovieLibrary Plugin <= 2.1.4.8 - Cross-Site Scripting: The WPMovieLibrary WordPress plugin through version 2.1.4.8 contains a reflected cross-site scripting vulnerability. The plugin does not properly sanitize and escape the 'order' parameter in the import page."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13624"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13624, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13624.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=wpmovielibrary-import(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13625_tube_video_ads_lite {
    meta:
        attack_type = "cve_2024_13625"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tube Video Ads Lite - Reflected XSS: Tube Video Ads Lite WordPress plugin <= 1.5.7 contains a reflected cross-site scripting caused by lack of sanitization and escaping of a parameter before outputting it in the page, letting attackers execute arbitrary scripts in the context."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13625"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13625, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13625.yaml"
    strings:
        $param0 = /(^|[?&;])page=embededcode_wpyoulink(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13628_wp_pricing_table {
    meta:
        attack_type = "cve_2024_13628"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP Pricing Table - Reflected XSS: WP Pricing Table WordPress plugin <= 1.1 contains a reflected cross-site scripting caused by unsanitized parameter output, letting attackers execute scripts in the context of high privilege users, exploit requires attacker to craft malicious URL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13628"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13628, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13628.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=wp-pricing-table-menu(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13727_memberspace_wordpress {
    meta:
        attack_type = "cve_2024_13727"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "MemberSpace WordPress - Cross-Site Scripting: MemberSpace WordPress plugin < 2.1.14 contains a reflected XSS caused by unsanitized and unescaped parameter output, letting unauthenticated attackers execute scripts, exploit requires no authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13727"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13727, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13727.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/memberspace\/admin\/partials\/notification-bar\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_13853_seo_automatic_seo_tools {
    meta:
        attack_type = "cve_2024_13853"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress SEO Tools Plugin 4.0.7 - Cross-Site Scripting: The SEO Tools WordPress plugin through version 4.0.7 contains a reflected cross-site scripting vulnerability. The plugin does not properly sanitize and escape the 'src' parameter in the rssread.php file before outputting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13853"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13853, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13853.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/seo-automatic-seo-tools\/feedcommander\/rssread\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_13979_st_joe_erp_system {
    meta:
        attack_type = "cve_2024_13979"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "St. Joe ERP system - SQL Injection: A SQL injection vulnerability exists in the St. Joe ERP system ('ERP') that allows unauthenticated remote attackers to execute arbitrary SQL commands via crafted HTTP POST requests to the login endpoint. The application fails to properly."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13979"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13979, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13979.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/erp\/dwr\/call\/plaincall\/SingleRowQueryConvertor\.queryForString\.dwr(\/|;|$)/ nocase
        $param0 = /(^|[?&;])page=\/erp\/dwr\/test\/SingleRowQueryConvertor(&|$)/ nocase
        $param1 = /(^|[?&;])scriptSessionId=D528B0534A8BE018344AB2D54E02931D86(&|$)/ nocase
        $param2 = /(^|[?&;])c0-scriptName=SingleRowQueryConvertor(&|$)/ nocase
        $param3 = /(^|[?&;])c0-methodName=queryForString(&|$)/ nocase
        $param4 = /(^|[?&;])c0-param1=Array:\[\](&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_13985_dahua_eims {
    meta:
        attack_type = "cve_2024_13985"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dahua EIMS - Unauthenticated Remote Code Execution via capture_handle: A command injection vulnerability in Dahua EIMS versions prior to 2240008 allows unauthenticated remote attackers to execute arbitrary system commands via the capture_handle.action interface. The flaw stems."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-13985"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-13985, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-13985.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/config\/asst\/system_setPassWordValidate\.action\/capture_handle\.action(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_14015_studiocart_2_9_0 {
    meta:
        attack_type = "cve_2024_14015"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Studiocart <= 2.9.0 - Cross-Site Scripting: The Studiocart plugin for WordPress is vulnerable to Reflected Cross-Site Scripting in versions up to, and including, 2.9.0 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-14015"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-14015, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-14015.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=sc_order(&|$)/ nocase
        $param1 = /(^|[?&;])order_type=orders(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_1728_gradio {
    meta:
        attack_type = "cve_2024_1728"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Gradio > 4.19.1 UploadButton - Path Traversal: gradio-app/gradio is vulnerable to a local file inclusion vulnerability due to improper validation of user-supplied input in the UploadButton component."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-1728"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-1728, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-1728.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/queue\/data(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_1751_tutor_lms_2_1_10 {
    meta:
        attack_type = "cve_2024_1751"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Tutor LMS <= 2.1.10 - SQL Injection: Tutor LMS eLearning and online course solution plugin for WordPress [all versions up to 2.6.1] contains a time-based SQL Injection caused by insufficient escaping on the question_id parameter in SQL queries, letting authenticated attackers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-1751"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-1751, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-1751.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])short_by=ASC,\(SELECT SLEEP\(7\)\)-- -(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_20404_cisco_finesse {
    meta:
        attack_type = "cve_2024_20404"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Cisco Finesse - Server-Side Request Forgery (SSRF): Cisco Finesse contains an SSRF caused by insufficient validation of user-supplied input in HTTP requests, letting unauthenticated remote attackers access limited sensitive information, exploit requires sending crafted HTTP."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-20404"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-20404, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-20404.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/gadgets\/metadata(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_20419_cisco_ssm_on_prem_8_202206 {
    meta:
        attack_type = "cve_2024_20419"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cisco SSM On-Prem <= 8-202206 - Password Reset Account Takeover: A vulnerability in the authentication system of Cisco Smart Software Manager On-Prem (SSM On-Prem) could allow an unauthenticated, remote attacker to change the password of any user, including administrative."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-20419"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-20419, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-20419.yaml"
    strings:
        $path0 = /\/backend\/settings\/oauth_adfs(\/|;|$)/ nocase
        $path1 = /\/backend\/reset_password\/generate_code(\/|;|$)/ nocase
        $path2 = /\/backend\/reset_password(\/|;|$)/ nocase
        $path3 = /\/backend\/auth\/identity\/callback(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_20439_hardcoded_admin_credentials_fo {
    meta:
        attack_type = "cve_2024_20439"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Hardcoded Admin Credentials For Cisco Smart Licensing Utility API: A vulnerability in Cisco Smart Licensing Utility could allow an unauthenticated, remote attacker to log in to an affected system by using a static administrative credential.This vulnerability is due to an."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-20439"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-20439, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-20439.yaml"
    strings:
        $path0 = /\/cslu\/v1\/scheduler\/jobs(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_20440_cisco_smart_licensing_utility {
    meta:
        attack_type = "cve_2024_20440"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cisco Smart Licensing Utility UnAuthenticated Logs Exposure Leaking Plaintext Credentials: A vulnerability in Cisco Smart Licensing Utility could allow an unauthenticated, remote attacker to access sensitive information.This vulnerability is due to excessive verbosity in a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-20440"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-20440, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-20440.yaml"
    strings:
        $path0 = /\/cslu\/v1\/var\/logs\/customer-cslu-lib-log\.log(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_2053_artica_proxy {
    meta:
        attack_type = "cve_2024_2053"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Artica Proxy - Unauthenticated LFI: The Artica Proxy administrative web application will deserialize arbitrary PHP objects supplied by unauthenticated users and subsequently enable code execution as the 'www-data' user. This issue was demonstrated on version 4.50 of the The."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-2053"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-2053, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-2053.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/images\.listener\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])mailattach=\.\.\.\/\.\/\.\.\.\/\.\/\.\.\.\/\.\/\.\.\.\/\.\/\.\.\.\/\.\/epasswdtc\/ppasswdasswd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_20767_coldfusion {
    meta:
        attack_type = "cve_2024_20767"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Adobe ColdFusion - Arbitrary File Read: ColdFusion versions 2023.6, 2021.12 and earlier are affected by an Improper Access Control vulnerability that could lead to arbitrary file system read. An attacker could leverage this vulnerability to bypass security measures and gain."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-20767"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-20767, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-20767.yaml"
    strings:
        $path0 = /\/hax\/\.\.CFIDE\/adminapi\/_servermanager\/servermanager\.cfc(\/|;|$)/ nocase
        $param0 = /(^|[?&;])method=getHeartBeat(&|$)/ nocase
        $param1 = /(^|[?&;])module=logging(&|$)/ nocase
        $param2 = /(^|[?&;])file_name=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_21136_retail_xstore_office {
    meta:
        attack_type = "cve_2024_21136"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Oracle Retail Xstore Suite - Pre-authenticated Path Traversal: Vulnerability in the Oracle Retail Xstore Office product of Oracle Retail Applications (component: Security). Supported versions that are affected are 19.0.5, 20.0.3, 20.0.4, 22.0.0 and 23.0.1. Easily exploitable."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-21136"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-21136, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-21136.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/xstoremgwt\/cheetahImages(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_21633_mobile_security_framework {
    meta:
        attack_type = "cve_2024_21633"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MobSF - Path Traversal: MobSF is vulnerable to an issue with apktool (CVE-2024-21633) that allows for RCE or arbitrary file writing. It does this through a path traversal vulnerability. This template tests for it by writing to a local file and reading that file. RCE can be."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-21633"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-21633, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-21633.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/static_analyzer/" ascii nocase
        $path1 = /\/download\/mobsf-cve-2024-21633\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_21644_pyload {
    meta:
        attack_type = "cve_2024_21644"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "pyLoad Flask Config - Access Control: pyLoad is the free and open-source Download Manager written in pure Python. Any unauthenticated user can browse to a specific URL to expose the Flask config, including the `SECRET_KEY` variable. This issue has been patched in version."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-21644"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-21644, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-21644.yaml"
    strings:
        $path0 = /\/render\/info\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_21650_xwiki {
    meta:
        attack_type = "cve_2024_21650"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "XWiki < 4.10.20 - Remote code execution: XWiki is vulnerable to a remote code execution (RCE) attack through its user registration feature. This issue allows an attacker to execute arbitrary code by crafting malicious payloads in the 'first name' or 'last name' fields during."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-21650"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-21650, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-21650.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/bin\/register\/XWiki\/XWikiRegister(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_21683_confluence_data_center {
    meta:
        attack_type = "cve_2024_21683"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Atlassian Confluence Data Center and Server - Remote Code Execution: Detects a Remote Code Execution vulnerability in Confluence Data Center and Server versions prior to X.X (affected versions). This issue allows authenticated attackers to execute arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-21683"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-21683, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-21683.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/doauthenticate\.action(\/|;|$)/ nocase
        $path1 = /\/admin\/plugins\/newcode\/addlanguage\.action(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_21893_connect_secure {
    meta:
        attack_type = "cve_2024_21893"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Ivanti SAML - Server Side Request Forgery (SSRF): A server-side request forgery vulnerability in the SAML component of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x) and Ivanti Neurons for ZTA allows an attacker to access certain restricted resources."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-21893"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-21893, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-21893.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/dana-ws\/saml20\.ws(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_22319_operational_decision_manager {
    meta:
        attack_type = "cve_2024_22319"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "IBM Operational Decision Manager - JNDI Injection: IBM Operational Decision Manager 8.10.3, 8.10.4, 8.10.5.1, 8.11, 8.11.0.1, and 8.12.0.1 is susceptible to remote code execution attack via JNDI injection when passing an unchecked argument to a certain API. IBM X-Force ID."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-22319"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-22319, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-22319.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/decisioncenter-api\/v1\/about(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_22476_intel_neural_compressor_2_5_0 {
    meta:
        attack_type = "cve_2024_22476"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Intel Neural Compressor <2.5.0 - SQL Injection: Improper input validation in some Intel(R) Neural Compressor software before version 2.5.0 may allow an unauthenticated user to potentially enable escalation of privilege via remote access."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-22476"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-22476, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-22476.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/task/submit/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_22927_eyoucms {
    meta:
        attack_type = "cve_2024_22927"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "eyoucms v.1.6.5 - Cross-Site Scripting: Cross Site Scripting (XSS) vulnerability in the func parameter in eyoucms v.1.6.5 allows a remote attacker to run arbitrary code via crafted URL."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-22927"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-22927, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-22927.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])c=Uploadimgnew(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_2330_ns_asg_application_security_ga {
    meta:
        attack_type = "cve_2024_2330"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "NS-ASG Application Security Gateway 6.3 - Sql Injection: A vulnerability was found in Netentsec NS-ASG Application Security Gateway 6.3. It has been classified as critical. This affects an unknown part of the file /protocol/index.php. The manipulation of the argument IPAddr."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-2330"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-2330, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-2330.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/protocol\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_2340_avada_7_11_7 {
    meta:
        attack_type = "cve_2024_2340"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Avada < 7.11.7 - Information Disclosure: The Avada theme for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 7.11.6 via the '/wp-content/uploads/fusion-forms/' directory. This makes it possible for unauthenticated attackers to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-2340"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-2340, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-2340.yaml"
    strings:
        $path0 = "/wp-content/uploads/fusion-forms/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_2389_progress_kemp_flowmon {
    meta:
        attack_type = "cve_2024_2389"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Progress Kemp Flowmon - Command Injection: In Flowmon versions prior to 11.1.14 and 12.3.5, an operating system command injection vulnerability has been identified. An unauthenticated user can gain entry to the system via the Flowmon management interface, allowing for the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-2389"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-2389, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-2389.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/service\.pdfs\/confluence(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_23917_teamcity {
    meta:
        attack_type = "cve_2024_23917"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JetBrains TeamCity > 2023.11.3 - Authentication Bypass: In JetBrains TeamCity before 2023.11.3 authentication bypass leading to RCE was possible"
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-23917"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-23917, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-23917.yaml"
    strings:
        $path0 = "/app/rest/users/id:1/tokens/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_2473_wps_hide_login {
    meta:
        attack_type = "cve_2024_2473"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WPS Hide Login <= 1.9.15.2 - Login Page Disclosure: The WPS Hide Login plugin for WordPress is vulnerable to Login Page Disclosure in all versions up to, and including, 1.9.15.2. This is due to a bypass that is created when the 'action=postpass' parameter is supplied. This."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-2473"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-2473, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-2473.yaml"
    strings:
        $param0 = /(^|[?&;])action=postpass(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_24759_mindsdb {
    meta:
        attack_type = "cve_2024_24759"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MindsDB -DNS Rebinding SSRF Protection Bypass: Detects DNS rebinding vulnerability that allows bypass of SSRF protection. The vulnerability exists in the URL validation mechanism where DNS resolution is performed without considering DNS rebinding attacks."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-24759"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-24759, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-24759.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/check_private_url(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_24809_traccar {
    meta:
        attack_type = "cve_2024_24809"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Traccar - Unrestricted File Upload: Traccar is an open source GPS tracking system. Versions prior to 6.0 are vulnerable to path traversal and unrestricted upload of file with dangerous type. Since the system allows registration by default, attackers can acquire ordinary user."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-24809"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-24809, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-24809.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/devices(\/|;|$)/ nocase
        $path1 = "/api/devices/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_24882_masteriyo {
    meta:
        attack_type = "cve_2024_24882"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Masteriyo LMS <= 1.7.2 - Unauthenticated Privilege Escalation: The Masteriyo LMS eLearning and Online Course Builder for WordPress plugin for WordPress is vulnerable to privilege escalation due to a missing capability check on the update_logged_in_user() function in all."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-24882"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-24882, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-24882.yaml"
    strings:
        $path0 = "/wp-json/masteriyo/v1/users/me/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_25608_digital_experience_platform_li {
    meta:
        attack_type = "cve_2024_25608"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Liferay Portal - Open Redirect: HtmlUtil.escapeRedirect in Liferay Portal 7.2.0 through 7.4.3.18, and older unsupported versions, and Liferay DXP 7.4 before update 19, 7.3 before update 4, 7.2 before fix pack 19, and older unsupported versions can be circumvented by using the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-25608"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-25608, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-25608.yaml"
    strings:
        $path0 = /\/html\/common\/forward_jsp\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_25735_apollo_vx20 {
    meta:
        attack_type = "cve_2024_25735"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WyreStorm Apollo VX20 - Information Disclosure: An issue was discovered on WyreStorm Apollo VX20 devices before 1.3.58. Remote attackers can discover cleartext credentials for the SoftAP (access point) Router /device/config using an HTTP GET request."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-25735"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-25735, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-25735.yaml"
    strings:
        $path0 = /\/device\/config(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_25852_re7000 {
    meta:
        attack_type = "cve_2024_25852"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Linksys RE7000 - Command Injection: Linksys RE7000 v2.0.9, v2.0.11, and v2.0.15 have a command execution vulnerability in the 'AccessControlList' parameter of the access control function point"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-25852"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-25852, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-25852.yaml"
    strings:
        $path0 = /\/goform\/AccessControl(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_2667_instawp_connect {
    meta:
        attack_type = "cve_2024_2667"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "InstaWP Connect <= 0.1.0.22 - Unauthenticated Arbitrary File Upload: The InstaWP Connect 1-click WP Staging & Migration plugin for WordPress is vulnerable to arbitrary file uploads due to insufficient file validation in the /wp-json/instawp-connect/v1/config REST API endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-2667"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-2667, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-2667.yaml"
    strings:
        $param0 = /(^|[?&;])rest_route=\/instawp-connect\/v1\/config(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_27115_soplanning {
    meta:
        attack_type = "cve_2024_27115"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SOPlanning - Remote Code Execution: Detects a remote code execution vulnerability in SOPlanning version 1.52.01 through authenticated PHP file upload."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-27115"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-27115, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-27115.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/process\/upload\.php(\/|;|$)/ nocase
        $path1 = "/upload/files/soonghee/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_27199_teamcity {
    meta:
        attack_type = "cve_2024_27199"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "TeamCity < 2023.11.4 - Authentication Bypass: In JetBrains TeamCity before 2023.11.4 path traversal allowing to perform limited admin actions was possible"
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-27199"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-27199, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-27199.yaml"
    strings:
        $path0 = /\/res\/\.\.\/admin\/diagnostic\.jsp(\/|;|$)/ nocase
        $path1 = /\/\.well-known\/acme-challenge\/\.\.\/\.\.\/admin\/diagnostic\.jsp(\/|;|$)/ nocase
        $path2 = /\/update\/\.\.\/admin\/diagnostic\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_27564_chatgpt_web {
    meta:
        attack_type = "cve_2024_27564"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "ChatGPT - Server Side Request Forgery: A Server-Side Request Forgery (SSRF) in pictureproxy.php of ChatGPT commit f9f4bbc allows attackers to force the application to make arbitrary requests via injection of crafted URLs into the urlparameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-27564"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-27564, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-27564.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/pictureproxy\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_27718_smart_s200_management_platform {
    meta:
        attack_type = "cve_2024_27718"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Smart s200 Management Platform v.S200 - SQL Injection: SQL Injection vulnerability in Baizhuo Network Smart s200 Management Platform v.S200 allows a local attacker to obtain sensitive information and escalate privileges via the /importexport.php component."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-27718"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-27718, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-27718.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/importexport\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])type=exportexcelbysql(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_2782_contact_form {
    meta:
        attack_type = "cve_2024_2782"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress FluentForms <= 5.1.16 - Broken Access Control: The Contact Form Plugin by Fluent Forms for Quiz, Survey, and Drag & Drop WP Form Builder plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-2782"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-2782, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-2782.yaml"
    strings:
        $path0 = /\/wp-json\/fluentform\/v1\/global-settings(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_27954_wordpress_automatic_plugin_3_9 {
    meta:
        attack_type = "cve_2024_27954"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Automatic Plugin <3.92.1 - Arbitrary File Download and SSRF: WordPress Automatic plugin <3.92.1 is vulnerable to unauthenticated Arbitrary File Download and SSRF Located in the downloader.php file, could permit attackers to download any file from a site. Sensitive."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-27954"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-27954, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-27954.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])wp_automatic=download(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_28253_openmetadata {
    meta:
        attack_type = "cve_2024_28253"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "OpenMetaData - SpEL Injection in PUT /api/v1/policies: OpenMetadata is a unified platform for discovery, observability, and governance powered by a central metadata repository, in-depth lineage, and seamless team collaboration. `CompiledRule::validateExpression` is also called."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-28253"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-28253, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-28253.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/v1\/policies(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_28397_pyload {
    meta:
        attack_type = "cve_2024_28397"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "pyload-ng js2py - Remote Code Execution: An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-28397"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-28397, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-28397.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])crypted=MTIzNA==(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_2862_lg_led_assistant {
    meta:
        attack_type = "cve_2024_2862"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LG LED Assistant - Unauthenticated Password Reset: The /api/changePw endpoint in LG LED Assistant allows unauthenticated password resets when requests are considered to come from localhost. An attacker can spoof the X-Forwarded-For header with value 127.0.0.1 to trigger the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-2862"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-2862, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-2862.yaml"
    strings:
        $path0 = /\/api\/changePw(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_2863_lg_led_assistant {
    meta:
        attack_type = "cve_2024_2863"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LG LED Assistant - Thumbnail Path Traversal File Upload: A path traversal vulnerability exists in the endpoint handler for /api/thumbnail in Common.js. An unauthenticated remote attacker can exploit this to upload arbitrary files to any location on the disk drive where the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-2863"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-2863, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-2863.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/api\/thumbnail(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_28734_coda_v_2024q1 {
    meta:
        attack_type = "cve_2024_28734"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Coda v.2024Q1 - Cross-Site Scripting: Cross Site Scripting vulnerability in Unit4 Financials by Coda v.2024Q1 allows a remote attacker to escalate privileges via a crafted script to the cols parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-28734"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-28734, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-28734.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/coda\/frameset(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_2876_wordpress_email_subscribers_by {
    meta:
        attack_type = "cve_2024_2876"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Wordpress Email Subscribers by Icegram Express - SQL Injection: The Email Subscribers by Icegram Express - Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-2876"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-2876, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-2876.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])page=es_subscribers(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_28987_solarwinds_web_help_desk {
    meta:
        attack_type = "cve_2024_28987"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "SolarWinds Web Help Desk - Hardcoded Credential: The SolarWinds Web Help Desk (WHD) software is affected by a hardcoded credential vulnerability, allowing remote unauthenticated user to access internal functionality and modify data."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-28987"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-28987, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-28987.yaml"
    strings:
        $path0 = "/helpdesk/WebObjects/Helpdesk.woa/ra/OrionTickets/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_29028_memos_0_13_2 {
    meta:
        attack_type = "cve_2024_29028"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Memos 0.13.2 - Server-Side Request Forgery: SSRF vulnerabilities exist in the memos API service `/o/get/httpmeta` that allow unauthenticated and authenticated users to enumerate and read from the internal network. In addition, one SSRF vulnerability leads to a reflected XSS."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-29028"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-29028, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-29028.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/o\/get\/httpmeta(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_29059_net_framework {
    meta:
        attack_type = "cve_2024_29059"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = ".NET Framework - Leaking ObjRefs via HTTP .NET Remoting: .NET Framework Information Disclosure Vulnerability"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-29059"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-29059, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-29059.yaml"
    strings:
        $path0 = /\/RemoteApplicationMetadata\.rem(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_29272_vvvebjs {
    meta:
        attack_type = "cve_2024_29272"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "VvvebJs < 1.7.5 - Arbitrary File Upload: Arbitrary File Upload vulnerability in VvvebJs before version 1.7.5, allows unauthenticated remote attackers to execute arbitrary code and obtain sensitive information via the sanitizeFileName parameter in save.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-29272"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-29272, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-29272.yaml"
    strings:
        $path0 = /\/demo\/landing\/index\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])file=demo\/landing\/index\.php(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_29792_unlimited_elements_for_element {
    meta:
        attack_type = "cve_2024_29792"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Unlimited Elements for Elementor <= 1.5.93 - Cross Site Scripting: Unlimited Elements For Elementor (Free Widgets, Addons, Templates) versions up to 1.5.93 contain a reflected cross-site scripting caused by improper neutralization of input during web page generation, letting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-29792"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-29792, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-29792.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=unlimitedelements(&|$)/ nocase
        $param1 = /(^|[?&;])view=settingselementor(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_29824_ivanti_epm {
    meta:
        attack_type = "cve_2024_29824"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Ivanti EPM - Remote Code Execution: An unspecified SQL Injection vulnerability in Core server of Ivanti EPM 2022 SU5 and prior allows an unauthenticated attacker within the same network to execute arbitrary code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-29824"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-29824, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-29824.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/WSStatusEvents\/EventHandler\.asmx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_29889_glpi {
    meta:
        attack_type = "cve_2024_29889"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "GLPI 10.0.10-10.0.14 - SQL Injection: GLPI is a Free Asset and IT Management Software package. Prior to 10.0.15, an authenticated user can exploit a SQL injection vulnerability in the saved searches feature to alter another user account data take control of it."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-29889"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-29889, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-29889.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/front\/preference\.php(\/|;|$)/ nocase
        $path1 = /\/ajax\/pin_savedsearches\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])_glpi_tab=User\$1(&|$)/ nocase
        $param1 = /(^|[?&;])main_class=tab_cadre_fixe(&|$)/ nocase
        $param2 = /(^|[?&;])_target=\/glpi\/front\/preference\.php(&|$)/ nocase
        $param3 = /(^|[?&;])_itemtype=Preference(&|$)/ nocase
        $param4 = /(^|[?&;])itemtype=Monitor(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_29895_cacti {
    meta:
        attack_type = "cve_2024_29895"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Cacti cmd_realtime.php - Command Injection: Cacti provides an operational monitoring and fault management framework. A command injection vulnerability on the 1.3.x DEV branch allows any unauthenticated user to execute arbitrary command on the server when `register_argc_argv`."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-29895"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-29895, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-29895.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cacti\/cmd_realtime\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_29973_nas326_firmware {
    meta:
        attack_type = "cve_2024_29973"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Zyxel NAS326 Firmware < V5.21(AAZF.17)C0 - Command Injection: The command injection vulnerability in the setCookie parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-29973"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-29973, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-29973.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/cmd,\/simZysh\/register_main\/setCookie(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_30188_dolphinscheduler {
    meta:
        attack_type = "cve_2024_30188"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache DolphinScheduler >= 3.1.0, < 3.2.2 Resource File Read And Write: File read and write vulnerability in Apache DolphinScheduler, authenticated users can illegally access additional resource files. This issue affects Apache DolphinScheduler from 3.1.0 before 3.2.2."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-30188"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-30188, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-30188.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/dolphinscheduler\/login(\/|;|$)/ nocase
        $path1 = /\/dolphinscheduler\/resources\/download(\/|;|$)/ nocase
        $param0 = /(^|[?&;])fullName=file:\/\/\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_30194_sunshine_photo_cart {
    meta:
        attack_type = "cve_2024_30194"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Sunshine Photo Cart <= 3.1.1 - Reflected Cross-Site Scripting: WP Sunshine Sunshine Photo Cart versions up to 3.1.1 contain a cross-site scripting caused by improper neutralization of input during web page generation, letting attackers execute malicious scripts in users'."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-30194"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-30194, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-30194.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=sunshine-gallery(&|$)/ nocase
        $param1 = /(^|[?&;])page=sunshine-reports(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_30490_profilegrid_5_7_8 {
    meta:
        attack_type = "cve_2024_30490"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ProfileGrid <= 5.7.8 - SQL Injection: The ProfileGrid User Profiles, Groups and Communities plugin for WordPress is vulnerable to SQL Injection in versions up to, and including, 5.7.8 due to insufficient escaping on the user supplied 'search' parameter and lack of sufficient."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-30490"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-30490, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-30490.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])sortby=newest(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_30498_crm_perks_forms_1_1_4 {
    meta:
        attack_type = "cve_2024_30498"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CRM Perks Forms <= 1.1.4 - SQL Injection: CRM Perks CRM Perks Forms (affected versions 1.1.4 and earlier) contains a SQL injection caused by improper neutralization of special elements used in an SQL command, letting attackers execute arbitrary SQL commands, exploit requires."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-30498"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-30498, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-30498.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])form_id=1'OR\(EXP\(~\(SELECT\*FROM\(SELECT\(SLEEP\(8\)\)\)a\)\)\)OR'(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_30502_wp_travel_engine_5_7_9 {
    meta:
        attack_type = "cve_2024_30502"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WP Travel Engine <= 5.7.9 - SQL Injection: WP Travel Engine 5.7.9 and earlier contains a SQL injection caused by improper neutralization of special elements used in an SQL command, letting attackers execute arbitrary SQL queries, exploit requires user interaction."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-30502"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-30502, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-30502.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=wp_travel_engine_new_booking_process_action(&|$)/ nocase
        $param1 = /(^|[?&;])wpte_checkout_paymnet_method=booking_only(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_30568_netgear_r6850_router {
    meta:
        attack_type = "cve_2024_30568"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Netgear R6850 V1.1.0.88 - Command Injection: Netgear R6850 router firmware version V1.1.0.88 suffers from a command injection vulnerability in the ping_test functionality. An unauthenticated attacker can inject arbitrary system commands through the c4_IPAddr parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-30568"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-30568, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-30568.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])c4_IPAddr=127\.0\.0\.1(&|$)/ nocase
        $param1 = /(^|[?&;])next_file=diagping\.htm(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_30569_r6850_firmware {
    meta:
        attack_type = "cve_2024_30569"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Netgear R6850 - Information Disclosure: Netgear R6850 router firmware version V1.1.0.88 contains an information leakage vulnerability in the currentsetting.htm page.This hidden interface is not protected by authentication, allowing unauthenticated attackers to access sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-30569"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-30569, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-30569.yaml"
    strings:
        $path0 = /\/currentsetting\.htm(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_30570_netgear_r6850_router {
    meta:
        attack_type = "cve_2024_30570"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Netgear R6850 - Information Disclosure: Netgear R6850 router firmware version V1.1.0.88 contains an information leakage vulnerability in the debuginfo.htm page. This hidden interface is not protected by authentication, allowing unauthenticated attackers to access sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-30570"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-30570, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-30570.yaml"
    strings:
        $path0 = /\/debuginfo\.htm(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_3080_asus_dsl_ac88u {
    meta:
        attack_type = "cve_2024_3080"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ASUS DSL-AC88U - Authentication Bypass: A vulnerability in the ASUS DSL-AC88U router permits unauthorized individuals to bypass authentication.When adding '/js/..%2f%2f' or '/images/..%2f%2e' to the requested URL, it will be recognized as passing the authentication.This."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3080"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3080, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3080.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/js/../wizard.htm" ascii nocase
        $path1 = "/images/../wizard.htm" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_3097_nextgen_gallery {
    meta:
        attack_type = "cve_2024_3097"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "NextGEN Gallery <= 3.59 - Missing Authorization to Unauthenticated Information Disclosure: The WordPress Gallery Plugin NextGEN Gallery plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the get_item function in versions up."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3097"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3097, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3097.yaml"
    strings:
        $path0 = "/wp-json/ngg/v1/admin/block/image/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_3136_masterstudy_lms {
    meta:
        attack_type = "cve_2024_3136"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "MasterStudy LMS <= 3.3.3 - Unauthenticated Local File Inclusion via template: The MasterStudy LMS plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 3.3.3 via the 'template' parameter. This makes it possible for unauthenticated."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3136"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3136, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3136.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])template=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/usr\/local\/lib\/php\/pearcmd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_31621_flowise_1_6_5 {
    meta:
        attack_type = "cve_2024_31621"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Flowise 1.6.5 - Authentication Bypass: The flowise version <= 1.6.5 is vulnerable to authentication bypass vulnerability."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-31621"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-31621, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-31621.yaml"
    strings:
        $path0 = /\/API\/V1\/credentials(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_31750_f_logic_datacube3 {
    meta:
        attack_type = "cve_2024_31750"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "F-logic DataCube3 - SQL Injection: SQL injection vulnerability in f-logic datacube3 v.1.0 allows a remote attacker to obtain sensitive information via the req_id parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-31750"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-31750, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-31750.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/admin\/pr_monitor\/getting_index_data\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_31982_xwiki {
    meta:
        attack_type = "cve_2024_31982"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "XWiki < 4.10.20 - Remote code execution: XWiki Platform is a generic wiki platform. Starting in version 2.4-milestone-1 and prior to versions 4.10.20, 15.5.4, and 15.10-rc-1, XWiki's database search allows remote code execution through the search text. This allows remote code."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-31982"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-31982, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-31982.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/xwiki\/bin\/get\/Main\/DatabaseSearch(\/|;|$)/ nocase
        $path1 = /\/bin\/get\/Main\/DatabaseSearch(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_32114_activemq {
    meta:
        attack_type = "cve_2024_32114"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache ActiveMQ 6.x < 6.1.2 - Broken Access Control: Apache ActiveMQ 6.x contains an unauthenticated API web context caused by default configuration lacking security measures in the Jetty server, letting anyone interact with broker APIs and messaging layers, exploit requires no."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-32114"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-32114, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-32114.yaml"
    strings:
        $path0 = /\/api\/jolokia\/search\/org\.apache\.activemq:type=Broker,\*(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_32128_wordpress_realtyna_organic_idx {
    meta:
        attack_type = "cve_2024_32128"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress Realtyna Organic IDX Plugin <= 4.14.4 - SQL Injection: The Realtyna Organic IDX plugin plugin for WordPress is vulnerable to SQL Injection in versions up to, and including, 4.14.4 due to insufficient escaping on the user supplied parameter and lack of sufficient."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-32128"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-32128, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-32128.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])wpl_format=f:property_listing:ajax(&|$)/ nocase
        $param1 = /(^|[?&;])wpl_function=get_total_results(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_32238_h3c_er8300g2_x {
    meta:
        attack_type = "cve_2024_32238"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "H3C ER8300G2-X - Password Disclosure: H3C ER8300G2-X is vulnerable to Incorrect Access Control. The password for the router's management system can be accessed via the management system page login interface."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-32238"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-32238, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-32238.yaml"
    strings:
        $path0 = /\/userLogin\.asp(\/|;|$)/ nocase
        $path1 = "/userLogin.asp/../actionpolicy_status/../" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_3231_popup4phone_1_3_2 {
    meta:
        attack_type = "cve_2024_3231"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Popup4Phone <= 1.3.2 - Unauthenticated Stored Cross-Site Scripting: Popup4Phone WordPress plugin through 1.3.2 contains a reflected cross-site scripting caused by unsanitized parameters, letting unauthenticated users execute scripts in admin browsers, exploit requires sending."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3231"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3231, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3231.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])popup4phone\[ws_pages_submit_title\]=Popup4Phone(&|$)/ nocase
        $param1 = /(^|[?&;])popup4phone\[email\]=test@test\.com(&|$)/ nocase
        $param2 = /(^|[?&;])page=popup4phone(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_32399_raidenmaild {
    meta:
        attack_type = "cve_2024_32399"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "RaidenMAILD Mail Server v.4.9.4 - Path Traversal: Directory Traversal vulnerability in RaidenMAILD Mail Server v.4.9.4 and before allows a remote attacker to obtain sensitive information via the /webeditor/ component."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-32399"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-32399, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-32399.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/webeditor\/\.\.\/\.\.\/\.\.\/windows\/win\.ini(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_32640_masacms {
    meta:
        attack_type = "cve_2024_32640"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Mura/Masa CMS - SQL Injection: The Mura/Masa CMS is vulnerable to SQL Injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-32640"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-32640, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-32640.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])method=processAsyncObject(&|$)/ nocase
        $param1 = /(^|[?&;])object=displayregion(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_3272_dns_320l_firmware {
    meta:
        attack_type = "cve_2024_3272"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "D-Link Network Attached Storage - Backdoor Account: A vulnerability, which was classified as very critical, has been found in D-Link DNS-320L, DNS-325, DNS-327L and DNS-340L up to 20240403. This issue affects some unknown processing of the file /cgi-bin/nas_sharing.cgi of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3272"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3272, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3272.yaml"
    strings:
        $path0 = /\/cgi-bin\/nas_sharing\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_32735_cyberpower {
    meta:
        attack_type = "cve_2024_32735"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CyberPower - Missing Authentication: An issue regarding missing authentication for certain utilities exists in CyberPower PowerPanel Enterprise prior to v2.8.3."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-32735"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-32735, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-32735.yaml"
    strings:
        $path0 = /\/api\/v1\/devices(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_32825_simply_static {
    meta:
        attack_type = "cve_2024_32825"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Simply Static - Information Disclosure: Patrick Posner Simply Static versions up to 3.1.3 contain a vulnerability for insertion of sensitive information into log files caused by improper handling of log data, letting attackers potentially access sensitive information, exploit."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-32825"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-32825, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-32825.yaml"
    strings:
        $path0 = "/wp-content/uploads/simply-static/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_32870_itop {
    meta:
        attack_type = "cve_2024_32870"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "iTop Hub Connector - Information Disclosure: Combodo iTop is a simple, web based IT Service Management tool. Server, OS, DBMS, PHP, and iTop info (name, version and parameters) can be read by anyone having access to iTop URI. This issue has been patched in versions 2.7.11."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-32870"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-32870, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-32870.yaml"
    strings:
        $param0 = /(^|[?&;])exec_module=itop-hub-connector(&|$)/ nocase
        $param1 = /(^|[?&;])exec_page=launch\.php(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_3300_delmia_apriso {
    meta:
        attack_type = "cve_2024_3300"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Delmia Apriso - Pre-Authentication Unsafe .NET Object Deserialization: An unsafe .NET object deserialization vulnerability in DELMIA Apriso Release 2019 through Release 2024 could lead to pre-authentication remote code execution."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3300"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3300, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3300.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/apriso\/portal\/kiosk\/querylogin\.aspx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_33326_lumis_experience_platform {
    meta:
        attack_type = "cve_2024_33326"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LumisXP - Cross-site Scripting: A cross-site scripting (XSS) vulnerability in the XsltResultControllerHtml.jsp component of LumisXP v15.0.x to v16.1.x allows attackers to execute arbitrary web scripts or HTML via the lumPageID parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-33326"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-33326, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-33326.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/portal\/XsltResultControllerHtml\.jsp(\/|;|$)/ nocase
        $path1 = /\/XsltResultControllerHtml\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_33575_user_meta {
    meta:
        attack_type = "cve_2024_33575"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "User Meta WP Plugin < 3.1 - Sensitive Information Exposure: The User Meta is vulnerable to Sensitive Information Exposure in all versions up to, and including, 3.0 via the /views/debug.php file. This makes it possible for unauthenticated attackers, with to extract sensitive."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-33575"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-33575, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-33575.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/user-meta\/views\/debug\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_33605_mx_3550v_firmware {
    meta:
        attack_type = "cve_2024_33605"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Sharp Multifunction Printers - Directory Listing: It was observed that Sharp printers are vulnerable to an arbitrary directory listing without authentication. Any attacker can list any directory located in the printer and recover any file."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-33605"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-33605, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-33605.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/installed_emanual_list\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_33610_sharp_multifunction_printers {
    meta:
        attack_type = "cve_2024_33610"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Sharp Multifunction Printers - Cookie Exposure: It was observed that Sharp printers are vulnerable to a listing of session cookies without authentication. Any attacker can list valid cookies by visiting a backdoor webpage and use them to authenticate to the printers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-33610"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-33610, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-33610.yaml"
    strings:
        $path0 = /\/sessionlist\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_33724_soplanning {
    meta:
        attack_type = "cve_2024_33724"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SOPlanning 1.52.00 Cross Site Scripting: SOPlanning v1.52.00 is vulnerable to XSS via the 'groupe_id' parameters a remote unautheticated attacker can hijack the admin account or other users. The remote attacker can hijack a users session or credentials and perform a takeover of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-33724"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-33724, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-33724.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/process\/groupe_save\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])nom=Project New(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_3378_secure_web_gateway {
    meta:
        attack_type = "cve_2024_3378"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "iboss Secure Web Gateway - Stored Cross-Site Scripting: A cross-site scripting vulnerability has been found in iboss Secure Web Gateway up to version 10.1. The vulnerability affects the /login file of the Login Portal component, where manipulation of the redirectUrl parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3378"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3378, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3378.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/user_login_submit(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_33939_masteriyo_lms_1_7_3 {
    meta:
        attack_type = "cve_2024_33939"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Masteriyo LMS <= 1.7.3 - Insecure Direct Object Reference: Authentication Bypass Using an Alternate Path or Channel vulnerability in Masteriyo Masteriyo - LMS. Unauth access to course progress.This issue affects Masteriyo - LMS: from n/a through 1.7.3."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-33939"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-33939, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-33939.yaml"
    strings:
        $path0 = /\/wp-json\/masteriyo\/v1\/course-progress(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_34061_changedetection_io_v0_45_21 {
    meta:
        attack_type = "cve_2024_34061"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Changedetection.io <=v0.45.21 - Cross-Site Scripting: Changedetection.io is a free open source web page change detection, website watcher, restock monitor and notification service. In affected versions Input in parameter notification_urls is not processed resulting in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-34061"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-34061, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-34061.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])application-fetch_backend=html_requests(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_3408_dtale {
    meta:
        attack_type = "cve_2024_3408"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "D-Tale 3.10.0 - 3.15.1 - Authentication Bypass & Remote Code Execution: man-group/dtale 3.10.0 contains an authentication bypass and remote code execution caused by improper input validation and a hardcoded SECRET_KEY in Flask configuration, letting attackers forge session."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3408"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3408, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3408.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/dtale\/popup\/upload(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_34102_magento {
    meta:
        attack_type = "cve_2024_34102"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Adobe Commerce & Magento - CosmicSting: Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-34102"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-34102, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-34102.yaml"
    strings:
        $path0 = /\/rest\/V1\/guest-carts\/1\/estimate-shipping-methods(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_34470_hsc_mailinspector_5_2_17_3_thr {
    meta:
        attack_type = "cve_2024_34470"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "HSC Mailinspector 5.2.17-3 through 5.2.18 - Local File Inclusion: An Unauthenticated Path Traversal vulnerability exists in the /public/loaderphp file The path parameter does not properly filter whether the file and directory passed are part of the webroot, allowing an attacker."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-34470"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-34470, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-34470.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/mailinspector\/login\.php(\/|;|$)/ nocase
        $path1 = /\/mailinspector\/public\/loader\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_3469_gp_premium {
    meta:
        attack_type = "cve_2024_3469"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "GP Premium <= 2.4.0 - Cross-Site Scripting: The GP Premium plugin for WordPress up to 2.4.0 is vulnerable to reflected XSS via the 'message' parameter in inc/verify.php (lines 95-101), where a message passed with sl_activation=false is URL-decoded and used unsanitized in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3469"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3469, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3469.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=generate-options(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_35219_openapi_generator_7_5_0 {
    meta:
        attack_type = "cve_2024_35219"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OpenAPI Generator <= 7.5.0 - Arbitrary File Read/Delete: OpenAPI Generator versions 7.5.0 and below are prone to an Arbitrary File Read/Delete vulnerability. Attackers can exploit this vulnerability to read and delete files and folders from an arbitrary, writable directory."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-35219"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-35219, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-35219.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/api\/gen\/clients\/csharp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_3552_web_directory_free {
    meta:
        attack_type = "cve_2024_3552"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Web Directory Free < 1.7.0 - SQL Injection: The plugin does not sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection with different techniques like UNION, Time-Based and Error-Based."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3552"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3552, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3552.yaml"
    strings:
        $param0 = /(^|[?&;])locations_ids\[\]=\(select if\(1=1,sleep\(6\),0\) from \(select 1\)x\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_35693_12_step_meeting_list {
    meta:
        attack_type = "cve_2024_35693"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WordPress 12 Step Meeting List Plugin <= 3.14.33 - Cross-Site Scripting: Code for Recovery 12 Step Meeting List versions up to 3.14.33 contain a reflected cross-site scripting caused by improper input neutralization during web page generation, letting attackers execute."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-35693"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-35693, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-35693.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])post_type=tsml_meeting(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_3605_wp_hotel_booking_2_1_0 {
    meta:
        attack_type = "cve_2024_3605"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WP Hotel Booking <= 2.1.0 - SQL Injection: The WP Hotel Booking plugin for WordPress is vulnerable to SQL Injection via the 'room_type' parameter of the /wphb/v1/rooms/search-rooms REST API endpoint in all versions up to, and including, 2.1.0 due to insufficient escaping on the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3605"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3605, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3605.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/wp-json\/wphb\/v1\/rooms\/search-rooms(\/|;|$)/ nocase
        $param0 = /(^|[?&;])check_in_date=2025-01-01(&|$)/ nocase
        $param1 = /(^|[?&;])check_out_date=2025-01-10(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_36420_flowise {
    meta:
        attack_type = "cve_2024_36420"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Flowise 1.4.3 - Arbitrary File Read: Flowise 1.4.3 contains a path traversal caused by lack of sanitization of 'fileName' parameter in /api/v1/openai-assistants-file endpoint in index.ts, letting attackers read arbitrary files, exploit requires attacker to send crafted request."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-36420"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-36420, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-36420.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/api\/v1\/openai-assistants-file(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_3656_keycloak {
    meta:
        attack_type = "cve_2024_3656"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Keycloak < 24.0.5 - Broken Access Control: A flaw was found in Keycloak. Certain endpoints in Keycloak's admin REST API allow low-privilege users to access administrative functionalities. This flaw allows users to perform actions reserved for administrators, potentially leading."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3656"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3656, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3656.yaml"
    strings:
        $path0 = /\/login-actions\/authenticate(\/|;|$)/ nocase
        $path1 = /\/protocol\/openid-connect\/token(\/|;|$)/ nocase
        $path2 = /\/testLDAPConnection(\/|;|$)/ nocase
        $param0 = /(^|[?&;])code_challenge_method=S256(&|$)/ nocase
        $param1 = /(^|[?&;])client_data=eyJydCI6ImNvZGUiLCJybSI6InF1ZXJ5Iiwic3QiOiIxIn0=(&|$)/ nocase
        $param2 = /(^|[?&;])grant_type=authorization_code(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_36675_lylme_spage {
    meta:
        attack_type = "cve_2024_36675"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LyLme spage v1.9.5 - Server-Side Request Forgery: LyLme spage v1.9.5 is vulnerable to server-side request forgery (SSRF) via the url parameter in apply/index.php. An attacker can force the server to make arbitrary requests, potentially accessing internal resources."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-36675"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-36675, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-36675.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/apply\/index\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_36683_prestashop_productsalert {
    meta:
        attack_type = "cve_2024_36683"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "PrestaShop productsalert - SQL Injection: In the module 'Products Alert' (productsalert) up to version 1.7.4 from Smart Modules for PrestaShop, a guest can perform SQL injection in affected versions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-36683"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-36683, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-36683.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])pasubmit=Crea un nuovo messaggio di notifica(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_3673_web_directory_free {
    meta:
        attack_type = "cve_2024_3673"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Web Directory Free < 1.7.3 - Local File Inclusion: The Web Directory Free WordPress plugin before 1.7.3 does not validate a parameter before using it in an include(), which could lead to Local File Inclusion issues."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3673"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3673, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3673.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])action=w2dc_controller_request(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_36837_crmeb {
    meta:
        attack_type = "cve_2024_36837"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "CRMEB v.5.2.2 - SQL Injection: SQL Injection vulnerability in CRMEB v.5.2.2 allows a remote attacker to obtain sensitive information via the getProductList function in the ProductController.php file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-36837"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-36837, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-36837.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/api\/products(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_36858_jan {
    meta:
        attack_type = "cve_2024_36858"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Jan v0.4.12 - Arbitrary File Upload: An arbitrary file upload vulnerability in the /v1/app/writeFileSync interface of Jan v0.4.12 allows attackers to execute arbitrary code via uploading a crafted file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-36858"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-36858, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-36858.yaml"
    strings:
        $path0 = /\/v1\/app\/appendFileSync(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_37393_securenvoy_two_factor_authenti {
    meta:
        attack_type = "cve_2024_37393"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SecurEnvoy Two Factor Authentication - LDAP Injection: Multiple LDAP injections vulnerabilities exist in SecurEnvoy MFA before 9.4.514 due to improper validation of user-supplied input. An unauthenticated remote attacker could exfiltrate data from Active Directory through blind."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-37393"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-37393, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-37393.yaml"
    strings:
        $param0 = /(^|[?&;])FLAG=DESKTOP(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_3753_hostel_1_1_5_3 {
    meta:
        attack_type = "cve_2024_3753"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Hostel < 1.1.5.3 - Cross-Site Scripting: The Hostel WordPress plugin before 1.1.5.3 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against high privilege users such as admin."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3753"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3753, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3753.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=wphostel_bookings(&|$)/ nocase
        $param1 = /(^|[?&;])type=upcoming(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_37656_gnuboard {
    meta:
        attack_type = "cve_2024_37656"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "GnuBoard5 5.5.16 - Open Redirect: Gnuboard5 5.5.16 contains an open redirect vulnerability caused by insufficient URL parameter verification in bbs/logout.php, letting remote attackers redirect users to arbitrary URLs, exploit requires crafted URL parameter."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-37656"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-37656, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-37656.yaml"
    strings:
        $path0 = /\/gnuboard5\/bbs\/logout\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_37728_officeweb365_indexs_interface {
    meta:
        attack_type = "cve_2024_37728"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OfficeWeb365 Indexs Interface - Arbitrary File Read: There is any file reading in the officeWeb365 Indexs interface."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-37728"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-37728, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-37728.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/Pic\/Indexs(\/|;|$)/ nocase
        $param0 = /(^|[?&;])imgs=DJwkiEm6KXJZ7aEiGyN4Cz83Kn1PLaKA09(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_3822_base64_encoder_decoder_0_9_2 {
    meta:
        attack_type = "cve_2024_3822"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Base64 Encoder/Decoder <= 0.9.2 - Cross-Site Scripting: The Base64 Encoder/Decoder WordPress plugin through 0.9.2 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against high."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3822"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3822, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3822.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/wp-content\/plugins\/base64-encoderdecoder\/base64-decode\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])string=PHNjcmlwdD5hbGVydCgiZG9jdW1lbnQuZG9tYWluIik8L3NjcmlwdD4=(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_38514_nextchat {
    meta:
        attack_type = "cve_2024_38514"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "NextChat - Server-Side Request Forgery: NextChat v2.12.3 suffers from a Server-Side Request Forgery (SSRF) and Cross-Site Scripting vulnerability due to a lack of validation of the GET parameter on the WebDav API endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-38514"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-38514, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-38514.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/api\/webdav\/chatgpt-next-web\/backup\.json(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_38773_formlift_for_infusionsoft_web {
    meta:
        attack_type = "cve_2024_38773"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "FormLift for Infusionsoft Web Forms <= 7.5.17 - SQL Injection: The FormLift for Infusionsoft Web Forms plugin for WordPress is vulnerable to SQL Injection via the 'form_id' parameter in versions up to, and including, 7.5.17 due to insufficient escaping on the user supplied."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-38773"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-38773, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-38773.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=formlift_submit_form(&|$)/ nocase
        $param1 = /(^|[?&;])form_id=0 UNION SELECT SLEEP\(7\)--(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_38856_ofbiz {
    meta:
        attack_type = "cve_2024_38856"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Apache OFBiz - Improper Authorization & Remote Code Execution: Improper Authorization vulnerability in Apache OFBiz. This issue affects Apache OFBiz: through 18.12.14. Users are recommended to upgrade to version 18.12.15, which fixes the issue. Unauthenticated endpoints could."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-38856"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-38856, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-38856.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/webtools\/control\/main\/ProgramExport(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_3922_dokan {
    meta:
        attack_type = "cve_2024_3922"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dokan Pro <= 3.10.3 - SQL Injection: The Dokan Pro plugin for WordPress is vulnerable to SQL Injection via the 'code' parameter in all versions up to, and including, 3.10.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-3922"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3922, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3922.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/wp-content\/plugins\/dokan-pro\/changelog\.txt(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_39646_custom_404_pro {
    meta:
        attack_type = "cve_2024_39646"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Custom 404 Pro <= 3.11.1 - Reflected XSS: Improper Neutralization of Input During Web Page Generation (XSS or 'Cross-site Scripting') vulnerability in Kunal Nagar Custom 404 Pro allows Reflected XSS.This issue affects Custom 404 Pro: from n/a through 3.11.1."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-39646"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-39646, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-39646.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])c4pmessage=hello(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_39713_rocket_chat {
    meta:
        attack_type = "cve_2024_39713"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Rocket.Chat - Server-Side Request Forgery (SSRF): A Server-Side Request Forgery (SSRF) affects Rocket.Chat's Twilio webhook endpoint before version 6.10.1."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-39713"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-39713, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-39713.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/api\/v1\/livechat\/sms-incoming\/twilio(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_39887_superset {
    meta:
        attack_type = "cve_2024_39887"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Apache Superset < 4.0.2 - SQL Injection: An SQL Injection vulnerability in Apache Superset exists due to improper neutralization of special elements used in SQL commands. Specifically, certain engine-specific functions are not checked, which allows attackers to bypass Apache."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-39887"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-39887, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-39887.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/api\/v1\/chart\/data(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_39907_1panel {
    meta:
        attack_type = "cve_2024_39907"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "1Panel SQL Injection - Authenticated: 1Panel is a web-based linux server management control panel. There are many sql injections in the project, and some of them are not well filtered, leading to arbitrary file writes, and ultimately leading to RCEs. These sql injections have."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-39907"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-39907, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-39907.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/api\/v1\/hosts\/command\/search(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_40348_bazarr {
    meta:
        attack_type = "cve_2024_40348"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Bazarr < 1.4.3 - Arbitrary File Read: Bazarr 1.4.3 and earlier versions have a arbitrary file read vulnerability."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-40348"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-40348, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-40348.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/api\/swaggerui\/static\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_40422_devika {
    meta:
        attack_type = "cve_2024_40422"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Devika v1 - Path Traversal: The snapshot_path parameter in the /api/get-browser-snapshot endpoint in stitionai devika v1 is susceptible to a path traversal attack. An attacker can manipulate the snapshot_path parameter to traverse directories and access sensitive files on the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-40422"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-40422, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-40422.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])snapshot_path=\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_40711_veeam_backup_replication {
    meta:
        attack_type = "cve_2024_40711"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Veeam Backup & Replication - Unauthenticated: A deserialization of untrusted data vulnerability with a malicious payload can allow an unauthenticated remote code execution (RCE)."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-40711"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-40711, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-40711.yaml"
    strings:
        $path0 = /\/api\/v1\/serverinfo(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_41107_cloudstack {
    meta:
        attack_type = "cve_2024_41107"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache CloudStack - SAML Signature Exclusion: The CloudStack SAML authentication (disabled by default) does not enforce signature check. In CloudStack environments where SAML authentication is enabled, an attacker that initiates CloudStack SAML single sign-on authentication can."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-41107"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-41107, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-41107.yaml"
    strings:
        $path0 = /\/client\/api(\/|;|$)/ nocase
        $param0 = /(^|[?&;])command=samlSso(&|$)/ nocase
        $param1 = /(^|[?&;])RelayState=undefined(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_41667_openam_15_0_3_freemarker {
    meta:
        attack_type = "cve_2024_41667"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OpenAM<=15.0.3 FreeMarker - Template Injection: OpenAM is an open access management solution. In versions 15.0.3 and prior, the `getCustomLoginUrlTemplate` method in RealmOAuth2ProviderSettings.java is vulnerable to template injection due to its usage of user input"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-41667"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-41667, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-41667.yaml"
        response_type = "template_eval"
    strings:
        $path0 = /\/openam\/json\/realms\/root\/authenticate(\/|;|$)/ nocase
        $path1 = /\/openam\/realm\/RMRealm(\/|;|$)/ nocase
        $path2 = /\/openam\/agentconfig\/Agents(\/|;|$)/ nocase
        $path3 = /\/openam\/agentconfig\/AgentAdd(\/|;|$)/ nocase
        $path4 = /\/openam\/agentconfig\/GenericAgentProfile(\/|;|$)/ nocase
        $path5 = /\/openam\/json\/realms\/root\/realm-config\/services\/oauth-oidc(\/|;|$)/ nocase
        $param0 = /(^|[?&;])Agents\.tblSearch\.PrimarySortNameHiddenField=tblDataName(&|$)/ nocase
        $param1 = /(^|[?&;])Agents\.tblSearch\.PrimarySortOrderHiddenField=ascending(&|$)/ nocase
        $param2 = /(^|[?&;])Agents\.tblButtonAdd=New\.\.\.(&|$)/ nocase
        $param3 = /(^|[?&;])Agents\.tblSearchGroup\.PrimarySortNameHiddenField=tblDataGroupName(&|$)/ nocase
        $param4 = /(^|[?&;])Agents\.tblSearchGroup\.PrimarySortOrderHiddenField=ascending(&|$)/ nocase
        $param5 = /(^|[?&;])jato\.defaultCommand=\/btnSearch(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_41713_cmg_suite {
    meta:
        attack_type = "cve_2024_41713"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Mitel MiCollab - Authentication Bypass: A vulnerability in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab through 9.8 SP1 FP2 (9.8.1.201) could allow an unauthenticated attacker to conduct a path traversal attack, due to insufficient input validation. A."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-41713"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-41713, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-41713.yaml"
    strings:
        $path0 = /\/npm-pwg\/\.\.;\/axis2-AWC\/services\/listServices(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_4180_the_events_calendar {
    meta:
        attack_type = "cve_2024_4180"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "The Events Calendar < 6.4.0.1 - Cross-site Scripting: The Events Calendar WordPress plugin < 6.4.0.1 contains a stored XSS caused by improper sanitization of user-submitted content when rendering views via AJAX, letting attackers execute scripts in the context of the affected."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-4180"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4180, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4180.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=tribe_events_views_v2_fallback(&|$)/ nocase
        $param1 = /(^|[?&;])view=reflector(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_42323_hertzbeat {
    meta:
        attack_type = "cve_2024_42323"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Apache HertzBeat < 1.6.0 - SnakeYAML Deserialization Remote Code Execution: Apache HertzBeat versions before 1.6.0 use a vulnerable version of the SnakeYAML library to parse YAML files imported through the `/api/monitors/import` and `/api/alert/defines/import` endpoints. An."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-42323"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-42323, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-42323.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/monitors\/import(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_42640_angular_base64_upload {
    meta:
        attack_type = "cve_2024_42640"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Angular-Base64-Upload - Remote Code Execution: angular-base64-upload prior to v0.1.21 is vulnerable to unauthenticated remote code execution via demo/server.php. Exploiting this vulnerability allows an attacker to upload arbitrary content to the server, which can subsequently."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-42640"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-42640, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-42640.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/node_modules\/angular-base64-upload\/demo\/server\.php(\/|;|$)/ nocase
        $path1 = /\/bower_components\/angular-base64-upload\/demo\/server\.php(\/|;|$)/ nocase
        $path2 = "/node_modules/angular-base64-upload/demo/uploads/" ascii nocase
        $path3 = "/bower_components/angular-base64-upload/demo/uploads/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_42852_acutoweb {
    meta:
        attack_type = "cve_2024_42852"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "AcuToWeb server/10.5.0.7577c8b - Cross-Site Scripting: AcuToWeb server/10.5.0.7577c8b is vulnerable to reflected cross-site scripting (XSS) via the portgw parameter. Unsanitized user input is reflected in the response, allowing arbitrary JavaScript execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-42852"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-42852, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-42852.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])portgw=80089948; alert\(document\.domain\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_43160_berqwp {
    meta:
        attack_type = "cve_2024_43160"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "BerqWP <= 1.7.6 - Arbitrary File Upload: The BerqWP Automated All-In-One PageSpeed Optimization Plugin for Core Web Vitals, Cache, CDN, Images, CSS, and JavaScript plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-43160"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-43160, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-43160.yaml"
    strings:
        $path0 = /\/wp-json\/optifer\/v1\/store-webp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_4322_lollms_webui_9_8 {
    meta:
        attack_type = "cve_2024_4322"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LoLLMS WebUI < 9.8 - Path Traversal: parisneo/lollms-webui contains a path traversal caused by improper handling of 'category' parameter in /list_personalities endpoint, letting attackers list arbitrary directories, exploit requires control over 'category' parameter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-4322"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4322, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4322.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/list_personalities(\/|;|$)/ nocase
        $param0 = /(^|[?&;])category=\.\.\/\.\.(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_4325_gradio {
    meta:
        attack_type = "cve_2024_4325"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Gradio - Server-Side Request Forgery: A Server-Side Request Forgery (SSRF) vulnerability exists in the gradio-app/gradio version 4.21.0, specifically within the `/queue/join` endpoint and the `save_url_to_cache` function. The vulnerability arises when the `path` value, obtained."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-4325"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4325, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4325.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = "/file=/tmp/gradio/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_43283_contest_gallery {
    meta:
        attack_type = "cve_2024_43283"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Contest Gallery - Broken Access Control: Contest Gallery from n/a through 23.1.2 contains an exposure of sensitive information to an unauthorized actor caused by insufficient access controls, letting attackers access sensitive data, exploit requires no specific conditions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-43283"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-43283, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-43283.yaml"
    strings:
        $path0 = "/wp-content/uploads/contest-gallery/gallery-id-" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_43425_moodle {
    meta:
        attack_type = "cve_2024_43425"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Moodle - Remote Code Execution: Attackers with the permission to create or modify questions in Moodle courses are able to craft malicious inputs for calculated questions, which can be abused to execute arbitrary commands on the underlying system."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-43425"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-43425, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-43425.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/my\/courses\.php(\/|;|$)/ nocase
        $path1 = /\/question\/bank\/editquestion\/question\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])info=core_course_get_enrolled_courses_by_timeline_classification(&|$)/ nocase
        $param1 = /(^|[?&;])wizard=datasetdefinitions(&|$)/ nocase
        $param2 = /(^|[?&;])qtype=calculated(&|$)/ nocase
        $param3 = /(^|[?&;])category=2,11(&|$)/ nocase
        $param4 = /(^|[?&;])tolerance\[0\]=0\.01(&|$)/ nocase
        $param5 = /(^|[?&;])tags=_qf__force_multiselect_submission(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_4348_oscommerce {
    meta:
        attack_type = "cve_2024_4348"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "osCommerce v4.0 - Cross-site Scripting: A vulnerability, which was classified as problematic, was found in osCommerce 4. Affected is an unknown function of the file /catalog/all-products. The manipulation of the argument cat leads to cross site scripting. It is possible to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-4348"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4348, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4348.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/furniture\/catalog\/all-products(\/|;|$)/ nocase
        $path1 = /\/watch\/catalog\/all-products(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_4358_telerik_report_server {
    meta:
        attack_type = "cve_2024_4358"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Progress Telerik Report Server - Authentication Bypass: In Progress Telerik Report Server, version 2024 Q1 (10.0.24.305) or earlier, on IIS, an unauthenticated attacker can gain access to Telerik Report Server restricted functionality via an authentication bypass vulnerability."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-4358"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4358, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4358.yaml"
    strings:
        $path0 = /\/Startup\/Register(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_43917_ti_woocommerce_wishlist {
    meta:
        attack_type = "cve_2024_43917"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress TI WooCommerce Wishlist Plugin <= 2.8.2 - SQL Injection: In the latest version (2.8.2 as of writing the article) and below, the plugin is vulnerable to a SQL injection vulnerability that allows any users to execute arbitrary SQL queries in the database of the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-43917"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-43917, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-43917.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/product-category/uncategorized/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_43919_yet_another_related_posts_plug {
    meta:
        attack_type = "cve_2024_43919"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "YARPP <= 5.30.10 - Missing Authorization: The YARPP Yet Another Related Posts Plugin plugin for WordPress is vulnerable to unauthorized access due to a missing capability check in the ~/includes/yarpp_pro_set_display_types.php file in all versions up to, and including, 5.30.10.."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-43919"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-43919, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-43919.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/yet-another-related-posts-plugin\/includes\/yarpp_pro_set_display_types\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])types\[\]=page(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_43971_sunshine_photo_cart {
    meta:
        attack_type = "cve_2024_43971"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Sunshine Photo Cart <= 3.2.5 - Reflected Cross-Site Scripting: WP Sunshine Sunshine Photo Cart versions up to 3.2.5 contain a reflected cross-site scripting caused by improper input neutralization during web page generation, letting attackers execute malicious scripts in users'."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-43971"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-43971, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-43971.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=sunshine(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_4399_cas {
    meta:
        attack_type = "cve_2024_4399"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress CAS Theme <= 1.0.0 - Server-Side Request Forgery: The CAS WordPress theme through version 1.0.0 is vulnerable to Server-Side Request Forgery (SSRF) via the 'url' parameter in the get_remote_data.php script. This vulnerability allows unauthenticated attackers to make."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-4399"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4399, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4399.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/wp-content\/themes\/cas\/get_remote_data\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_44000_litespeed_cache {
    meta:
        attack_type = "cve_2024_44000"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LiteSpeed Cache <= 6.4.1 - Sensitive Information Exposure: The LiteSpeed Cache plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 6.4.1 through the debug.log file that is publicly exposed. This makes it possible for."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-44000"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-44000, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-44000.yaml"
    strings:
        $path0 = /\/wp-content\/debug\.log(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_44349_anteeowms_v4_7_34 {
    meta:
        attack_type = "cve_2024_44349"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "AnteeoWMS < v4.7.34 - SQL Injection: A SQL injection vulnerability in login portal in AnteeoWMS before v4.7.34 allows unauthenticated attackers to execute arbitrary SQL commands via the username parameter and disclosure of some data in the underlying DB."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-44349"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-44349, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-44349.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])__CALLBACKID=ctl00\$MainContentPlaceHolder\$ASPxCallbackPanel(&|$)/ nocase
        $param1 = /(^|[?&;])__CALLBACKPARAM=c0:\[object Object\](&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_4439_wordpress_core_6_5_2 {
    meta:
        attack_type = "cve_2024_4439"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress Core <6.5.2 - Cross-Site Scripting: WordPress Core is vulnerable to Stored Cross-Site Scripting via user display names in the Avatar block in various versions up to 6.5.2 due to insufficient output escaping on the display name."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-4439"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4439, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4439.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])email=admin@gmail\.com(&|$)/ nocase
        $param1 = /(^|[?&;])comment=Unauthenticated Comment(&|$)/ nocase
        $param2 = /(^|[?&;])email=example@gmail\.com(&|$)/ nocase
        $param3 = /(^|[?&;])url=example\.com(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_44762_usermin {
    meta:
        attack_type = "cve_2024_44762"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Usermin 2.100 - Username Enumeration: Usermin version 2.100 and below is susceptible to username enumeration via the password change functionality. An attacker can determine valid usernames by analyzing the response messages from the password change endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-44762"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-44762, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-44762.yaml"
    strings:
        $path0 = /\/password_change\.cgi(\/|;|$)/ nocase
        $param0 = /(^|[?&;])old=fakePassword(&|$)/ nocase
        $param1 = /(^|[?&;])new1=password(&|$)/ nocase
        $param2 = /(^|[?&;])new2=password(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_44849_qualitor {
    meta:
        attack_type = "cve_2024_44849"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Qualitor <= 8.24 - Remote Code Execution: Qualitor up to 8.24 is vulnerable to Remote Code Execution (RCE) via Arbitrary File Upload in checkAcesso.php."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-44849"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-44849, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-44849.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/html\/ad\/adfilestorage\/request\/checkAcesso\.php(\/|;|$)/ nocase
        $path1 = "/html/ad/adfilestorage/request/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_45195_ofbiz {
    meta:
        attack_type = "cve_2024_45195"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Apache OFBiz - Remote Code Execution: Apache OFBiz below 18.12.16 is vulnerable to unauthenticated remote code execution on Linux and Windows. An attacker with no valid credentials can exploit missing view authorization checks in the web application to execute arbitrary code on."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-45195"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-45195, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45195.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/webtools\/control\/forgotPassword\/xmldsdump(\/|;|$)/ nocase
        $param0 = /(^|[?&;])outpath=\.\/themes\/common-theme\/webapp\/common-theme\/(&|$)/ nocase
        $param1 = /(^|[?&;])entityName=UserLogin(&|$)/ nocase
        $param2 = /(^|[?&;])entityName=CreditCard(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_45216_apache_solr {
    meta:
        attack_type = "cve_2024_45216"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache Solr - Authentication Bypass: Solr instances using the PKIAuthenticationPlugin, which is enabled by default when Solr Authentication is used, are vulnerable to Authentication bypass.A fake ending at the end of any Solr API URL path, will allow requests to skip."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-45216"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-45216, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45216.yaml"
    strings:
        $path0 = /\/solr\/admin\/info\/properties:\/admin\/info\/key(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_45241_crywolf {
    meta:
        attack_type = "cve_2024_45241"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "CentralSquare CryWolf - Path Traversal: A traversal vulnerability in GeneralDocs.aspx in CentralSquare CryWolf (False Alarm Management) through 2024-08-09 allows unauthenticated attackers to read files outside of the working web directory via the rpt parameter, leading to the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-45241"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-45241, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45241.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/GeneralDocs\.aspx(\/|;|$)/ nocase
        $path1 = /\/gdoc1\.ashx(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_45293_tablepress {
    meta:
        attack_type = "cve_2024_45293"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "TablePress < 2.4.3 - XXE Injection: The PHPSpreadsheet library used by the plugin is affected by an XXE as the security scanner that prevents XXE attacks in the XLSX reader can be bypassed by slightly modifying the XML structure, utilizing white spaces. On servers that allow."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-45293"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-45293, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45293.yaml"
    strings:
        $param0 = /(^|[?&;])page=tablepress_import(&|$)/ nocase
        $param1 = /(^|[?&;])page=tablepress(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_45309_onedev {
    meta:
        attack_type = "cve_2024_45309"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "OneDev.io < 11.0.9 - Arbitrary File Read: Files on the host computer can be accessed by directory traversal."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-45309"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-45309, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45309.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/~site/../../../../../../" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_45388_hoverfly_1_10_3 {
    meta:
        attack_type = "cve_2024_45388"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hoverfly < 1.10.3 - Arbitrary File Read: Hoverfly is a lightweight service virtualization/ API simulation / API mocking tool for developers and testers. The /api/v2/simulation POST handler allows users to create new simulation views from the contents of a user-specified file.."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-45388"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-45388, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45388.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/api\/v2\/simulation(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_45440_drupal {
    meta:
        attack_type = "cve_2024_45440"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Drupal 11.x-dev - Full Path Disclosure: core/authorize.php in Drupal 11.x-dev allows Full Path Disclosure (even when error logging is None) if the value of hash_salt is file_get_contents of a file that does not exist."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-45440"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-45440, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45440.yaml"
    strings:
        $path0 = /\/core\/authorize\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_45488_safeguard_for_privileged_passw {
    meta:
        attack_type = "cve_2024_45488"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SafeGuard for Privileged Passwords < 7.5.2 - Authentication Bypass: One Identity Safeguard for Privileged Passwords before 7.5.2 allows unauthorized access because of an issue related to cookies. This only affects virtual appliance installations (VMware or HyperV). The fixed."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-45488"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-45488, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45488.yaml"
    strings:
        $path0 = /\/RSTS\/UserLogin\/LoginController(\/|;|$)/ nocase
        $param0 = /(^|[?&;])response_type=token(&|$)/ nocase
        $param1 = /(^|[?&;])redirect_uri=https:\/\/localhost(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_45507_ofbiz {
    meta:
        attack_type = "cve_2024_45507"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Apache OFBiz - Remote Code Execution: Apache OFBiz below 18.12.16 is vulnerable to unauthenticated remote code execution on Linux and Windows. An attacker with no valid credentials can exploit missing view authorization checks in the web application to execute arbitrary code on."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-45507"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-45507, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45507.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/webtools\/control\/view\/StatsSinceStart(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_45591_xwiki_platform {
    meta:
        attack_type = "cve_2024_45591"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "XWiki Platform - Unauthorized Document History Access: A vulnerability in XWiki Platform's REST API allows unauthorized users to access document history information. The REST API endpoint exposes the history of any page including modification times, version numbers, author."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-45591"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-45591, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45591.yaml"
    strings:
        $path0 = /\/xwiki\/rest\/wikis\/xwiki\/spaces\/Main\/pages\/WebHome\/history(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_45622_asis {
    meta:
        attack_type = "cve_2024_45622"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ASIS - SQL Injection Authentication Bypass: ASIS (aka Aplikasi Sistem Sekolah using CodeIgniter 3) 3.0.0 through 3.2.0 allows index.php username SQL injection for Authentication Bypass."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-45622"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-45622, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-45622.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/asispanel\/login\/cek(\/|;|$)/ nocase
        $path1 = /\/asispanel\/home(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_4620_arforms {
    meta:
        attack_type = "cve_2024_4620"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ArForms < 6.6 - Remote Code Execution: The ARForms - Premium WordPress Form Builder Plugin WordPress plugin before 6.6 allows unauthenticated users to modify uploaded files in such a way that PHP code can be uploaded when an upload file input is included on a form"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-4620"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4620, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4620.yaml"
    strings:
        $path0 = "/wp-content/uploads/arforms/userfiles/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_46310_fxserver {
    meta:
        attack_type = "cve_2024_46310"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "FXServer < v9601 - Information Exposure: Incorrect Access Control in FXServer version's v9601 and prior, for CFX.re FiveM, allows unauthenticated users to modify and read userdata via exposed api endpoint."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-46310"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-46310, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-46310.yaml"
    strings:
        $path0 = /\/players\.json(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_46506_netalertx {
    meta:
        attack_type = "cve_2024_46506"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "NetAlertX 23.01.1424.x < 24.10.12 - Remote Code Execution: NetAlertX 23.01.14 through 24.x before 24.10.12 allows unauthenticated command injection via settings update because function=savesettings lacks an authentication requirement, as exploited in the wild in May 2025. This."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-46506"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-46506, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-46506.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/api\/table_settings\.json(\/|;|$)/ nocase
        $param0 = /(^|[?&;])function=savesettings(&|$)/ nocase
        $param1 = /(^|[?&;])function=addToExecutionQueue(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_46507_yeti_platform_2_1_12 {
    meta:
        attack_type = "cve_2024_46507"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Yeti Platform < 2.1.12 - Server-Side Template Injection to RCE: The Yeti Platform < 2.1.12 contains a Server-Side Template Injection (SSTI) vulnerability that can lead to Remote Code Execution (RCE) when exploited by an authenticated user. Attackers with valid credentials can."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-46507"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-46507, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-46507.yaml"
        response_type = "template_eval"
    strings:
        $path0 = "/api/v2/templates/" ascii nocase
        $path1 = /\/api\/v2\/observables\/extended(\/|;|$)/ nocase
        $path2 = /\/api\/v2\/templates\/render(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_46938_experience_commerce {
    meta:
        attack_type = "cve_2024_46938"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Sitecore Experience Platform <= 10.4 - Arbitrary File Read: An issue was discovered in Sitecore Experience Platform (XP), Experience Manager (XM), and Experience Commerce (XC) 8.0 Initial Release through 10.4 Initial Release. An unauthenticated attacker can read arbitrary files."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-46938"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-46938, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-46938.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/-\/xaml\/Sitecore\.Shell\.Applications\.ContentEditor\.Dialogs\.EditHtml\.ValidateXHtml(\/|;|$)/ nocase
        $param0 = /(^|[?&;])__PAGESTATE=\/\.\.\/\.\.\/x\/x(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_47062_navidrome_0_53_0 {
    meta:
        attack_type = "cve_2024_47062"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Navidrome < 0.53.0 - Authenticated SQL Injection: Navidrome is an open source web-based music collection server and streamer. Navidrome automatically adds parameters in the URL to SQL queries. This can be exploited to access information by adding parameters like `password=...`."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-47062"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-47062, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-47062.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/api\/album(\/|;|$)/ nocase
        $param0 = /(^|[?&;])_sort=recently_added(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_47308_templately {
    meta:
        attack_type = "cve_2024_47308"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Templately <= 3.1.2 - Broken Access Control: Templately allow an attacker to logout users who signed in to their templately account, so you can sign in your templately account to exploit this vulnerability. Go to."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-47308"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-47308, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-47308.yaml"
    strings:
        $path0 = /\/wp-json\/templately\/v1\/logout(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_48259_cloudlog {
    meta:
        attack_type = "cve_2024_48259"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Cloudlog - SQL Injection: Cloudlog 2.6.15 contains a SQL injection caused by unsanitized input in oqrs.php request_form, letting attackers execute arbitrary SQL commands via station_id or callsign, exploit requires sending crafted request."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-48259"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-48259, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-48259.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/index\.php\/oqrs\/request_form(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_48307_jeecg_boot {
    meta:
        attack_type = "cve_2024_48307"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "JeecgBoot v3.7.1 - SQL Injection: The JeecgBoot application is vulnerable to SQL Injection via the `getTotalData` endpoint. An attacker can exploit this vulnerability to extract sensitive information from the database by injecting SQL commands."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-48307"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-48307, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-48307.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "drag/onlDragDatasetHead/getTotalData" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_48360_qualitor {
    meta:
        attack_type = "cve_2024_48360"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Qualitor <= v8.24 - Server-Side Request Forgery: Qualitor v8.24 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /request/viewValidacao.php."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-48360"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-48360, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-48360.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/html\/ad\/adformmobile\/request\/viewValidacao\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_4841_lollms_webui {
    meta:
        attack_type = "cve_2024_4841"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LoLLMS WebUI - Subfolder Prediction via Path Traversal: A Path Traversal vulnerability exists in the parisneo/lollms-webui, specifically within the 'add_reference_to_local_mode' function due to the lack of input sanitization. This vulnerability affects versions v9.6 to the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-4841"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4841, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4841.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/add_reference_to_local_model(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_48455_netis_wifi_router {
    meta:
        attack_type = "cve_2024_48455"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Netis Wifi Router - Information Disclosure: An issue in Netis Wifi6 Router NX10 2.0.1.3643 and 2.0.1.3582 and Netis Wifi 11AC Router NC65 3.0.0.3749 and Netis Wifi 11AC Router NC63 3.0.0.3327 and 3.0.0.3503 and Netis Wifi 11AC Router NC21 3.0.0.3800, 3.0.0.3500 and 3.0.0.3329."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-48455"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-48455, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-48455.yaml"
    strings:
        $param0 = /(^|[?&;])mode_name=skk_get(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_4885_whatsup_gold {
    meta:
        attack_type = "cve_2024_4885"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Progress Software WhatsUp Gold GetFileWithoutZip Directory Traversal - Remote Code Execution: This vulnerability allows remote attackers to execute arbitrary code on affected installations of Progress Software WhatsUp Gold. Authentication is not required to exploit this."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-4885"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4885, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4885.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/NmAPI\/RecurringReport(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_48914_vendure {
    meta:
        attack_type = "cve_2024_48914"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Vendure - Arbitrary File Read: Vendure is an open-source headless commerce platform. Prior to versions 3.0.5 and 2.3.3, a vulnerability in Vendure's asset server plugin allows an attacker to craft a request which is able to traverse the server file system and retrieve the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-48914"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-48914, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-48914.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/assets\/\.\.\/package\.json(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_4898_instawp_connect {
    meta:
        attack_type = "cve_2024_4898"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress InstaWP Connect <= 0.1.0.38 - Unauthenticated User Creation: The InstaWP Connect 1-click WP Staging & Migration plugin for WordPress is vulnerable to arbitrary option updates due to a missing authorization checks on the REST API calls in all versions up to, and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-4898"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-4898, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-4898.yaml"
    strings:
        $path0 = /\/wp-json\/instawp-connect\/v1\/config(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_50340_symfony_profiler {
    meta:
        attack_type = "cve_2024_50340"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Symfony Profiler - Remote Access via Injected Arguments: symfony/runtime is a module for the Symphony PHP framework which enables decoupling PHP applications from global state. When the `register_argv_argc` php directive is set to `on` , and users call any URL with a special."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-50340"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-50340, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-50340.yaml"
    strings:
        $path0 = /\/_profiler\/phpinfo(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_50498_wp_query_console {
    meta:
        attack_type = "cve_2024_50498"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WP Query Console <= 1.0 - Remote Code Execution: Improper Control of Generation of Code ('Code Injection') vulnerability in LUBUS WP Query Console allows Code Injection.This issue affects WP Query Console- from n/a through 1.0."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-50498"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-50498, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-50498.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])rest_route=\/wqc\/v1\/query(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_50603_controller {
    meta:
        attack_type = "cve_2024_50603"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Aviatrix Controller - Remote Code Execution: An issue was discovered in Aviatrix Controller before 7.1.4191 and 7.2.x before 7.2.4996. Due to the improper neutralization of special elements used in an OS command, an unauthenticated attacker is able to execute arbitrary code.."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-50603"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-50603, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-50603.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])action=list_flightpath_destination_instances(&|$)/ nocase
        $param1 = /(^|[?&;])CID=anything_goes_here(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_5082_nexus_repository_2 {
    meta:
        attack_type = "cve_2024_5082"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Nexus Repository 2 - Remote Code Execution: A Remote Code Execution vulnerability has been discovered in Sonatype Nexus Repository 2.This issue affects Nexus Repository 2 OSS/Pro versions up to and including 2.15.1."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5082"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5082, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5082.yaml"
    strings:
        $path0 = /\/nexus\/service\/local\/repositories\/releases\/content\/com\/sbt\/ignite\/ignite-bom\/maven-metadata\.xml(\/|;|$)/ nocase
        $path1 = "/nexus/service/local/repositories/releases/content/.nexus/attributes/com/sbt/ignite/ignite-bom/maven-metadata.xml" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_5084_hash_form {
    meta:
        attack_type = "cve_2024_5084"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Hash Form <= 1.1.0 - Arbitrary File Upload: The Hash Form Drag & Drop Form Builder plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'file_upload_action' function in all versions up to, and including, 1.1.0. This makes it."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5084"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5084, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5084.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/uploads/hashform/temp/" ascii nocase
        $param0 = /(^|[?&;])action=hashform_file_upload_action(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_50857_gestioip {
    meta:
        attack_type = "cve_2024_50857"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "GestioIP - Reflected Cross-Site Scripting: GestioIP v3.5.7 contains a reflected cross-site scripting caused by unsanitized input in the ip_do_job request, letting attackers execute scripts in the victim's browser, exploit requires specific user permissions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-50857"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-50857, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-50857.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/gestioip\/res\/cm\/ip_do_job\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_50967_datagerry {
    meta:
        attack_type = "cve_2024_50967"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "DATAGERRY - Improper Access Control: The /rest/rights/ REST API endpoint in Becon DATAGerry through 2.2.0 contains an Incorrect Access Control vulnerability. An attacker can remotely access this endpoint without authentication, leading to unauthorized disclosure of sensitive."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-50967"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-50967, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-50967.yaml"
    strings:
        $path0 = "/rest/rights/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_51228_totolink_cx_a3002ru {
    meta:
        attack_type = "cve_2024_51228"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "TOTOLINK CX-A3002RU - Remote Code Execution: An issue in TOTOLINK-CX-A3002RU V1.0.4-B20171106.1512 and TOTOLINK-CX-N150RT V2.1.6-B20171121.1002 and TOTOLINK-CX-N300RT V2.1.6-B20170724.1420 and TOTOLINK-CX-N300RT V2.1.8-B20171113.1408 and TOTOLINK-CX-N300RT V2.1.8-B20191010.1107."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-51228"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-51228, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-51228.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])sysCmd=sleep 6(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_51482_zoneminder {
    meta:
        attack_type = "cve_2024_51482"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "ZoneMinder v1.37.* <= 1.37.64 - SQL Injection: ZoneMinder is a free, open source closed-circuit television software application. ZoneMinder v1.37.* <= 1.37.64 is vulnerable to boolean-based SQL Injection in function of web/ajax/event.php. This is fixed in 1.37.65."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-51482"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-51482, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-51482.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])view=request(&|$)/ nocase
        $param1 = /(^|[?&;])request=event(&|$)/ nocase
        $param2 = /(^|[?&;])action=removetag(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_51483_changedetection {
    meta:
        attack_type = "cve_2024_51483"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Changedetection.io <= 0.47.4 - Path Traversal: changedetection.io is free, open source web page change detection software. Prior to version 0.47.5, when a WebDriver is used to fetch files, `source-file-///etc/passwd` can be used to retrieve local system files, where the more."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-51483"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-51483, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-51483.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/form\/add\/quickwatch(\/|;|$)/ nocase
        $path1 = /\/api\/checknow(\/|;|$)/ nocase
        $path2 = "/api/v1/watch/" ascii nocase
        $param0 = /(^|[?&;])application-fetch_backend=html_webdriver(&|$)/ nocase
        $param1 = /(^|[?&;])watch_submit_button=Watch(&|$)/ nocase
        $param2 = /(^|[?&;])processor=text_json_diff(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_51568_cyberpanel {
    meta:
        attack_type = "cve_2024_51568"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CyberPanel - Command Injection: CyberPanel (aka Cyber Panel) before 2.3.5 allows Command Injection via completePath in the ProcessUtilities.outputExecutioner() sink. There is /filemanager/upload (aka File Manager upload) unauthenticated remote code execution via shell."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-51568"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-51568, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-51568.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/filemanager\/upload(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_51739_itop {
    meta:
        attack_type = "cve_2024_51739"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "iTop - User Enumeration via REST Endpoint: From the webservices/rest.php file, several operations are accessible from an unauthenticated user. One of them is `do_reset_pwd`, allowing to reset a user password. This feature can be abused to perform user enumeration when a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-51739"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-51739, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-51739.yaml"
    strings:
        $path0 = /\/webservices\/rest\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])loginop=do_reset_pwd(&|$)/ nocase
        $param1 = /(^|[?&;])auth_user=doesnotexist(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_51978_brother_printers_authenticatio {
    meta:
        attack_type = "cve_2024_51978"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Brother Printers Authentication Bypass via Default Admin Password: By leaking a target device's serial number, a remote attacker can generate the target device's default administrator password. The target device may leak its serial number via unauthenticated HTTP, HTTPS, IPP."
        mitre_attack = "T1078.001"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-51978"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-51978, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-51978.yaml"
    strings:
        $path0 = /\/general\/status\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_5230_fleetcart_4_1_1 {
    meta:
        attack_type = "cve_2024_5230"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "FleetCart 4.1.1 - Information Disclosure: Issues with information disclosure in redirect responses. Accessing the majority of the website's pages exposes sensitive data, including the 'Razorpay' 'razorpayKeyId'."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5230"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5230, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5230.yaml"
    strings:
        $path0 = /\/en\/products(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_5276_fortra_filecatalyst_workflow_v {
    meta:
        attack_type = "cve_2024_5276"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Fortra FileCatalyst Workflow <= v5.1.6 - SQL Injection: A SQL Injection vulnerability in Fortra FileCatalyst Workflow allows an attacker to modify application data. Likely impacts include creation of administrative users and deletion or modification of data in the application."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5276"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5276, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5276.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/jsp/logon.jsp;jsessionid=" ascii nocase
        $path1 = /\/servlet\/pdf_servlet(\/|;|$)/ nocase
        $path2 = /\/jsp\/logon\.jsp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_52763_ganglia_web {
    meta:
        attack_type = "cve_2024_52763"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ganglia Web Interface (v3.7.3 - v3.7.5) - Cross-Site Scripting: A cross-site scripting (XSS) vulnerability in the component /graph_all_periods.php of Ganglia-web v3.73 to v3.75 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the 'g'."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-52763"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-52763, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-52763.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/ganglia\/graph_all_periods\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_52875_kerio_control_v9_2_5 {
    meta:
        attack_type = "cve_2024_52875"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Kerio Control v9.2.5 - CRLF Injection: Kerio Control, formerly known as Kerio WinRoute Firewall, has been found vulnerable to multiple HTTP Response Splitting vulnerabilities in product affecting versions 9.2.5"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-52875"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-52875, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-52875.yaml"
    strings:
        $path0 = /\/nonauth\/guestConfirm\.cs(\/|;|$)/ nocase
        $path1 = /\/nonauth\/addCertException\.cs(\/|;|$)/ nocase
        $path2 = /\/nonauth\/expiration\.cs(\/|;|$)/ nocase
        $param0 = /(^|[?&;])dest=VGVzdA0KQ1JMRjo=(&|$)/ nocase
        $param1 = /(^|[?&;])dest=Cgo8c2NyaXB0PmFsZXJ0KGRvY3VtZW50LmRvbWFpbik8L3NjcmlwdD4=(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_5315_dolibarr_erp_crm {
    meta:
        attack_type = "cve_2024_5315"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Dolibarr ERP CMS `list.php` - SQL Injection: Vulnerabilities in Dolibarr ERP - CRM that affect version 9.0.1 and allow SQL injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5315"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5315, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5315.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/htdocs\/index\.php(\/|;|$)/ nocase
        $path1 = /\/htdocs\/commande\/list\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_5334_devika {
    meta:
        attack_type = "cve_2024_5334"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Devika - Local File Inclusion: A local file read vulnerability exists in the stitionai/devika repository, affecting the latest version. The vulnerability is due to improper handling of the 'snapshot_path' parameter in the '/api/get-browser-snapshot' endpoint. An attacker can."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5334"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5334, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5334.yaml"
        response_type = "path_traversal"
    strings:
        $param0 = /(^|[?&;])snapshot_path=\/etc\/passwd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_53704_ssl_vpn_session_hijacking {
    meta:
        attack_type = "cve_2024_53704"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "SSL VPN Session Hijacking: An Improper Authentication vulnerability in the SSLVPN authentication mechanism allows a remote attacker to bypass authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-53704"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-53704, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-53704.yaml"
    strings:
        $path0 = /\/cgi-bin\/sslvpnclient(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_5420_seh_utnserver_pro_promax_inu_1 {
    meta:
        attack_type = "cve_2024_5420"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "SEH utnserver Pro/ProMAX/INU-100 20.1.22 - Cross-Site Scripting: A vulnerability was found in utnserver Pro, utnserver ProMAX, and INU-100 version 20.1.22 and earlier, affecting the device description parameter in the web interface. This flaw allows stored cross-site scripting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5420"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5420, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5420.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/device\/description_en\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_54330_hurrakify {
    meta:
        attack_type = "cve_2024_54330"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Hurrakify <= 2.4 - Server-Side Request Forgery: The Hurrakify plugin for WordPress is vulnerable to Server-Side Request Forgery in all versions up to, and including, 2.4. This makes it possible for unauthenticated attackers to make web requests to arbitrary locations."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-54330"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-54330, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-54330.yaml"
        response_type = "cloud_metadata"
    strings:
        $param0 = /(^|[?&;])action=hurraki_tooltip_proxy(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_54763_a2004 {
    meta:
        attack_type = "cve_2024_54763"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ipTIME A2004 - Unauthorized Access: An access control issue in the component /login/hostinfo.cgi of ipTIME A2004 v12.17.0 allows attackers to obtain sensitive information without authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-54763"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-54763, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-54763.yaml"
    strings:
        $path0 = /\/login\/hostinfo\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_54764_a2004 {
    meta:
        attack_type = "cve_2024_54764"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "ipTIME A2004 - Unauthorized Access: An access control issue exists in the component /login/hostinfo2.cgi of ipTIME A2004 v12.17.0 that allows attackers to obtain sensitive information without authentication. The vulnerability allows unauthenticated access to device settings and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-54764"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-54764, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-54764.yaml"
    strings:
        $path0 = /\/login\/hostinfo2\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_54767_avm_fritz_box_7530_ax {
    meta:
        attack_type = "cve_2024_54767"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "AVM FRITZ!Box 7530 AX - Unauthorized Access: An access control issue in the component /juis_boxinfo.xml of AVM FRITZ!Box 7530 AX v7.59 allows attackers to obtain sensitive information without authentication."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-54767"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-54767, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-54767.yaml"
    strings:
        $path0 = /\/juis_boxinfo\.xml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_5488_seopress_7_9 {
    meta:
        attack_type = "cve_2024_5488"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SEOPress < 7.9 - Authentication Bypass: The SEOPress WordPress plugin before 7.9 does not properly protect some of its REST API routes, which combined with another Object Injection vulnerability can allow unauthenticated attackers to unserialize malicious gadget chains."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5488"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5488, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5488.yaml"
    strings:
        $path0 = /\/wp-json\/seopress\/v1\/posts\/1\/title-description-metas(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_5522_html5_video_player {
    meta:
        attack_type = "cve_2024_5522"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress HTML5 Video Player < 2.5.27 - SQL Injection: The HTML5 Video Player WordPress plugin before 2.5.27 does not sanitize and escape a parameter from a REST route before using it in a SQL statement, allowing unauthenticated users to perform SQL injection attacks"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5522"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5522, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5522.yaml"
        response_type = "sql_error"
    strings:
        $path0 = "/wp-json/h5vp/v1/video/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_55416_devdojo_voyager_1_8_0 {
    meta:
        attack_type = "cve_2024_55416"
        classification = "attack"
        severity = 3
        confidence = "medium"
        description = "DevDojo Voyager <=1.8.0 - Cross-Site Scripting: DevDojo Voyager through version 1.8.0 is vulnerable to reflected XSS via /admin/compass. By manipulating an authenticated user to click on a link, arbitrary Javascript can be executed."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-55416"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-55416, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-55416.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])del=PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPi5sb2c=(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_55457_mastersam_star_gate_v11 {
    meta:
        attack_type = "cve_2024_55457"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "MasterSAM Star Gate v11 - Local File Inclusion: MasterSAM Star Gate v11 is vulnerable to a directory traversal attack via the endpoint /adama/adama/downloadService. An attacker can exploit this vulnerability by manipulating the file parameter to access arbitrary files on the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-55457"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-55457, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-55457.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/adama\/adama\/downloadService(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_55550_cmg_suite {
    meta:
        attack_type = "cve_2024_55550"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Mitel MiCollab - Arbitary File Read: The Mitel Collab Arbitrary File Read vulnerability allows an unauthenticated attacker to read arbitrary files from the underlying file system on a Mitel Collab server. Exploiting this flaw involves sending specially crafted requests to the."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-55550"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-55550, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-55550.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/npm-pwg\/\.\.;\/usp\/searchUsers\.do(\/|;|$)/ nocase
        $path1 = /\/npm-pwg\/\.\.;\/ReconcileWizard\/reconcilewizard\/sc\/IDACall(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_56064_indeed_wp_superbackup {
    meta:
        attack_type = "cve_2024_56064"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WP SuperBackup <= 2.3.3 - Unauthenticated Arbitrary File Upload to RCE: The Super Backup & Clone - Migrate for WordPress plugin (indeed-wp-superbackup) is vulnerable to arbitrary file uploads due to missing file type validation and a missing capability check on the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-56064"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-56064, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-56064.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-content/uploads/isnapshots/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_56159_astro {
    meta:
        attack_type = "cve_2024_56159"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Astro - Information Disclosure: Astro versions v5.0.3 through v5.0.7 and Astro v4.16.17 or older with sourcemaps enabled contain a source code disclosure caused by sourcemap files being publicly accessible in the build output folder, letting unauthenticated users read server."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-56159"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-56159, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-56159.yaml"
    strings:
        $path0 = /\/pages\/index\.astro\.mjs\.map(\/|;|$)/ nocase
        $path1 = /\/index\.astro\.mjs\.map(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_56511_dataease {
    meta:
        attack_type = "cve_2024_56511"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "DataEase < 2.10.4 - Authentication Bypass via Whitelist Path Traversal: DataEase versions up to and including 2.10.3 contain an authentication bypass in `io.dataease.auth.filter.TokenFilter`. The filter passes the raw, unnormalized request URI to `WhitelistUtils.match()`, which."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-56511"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-56511, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-56511.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/geo\/\.\.\/de2api\/datasource\/types(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_56829_huang_yaoshi {
    meta:
        attack_type = "cve_2024_56829"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Huang Yaoshi Pharmaceutical Management Software - Unrestricted File Upload: Huang Yaoshi Pharmaceutical Management Software up to 16.0 contains an unrestricted file upload caused by accepting .asp filenames in the UploadFile element of a SOAP request to /XSDService.asmx."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-56829"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-56829, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-56829.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/XSDService\.asmx(\/|;|$)/ nocase
        $path1 = "/Upload2015/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_57049_tp_link_archer_c20 {
    meta:
        attack_type = "cve_2024_57049"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TP-Link Archer C20 - Authentication Bypass: A vulnerability in the TP-Link Archer C20 router with firmware version V6.6_230412 and earlier permits unauthorized individuals to bypass authentication on interfaces under the /cgi directory. When adding a Referer header with value."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-57049"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-57049, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-57049.yaml"
    strings:
        $path0 = /\/cgi\/getGDPRParm(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_5765_wpstickybar_2_1_0 {
    meta:
        attack_type = "cve_2024_5765"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WpStickyBar <= 2.1.0 - SQL Injection: The plugin does not properly sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5765"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5765, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5765.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=stickybar_display(&|$)/ nocase
        $param1 = /(^|[?&;])banner_id=1 AND SLEEP\(6\);(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_57727_simplehelp {
    meta:
        attack_type = "cve_2024_57727"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "SimpleHelp <= 5.5.7 - Unauthenticated Path Traversal: SimpleHelp remote support software v5.5.7 and before is vulnerable to multiple path traversal vulnerabilities that enable unauthenticated remote attackers to download arbitrary files from the SimpleHelp host via crafted HTTP."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-57727"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-57727, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-57727.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/toolbox-resource\/\.\.\/serverconfig\.xml(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_5827_vanna {
    meta:
        attack_type = "cve_2024_5827"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Vanna - SQL injection: Vanna v0.3.4 is vulnerable to SQL injection in its DuckDB integration exposed to its Flask Web APIs. Attackers can inject malicious SQL training data and generate corresponding queries to write arbitrary files on the victim's file system, such as."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5827"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5827, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5827.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/api\/v0\/train(\/|;|$)/ nocase
        $path1 = /\/api\/v0\/generate_sql(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_5910_expedition {
    meta:
        attack_type = "cve_2024_5910"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Palo Alto Expedition - Admin Account Takeover: Missing authentication for a critical function in Palo Alto Networks Expedition can lead to an Expedition admin account takeover for attackers with network access to Expedition."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5910"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5910, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5910.yaml"
    strings:
        $path0 = /\/OS\/startup\/restore\/restoreAdmin\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_5932_givewp {
    meta:
        attack_type = "cve_2024_5932"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "GiveWP - PHP Object Injection: The GiveWP Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5932"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5932, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5932.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/wp-json/wp/v2/give_forms/" ascii nocase
        $param0 = /(^|[?&;])give-price-id=custom(&|$)/ nocase
        $param1 = /(^|[?&;])give_action=purchase(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_5975_cz_loan_management {
    meta:
        attack_type = "cve_2024_5975"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "CZ Loan Management <= 1.1 - SQL Injection: The CZ Loan Management WordPress plugin through 1.1 does not properly sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-5975"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-5975, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-5975.yaml"
    strings:
        $param0 = /(^|[?&;])action=cz_plugin_for_user_get_percentage(&|$)/ nocase
        $param1 = /(^|[?&;])selectedperiod=\(select\*from\(select\(sleep\(6\)\)\)a\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_6028_quiz_maker {
    meta:
        attack_type = "cve_2024_6028"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Quiz Maker <= 6.5.8.3 - SQL Injection: The Quiz Maker plugin for WordPress is vulnerable to time-based SQL Injection via the 'ays_questions' parameter in all versions up to, and including, 6.5.8.3 due to insufficient escaping on the user supplied parameter and lack of."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6028"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6028, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6028.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])ays_quiz_questions=1,2,3(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_6095_localai {
    meta:
        attack_type = "cve_2024_6095"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "LocalAI - Partial Local File Read: A vulnerability in the /models/apply endpoint of mudler/localai versions 2.15.0 allows for Server-Side Request Forgery (SSRF) and partial Local File Inclusion (LFI). The endpoint supports both http(s)-// and file-// schemes, where the latter."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6095"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6095, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6095.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/models/jobs/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6159_push_notification_for_post_and {
    meta:
        attack_type = "cve_2024_6159"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Push Notification for Post and BuddyPress <= 1.93 - SQL Injection: Push Notification for Post and BuddyPress plugin for WordPress is vulnerable to SQL Injection via the 'onesignal_externalid' and 'onesignal_get_subscriptionoptions_id' paramters in all versions up to, and."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6159"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6159, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6159.yaml"
    strings:
        $param0 = /(^|[?&;])action=icpushcallback(&|$)/ nocase
        $param1 = /(^|[?&;])onesignal_externalid=1 AND SLEEP\(6\)(&|$)/ nocase
        $param2 = /(^|[?&;])pushtype=onesignal_subscribed_users(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_6188_tracksys {
    meta:
        attack_type = "cve_2024_6188"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "TrakSYS 11.x.x - Sensitive Data Exposure: A vulnerability was found in Parsec Automation TrackSYS 11.x.x and classified as problematic. This issue affects some unknown processing of the file /TS/export/pagedefinition. The manipulation of the argument ID leads to direct request.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6188"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6188, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6188.yaml"
    strings:
        $path0 = /\/TS\/export\/pagedefinition(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6235_netscaler_console {
    meta:
        attack_type = "cve_2024_6235"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "NetScaler Console - Sensitive Information Disclosure: Sensitive information disclosure in NetScaler Console"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6235"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6235, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6235.yaml"
    strings:
        $path0 = /\/internal\/v2\/config\/mps_secret\/ADM_SESSIONID(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6396_aim {
    meta:
        attack_type = "cve_2024_6396"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Aimhubio Aim Server 3.19.3 - Arbitrary File Overwrite: A vulnerability in the `_backup_run` function in aimhubio/aim version 3.19.3 allows remote attackers to overwrite any file on the host server and exfiltrate arbitrary data. The vulnerability arises due to improper handling."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6396"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6396, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6396.yaml"
    strings:
        $path0 = /\/tracking\/client_1\/get-resource(\/|;|$)/ nocase
        $path1 = /\/tracking\/client_1\/read-instruction(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6517_ds_cf7_math_captcha {
    meta:
        attack_type = "cve_2024_6517"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Contact Form 7 Math Captcha <= 2.0.1 - Cross-site Scripting: The Contact Form 7 Math Captcha WordPress plugin through 2.0.1 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6517"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6517, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6517.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=dscf7_refreshcaptcha(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_6555_wp_popups {
    meta:
        attack_type = "cve_2024_6555"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WP Popups - Information Disclosure: WP Popups - WordPress Popup builder plugin for WordPress contains a full path disclosure caused by using mobiledetect without access restrictions, letting unauthenticated attackers retrieve server paths, exploit requires no specific conditions."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6555"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6555, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6555.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/wp-popups-lite\/src\/vendor\/mobiledetect\/mobiledetectlib\/export\/exportToJSON\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6569_campaign_monitor_for_wordpress {
    meta:
        attack_type = "cve_2024_6569"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Campaign Monitor for WordPress - Information Disclosure: Campaign Monitor for WordPress plugin for WordPress versions up to 2.8.15 contains a full path disclosure caused by improper access restriction and enabled display_errors in /forms/views/admin/create.php, letting."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6569"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6569, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6569.yaml"
    strings:
        $path0 = /\/wp-content\/plugins\/forms-for-campaign-monitor\/forms\/views\/admin\/create\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6586_lightdash {
    meta:
        attack_type = "cve_2024_6586"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Lightdash v0.1024.6 - Server-Side Request Forgery: Server-Side Request Forgery (SSRF) in the export dashboard functionality of Lightdash version 0.1024.6 allows remote authenticated threat actors to obtain the session cookie of any user who exports a crafted dashboard. When."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6586"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6586, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6586.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/api\/v1\/org\/projects(\/|;|$)/ nocase
        $path1 = "/api/v1/projects/" ascii nocase
        $path2 = "/api/v1/dashboards/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6587_litellm {
    meta:
        attack_type = "cve_2024_6587"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "LiteLLM - Server-Side Request Forgery: LiteLLM vulnerable to Server-Side Request Forgery (SSRF) vulnerability Exposes OpenAI API Keys."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6587"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6587, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6587.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/chat\/completions(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6651_wp_file_upload {
    meta:
        attack_type = "cve_2024_6651"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WordPress File Upload Plugin < 4.24.8 - Cross-Site Scripting: The WordPress File Upload plugin before version 4.24.8 contains a reflected cross-site scripting vulnerability. The plugin does not properly sanitize and escape the 'dir' parameter in the file browser page before."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6651"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6651, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6651.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=wordpress_file_upload(&|$)/ nocase
        $param1 = /(^|[?&;])action=file_browser(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_6670_whatsup_gold {
    meta:
        attack_type = "cve_2024_6670"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "WhatsUp Gold HasErrors SQL Injection - Authentication Bypass: In WhatsUp Gold versions released before 2024.0.0, a SQL Injection vulnerability allows an unauthenticated attacker to retrieve the users encrypted password."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6670"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6670, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6670.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/NmConsole\/Platform\/PerformanceMonitorErrors\/HasErrors(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6671_whatsup_gold {
    meta:
        attack_type = "cve_2024_6671"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WhatsUp Gold GetStatisticalMonitorList SQL Injection - Authentication Bypass: In WhatsUp Gold versions released before 2024.0.0, if the application is configured with only a single user, a SQL Injection vulnerability allows an unauthenticated attacker to retrieve the users."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6671"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6671, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6671.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/NmConsole\/Platform\/Filter\/DeviceStatisticalMonitors(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6746_easyspider {
    meta:
        attack_type = "cve_2024_6746"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "EasySpider 0.6.2 - Arbitrary File Read: A vulnerability classified as problematic was found in NaiboWang EasySpider 0.6.2 on Windows. Affected by this vulnerability is an unknown functionality of the file /EasySpider/resources/app/server.js of the component HTTP GET Request."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6746"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6746, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6746.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/taskGrid\/tasklist\.html(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6753_social_auto_poster_5_3_14 {
    meta:
        attack_type = "cve_2024_6753"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Social Auto Poster <= 5.3.14 - Stored Cross-Site Scripting: Social Auto Poster plugin for WordPress versions up to 5.3.14 contains a stored cross-site scripting caused by insufficient sanitization and escaping of 'mapTypes' parameter in the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6753"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6753, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6753.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])action=wpw_auto_poster_map_wordpress_post_type(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_6845_smartsearchwp {
    meta:
        attack_type = "cve_2024_6845"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SmartSearchWP < 2.4.6 - OpenAI Key Disclosure: The plugin does not have proper authorization in one of its REST endpoint, allowing unauthenticated users to retrieve the encoded key and then decode it, thereby leaking the OpenAI API key."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6845"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6845, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6845.yaml"
    strings:
        $path0 = /\/wp-json\/wdgpt\/v1\/api-key(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6846_smartsearchwp {
    meta:
        attack_type = "cve_2024_6846"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "SmartSearchWP <= 2.4.4 - Unauthenticated Log Purge: The Chatbot with ChatGPT WordPress plugin before 2.4.5 does not validate access on some REST routes, allowing for an unauthenticated user to purge error and chat logs."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6846"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6846, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6846.yaml"
    strings:
        $path0 = /\/wp-json\/wdgpt\/v1\/purge-error-logs(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6892_journyx {
    meta:
        attack_type = "cve_2024_6892"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Journyx 11.5.4 - Reflected Cross Site Scripting: Attackers can craft a malicious link that once clicked will execute arbitrary JavaScript in the context of the Journyx web application."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6892"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6892, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6892.yaml"
        response_type = "xss"
    strings:
        $path0 = /\/jtcgi\/r\/adlogin\/sso(\/|;|$)/ nocase
        $param0 = /(^|[?&;])state=foobar(&|$)/ nocase
        $param1 = /(^|[?&;])id_token=zoinks(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_6893_journyx_jtime {
    meta:
        attack_type = "cve_2024_6893"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Journyx - XML External Entities Injection (XXE): The 'soap_cgi.pyc' API handler allows the XML body of SOAP requests to contain references to external entities. This allows an unauthenticated attacker to read local files, perform server-side request forgery, and overwhelm the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6893"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6893, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6893.yaml"
    strings:
        $path0 = /\/jtcgi\/soap_cgi\.pyc(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6911_processplus {
    meta:
        attack_type = "cve_2024_6911"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PerkinElmer ProcessPlus <= 1.11.6507.0 - Local File Inclusion: Files on the Windows system are accessible without authentication to external parties due to a local file inclusion in PerkinElmer ProcessPlus.This issue affects ProcessPlus through 1.11.6507.0."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6911"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6911, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6911.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/ProcessPlus(\/|;|$)/ nocase
        $path1 = "/ProcessPlus/Log/Download/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6922_automation_360 {
    meta:
        attack_type = "cve_2024_6922"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Automation Anywhere Automation 360 - Server-Side Request Forgery: Automation Anywhere Automation 360 v21-v32 is vulnerable to Server-Side Request Forgery in a web API component."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6922"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6922, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6922.yaml"
        response_type = "cloud_metadata"
    strings:
        $path0 = /\/v1\/proxy\/test(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_6924_truebooker {
    meta:
        attack_type = "cve_2024_6924"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "TrueBooker <= 1.0.2 - SQL Injection: The TrueBooker Appointment Booking and Scheduler Plugin. plugin for WordPress is vulnerable to SQL Injection in all versions up to, and including, 1.0.2 due to insufficient escaping on the user supplied parameter and lack of sufficient."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6924"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6924, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6924.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])tba_service_id=\(SLEEP\(6\)\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_6926_viral_signup {
    meta:
        attack_type = "cve_2024_6926"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Viral Signup <= 2.1 - SQL Injection: The Viral Signup limited opt-in with viral referral sharing plugin for WordPress is vulnerable to SQL Injection in all versions up to, and including, 2.1 due to insufficient escaping on the user supplied parameter and lack of sufficient."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6926"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6926, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6926.yaml"
    strings:
        $param0 = /(^|[?&;])idsignup=\(select\*from\(select\(sleep\(6\)\)\)a\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_6928_opti_marketing {
    meta:
        attack_type = "cve_2024_6928"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Opti Marketing <= 2.0.9 - SQL Injection: The Opti Marketing plugin for WordPress is vulnerable to SQL Injection in all versions up to, and including, 2.0.9 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-6928"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-6928, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-6928.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])action=save_article(&|$)/ nocase
        $param1 = /(^|[?&;])postId=\(select\*from\(select\(sleep\(6\)\)\)a\)(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_7008_calibre_7_15_0 {
    meta:
        attack_type = "cve_2024_7008"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Calibre <= 7.15.0 - Reflected Cross-Site Scripting (XSS): It is possible to inject arbitrary JavaScript code into the /browse endpoint of the Calibre content server, allowing an attacker to craft a URL that when clicked by a victim, will execute the attackers JavaScript code in."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7008"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7008, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7008.yaml"
        response_type = "xss"
    strings:
        $path0 = "/browse/book/TEST&quot;;window.stop();alert(document.domain);/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_7097_wso2_user_registration {
    meta:
        attack_type = "cve_2024_7097"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "WSO2 User Registration - Arbitrary Account Creation: The SOAP admin service in WSO2 products has a security vulnerability that allows the creation of new user accounts regardless of the self-registration configuration settings."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7097"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7097, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7097.yaml"
    strings:
        $path0 = "/services/UserRegistrationAdminService.UserRegistrationAdminServiceHttpsSoap11Endpoint/" ascii nocase
        $path1 = /\/services\/AuthenticationAdmin(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_7120_raisecom_msg1200_msg2100e_msg2 {
    meta:
        attack_type = "cve_2024_7120"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Raisecom MSG1200, MSG2100E, MSG2200 and MSG2300 3.90 - Command Injection: A vulnerability, which was classified as critical, was found in Raisecom MSG1200, MSG2100E, MSG2200 and MSG2300 3.90. This affects an unknown part of the file list_base_config.php of the component Web."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7120"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7120, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7120.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])parts=base_config(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_7314_report {
    meta:
        attack_type = "cve_2024_7314"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "AJ-Report < 1.4.1 - Remote Code Execution: AJ-Report before version 1.4.1 is affected by an authentication bypass vulnerability. A remote and unauthenticated attacker can append ';swagger-ui' to HTTP requests to bypass authentication and execute arbitrary Java code on the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7314"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7314, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7314.yaml"
        response_type = "command_injection"
    strings:
        $path0 = "/dataSetParam/verification;swagger-ui/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_7332_cp450_firmware {
    meta:
        attack_type = "cve_2024_7332"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "TOTOLINK CP450 v4.1.0cu.747_B20191224 - Hard-Coded Password Vulnerability: A critical vulnerability has been discovered in TOTOLINK CP450 version 4.1.0cu.747_B20191224. This vulnerability affects an unknown part of the file /web_cste/cgi-bin/product.ini of the Telnet Service."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7332"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7332, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7332.yaml"
    strings:
        $path0 = /\/web_cste\/cgi-bin\/product\.ini(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_7339_tvt_dvr_sensitive_device {
    meta:
        attack_type = "cve_2024_7339"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "TVT DVR Sensitive Device - Information Disclosure: A vulnerability has been found in TVT DVR TD-2104TS-CL, DVR TD-2108TS-HP, Provision-ISR DVR SH-4050A5-5L(MM) and AVISION DVR AV108T and classified as problematic. This vulnerability affects unknown code of the file."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7339"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7339, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7339.yaml"
    strings:
        $path0 = /\/queryDevInfo(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_7340_w_b_weave_server {
    meta:
        attack_type = "cve_2024_7340"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "W&B Weave Server - Remote Arbitrary File Leak: The Weave server API allows remote users to fetch files from a specific directory, but due to a lack of input validation, it is possible to traverse and leak arbitrary files remotely. In various common scenarios, this allows a."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7340"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7340, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7340.yaml"
    strings:
        $path0 = /\/__weave\/file\/tmp\/weave\/fs\/\.\.\/\.\.\/\.\.\/etc\/passwd(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_7354_ninja_forms {
    meta:
        attack_type = "cve_2024_7354"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Ninja Forms 3.8.6-3.8.10 - Cross-Site Scripting: The Ninja Forms WordPress plugin before 3.8.11 does not escape an URL before outputting it back in an attribute, leading to a Reflected Cross-Site Scripting which could be used against high privilege users such as admin"
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7354"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7354, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7354.yaml"
        response_type = "xss"
    strings:
        $param0 = /(^|[?&;])page=nf-submissions(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_7399_magicinfo_9_server {
    meta:
        attack_type = "cve_2024_7399"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Samsung MagicINFO 9 Server 21.1050.0 - Remote Code Execution: Improper limitation of a pathname to a restricted directory vulnerability in Samsung MagicINFO 9 Server version before 21.1050 allows attackers to write arbitrary file as system authority."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7399"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7399, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7399.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])byte\[\] decodedBytes=Base64\.getDecoder\(\)\.decode\(base64Input\);(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_7591_loadmaster {
    meta:
        attack_type = "cve_2024_7591"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Kemp LoadMaster Load Balancer - Unauthenticated Command Injection: Improper Input Validation vulnerability in Progress LoadMaster allows OS Command Injection.This issue affects: LoadMaster: 7.2.40.0 and above. ECS: All versions.Multi-Tenancy: 7.1.35.4 and above."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7591"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7591, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7591.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/progs\/homepage(\/|;|$)/ nocase
        $path1 = /\/progs\/status\/login(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_7593_virtual_traffic_manager {
    meta:
        attack_type = "cve_2024_7593"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "Ivanti vTM - Authentication Bypass: Incorrect implementation of an authentication algorithm in Ivanti vTM other than versions 22.2R1 or 22.7R2 allows a remote unauthenticated attacker to bypass authentication of the admin panel."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7593"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7593, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7593.yaml"
    strings:
        $path0 = /\/apps\/zxtm\/wizard\.fcgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_7714_ays_chatgpt_assistant {
    meta:
        attack_type = "cve_2024_7714"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "AI Assistant with ChatGPT by AYS <= 2.0.9 - Unauthenticated AJAX Calls: The plugin lacks sufficient access controls allowing an unauthenticated user to disconnect the plugin from OpenAI, thereby disabling the plugin. Multiple actions are accessible: ays_chatgpt_disconnect."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7714"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7714, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7714.yaml"
    strings:
        $param0 = /(^|[?&;])function=ays_chatgpt_disconnect(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_7786_sensei_lms {
    meta:
        attack_type = "cve_2024_7786"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Sensei LMS < 4.24.2 - Email Template Leak: The Sensei LMS WordPress plugin before 4.24.2 does not properly protect some its REST API routes, allowing unauthenticated attackers to leak email templates."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7786"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7786, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7786.yaml"
    strings:
        $path0 = "/index.php/wp-json/wp/v2/sensei_email/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_7954_spip {
    meta:
        attack_type = "cve_2024_7954"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "SPIP Porte Plume Plugin - Remote Code Execution: The porte_plume plugin used by SPIP before 4.30-alpha2, 4.2.13, and 4.1.16 is vulnerable to an arbitrary code execution vulnerability. A remote and unauthenticated attacker can execute arbitrary PHP as the SPIP user by sending a."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-7954"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-7954, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-7954.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])action=porte_plume_previsu(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_8353_givewp {
    meta:
        attack_type = "cve_2024_8353"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "GiveWP Donation Plugin <= 3.16.1 - Unauthenticated PHP Object Injection: The GiveWP Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.16.1. This is due to insufficient input validation on."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-8353"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-8353, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-8353.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])give-gateway=offline(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_8425_woocommerce_ultimate_gift_card {
    meta:
        attack_type = "cve_2024_8425"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WooCommerce Ultimate Gift Card 2.6.0 - Arbitrary File Upload: The WooCommerce Ultimate Gift Card plugin for WordPress is vulnerable to arbitrary file uploads due to insufficient file type validation in the 'mwb_wgm_preview_mail' and 'mwb_wgm_woocommerce_add_cart_item_data'."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-8425"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-8425, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-8425.yaml"
    strings:
        $path0 = "/wp-content/uploads/mwb_browse/" ascii nocase
        $param0 = /(^|[?&;])action=mwb_wgm_preview_mail(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_8503_vicidial {
    meta:
        attack_type = "cve_2024_8503"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "VICIdial - SQL Injection: An unauthenticated attacker can leverage a time-based SQL injection vulnerability in VICIdial to enumerate database records. By default, VICIdial stores plaintext credentials within the database."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-8503"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-8503, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-8503.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/vicidial\/welcome\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_8698_keycloak {
    meta:
        attack_type = "cve_2024_8698"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Keycloak - SAML Core Package Signature Validation Flaw: A flaw exists in the SAML signature validation method within the Keycloak XMLSignatureUtil class. The method incorrectly determines whether a SAML signature is for the full document or only for specific assertions based on."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-8698"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-8698, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-8698.yaml"
    strings:
        $path0 = /\/realms\/master\/broker\/saml\/endpoint(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_8856_wp_time_capsule_plugin {
    meta:
        attack_type = "cve_2024_8856"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WP Time Capsule Plugin - Remote Code Execution: The Backup and Staging by WP Time Capsule plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the the UploadHandler.php file and no direct file access prevention in all versions up."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-8856"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-8856, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-8856.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/wp-content\/plugins\/wp-time-capsule\/wp-tcapsule-bridge\/upload\/php\/index\.php(\/|;|$)/ nocase
        $path1 = "/wp-content/plugins/wp-time-capsule/wp-tcapsule-bridge/upload/php/files/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_8877_netman_204_firmware {
    meta:
        attack_type = "cve_2024_8877"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Riello Netman 204 - SQL Injection: The three endpoints /cgi-bin/db_datalog_w.cgi, /cgi-bin/db_eventlog_w.cgi, and /cgi-bin/db_multimetr_w.cgi are vulnerable to SQL injection without prior authentication. This enables an attacker to modify the collected log data in an arbitrary."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-8877"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-8877, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-8877.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/cgi-bin\/db_eventlog_w\.cgi(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_8883_keycloak {
    meta:
        attack_type = "cve_2024_8883"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "Keycloak - Open Redirect: A misconfiguration flaw was found in Keycloak. This issue can allow an attacker to redirect users to an arbitrary URL if a 'Valid Redirect URI' is set to http://localhost or http://127.0.0.1, enabling sensitive information such as authorization codes."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-8883"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-8883, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-8883.yaml"
    strings:
        $path0 = /\/realms\/master\/protocol\/openid-connect\/auth(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_8911_latepoint {
    meta:
        attack_type = "cve_2024_8911"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LatePoint <= 5.0.11 - SQL Injection: The LatePoint plugin for WordPress is vulnerable to Arbitrary User Password Change via SQL Injection in versions up to, and including, 5.0.11. This is due to insufficient escaping on the user supplied parameter and lack of sufficient."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-8911"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-8911, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-8911.yaml"
        response_type = "sql_error"
    strings:
        $param0 = /(^|[?&;])route_name=customer_cabinet__change_password(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_8943_latepoint {
    meta:
        attack_type = "cve_2024_8943"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "LatePoint <= 5.0.12 - Authentication Bypass: LatePoint plugin for WordPress versions up to 5.0.12 contains an authentication bypass caused by insufficient verification of user during booking, letting unauthenticated attackers log in as any existing user if they have user ID."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-8943"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-8943, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-8943.yaml"
    strings:
        $param0 = /(^|[?&;])route_name=steps__load_step(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_9007_123solar {
    meta:
        attack_type = "cve_2024_9007"
        classification = "attack"
        severity = 5
        confidence = "medium"
        description = "123Solar 1.8.4.5 - Cross-Site Scripting: 123Solar 1.8.4.5 is vulnerable to reflected cross-site scripting (XSS) via the date1 parameter in detailed.php. Unsanitized user input is reflected in the response, allowing arbitrary JavaScript execution."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9007"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9007, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9007.yaml"
        response_type = "xss"
    strings:
        $path0 = "/123solar/" ascii nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_9047_wordpress_file_upload {
    meta:
        attack_type = "cve_2024_9047"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress File Upload <= 4.24.11 - Arbitrary File Read: The WordPress File Upload plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 4.24.11 via wfu_file_downloader.php. This makes it possible for unauthenticated attackers to read or."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9047"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9047, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9047.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/wp-content\/plugins\/wp-file-upload\/wfu_file_downloader\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])handler=dboption(&|$)/ nocase
        $param1 = /(^|[?&;])dboption_base=cookies(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_9061_wp_popup_builder {
    meta:
        attack_type = "cve_2024_9061"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "WP Popup Builder Popup Forms and Marketing Lead Generation <= 1.3.5 - Arbitrary Shortcode Execution: The The WP Popup Builder Popup Forms and Marketing Lead Generation plugin for WordPress is vulnerable to arbitrary shortcode execution via the wp_ajax_nopriv_shortcode_Api_Add."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9061"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9061, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9061.yaml"
    strings:
        $param0 = /(^|[?&;])action=shortcode_Api_Add(&|$)/ nocase
        $param1 = /(^|[?&;])shortcode=CVE-2024-9061(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_9193_whmpress_6_3_revision_0 {
    meta:
        attack_type = "cve_2024_9193"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WHMpress <= 6.3-revision-0 - Unauthenticated Local File Inclusion to Arbitrary Options Update: The WHMpress - WHMCS WordPress Integration Plugin plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 6.3-revision-0 via the."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9193"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9193, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9193.yaml"
    strings:
        $param0 = /(^|[?&;])action=whmpress_action(&|$)/ nocase
        $param1 = /(^|[?&;])do=whmpress_domain_search_ajax_extended_results(&|$)/ nocase
        $param2 = /(^|[?&;])params\[style\]=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/usr\/local\/lib\/php\/pearcmd(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_9234_gutenkit {
    meta:
        attack_type = "cve_2024_9234"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "GutenKit <= 2.1.0 - Arbitrary File Upload: The GutenKit Page Builder Blocks, Patterns, and Templates for Gutenberg Block Editor plugin for WordPress is vulnerable to arbitrary file uploads due to a missing capability check on the install_and_activate_plugin_from_external()."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9234"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9234, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9234.yaml"
    strings:
        $path0 = /\/wp-json\/gutenkit\/v1\/install-active-plugin(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_9264_grafana {
    meta:
        attack_type = "cve_2024_9264"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Grafana Post-Auth DuckDB - SQL Injection To File Read: The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9264"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9264, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9264.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/api\/ds\/query(\/|;|$)/ nocase
        $param0 = /(^|[?&;])ds_type=__expr__(&|$)/ nocase
        $param1 = /(^|[?&;])requestId=Q101(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_9362_polyaxon {
    meta:
        attack_type = "cve_2024_9362"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Polyaxon - Unauthenticated Directory Traversal: Polyaxon latest version contains a path traversal caused by insufficient validation in directory access, letting unauthenticated attackers retrieve directory information and file contents, exploit requires no authentication."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9362"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9362, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9362.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = /\/streams\/v1\/polyaxon\/default\/s\/runs\/\.\.\/artifact(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_9463_expedition {
    meta:
        attack_type = "cve_2024_9463"
        classification = "attack"
        severity = 10
        confidence = "medium"
        description = "PaloAlto Networks Expedition - Remote Code Execution: An OS command injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to run arbitrary OS commands as root in Expedition, resulting in disclosure of usernames, cleartext passwords, device."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9463"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9463, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9463.yaml"
        response_type = "command_injection"
    strings:
        $path0 = /\/API\/convertCSVtoParquet\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_9465_expedition {
    meta:
        attack_type = "cve_2024_9465"
        classification = "attack"
        severity = 8
        confidence = "medium"
        description = "Palo Alto Expedition - SQL Injection: An SQL injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to reveal Expedition database contents, such as password hashes, usernames, device configurations, and device API keys. With this, attackers."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9465"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9465, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9465.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/bin\/configurations\/parsers\/Checkpoint\/CHECKPOINT\.php(\/|;|$)/ nocase
        $param0 = /(^|[?&;])type=existing_ruleBases(&|$)/ nocase
        $param1 = /(^|[?&;])project=pandbRBAC(&|$)/ nocase
        $param2 = /(^|[?&;])signatureid=1 AND \(SELECT 1234 FROM \(SELECT\(SLEEP\(6\)\)\)test\)(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_9593_time_clock_time_clock_pro {
    meta:
        attack_type = "cve_2024_9593"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "Time Clock <= 1.2.2 & Time Clock Pro <= 1.1.4 - Remote Code Execution: The Time Clock plugin and Time Clock Pro plugin for WordPress are vulnerable to Remote Code Execution in versions up to, and including, 1.2.2 (for Time Clock) and 1.1.4 (for Time Clock Pro) via the."
        mitre_attack = "T1190, T1059"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9593"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9593, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9593.yaml"
        response_type = "command_injection"
    strings:
        $param0 = /(^|[?&;])action=etimeclockwp_load_function(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_9643_f3x36 {
    meta:
        attack_type = "cve_2024_9643"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Four-Faith F3x36 - Authentication Bypass: Four-Faith F3x36 router with firmware v2.0.0 contains an authentication bypass caused by hard-coded credentials in the administrative web server, letting attackers with knowledge of credentials gain administrative access via crafted."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9643"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9643, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9643.yaml"
    strings:
        $path0 = /\/Status_Router\.asp(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_9796_wp_advanced_search {
    meta:
        attack_type = "cve_2024_9796"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "WordPress WP-Advanced-Search <= 3.3.9 - SQL Injection: The WordPress WP-Advanced-Search plugin for WordPress is vulnerable to SQL Injection in all versions up to, and including, 3.3.9 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation."
        mitre_attack = "T1190"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9796"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9796, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9796.yaml"
        response_type = "sql_error"
    strings:
        $path0 = /\/wp-content\/plugins\/wp-advanced-search\/class\.inc\/autocompletion\/autocompletion-PHP5\.5\.php(\/|;|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*))
}

rule krawl_cve_2024_9935_pdf_generator_addon_for_elemen {
    meta:
        attack_type = "cve_2024_9935"
        classification = "attack"
        severity = 7
        confidence = "medium"
        description = "PDF Generator Addon for Elementor Page Builder <= 1.7.5 - Arbitrary File Download: The PDF Generator Addon for Elementor Page Builder plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 1.7.5 via the rtw_pgaepb_dwnld_pdf() function. This."
        mitre_attack = "T1190, T1083"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9935"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9935, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9935.yaml"
        response_type = "path_traversal"
    strings:
        $path0 = "/elementor-84/" ascii nocase
        $param0 = /(^|[?&;])rtw_pdf_file=\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd(&|$)/ nocase
    condition:
        (scan_target == "path" and any of ($path*)) or ((scan_target == "query" or scan_target == "body") and any of ($param*))
}

rule krawl_cve_2024_9989_crypto_tool {
    meta:
        attack_type = "cve_2024_9989"
        classification = "attack"
        severity = 9
        confidence = "medium"
        description = "Crypto <= 2.15 - Authentication Bypass: The Crypto plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 2.15. This is due a to limited arbitrary method call to 'crypto_connect_ajax_process::log_in' function in the."
        mitre_attack = "T1190, T1078"
        version = "1.0"
        date = "2026-10-27"
        modified = "2026-10-27"
        author = "Krawl (indicators from nuclei-templates)"
        false_positives = "Requests to a real installation of the product; a honeypot does not run it."
        cve = "CVE-2024-9989"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-9989, https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-9989.yaml"
    strings:
        $param0 = /(^|[?&;])action=crypto_connect_ajax_process(&|$)/ nocase
    condition:
        ((scan_target == "query" or scan_target == "body") and any of ($param*))
}
